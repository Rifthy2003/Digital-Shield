/**
 * Browser-side password strength & privacy-preserving HIBP Pwned Passwords
 * k-anonymity check (Phase P1-A).
 *
 * Privacy guarantees:
 * - Strength analysis runs 100% locally in browser memory with zero network calls.
 * - For breach checking, SHA-1 is computed via Web Crypto API and ONLY the first
 *   5 hex characters (prefix) are sent to `https://api.pwnedpasswords.com/range/{prefix}`
 *   with `Add-Padding: true`.
 * - Plaintext passwords and full SHA-1 hashes are never stored, logged, or sent
 *   to the Infora backend.
 */

export type StrengthLabel = "very weak" | "weak" | "fair" | "strong" | "very strong";

export interface LocalPasswordStrengthResult {
  score: 0 | 1 | 2 | 3 | 4;
  label: StrengthLabel;
  isCommon: boolean;
  suggestions: string[];
}

export type PwnedCheckStatus = "idle" | "checking" | "safe" | "pwned" | "unavailable";

export interface PwnedCheckResult {
  status: Exclude<PwnedCheckStatus, "idle" | "checking">;
  count: number | null;
  message: string;
}

const HIBP_RANGE_API = "https://api.pwnedpasswords.com/range/";
const HIBP_TIMEOUT_MS = 8000;

const COMMON_PASSWORDS = new Set([
  "password",
  "123456",
  "12345678",
  "123456789",
  "qwerty",
  "abc123",
  "password1",
  "password123",
  "passw0rd",
  "qwerty123",
  "111111",
  "123123",
  "letmein",
  "welcome",
  "admin",
  "iloveyou",
  "changeme",
  "football",
  "monkey",
  "dragon",
  "baseball",
  "sunshine",
  "princess",
]);

const SEQUENTIAL_PATTERNS = [
  "012345",
  "123456",
  "234567",
  "345678",
  "456789",
  "abcdef",
  "qwerty",
  "asdfgh",
  "zxcvbn",
];

export function analyzePasswordStrengthLocal(password: string): LocalPasswordStrengthResult {
  if (!password) {
    return {
      score: 0,
      label: "very weak",
      isCommon: false,
      suggestions: [],
    };
  }

  const lower = password.toLowerCase();
  const isCommon = COMMON_PASSWORDS.has(lower);
  const suggestions: string[] = [];

  const hasLower = /[a-z]/.test(password);
  const hasUpper = /[A-Z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSymbol = /[^a-zA-Z0-9]/.test(password);
  const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

  const hasRepeatedRun = /(.)\1{3,}/.test(password);
  const lowUniqueChars = password.length >= 6 && new Set(lower).size <= 3;
  const hasSequence = SEQUENTIAL_PATTERNS.some((seq) => lower.includes(seq));

  // Long passphrases (e.g., multiple words separated by spaces/hyphens)
  const wordTokens = password.trim().split(/[\s\-_]+/).filter((t) => t.length >= 2);
  const isLongPassphrase = password.length >= 18 && wordTokens.length >= 3 && !lowUniqueChars;

  let raw = 0;
  if (password.length >= 20) raw += 2.6;
  else if (password.length >= 16) raw += 2.1;
  else if (password.length >= 12) raw += 1.5;
  else if (password.length >= 8) raw += 0.8;

  raw += variety * 0.4;
  if (isLongPassphrase) {
    raw += 0.8;
  }

  if (isCommon) {
    raw = 0;
    suggestions.push("This is one of the most commonly breached passwords — avoid it entirely.");
  }
  if (password.length < 12) {
    suggestions.push("Use at least 12 characters (16+ or a multi-word passphrase is even stronger).");
  }
  if (!isLongPassphrase && variety < 3) {
    suggestions.push("Mix uppercase, lowercase, numbers, and symbols — or use a longer passphrase.");
  }
  if (hasRepeatedRun || lowUniqueChars) {
    raw -= 1.5;
    suggestions.push("Avoid repeating the same character multiple times.");
  }
  if (hasSequence) {
    raw -= 1.0;
    suggestions.push("Avoid predictable keyboard or numeric sequences (like 123456 or qwerty).");
  }

  if (suggestions.length === 0 && !isCommon) {
    suggestions.push("Looks strong. Avoid reusing this password on other accounts.");
  }

  const clamped = isCommon ? 0 : (Math.max(0, Math.min(4, Math.round(raw))) as 0 | 1 | 2 | 3 | 4);
  const labels: Record<0 | 1 | 2 | 3 | 4, StrengthLabel> = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "very strong",
  };

  return {
    score: clamped,
    label: labels[clamped],
    isCommon,
    suggestions,
  };
}

export async function sha1HexUpper(input: string): Promise<string> {
  if (typeof globalThis.crypto?.subtle?.digest !== "function") {
    throw new Error("Web Crypto API SHA-1 is unavailable in this browser.");
  }
  const encoded = new TextEncoder().encode(input);
  const buffer = await globalThis.crypto.subtle.digest("SHA-1", encoded);
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export function splitKAnonymityHash(sha1Upper: string): { prefix: string; suffix: string } {
  return {
    prefix: sha1Upper.slice(0, 5),
    suffix: sha1Upper.slice(5),
  };
}

export function findMatchingPwnedSuffixCount(rangeBody: string, suffix: string): number {
  const target = suffix.toUpperCase();
  const lines = rangeBody.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const colonIdx = trimmed.indexOf(":");
    if (colonIdx <= 0) continue;
    const lineSuffix = trimmed.slice(0, colonIdx).trim().toUpperCase();
    const count = Number.parseInt(trimmed.slice(colonIdx + 1).trim(), 10);
    // Ignore HIBP Add-Padding dummy entries (count === 0)
    if (!Number.isFinite(count) || count <= 0) continue;
    if (lineSuffix === target) {
      return count;
    }
  }
  return 0;
}

export async function checkPwnedPassword(
  password: string,
  fetchFn: typeof fetch = globalThis.fetch,
): Promise<PwnedCheckResult> {
  if (!password) {
    return {
      status: "unavailable",
      count: null,
      message: "Enter a password first to check breach exposure.",
    };
  }

  let prefix: string;
  let suffix: string;
  try {
    const hash = await sha1HexUpper(password);
    ({ prefix, suffix } = splitKAnonymityHash(hash));
  } catch {
    return {
      status: "unavailable",
      count: null,
      message: "Browser cryptography is unavailable; cannot run breach check safely.",
    };
  }

  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), HIBP_TIMEOUT_MS) : null;

  try {
    const resp = await fetchFn(`${HIBP_RANGE_API}${prefix}`, {
      method: "GET",
      headers: {
        "Add-Padding": "true",
      },
      signal: controller?.signal,
    });

    if (resp.status === 429) {
      return {
        status: "unavailable",
        count: null,
        message: "Breach check rate-limited by Have I Been Pwned. Please wait a moment and try again.",
      };
    }

    if (!resp.ok) {
      return {
        status: "unavailable",
        count: null,
        message: "Have I Been Pwned breach check is currently unavailable.",
      };
    }

    const body = await resp.text();
    const count = findMatchingPwnedSuffixCount(body, suffix);
    if (count > 0) {
      return {
        status: "pwned",
        count,
        message: `Found in ${count.toLocaleString()} known data breach record${count === 1 ? "" : "s"}. Change this password anywhere it is reused.`,
      };
    }

    return {
      status: "safe",
      count: 0,
      message: "No match found in Have I Been Pwned known password breaches.",
    };
  } catch {
    return {
      status: "unavailable",
      count: null,
      message: "Unable to reach Have I Been Pwned right now. Breach status could not be verified.",
    };
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}
