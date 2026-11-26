import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import PasswordHealth from "@/pages/PasswordHealth";
import {
  analyzePasswordStrengthLocal,
  checkPwnedPassword,
  findMatchingPwnedSuffixCount,
  sha1HexUpper,
  splitKAnonymityHash,
} from "@/utils/passwordStrength";

describe("Client-Side Password Health & HIBP k-Anonymity (P1-A)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("handles empty password and weak/common/repeated patterns locally", () => {
    const empty = analyzePasswordStrengthLocal("");
    expect(empty.score).toBe(0);
    expect(empty.suggestions).toEqual([]);

    const common = analyzePasswordStrengthLocal("password123");
    expect(common.score).toBe(0);
    expect(common.isCommon).toBe(true);

    const repeated = analyzePasswordStrengthLocal("aaaaaaaa1111");
    expect(repeated.score).toBeLessThanOrEqual(2);
    expect(repeated.suggestions.some((s) => s.toLowerCase().includes("repeating"))).toBe(true);
  });

  it("scores strong passwords and long passphrases appropriately", () => {
    const strong = analyzePasswordStrengthLocal("T!g3r#M0untain$2026");
    expect(strong.score).toBeGreaterThanOrEqual(3);
    expect(strong.isCommon).toBe(false);

    const passphrase = analyzePasswordStrengthLocal("correct-horse-battery-staple-river");
    expect(passphrase.score).toBeGreaterThanOrEqual(3);
    expect(["strong", "very strong"]).toContain(passphrase.label);
  });

  it("computes SHA-1 hex and splits 5-char k-anonymity prefix/suffix", async () => {
    // Known test string: "abc" -> SHA-1 A9993E364706816ABA3E25717850C26C9CD0D89D
    const digest = await sha1HexUpper("abc");
    expect(digest).toBe("A9993E364706816ABA3E25717850C26C9CD0D89D");

    const { prefix, suffix } = splitKAnonymityHash(digest);
    expect(prefix).toBe("A9993");
    expect(suffix).toBe("E364706816ABA3E25717850C26C9CD0D89D");
  });

  it("matches HIBP suffix and ignores Add-Padding zero-count entries", async () => {
    const hash = await sha1HexUpper("test-pwned-candidate-123");
    const { prefix, suffix } = splitKAnonymityHash(hash);

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => `${suffix}:0\nOTHERHASH123:42\n${suffix}:17\n`,
    });

    // Zero-count padding entry alone must NOT count as breached
    expect(findMatchingPwnedSuffixCount(`${suffix}:0\n`, suffix)).toBe(0);

    const res = await checkPwnedPassword("test-pwned-candidate-123", mockFetch as unknown as typeof fetch);
    expect(res.status).toBe("pwned");
    expect(res.count).toBe(17);

    // Verify ONLY the 5-char prefix is sent and Add-Padding: true is included
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = mockFetch.mock.calls[0];
    expect(calledUrl).toBe(`https://api.pwnedpasswords.com/range/${prefix}`);
    expect(calledUrl).not.toContain(suffix);
    expect(calledUrl).not.toContain("test-pwned-candidate-123");
    expect(calledInit.headers["Add-Padding"]).toBe("true");
  });

  it("returns safe status when no suffix matches and unavailable on network/rate-limit errors", async () => {
    const safeFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:0\n",
    });
    const safeRes = await checkPwnedPassword("Unique!Passphrase#2026", safeFetch as unknown as typeof fetch);
    expect(safeRes.status).toBe("safe");
    expect(safeRes.count).toBe(0);

    const errFetch = vi.fn().mockRejectedValue(new Error("Network down"));
    const errRes = await checkPwnedPassword("Unique!Passphrase#2026", errFetch as unknown as typeof fetch);
    expect(errRes.status).toBe("unavailable");
    expect(errRes.count).toBeNull();
    expect(errRes.message.toLowerCase()).not.toContain("not breached");

    const rateFetch = vi.fn().mockResolvedValue({ ok: false, status: 429 });
    const rateRes = await checkPwnedPassword("Unique!Passphrase#2026", rateFetch as unknown as typeof fetch);
    expect(rateRes.status).toBe("unavailable");
  });

  it("performs zero network requests during typing, never calls Infora API, and never stores passwords", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0\n",
    } as Response);
    const apiPostSpy = vi.spyOn(api, "post");

    render(<PasswordHealth />);
    expect(
      screen.getByText(/Your password is checked locally on this device/i)
    ).toBeInTheDocument();

    const input = screen.getByLabelText(/Try a password or passphrase/i);
    fireEvent.change(input, { target: { value: "My!Test#Passphrase2026" } });

    // Local strength updates immediately with ZERO network requests
    expect(screen.getByText(/4\/4/)).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(apiPostSpy).not.toHaveBeenCalled();

    // Trigger HIBP k-anonymity check explicitly
    fireEvent.click(screen.getByRole("button", { name: /Check breach exposure/i }));

    await waitFor(() => {
      expect(screen.getByText(/No breach match found/i)).toBeInTheDocument();
    });

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(apiPostSpy).not.toHaveBeenCalled();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});
