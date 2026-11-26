import { useEffect, useState } from "react";

import { Card } from "@/components/Card";
import {
  analyzePasswordStrengthLocal,
  checkPwnedPassword,
  type LocalPasswordStrengthResult,
  type PwnedCheckResult,
  type PwnedCheckStatus,
} from "@/utils/passwordStrength";

const LABEL_COLOR: Record<string, string> = {
  "very weak": "bg-risk-high",
  weak: "bg-risk-high",
  fair: "bg-risk-medium",
  strong: "bg-risk-low",
  "very strong": "bg-risk-low",
};

export default function PasswordHealth() {
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<LocalPasswordStrengthResult | null>(null);
  const [pwnedStatus, setPwnedStatus] = useState<PwnedCheckStatus>("idle");
  const [pwnedResult, setPwnedResult] = useState<PwnedCheckResult | null>(null);

  // Clear password and derived results from component state on unmount
  useEffect(() => {
    return () => {
      setPassword("");
      setResult(null);
      setPwnedStatus("idle");
      setPwnedResult(null);
    };
  }, []);

  function handleChange(value: string) {
    setPassword(value);
    setPwnedStatus("idle");
    setPwnedResult(null);
    if (!value) {
      setResult(null);
      return;
    }
    setResult(analyzePasswordStrengthLocal(value));
  }

  async function handlePwnedCheck() {
    if (!password || pwnedStatus === "checking") return;
    setPwnedStatus("checking");
    setPwnedResult(null);
    const res = await checkPwnedPassword(password);
    setPwnedResult(res);
    setPwnedStatus(res.status);
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-slate-100">Password Health</h1>
        <p className="mt-1 text-sm text-slate-400">
          Your password is checked locally on this device. Infora never receives or stores it. For
          breach checking, only the first five characters of its SHA-1 hash are sent to Have I Been
          Pwned.
        </p>
      </div>

      <Card className="space-y-4 border-slate-800/80 bg-surface-raised/90">
        <div>
          <label className="mb-1.5 block text-sm font-medium text-slate-200" htmlFor="pw">
            Try a password or passphrase
          </label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              id="pw"
              type="password"
              autoComplete="off"
              value={password}
              onChange={(e) => handleChange(e.target.value)}
              placeholder="Type a password to test its strength"
              className="flex-1 rounded-lg border border-slate-700 bg-surface px-3 py-2 text-sm text-slate-100 focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500"
            />
            <button
              type="button"
              disabled={!password || pwnedStatus === "checking"}
              onClick={handlePwnedCheck}
              className="shrink-0 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {pwnedStatus === "checking" ? "Checking…" : "Check breach exposure"}
            </button>
          </div>
        </div>

        {result && (
          <div className="space-y-3 border-t border-slate-800 pt-4">
            <div>
              <div className="mb-1.5 flex justify-between text-sm">
                <span className="font-medium capitalize text-slate-200">{result.label}</span>
                <span className="font-mono text-xs text-slate-400">{result.score}/4</span>
              </div>
              <div className="flex gap-1.5">
                {[0, 1, 2, 3].map((i) => (
                  <div
                    key={i}
                    className={`h-2 flex-1 rounded-full ${
                      i < result.score ? LABEL_COLOR[result.label] : "bg-slate-800"
                    }`}
                  />
                ))}
              </div>
            </div>

            {result.isCommon && (
              <p className="rounded-lg bg-risk-high/10 p-3 text-sm font-medium text-risk-high">
                This is one of the most commonly breached passwords. Avoid it entirely.
              </p>
            )}

            <ul className="list-inside list-disc space-y-1 text-sm text-slate-300">
              {result.suggestions.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
          </div>
        )}

        {pwnedStatus === "checking" && (
          <div role="status" className="rounded-lg border border-slate-800 bg-surface/60 p-3 text-sm text-slate-300">
            Checking Have I Been Pwned using k-anonymity (5-character SHA-1 prefix only)…
          </div>
        )}

        {pwnedResult && pwnedStatus !== "checking" && (
          <div
            role={pwnedResult.status === "pwned" ? "alert" : "status"}
            className={`rounded-lg border p-3.5 text-sm ${
              pwnedResult.status === "pwned"
                ? "border-risk-high/40 bg-risk-high/10 text-risk-high"
                : pwnedResult.status === "safe"
                  ? "border-risk-low/40 bg-risk-low/10 text-risk-low"
                  : "border-risk-medium/40 bg-risk-medium/10 text-risk-medium"
            }`}
          >
            <p className="font-semibold">
              {pwnedResult.status === "pwned"
                ? `Compromised password match (${pwnedResult.count?.toLocaleString()} exposures)`
                : pwnedResult.status === "safe"
                  ? "No breach match found"
                  : "Breach check unavailable"}
            </p>
            <p className="mt-1 text-xs opacity-90">{pwnedResult.message}</p>
          </div>
        )}
      </Card>
    </div>
  );
}
