import { useEffect, useRef, useState, type FormEvent } from "react";

import { checkBreach } from "@/api/endpoints";
import type { BreachCheckResult } from "@/api/types";
import { Card } from "@/components/Card";
import {
  checkPwnedPassword,
  type PwnedCheckResult,
  type PwnedCheckStatus,
} from "@/utils/passwordStrength";

export default function BreachChecker() {
  // --- Email Breach Checker state ---
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<BreachCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // --- Password Breach Checker state ---
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [pwStatus, setPwStatus] = useState<PwnedCheckStatus>("idle");
  const [pwResult, setPwResult] = useState<PwnedCheckResult | null>(null);
  const pwCheckingRef = useRef(false);

  useEffect(() => {
    return () => {
      setPassword("");
      setShowPassword(false);
      setPwStatus("idle");
      setPwResult(null);
      pwCheckingRef.current = false;
    };
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      setResult(await checkBreach(email));
    } catch {
      setError("Could not run the breach check.");
    } finally {
      setLoading(false);
    }
  }

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    if (!password || pwCheckingRef.current || pwStatus === "checking") return;
    const candidate = password;
    pwCheckingRef.current = true;
    setPwStatus("checking");
    setPwResult(null);
    try {
      const res = await checkPwnedPassword(candidate);
      setPwResult(res);
      setPwStatus(res.status);
    } catch {
      setPwResult({
        status: "unavailable",
        count: null,
        message: "The password breach check could not be completed. Please try again later.",
      });
      setPwStatus("unavailable");
    } finally {
      setPassword("");
      setShowPassword(false);
      pwCheckingRef.current = false;
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Data Breach Monitoring</h1>
        <p className="text-sm text-slate-500">Check whether your email has appeared in a known data breach.</p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="email"
            required
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
          />
          <button type="submit" disabled={loading} className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60">
            {loading ? "Checking…" : "Check email"}
          </button>
        </form>
      </Card>

      {error && <p className="text-sm text-risk-high">{error}</p>}

      {result && (
        <Card className="space-y-3">
          {!result.configured ? (
            <p className="rounded-lg bg-slate-100 p-3 text-sm text-slate-600 dark:bg-slate-800 dark:text-slate-400">{result.message}</p>
          ) : result.exposure_found ? (
            <>
              <p className="font-medium text-risk-high">Exposure detected — found in {result.breach_count} known breach(es).</p>
              <ul className="list-inside list-disc space-y-1 text-sm">
                {result.recommended_actions.map((a, i) => <li key={i}>{a}</li>)}
              </ul>
            </>
          ) : (
            <p className="font-medium text-risk-low">{result.message}</p>
          )}
        </Card>
      )}

      <Card className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold">Password Breach Checker</h2>
          <p className="text-sm text-slate-500">
            Check whether your password has appeared in known data breaches.
          </p>
        </div>

        <p className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-900/50 dark:text-slate-400">
          Your password is checked on this device. Infora never receives or stores it. Only the first
          five characters of its SHA-1 hash are sent to Have I Been Pwned for the breach lookup.
        </p>

        <form onSubmit={handlePasswordSubmit} className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex flex-1">
            <input
              id="breach-password"
              aria-label="Password to check"
              type={showPassword ? "text" : "password"}
              autoComplete="off"
              placeholder="Enter password to check"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (pwStatus !== "checking") {
                  setPwStatus("idle");
                  setPwResult(null);
                }
              }}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 pr-16 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
            />
            <button
              type="button"
              aria-label={showPassword ? "Hide password" : "Show password"}
              onClick={() => setShowPassword((prev) => !prev)}
              className="absolute inset-y-0 right-2 my-auto h-7 rounded px-2 text-xs font-medium text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>

          <button
            type="submit"
            disabled={!password || pwStatus === "checking"}
            className="shrink-0 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {pwStatus === "checking" ? "Checking…" : "Check Password"}
          </button>
        </form>

        {pwStatus === "checking" && (
          <p className="text-sm text-slate-500" role="status">
            Checking password...
          </p>
        )}

        {pwResult && pwStatus !== "checking" && (
          <div className="rounded-lg border border-slate-200 p-4 dark:border-slate-800" role="status">
            {pwResult.status === "safe" ? (
              <div className="space-y-1">
                <p className="font-medium text-risk-low">No breach match found.</p>
                <p className="text-xs text-slate-500">{pwResult.message}</p>
              </div>
            ) : pwResult.status === "pwned" ? (
              <div className="space-y-1">
                <p className="font-medium text-risk-high">
                  Compromised password detected — appeared in{" "}
                  {(pwResult.count ?? 0).toLocaleString()} known breach record
                  {pwResult.count === 1 ? "" : "s"}.
                </p>
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Change this password immediately everywhere it is reused, and use a unique password or
                  passphrase for every account.
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="font-medium text-risk-medium">Breach check unavailable</p>
                <p className="text-xs text-slate-500">
                  The check could not be completed. {pwResult.message}
                </p>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
