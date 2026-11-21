import { useState, type FormEvent } from "react";

import { checkBreach } from "@/api/endpoints";
import type { BreachCheckResult } from "@/api/types";
import { Card } from "@/components/Card";

export default function BreachChecker() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState<BreachCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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
    </div>
  );
}
