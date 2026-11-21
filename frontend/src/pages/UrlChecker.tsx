import { useState, type FormEvent } from "react";

import { checkUrl } from "@/api/endpoints";
import type { UrlCheckResult } from "@/api/types";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/RiskBadge";

export default function UrlChecker() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<UrlCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const data = await checkUrl(url);
      setResult(data);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? "Could not analyze that URL.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">URL Threat Checker</h1>
        <p className="text-sm text-slate-500">
          Paste a suspicious link below. Scores are calculated from a documented, published set of
          weighted indicators — never an arbitrary number.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            required
            placeholder="https://example.com/suspicious-link"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            className="flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
          />
          <button type="submit" disabled={loading} className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60">
            {loading ? "Scanning…" : "Check URL"}
          </button>
        </form>
      </Card>

      {error && <p className="text-sm text-risk-high">{error}</p>}

      {result && (
        <Card className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-500">Scanned domain</p>
              <p className="font-medium">{result.domain}</p>
            </div>
            <RiskBadge level={result.risk_level} />
          </div>

          <div>
            <div className="mb-1 flex justify-between text-sm">
              <span>Risk score</span>
              <span className="font-semibold">{result.risk_score} / 100</span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${result.risk_score}%`,
                  backgroundColor: result.risk_level === "high" ? "var(--color-risk-high)" : result.risk_level === "medium" ? "var(--color-risk-medium)" : "var(--color-risk-low)",
                }}
              />
            </div>
          </div>

          <div>
            <h3 className="mb-2 text-sm font-semibold text-slate-500">Indicators checked</h3>
            <ul className="space-y-1.5">
              {result.indicators.map((ind) => (
                <li key={ind.key} className="flex items-start gap-2 text-sm">
                  <span className={`mt-0.5 shrink-0 ${ind.triggered ? "text-risk-high" : ind.not_evaluated ? "text-slate-400" : "text-risk-low"}`}>
                    {ind.triggered ? "⚠" : ind.not_evaluated ? "–" : "✓"}
                  </span>
                  <span className={ind.not_evaluated ? "text-slate-400 italic" : ""}>{ind.message}</span>
                </li>
              ))}
            </ul>
          </div>

          {result.risk_level !== "low" && (
            <p className="rounded-lg bg-risk-high/10 p-3 text-sm font-medium text-risk-high">
              Recommendation: do not enter any personal information or credentials on this site.
            </p>
          )}
        </Card>
      )}
    </div>
  );
}
