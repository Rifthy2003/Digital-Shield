import { useState, type FormEvent } from "react";

import { checkMessage } from "@/api/endpoints";
import type { MessageCheckResult } from "@/api/types";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/RiskBadge";

export default function MessageChecker() {
  const [content, setContent] = useState("");
  const [result, setResult] = useState<MessageCheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      setResult(await checkMessage(content));
    } catch {
      setError("Could not analyze that message.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Scam &amp; Phishing Message Analyzer</h1>
        <p className="text-sm text-slate-500">Paste a suspicious SMS, WhatsApp, or email message below.</p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-3">
          <textarea
            required
            rows={5}
            placeholder="Paste the message text here…"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
          />
          <button type="submit" disabled={loading} className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60">
            {loading ? "Analyzing…" : "Analyze message"}
          </button>
        </form>
      </Card>

      {error && <p className="text-sm text-risk-high">{error}</p>}

      {result && (
        <Card className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="font-medium">Analysis result</p>
            <RiskBadge level={result.risk_level} />
          </div>
          <p className="text-sm">
            Risk score: <span className="font-semibold">{result.risk_score} / 100</span>
          </p>
          <ul className="space-y-1.5">
            {result.indicators.map((ind) => (
              <li key={ind.key} className="flex items-start gap-2 text-sm">
                <span className={`mt-0.5 shrink-0 ${ind.triggered ? "text-risk-high" : "text-risk-low"}`}>{ind.triggered ? "⚠" : "✓"}</span>
                {ind.message}
              </li>
            ))}
          </ul>
          {result.links_found.length > 0 && (
            <div>
              <h3 className="mb-1 text-sm font-semibold text-slate-500">Links found</h3>
              <ul className="list-inside list-disc text-sm text-slate-500">
                {result.links_found.map((link, i) => <li key={i} className="break-all">{link}</li>)}
              </ul>
            </div>
          )}
          <p className="rounded-lg bg-slate-100 p-3 text-xs text-slate-600 dark:bg-slate-800 dark:text-slate-400">{result.disclaimer}</p>
        </Card>
      )}
    </div>
  );
}
