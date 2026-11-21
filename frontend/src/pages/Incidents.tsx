import { useEffect, useState, type FormEvent } from "react";

import { fetchMyIncidents, submitIncident } from "@/api/endpoints";
import type { IncidentReport } from "@/api/types";
import { Card } from "@/components/Card";

const CATEGORIES = [
  "online_scam", "phishing", "fake_website", "fake_job", "account_hacking",
  "identity_theft", "social_media_attack", "cyberbullying", "financial_fraud", "other",
];

export default function Incidents() {
  const [category, setCategory] = useState(CATEGORIES[0]);
  const [description, setDescription] = useState("");
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function load() {
    fetchMyIncidents().then(setReports);
  }
  useEffect(load, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await submitIncident({ category, description });
      setDescription("");
      load();
    } catch {
      setError("Could not submit the report. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Citizen Cyber Incident Reporting</h1>
        <p className="mt-2 rounded-lg bg-risk-medium/10 p-3 text-sm text-risk-medium">
          This is a citizen support tool and is <strong>not</strong> a replacement for official police
          or government cybercrime reporting. For urgent matters, contact local law enforcement directly.
        </p>
      </div>

      <Card>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="mb-1 block text-sm font-medium" htmlFor="category">Category</label>
            <select id="category" value={category} onChange={(e) => setCategory(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:bg-surface">
              {CATEGORIES.map((c) => <option key={c} value={c}>{c.replace(/_/g, " ")}</option>)}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium" htmlFor="description">Description</label>
            <textarea id="description" required rows={4} minLength={10} value={description} onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm dark:border-slate-700 dark:bg-surface" />
          </div>
          {error && <p className="text-sm text-risk-high">{error}</p>}
          <button type="submit" disabled={submitting} className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60">
            {submitting ? "Submitting…" : "Submit report"}
          </button>
        </form>
      </Card>

      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-500">Your reports</h2>
        <div className="space-y-3">
          {reports.length === 0 && <p className="text-sm text-slate-500">No reports submitted yet.</p>}
          {reports.map((r) => (
            <Card key={r.report_id}>
              <div className="flex items-center justify-between">
                <p className="font-mono text-sm font-medium">{r.report_id}</p>
                <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium capitalize dark:bg-slate-800">{r.status.replace("_", " ")}</span>
              </div>
              <p className="mt-1 text-sm capitalize text-slate-500">{r.category.replace(/_/g, " ")}</p>
              <p className="mt-1 text-sm">{r.description}</p>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
