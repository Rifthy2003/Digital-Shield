import { useEffect, useState } from "react";

import { fetchDashboard } from "@/api/endpoints";
import type { DashboardData } from "@/api/types";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/RiskBadge";
import { ScoreRing } from "@/components/ScoreRing";

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboard()
      .then(setData)
      .catch(() => setError("Could not load your dashboard right now. Please try again shortly."));
  }, []);

  if (error) return <p className="text-risk-high">{error}</p>;
  if (!data) return <p className="text-slate-500">Loading your security overview…</p>;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Security Dashboard</h1>
        <p className="text-sm text-slate-500">All figures below are calculated live from your account's actual activity.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-3">
        <Card className="flex flex-col items-center justify-center md:col-span-1">
          <ScoreRing score={data.score} />
        </Card>

        <Card className="md:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-slate-500">Open Alerts</h2>
          <div className="flex gap-4">
            <div className="flex-1 rounded-xl bg-risk-high/10 p-4 text-center">
              <p className="text-2xl font-bold text-risk-high">{data.alerts_summary.high}</p>
              <p className="text-xs text-slate-500">Critical</p>
            </div>
            <div className="flex-1 rounded-xl bg-risk-medium/10 p-4 text-center">
              <p className="text-2xl font-bold text-risk-medium">{data.alerts_summary.medium}</p>
              <p className="text-xs text-slate-500">Medium</p>
            </div>
            <div className="flex-1 rounded-xl bg-risk-info/10 p-4 text-center">
              <p className="text-2xl font-bold text-risk-info">{data.alerts_summary.info}</p>
              <p className="text-xs text-slate-500">Informational</p>
            </div>
          </div>
        </Card>
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold text-slate-500">Score Breakdown</h2>
        <div className="space-y-3">
          {Object.entries(data.score_breakdown).map(([key, item]) => (
            <div key={key}>
              <div className="mb-1 flex justify-between text-sm">
                <span className="capitalize">{key.replace(/_/g, " ")}</span>
                <span className="text-slate-500">{item.points}/{item.max_points}</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                <div
                  className="h-full rounded-full bg-brand-500"
                  style={{ width: `${(item.points / item.max_points) * 100}%` }}
                />
              </div>
              <p className="mt-1 text-xs text-slate-500">{item.reason}</p>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-sm font-semibold text-slate-500">Recommendations</h2>
          {data.recommendations.length === 0 ? (
            <p className="text-sm text-slate-500">No outstanding recommendations — nice work.</p>
          ) : (
            <ul className="space-y-2">
              {data.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-500" />
                  {rec}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-semibold text-slate-500">Recent Activity</h2>
          {data.recent_alerts.length === 0 ? (
            <p className="text-sm text-slate-500">No recent alerts.</p>
          ) : (
            <ul className="space-y-3">
              {data.recent_alerts.map((alert) => (
                <li key={alert.id} className="flex items-start justify-between gap-3 border-b border-slate-100 pb-3 last:border-0 dark:border-slate-800">
                  <div>
                    <p className="text-sm font-medium">{alert.title}</p>
                    <p className="text-xs text-slate-500">{alert.message}</p>
                  </div>
                  <RiskBadge level={alert.severity === "info" ? "info" : alert.severity} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
