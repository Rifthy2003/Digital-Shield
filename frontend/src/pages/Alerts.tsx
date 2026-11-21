import { useEffect, useState } from "react";

import { fetchAlerts, markAlertRead, resolveAlert } from "@/api/endpoints";
import type { Alert } from "@/api/types";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/RiskBadge";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  function load() {
    fetchAlerts().then(setAlerts).finally(() => setLoading(false));
  }

  useEffect(load, []);

  async function handleRead(id: string) {
    await markAlertRead(id);
    load();
  }

  async function handleResolve(id: string) {
    await resolveAlert(id);
    load();
  }

  if (loading) return <p className="text-slate-500">Loading alerts…</p>;

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-2xl font-semibold">Security Alerts</h1>
      {alerts.length === 0 && <p className="text-sm text-slate-500">No alerts yet. Run a check to get started.</p>}
      {alerts.map((a) => (
        <Card key={a.id} className={`flex items-start justify-between gap-4 ${a.is_resolved ? "opacity-50" : ""}`}>
          <div>
            <div className="mb-1 flex items-center gap-2">
              <RiskBadge level={a.severity === "info" ? "info" : a.severity} />
              {!a.is_read && <span className="h-2 w-2 rounded-full bg-brand-500" title="Unread" />}
            </div>
            <p className="font-medium">{a.title}</p>
            <p className="text-sm text-slate-500">{a.message}</p>
            <p className="mt-1 text-xs text-slate-400">{new Date(a.created_at).toLocaleString()}</p>
          </div>
          <div className="flex shrink-0 flex-col gap-2">
            {!a.is_read && (
              <button onClick={() => handleRead(a.id)} className="rounded-lg border border-slate-300 px-3 py-1 text-xs font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800">
                Mark read
              </button>
            )}
            {!a.is_resolved && (
              <button onClick={() => handleResolve(a.id)} className="rounded-lg bg-brand-600 px-3 py-1 text-xs font-medium text-white hover:bg-brand-500">
                Resolve
              </button>
            )}
          </div>
        </Card>
      ))}
    </div>
  );
}
