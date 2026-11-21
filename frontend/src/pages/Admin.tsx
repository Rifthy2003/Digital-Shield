import { useEffect, useState } from "react";

import { fetchAdminStats, fetchAllIncidents, type AdminStats } from "@/api/endpoints";
import type { IncidentReport } from "@/api/types";
import { Card } from "@/components/Card";

export default function Admin() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [incidents, setIncidents] = useState<IncidentReport[]>([]);

  useEffect(() => {
    fetchAdminStats().then(setStats);
    fetchAllIncidents().then(setIncidents);
  }, []);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Admin Dashboard</h1>
        <p className="text-sm text-slate-500">
          Aggregate, non-identifying statistics only. Viewing any individual citizen's record is a
          separate, explicitly logged action.
        </p>
      </div>

      {stats && (
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Card className="text-center"><p className="text-2xl font-bold">{stats.total_users}</p><p className="text-xs text-slate-500">Total users</p></Card>
          <Card className="text-center"><p className="text-2xl font-bold">{stats.total_url_checks}</p><p className="text-xs text-slate-500">URL checks run</p></Card>
          <Card className="text-center"><p className="text-2xl font-bold">{stats.total_incident_reports}</p><p className="text-xs text-slate-500">Total reports</p></Card>
          <Card className="text-center"><p className="text-2xl font-bold text-risk-medium">{stats.open_incident_reports}</p><p className="text-xs text-slate-500">Open reports</p></Card>
        </div>
      )}

      <div>
        <h2 className="mb-3 text-sm font-semibold text-slate-500">Incident Report Queue</h2>
        <div className="space-y-3">
          {incidents.map((r) => (
            <Card key={r.report_id} className="flex items-center justify-between">
              <div>
                <p className="font-mono text-sm font-medium">{r.report_id}</p>
                <p className="text-sm capitalize text-slate-500">{r.category.replace(/_/g, " ")}</p>
              </div>
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium capitalize dark:bg-slate-800">{r.status.replace("_", " ")}</span>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
