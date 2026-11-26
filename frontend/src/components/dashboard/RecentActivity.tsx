import { Link } from "react-router-dom";
import type { Alert } from "@/api/types";
import { Card } from "@/components/Card";
import { RiskBadge } from "@/components/RiskBadge";

interface RecentActivityProps {
  alerts: Alert[];
}

export function RecentActivity({ alerts }: RecentActivityProps) {
  return (
    <Card className="space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
          Recent Security Events
        </h2>
        <Link to="/alerts" className="text-xs font-medium text-brand-500 hover:underline">
          All alerts →
        </Link>
      </div>

      {alerts.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-800 p-5 text-center text-sm text-slate-400">
          No recent security events recorded.
        </div>
      ) : (
        <ul className="space-y-3">
          {alerts.map((alert) => (
            <li
              key={alert.id}
              className="flex items-start justify-between gap-3 rounded-xl border border-slate-800/80 bg-surface/50 p-3.5"
            >
              <div className="min-w-0 space-y-1">
                <p className="text-sm font-medium text-slate-100">{alert.title}</p>
                <p className="text-xs text-slate-400">{alert.message}</p>
                <p className="text-[11px] text-slate-500">
                  {alert.category.replace(/_/g, " ")} ·{" "}
                  {new Date(alert.created_at).toLocaleString()}
                </p>
              </div>
              <div className="shrink-0">
                <RiskBadge level={alert.severity === "info" ? "info" : alert.severity} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
