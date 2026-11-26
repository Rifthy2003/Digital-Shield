import { Link } from "react-router-dom";
import { Card } from "@/components/Card";

interface AlertSummaryCardsProps {
  high: number;
  medium: number;
  info: number;
}

export function AlertSummaryCards({ high, medium, info }: AlertSummaryCardsProps) {
  const total = high + medium + info;

  const cards = [
    {
      label: "Critical / High",
      value: high,
      tone: "text-risk-high",
      ring: "border-risk-high/30 bg-risk-high/10",
      sub: "Immediate review",
    },
    {
      label: "Medium",
      value: medium,
      tone: "text-risk-medium",
      ring: "border-risk-medium/30 bg-risk-medium/10",
      sub: "Recommended action",
    },
    {
      label: "Informational",
      value: info,
      tone: "text-risk-info",
      ring: "border-risk-info/30 bg-risk-info/10",
      sub: "Security notices",
    },
    {
      label: "Total Open",
      value: total,
      tone: "text-slate-100",
      ring: "border-slate-700/70 bg-slate-800/50",
      sub: "Active alerts",
    },
  ];

  return (
    <Card className="flex h-full flex-col justify-between space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Open Alerts Summary
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Active findings across your scans and monitors
          </p>
        </div>
        <Link to="/alerts" className="text-xs font-medium text-brand-500 hover:underline">
          View all →
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {cards.map((c) => (
          <Link key={c.label} to="/alerts" className="group block">
            <div
              className={`rounded-xl border p-4 transition-transform duration-150 group-hover:-translate-y-0.5 ${c.ring}`}
            >
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                {c.label}
              </p>
              <p className={`mt-1.5 text-2xl font-bold tracking-tight ${c.tone}`}>{c.value}</p>
              <p className="mt-0.5 text-[11px] text-slate-400">{c.sub}</p>
            </div>
          </Link>
        ))}
      </div>
    </Card>
  );
}
