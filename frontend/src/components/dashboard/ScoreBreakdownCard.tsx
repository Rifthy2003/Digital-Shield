import type { ScoreBreakdownItem } from "@/api/types";
import { Card } from "@/components/Card";

interface ScoreBreakdownCardProps {
  breakdown: Record<string, ScoreBreakdownItem>;
}

export function ScoreBreakdownCard({ breakdown }: ScoreBreakdownCardProps) {
  const entries = Object.entries(breakdown);

  return (
    <Card className="flex h-full flex-col justify-between space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Score Breakdown
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">Factor-level posture signals</p>
        </div>
        <span className="text-xs text-slate-400">Live</span>
      </div>

      <div className="space-y-3">
        {entries.map(([key, item]) => {
          const pct = item.max_points > 0 ? Math.round((item.points / item.max_points) * 100) : 0;
          return (
            <div key={key} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium capitalize text-slate-200">
                  {key.replace(/_/g, " ")}
                </span>
                <span className="font-mono text-slate-400">
                  {item.points}/{item.max_points}
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full bg-brand-500 transition-all duration-500"
                  style={{ width: `${pct}%` }}
                />
              </div>
              <p className="text-[11px] text-slate-400">{item.reason}</p>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
