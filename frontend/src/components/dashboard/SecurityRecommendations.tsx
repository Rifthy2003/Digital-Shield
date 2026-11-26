import { Card } from "@/components/Card";

interface SecurityRecommendationsProps {
  recommendations: string[];
}

export function SecurityRecommendations({ recommendations }: SecurityRecommendationsProps) {
  return (
    <Card className="space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
          Security Recommendations
        </h2>
        <span className="text-xs text-slate-400">{recommendations.length} item{recommendations.length === 1 ? "" : "s"}</span>
      </div>

      {recommendations.length === 0 ? (
        <p className="text-sm text-slate-400">
          No outstanding recommendations — your verified controls look solid.
        </p>
      ) : (
        <ul className="space-y-2.5">
          {recommendations.map((rec, i) => (
            <li
              key={i}
              className="flex items-start gap-3 rounded-xl border border-slate-800/80 bg-surface/50 p-3 text-sm text-slate-200"
            >
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-brand-500" />
              <span>{rec}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
