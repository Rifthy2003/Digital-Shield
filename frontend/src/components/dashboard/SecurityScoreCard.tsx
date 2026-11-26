import { Card } from "@/components/Card";
import { ScoreRing } from "@/components/ScoreRing";

interface SecurityScoreCardProps {
  score: number;
}

export function SecurityScoreCard({ score }: SecurityScoreCardProps) {
  return (
    <Card className="flex h-full flex-col items-center justify-center border-slate-800/80 bg-surface-raised/90 text-center">
      <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">
        Security Score
      </p>
      <ScoreRing score={score} />
      <p className="mt-3 text-xs text-slate-400">
        Calculated live from verified account signals
      </p>
    </Card>
  );
}
