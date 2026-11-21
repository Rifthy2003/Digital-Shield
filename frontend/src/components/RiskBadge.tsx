const STYLES: Record<string, string> = {
  high: "bg-risk-high/15 text-risk-high border-risk-high/30",
  medium: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  low: "bg-risk-low/15 text-risk-low border-risk-low/30",
  info: "bg-risk-info/15 text-risk-info border-risk-info/30",
};

export function RiskBadge({ level }: { level: string }) {
  const style = STYLES[level] ?? STYLES.info;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium capitalize ${style}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {level} risk
    </span>
  );
}
