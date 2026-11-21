export function ScoreRing({ score }: { score: number }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 75 ? "var(--color-risk-low)" : score >= 50 ? "var(--color-risk-medium)" : "var(--color-risk-high)";
  const label = score >= 75 ? "Good" : score >= 50 ? "Needs attention" : "At risk";

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label={`Security score ${score} out of 100, ${label}`}>
        <circle cx="70" cy="70" r={radius} fill="none" stroke="currentColor" className="text-slate-200 dark:text-slate-700" strokeWidth="12" />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform="rotate(-90 70 70)"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
        <text x="70" y="66" textAnchor="middle" fontSize="28" fontWeight="700" fill="currentColor">
          {score}
        </text>
        <text x="70" y="86" textAnchor="middle" fontSize="12" fill="currentColor" opacity="0.6">
          / 100
        </text>
      </svg>
      <span className="text-sm font-medium" style={{ color }}>{label}</span>
    </div>
  );
}
