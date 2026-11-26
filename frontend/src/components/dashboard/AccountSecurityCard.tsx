import { Link } from "react-router-dom";
import type { ScoreBreakdownItem, User } from "@/api/types";
import { Card } from "@/components/Card";

interface AccountSecurityCardProps {
  user: User | null;
  breakdown: Record<string, ScoreBreakdownItem>;
}

export function AccountSecurityCard({ user, breakdown }: AccountSecurityCardProps) {
  const breachItem = Object.entries(breakdown).find(([k]) => k.toLowerCase().includes("breach"))?.[1];

  return (
    <Card className="space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Account Security
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Verified security signals for your Infora account
          </p>
        </div>
        <Link
          to="/profile"
          className="text-xs font-medium text-brand-500 hover:underline"
        >
          Manage →
        </Link>
      </div>

      <div className="divide-y divide-slate-800/80 text-sm">
        <div className="flex items-center justify-between py-2.5">
          <span className="text-slate-300">2FA / MFA Status</span>
          <span
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
              user?.mfa_enabled
                ? "bg-risk-low/15 text-risk-low"
                : "bg-risk-medium/15 text-risk-medium"
            }`}
          >
            {user ? (user.mfa_enabled ? "Enabled" : "Not enabled") : "Not available"}
          </span>
        </div>

        <div className="flex items-center justify-between py-2.5">
          <span className="text-slate-300">Password Health</span>
          <Link
            to="/password-health"
            className="text-xs font-medium text-slate-400 hover:text-slate-200"
          >
            Not yet checked · Check →
          </Link>
        </div>

        <div className="flex items-center justify-between gap-4 py-2.5">
          <span className="text-slate-300">Data Breach Exposure</span>
          <Link
            to="/breach-checker"
            className="text-right text-xs font-medium text-slate-400 hover:text-slate-200"
          >
            {breachItem ? breachItem.reason : "Not yet checked · Scan →"}
          </Link>
        </div>

        <div className="flex items-center justify-between gap-4 py-2.5">
          <span className="text-slate-300">External Login &amp; Device Activity</span>
          <span className="text-right text-xs text-slate-500">
            Not available via consumer OAuth APIs
          </span>
        </div>
      </div>
    </Card>
  );
}
