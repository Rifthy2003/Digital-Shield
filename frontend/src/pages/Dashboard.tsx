import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import {
  fetchConnectedAccounts,
  fetchDashboard,
  fetchOAuthProviders,
} from "@/api/endpoints";
import type { ConnectedAccount, DashboardData, OAuthProviderInfo } from "@/api/types";
import { AccountSecurityCard } from "@/components/dashboard/AccountSecurityCard";
import { AlertSummaryCards } from "@/components/dashboard/AlertSummaryCards";
import { ConnectedAccountsCard } from "@/components/dashboard/ConnectedAccountsCard";
import { RecentActivity } from "@/components/dashboard/RecentActivity";
import { ScoreBreakdownCard } from "@/components/dashboard/ScoreBreakdownCard";
import { SecurityRecommendations } from "@/components/dashboard/SecurityRecommendations";
import { SecurityScoreCard } from "@/components/dashboard/SecurityScoreCard";
import { ThreatActivityChart } from "@/components/dashboard/ThreatActivityChart";
import { useAuth } from "@/context/AuthContext";

export default function Dashboard() {
  const { user } = useAuth();
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [providers, setProviders] = useState<OAuthProviderInfo[]>([]);
  const [accounts, setAccounts] = useState<ConnectedAccount[]>([]);
  const [oauthLoading, setOauthLoading] = useState(true);
  const [oauthError, setOauthError] = useState(false);

  useEffect(() => {
    fetchDashboard()
      .then(setData)
      .catch(() => setError("Could not load your dashboard right now. Please try again shortly."));

    Promise.all([fetchOAuthProviders(), fetchConnectedAccounts()])
      .then(([provList, accList]) => {
        setProviders(provList);
        setAccounts(accList);
      })
      .catch(() => setOauthError(true))
      .finally(() => setOauthLoading(false));
  }, []);

  if (error) return <p role="alert" className="text-risk-high">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading your security overview…</p>;

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      {/* Top: Dashboard heading & quick actions */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Security Dashboard</h1>
          <p className="text-sm text-slate-400">
            Live security posture calculated from your verified account activity.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          <Link
            to="/url-checker"
            className="rounded-lg border border-slate-700 bg-surface-raised px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800"
          >
            Scan URL
          </Link>
          <Link
            to="/message-checker"
            className="rounded-lg border border-slate-700 bg-surface-raised px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800"
          >
            Analyze Message
          </Link>
          <Link
            to="/connected-accounts"
            className="rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-semibold text-white transition-colors hover:bg-brand-500"
          >
            Connected Accounts
          </Link>
        </div>
      </div>

      {/* Row 1: Security Score + Open Alerts summary */}
      <div className="grid gap-6 lg:grid-cols-12">
        <div className="lg:col-span-4">
          <SecurityScoreCard score={data.score} />
        </div>
        <div className="lg:col-span-8">
          <AlertSummaryCards
            high={data.alerts_summary.high}
            medium={data.alerts_summary.medium}
            info={data.alerts_summary.info}
          />
        </div>
      </div>

      {/* Row 2: Score Breakdown + Account Security Overview + Connected Accounts */}
      <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
        <ScoreBreakdownCard breakdown={data.score_breakdown} />
        <AccountSecurityCard user={user} breakdown={data.score_breakdown} />
        <ConnectedAccountsCard
          providers={providers}
          accounts={accounts}
          loading={oauthLoading}
          error={oauthError}
        />
      </div>

      {/* Row 3: Threat Activity Chart + Recent Activity */}
      <div className="grid gap-6 lg:grid-cols-2">
        <ThreatActivityChart
          high={data.alerts_summary.high}
          medium={data.alerts_summary.medium}
          info={data.alerts_summary.info}
        />
        <RecentActivity alerts={data.recent_alerts} />
      </div>

      {/* Row 4: Security Recommendations */}
      <SecurityRecommendations recommendations={data.recommendations} />
    </div>
  );
}
