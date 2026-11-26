import { Link } from "react-router-dom";
import type { ConnectedAccount, OAuthProviderInfo } from "@/api/types";
import { Card } from "@/components/Card";

interface ConnectedAccountsCardProps {
  providers: OAuthProviderInfo[];
  accounts: ConnectedAccount[];
  loading: boolean;
  error: boolean;
}

export function ConnectedAccountsCard({
  providers,
  accounts,
  loading,
  error,
}: ConnectedAccountsCardProps) {
  const googleProvider = providers.find((p) => p.provider === "google");
  const googleAccounts = accounts.filter((a) => a.provider === "google");
  const connectedProviderCount = new Set(accounts.map((a) => a.provider)).size;

  return (
    <Card className="space-y-4 border-slate-800/80 bg-surface-raised/90">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Connected Accounts
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            {loading
              ? "Loading provider status…"
              : error
                ? "Connected account status unavailable"
                : `${connectedProviderCount} connected provider${connectedProviderCount === 1 ? "" : "s"} · ${googleAccounts.length} Google account${googleAccounts.length === 1 ? "" : "s"}`}
          </p>
        </div>
        <Link
          to="/connected-accounts"
          className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-800"
        >
          Manage
        </Link>
      </div>

      {loading ? (
        <p className="py-4 text-xs text-slate-400">Loading connected accounts…</p>
      ) : error ? (
        <p className="py-2 text-xs text-risk-high">Could not load connected accounts.</p>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between rounded-xl border border-slate-800 bg-surface/60 px-3.5 py-2.5 text-xs">
            <span className="font-medium text-slate-200">Google OAuth Linking</span>
            <span
              className={`rounded-full px-2 py-0.5 font-medium ${
                googleProvider?.configured
                  ? "bg-risk-low/15 text-risk-low"
                  : "bg-slate-800 text-slate-400"
              }`}
            >
              {googleProvider?.configured ? "Configured" : "Not configured"}
            </span>
          </div>

          {googleAccounts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-800 p-4 text-center text-xs text-slate-400">
              No Google accounts connected yet.{" "}
              <Link to="/connected-accounts" className="font-medium text-brand-500 hover:underline">
                Connect Google →
              </Link>
            </div>
          ) : (
            <ul className="space-y-2">
              {googleAccounts.map((acc) => (
                <li
                  key={acc.id}
                  className="flex items-center justify-between rounded-xl border border-slate-800 bg-surface/50 px-3.5 py-2.5"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-100">
                      {acc.display_name ?? acc.provider_email ?? "Google Account"}
                    </p>
                    {acc.provider_email && (
                      <p className="truncate text-xs text-slate-400">{acc.provider_email}</p>
                    )}
                  </div>
                  <span className="ml-3 shrink-0 rounded-full bg-risk-low/15 px-2.5 py-0.5 text-xs font-medium capitalize text-risk-low">
                    {acc.status}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Card>
  );
}
