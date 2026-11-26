import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import {
  disconnectConnectedAccount,
  fetchConnectedAccounts,
  fetchOAuthProviders,
  startGoogleOAuth,
  startMicrosoftOAuth,
} from "@/api/endpoints";
import type { ConnectedAccount, OAuthProviderInfo } from "@/api/types";
import { Card } from "@/components/Card";
import { useAuth } from "@/context/AuthContext";

type SupportedProviderId = "google" | "microsoft";

const SUPPORTED_PROVIDER_META: Record<
  SupportedProviderId,
  {
    displayName: string;
    description: string;
    defaultLimitation: string;
  }
> = {
  google: {
    displayName: "Google",
    description:
      "Links your verified Google identity (basic profile and email). You can connect multiple Google accounts to your Infora profile.",
    defaultLimitation:
      "Personal Google OAuth does not expose private sign-in history, active devices, or Google 2FA status through these permissions.",
  },
  microsoft: {
    displayName: "Microsoft",
    description:
      "Links your verified personal Microsoft account identity (basic profile and email). You can connect multiple Microsoft accounts to your Infora profile.",
    defaultLimitation:
      "Personal Microsoft OAuth does not expose private sign-in history, active devices, or MFA enrollment status through these permissions.",
  },
};

const UPCOMING_PROVIDERS = [
  { id: "facebook", name: "Meta / Facebook", note: "Account linking planned for a future release." },
  { id: "linkedin", name: "LinkedIn", note: "Account linking planned for a future release." },
  { id: "apple", name: "Apple", note: "Account linking planned for a future release." },
];

interface ConnectedAccountsProps {
  onRedirect?: (url: string) => void;
}

export default function ConnectedAccounts({ onRedirect }: ConnectedAccountsProps) {
  const { user, restoreSession } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const [providers, setProviders] = useState<OAuthProviderInfo[]>([]);
  const [accounts, setAccounts] = useState<ConnectedAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [connectingProvider, setConnectingProvider] = useState<SupportedProviderId | null>(null);
  const [disconnectingId, setDisconnectingId] = useState<string | null>(null);
  const [confirmDisconnect, setConfirmDisconnect] = useState<ConnectedAccount | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(() => {
    const state = location.state as { oauthSuccess?: string } | null;
    return state?.oauthSuccess ?? null;
  });

  useEffect(() => {
    const state = location.state as { oauthSuccess?: string } | null;
    if (state?.oauthSuccess) {
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location.pathname, location.state, navigate]);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [providerList, accountList] = await Promise.all([
        fetchOAuthProviders(),
        fetchConnectedAccounts(),
      ]);
      setProviders(providerList);
      setAccounts(accountList);
    } catch {
      setError("Unable to load connected accounts. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleConnect(providerId: SupportedProviderId) {
    if (connectingProvider !== null) return;
    const displayName = SUPPORTED_PROVIDER_META[providerId].displayName;
    setConnectingProvider(providerId);
    setError(null);
    try {
      const activeUser = user ?? (await restoreSession());
      if (!activeUser) {
        setError(`Your Infora session has expired. Please sign in again before linking ${displayName}.`);
        setConnectingProvider(null);
        return;
      }
      const res = providerId === "microsoft" ? await startMicrosoftOAuth() : await startGoogleOAuth();
      if (onRedirect) {
        onRedirect(res.authorization_url);
      } else {
        window.location.assign(res.authorization_url);
      }
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(detail ?? `Unable to start ${displayName} account linking. Please try again.`);
      setConnectingProvider(null);
    }
  }

  async function handleDisconnect(account: ConnectedAccount) {
    setDisconnectingId(account.id);
    setError(null);
    const providerLabel =
      account.provider === "microsoft"
        ? "Microsoft"
        : account.provider === "google"
        ? "Google"
        : account.provider;
    try {
      const res = await disconnectConnectedAccount(account.id);
      setConfirmDisconnect(null);
      setSuccessMessage(
        res.upstream_revocation_status === "revoked"
          ? `${providerLabel} account disconnected and upstream access revoked.`
          : `${providerLabel} account disconnected from Infora.`
      );
      await loadData();
    } catch {
      setError("Failed to disconnect account. Please try again.");
    } finally {
      setDisconnectingId(null);
    }
  }

  const confirmProviderName =
    confirmDisconnect?.provider === "microsoft"
      ? "Microsoft"
      : confirmDisconnect?.provider === "google"
      ? "Google"
      : confirmDisconnect?.provider ?? "Provider";

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Connected Accounts</h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
          Connecting your personal accounts allows Infora to securely link your verified account
          identity. Available security information depends on the permissions and official
          capabilities provided by each provider.
        </p>
      </div>

      {successMessage && (
        <div
          role="status"
          className="flex items-center justify-between rounded-lg bg-emerald-500/10 px-4 py-3 text-sm font-medium text-emerald-700 dark:text-emerald-400"
        >
          <span>{successMessage}</span>
          <button
            type="button"
            aria-label="Dismiss success message"
            onClick={() => setSuccessMessage(null)}
            className="ml-3 font-bold hover:opacity-75"
          >
            ✕
          </button>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="flex items-center justify-between rounded-lg bg-risk-high/10 px-4 py-3 text-sm font-medium text-risk-high"
        >
          <span>{error}</span>
          <button
            type="button"
            onClick={loadData}
            className="ml-3 font-semibold underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {(["google", "microsoft"] as const).map((providerId) => {
        const meta = SUPPORTED_PROVIDER_META[providerId];
        const providerInfo = providers.find((p) => p.provider === providerId);
        const providerAccounts = accounts.filter((a) => a.provider === providerId);
        const isConnecting = connectingProvider === providerId;
        const limitationText =
          providerInfo?.limitations?.join(" ") || meta.defaultLimitation;

        return (
          <Card key={providerId} className="space-y-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-semibold">{meta.displayName}</h2>
                  {!loading && (
                    <span
                      className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${
                        providerInfo?.configured
                          ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                          : "bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                      }`}
                    >
                      {providerInfo?.configured ? "Available" : "Not configured"}
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-slate-500">{meta.description}</p>
              </div>

              <button
                type="button"
                disabled={loading || connectingProvider !== null || !providerInfo?.configured}
                onClick={() => handleConnect(providerId)}
                className="shrink-0 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isConnecting ? "Redirecting…" : `Connect ${meta.displayName}`}
              </button>
            </div>

            {providerInfo?.capabilities && (
              <div className="rounded-lg border border-slate-200/80 bg-slate-50/60 p-3 text-xs dark:border-slate-800 dark:bg-slate-900/40">
                <p className="font-medium text-slate-700 dark:text-slate-200">
                  Security Capabilities ({meta.displayName} Personal)
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <span className="rounded bg-emerald-500/10 px-2 py-0.5 text-emerald-700 dark:text-emerald-400">
                    Identity verification: {providerInfo.capabilities.identity_verification ?? "supported"}
                  </span>
                  <span className="rounded bg-slate-200 px-2 py-0.5 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    Sign-in history: {providerInfo.capabilities.login_history ?? "requires_enterprise"}
                  </span>
                  <span className="rounded bg-slate-200 px-2 py-0.5 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    Devices: {providerInfo.capabilities.device_session_visibility ?? "requires_enterprise"}
                  </span>
                  <span className="rounded bg-slate-200 px-2 py-0.5 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    MFA status: {providerInfo.capabilities.mfa_status ?? "requires_enterprise"}
                  </span>
                </div>
                <p className="mt-2 text-slate-500">{limitationText}</p>
              </div>
            )}

            {loading ? (
              <div className="py-6 text-center text-sm text-slate-500">
                Loading connected accounts…
              </div>
            ) : providerAccounts.length === 0 ? (
              <div className="rounded-lg border border-dashed border-slate-200 p-5 text-center text-sm text-slate-500 dark:border-slate-800">
                No {meta.displayName} accounts connected yet.
              </div>
            ) : (
              <div className="space-y-3">
                {providerAccounts.map((account) => (
                  <div
                    key={account.id}
                    className="flex flex-col gap-3 rounded-lg border border-slate-200 p-4 dark:border-slate-800 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">
                          {account.display_name ??
                            account.provider_email ??
                            `${meta.displayName} Account`}
                        </span>
                        <span className="rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium capitalize text-emerald-700 dark:text-emerald-400">
                          {account.status}
                        </span>
                        {account.provider_email_verified && (
                          <span className="rounded-full bg-brand-500/10 px-2 py-0.5 text-xs font-medium text-brand-600 dark:text-brand-400">
                            Verified email
                          </span>
                        )}
                      </div>
                      {account.provider_email && (
                        <p className="text-xs text-slate-600 dark:text-slate-300">
                          {account.provider_email}
                        </p>
                      )}
                      <p className="text-xs text-slate-500">
                        Connected {new Date(account.created_at).toLocaleDateString()}
                      </p>
                    </div>

                    <button
                      type="button"
                      disabled={disconnectingId !== null}
                      onClick={() => setConfirmDisconnect(account)}
                      className="self-start rounded-lg border border-risk-high/30 px-3 py-1.5 text-xs font-semibold text-risk-high transition-colors hover:bg-risk-high/10 disabled:opacity-50 sm:self-center"
                    >
                      {disconnectingId === account.id ? "Disconnecting…" : "Disconnect"}
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>
        );
      })}

      <Card className="space-y-3">
        <h2 className="text-base font-semibold">Other Providers</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {UPCOMING_PROVIDERS.map((p) => (
            <div
              key={p.id}
              className="flex items-center justify-between rounded-lg border border-slate-200 p-3 dark:border-slate-800"
            >
              <div>
                <p className="text-sm font-medium">{p.name}</p>
                <p className="text-xs text-slate-500">{p.note}</p>
              </div>
              <span className="shrink-0 rounded-full bg-slate-200 px-2.5 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                Coming soon
              </span>
            </div>
          ))}
        </div>
      </Card>

      {confirmDisconnect && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="disconnect-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <Card className="w-full max-w-md space-y-4">
            <h3 id="disconnect-dialog-title" className="text-base font-semibold">
              Disconnect {confirmProviderName} Account?
            </h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              This will unlink{" "}
              <span className="font-medium">
                {confirmDisconnect.provider_email ?? confirmDisconnect.display_name ?? "this account"}
              </span>{" "}
              from Infora Digital Shield and delete its stored OAuth credentials.
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                disabled={disconnectingId !== null}
                onClick={() => setConfirmDisconnect(null)}
                className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={disconnectingId !== null}
                onClick={() => handleDisconnect(confirmDisconnect)}
                className="rounded-lg bg-risk-high px-3 py-1.5 text-sm font-semibold text-white hover:opacity-90 disabled:opacity-50"
              >
                {disconnectingId === confirmDisconnect.id ? "Disconnecting…" : "Confirm disconnect"}
              </button>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
