import { useEffect, useState } from "react";
import { fetchSessions, revokeSession, logoutAllOtherSessions } from "@/api/endpoints";
import type { ActiveSession } from "@/api/types";
import { Card } from "@/components/Card";

export function SessionManager() {
  const [sessions, setSessions] = useState<ActiveSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Confirmation dialog state
  const [confirmRevokeSession, setConfirmRevokeSession] = useState<ActiveSession | null>(null);
  const [confirmLogoutAll, setConfirmLogoutAll] = useState(false);

  useEffect(() => {
    loadSessions();
  }, []);

  async function loadSessions() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchSessions();
      setSessions(data);
    } catch {
      setError("Unable to load active sessions. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRevoke(sessionId: string) {
    setActionLoading(sessionId);
    setError(null);
    try {
      await revokeSession(sessionId);
      setSuccessMessage("Session revoked successfully.");
      setConfirmRevokeSession(null);
      await loadSessions();
    } catch {
      setError("Failed to revoke session. Please try again.");
    } finally {
      setActionLoading(null);
    }
  }

  async function handleLogoutAll() {
    setActionLoading("all");
    setError(null);
    try {
      const res = await logoutAllOtherSessions();
      setSuccessMessage(
        res.revoked_sessions_count > 0
          ? `Successfully logged out ${res.revoked_sessions_count} other device${res.revoked_sessions_count > 1 ? "s" : ""}.`
          : "No other active sessions were found."
      );
      setConfirmLogoutAll(false);
      await loadSessions();
    } catch {
      setError("Failed to revoke other sessions. Please try again.");
    } finally {
      setActionLoading(null);
    }
  }

  const otherSessions = sessions.filter((s) => !s.is_current);

  return (
    <Card className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold">Active Sessions &amp; Devices</h2>
          <p className="text-xs text-slate-500">
            Manage devices currently logged into your Infora Digital Shield account.
          </p>
        </div>
        {otherSessions.length > 0 && (
          <button
            type="button"
            disabled={actionLoading !== null}
            onClick={() => setConfirmLogoutAll(true)}
            className="rounded-lg border border-risk-high/30 px-3 py-1.5 text-xs font-semibold text-risk-high transition-colors hover:bg-risk-high/10 disabled:opacity-50"
          >
            {actionLoading === "all" ? "Revoking…" : "Log out from all other devices"}
          </button>
        )}
      </div>

      {successMessage && (
        <div className="flex items-center justify-between rounded-lg bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-600 dark:text-emerald-400">
          <span>{successMessage}</span>
          <button
            type="button"
            onClick={() => setSuccessMessage(null)}
            className="ml-2 font-bold text-emerald-700 hover:text-emerald-900 dark:text-emerald-300"
          >
            ✕
          </button>
        </div>
      )}

      {error && (
        <div className="flex items-center justify-between rounded-lg bg-risk-high/10 px-3 py-2 text-xs font-medium text-risk-high">
          <span>{error}</span>
          <button
            type="button"
            onClick={loadSessions}
            className="ml-2 font-semibold underline hover:no-underline"
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="py-6 text-center text-xs text-slate-500">Loading active sessions…</div>
      ) : sessions.length === 0 ? (
        <div className="py-4 text-center text-xs text-slate-500">No active sessions found.</div>
      ) : (
        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {sessions.map((session) => (
            <div
              key={session.id}
              className="flex flex-col gap-3 py-3.5 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold">{session.device_name}</span>
                  {session.is_current ? (
                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
                      Current Device
                    </span>
                  ) : (
                    <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-400 capitalize">
                      {session.client_type}
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                  <span>IP: {session.ip_address ?? "Unknown"}</span>
                  <span>
                    Last active: {new Date(session.last_active_at).toLocaleString([], {
                      dateStyle: "short",
                      timeStyle: "short",
                    })}
                  </span>
                  <span>
                    Logged in: {new Date(session.created_at).toLocaleDateString([], {
                      dateStyle: "short",
                    })}
                  </span>
                </div>
              </div>

              {!session.is_current && (
                <div className="flex sm:justify-end">
                  <button
                    type="button"
                    disabled={actionLoading === session.id}
                    onClick={() => setConfirmRevokeSession(session)}
                    className="rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-slate-600 transition-colors hover:border-risk-high hover:bg-risk-high/10 hover:text-risk-high dark:border-slate-700 dark:text-slate-300 disabled:opacity-50"
                  >
                    {actionLoading === session.id ? "Revoking…" : "Revoke"}
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Confirmation Dialog: Revoke Individual Session */}
      {confirmRevokeSession && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-sm rounded-xl bg-surface-light p-5 shadow-lg dark:bg-surface-raised border border-slate-200 dark:border-slate-800 space-y-4">
            <h3 className="text-base font-semibold">Revoke Session</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Are you sure you want to revoke access for{" "}
              <strong className="text-slate-900 dark:text-slate-100">
                {confirmRevokeSession.device_name}
              </strong>
              ? This device will be logged out immediately.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setConfirmRevokeSession(null)}
                className="rounded-lg px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => handleRevoke(confirmRevokeSession.id)}
                className="rounded-lg bg-risk-high px-3 py-1.5 text-xs font-semibold text-white hover:bg-risk-high/90"
              >
                Yes, Revoke
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirmation Dialog: Logout All Other Devices */}
      {confirmLogoutAll && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="w-full max-w-sm rounded-xl bg-surface-light p-5 shadow-lg dark:bg-surface-raised border border-slate-200 dark:border-slate-800 space-y-4">
            <h3 className="text-base font-semibold">Log Out All Other Devices</h3>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Are you sure you want to log out from all {otherSessions.length} other device
              {otherSessions.length > 1 ? "s" : ""}? All other active sessions will be terminated
              immediately while keeping this device logged in.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setConfirmLogoutAll(false)}
                className="rounded-lg px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleLogoutAll}
                className="rounded-lg bg-risk-high px-3 py-1.5 text-xs font-semibold text-white hover:bg-risk-high/90"
              >
                Log Out Others
              </button>
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
