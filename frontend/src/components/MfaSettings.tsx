import { useEffect, useState, type FormEvent } from "react";
import QRCode from "qrcode";

import {
  disableMfa,
  fetchMfaStatus,
  regenerateMfaRecoveryCodes,
  startMfaEnrollment,
  verifyMfaEnrollment,
} from "@/api/endpoints";
import type { MfaEnrollStartResponse, MfaStatus } from "@/api/types";
import { Card } from "@/components/Card";
import { useAuth } from "@/context/AuthContext";

export function MfaSettings() {
  const { user, refreshUser } = useAuth();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [enrollData, setEnrollData] = useState<MfaEnrollStartResponse | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const [showRegenerate, setShowRegenerate] = useState(false);
  const [regenPassword, setRegenPassword] = useState("");
  const [regenCode, setRegenCode] = useState("");

  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function loadStatus() {
    try {
      const s = await fetchMfaStatus();
      setStatus(s);
    } catch {
      // Ignore transient status fetch failure; user.mfa_enabled remains fallback
    }
  }

  useEffect(() => {
    let cancelled = false;
    fetchMfaStatus()
      .then((s) => {
        if (!cancelled) setStatus(s);
      })
      .catch(() => {
        // Ignore transient status fetch failure
      });
    return () => {
      cancelled = true;
    };
  }, [user?.mfa_enabled]);

  const mfaEnabled = status?.mfa_enabled ?? user?.mfa_enabled ?? false;

  async function handleStartEnrollment() {
    setError(null);
    setNotice(null);
    setRecoveryCodes(null);
    setBusy(true);
    try {
      const data = await startMfaEnrollment();
      setEnrollData(data);
      const url = await QRCode.toDataURL(data.provisioning_uri, { width: 192, margin: 2 });
      setQrDataUrl(url);
      setVerifyCode("");
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? "Could not start MFA enrollment.");
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifyEnrollment(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await verifyMfaEnrollment(verifyCode.trim());
      setEnrollData(null);
      setQrDataUrl(null);
      setVerifyCode("");
      setRecoveryCodes(res.recovery_codes);
      setNotice("Two-factor authentication is now enabled for your Infora account.");
      await refreshUser();
      await loadStatus();
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? "Invalid 6-digit verification code.");
    } finally {
      setBusy(false);
    }
  }

  async function handleRegenerateCodes(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const res = await regenerateMfaRecoveryCodes({
        current_password: regenPassword,
        code: regenCode.trim(),
      });
      setRecoveryCodes(res.recovery_codes);
      setShowRegenerate(false);
      setRegenPassword("");
      setRegenCode("");
      setNotice("New recovery codes generated. Your previous codes are no longer valid.");
      await loadStatus();
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? "Could not regenerate recovery codes.");
    } finally {
      setBusy(false);
    }
  }

  async function handleDisableMfa(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const res = await disableMfa({
        current_password: disablePassword,
        code: disableCode.trim(),
      });
      setShowDisableConfirm(false);
      setDisablePassword("");
      setDisableCode("");
      setRecoveryCodes(null);
      setNotice(res.message);
      await refreshUser();
      await loadStatus();
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? "Could not disable two-factor authentication.");
    } finally {
      setBusy(false);
    }
  }

  async function copyText(text: string, onDone: (v: boolean) => void) {
    try {
      await navigator.clipboard.writeText(text);
      onDone(true);
      setTimeout(() => onDone(false), 2000);
    } catch {
      // Clipboard unavailable
    }
  }

  return (
    <Card className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">Infora Account Two-Factor Authentication (TOTP)</h2>
          <p className="mt-1 text-xs text-slate-500">
            Protects your Infora Digital Shield sign-in only. This setting does not manage or reflect
            2FA on connected Google, Microsoft, Facebook, or other external accounts.
          </p>
        </div>
        <span
          className={`rounded-full px-3 py-1 text-xs font-medium ${
            mfaEnabled
              ? "bg-risk-low/15 text-risk-low"
              : "bg-risk-medium/15 text-risk-medium"
          }`}
        >
          {mfaEnabled ? "Enabled" : "Not enabled"}
        </span>
      </div>

      {error && (
        <div className="rounded-lg border border-risk-high/40 bg-risk-high/10 px-3 py-2 text-sm text-risk-high" role="alert">
          {error}
        </div>
      )}

      {notice && (
        <div className="rounded-lg border border-risk-low/40 bg-risk-low/10 px-3 py-2 text-sm text-risk-low">
          {notice}
        </div>
      )}

      {recoveryCodes && (
        <div className="space-y-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4">
          <div>
            <h3 className="text-sm font-semibold text-amber-300">Save your one-time recovery codes</h3>
            <p className="mt-1 text-xs text-slate-300">
              Each code can be used once if you lose access to your authenticator app. Store them in a
              safe place now — they will not be shown again.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-2 rounded-md bg-slate-950/60 p-3 font-mono text-xs text-slate-100">
            {recoveryCodes.map((code) => (
              <div key={code} className="select-all">
                {code}
              </div>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => copyText(recoveryCodes.join("\n"), setCopiedCodes)}
              className="rounded-lg border border-slate-600 px-3 py-1.5 text-xs font-medium hover:bg-slate-800"
            >
              {copiedCodes ? "Copied!" : "Copy all codes"}
            </button>
            <button
              type="button"
              onClick={() => setRecoveryCodes(null)}
              className="rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-brand-500"
            >
              I have saved my recovery codes
            </button>
          </div>
        </div>
      )}

      {!mfaEnabled && !enrollData && (
        <div className="flex items-center justify-between rounded-lg border border-slate-700/60 p-3">
          <p className="text-sm text-slate-400">
            Add an authenticator app (Google Authenticator, Authy, 1Password, or Bitwarden) to earn +30
            Security Score points.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={handleStartEnrollment}
            className="ml-4 shrink-0 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60"
          >
            {busy ? "Starting…" : "Enable 2FA"}
          </button>
        </div>
      )}

      {!mfaEnabled && enrollData && (
        <form onSubmit={handleVerifyEnrollment} className="space-y-4 rounded-lg border border-slate-700/60 p-4">
          <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
            {qrDataUrl && (
              <img
                src={qrDataUrl}
                alt="Infora TOTP QR Code"
                className="h-44 w-44 rounded-lg bg-white p-2"
              />
            )}
            <div className="flex-1 space-y-2 text-sm">
              <p className="font-medium">1. Scan this QR code with your authenticator app</p>
              <p className="text-xs text-slate-400">
                Or enter this setup key manually:
              </p>
              <div className="flex items-center gap-2">
                <code className="break-all rounded bg-slate-900 px-2 py-1 font-mono text-xs text-slate-200">
                  {enrollData.secret}
                </code>
                <button
                  type="button"
                  onClick={() => copyText(enrollData.secret, setCopiedSecret)}
                  className="shrink-0 rounded border border-slate-600 px-2 py-1 text-xs hover:bg-slate-800"
                >
                  {copiedSecret ? "Copied" : "Copy"}
                </button>
              </div>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium" htmlFor="enroll-totp-code">
              2. Enter the 6-digit verification code to confirm
            </label>
            <input
              id="enroll-totp-code"
              type="text"
              inputMode="numeric"
              pattern="\d{6}"
              maxLength={6}
              required
              placeholder="123456"
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value)}
              className="w-full max-w-xs rounded-lg border border-slate-700 bg-surface px-3 py-2 font-mono text-sm tracking-widest focus:border-brand-500 focus:outline-none"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="submit"
              disabled={busy}
              className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-500 disabled:opacity-60"
            >
              {busy ? "Verifying…" : "Verify & Enable 2FA"}
            </button>
            <button
              type="button"
              onClick={() => {
                setEnrollData(null);
                setQrDataUrl(null);
              }}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium hover:bg-slate-800"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {mfaEnabled && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-700/60 p-3 text-sm">
            <div>
              <p className="font-medium">Recovery codes remaining: {status?.recovery_codes_remaining ?? "—"}</p>
              <p className="text-xs text-slate-500">
                Regenerating codes invalidates any unused previous recovery codes.
              </p>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowRegenerate((v) => !v);
                  setShowDisableConfirm(false);
                }}
                className="rounded-lg border border-slate-600 px-3 py-1.5 text-xs font-medium hover:bg-slate-800"
              >
                Regenerate recovery codes
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowDisableConfirm((v) => !v);
                  setShowRegenerate(false);
                }}
                className="rounded-lg border border-risk-high/50 px-3 py-1.5 text-xs font-medium text-risk-high hover:bg-risk-high/10"
              >
                Disable 2FA
              </button>
            </div>
          </div>

          {showRegenerate && (
            <form onSubmit={handleRegenerateCodes} className="space-y-3 rounded-lg border border-slate-700/60 p-4">
              <h3 className="text-sm font-semibold">Regenerate recovery codes</h3>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium" htmlFor="regen-password">
                    Current password
                  </label>
                  <input
                    id="regen-password"
                    type="password"
                    required
                    value={regenPassword}
                    onChange={(e) => setRegenPassword(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-surface px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium" htmlFor="regen-code">
                    6-digit authenticator code
                  </label>
                  <input
                    id="regen-code"
                    type="text"
                    inputMode="numeric"
                    required
                    placeholder="123456"
                    value={regenCode}
                    onChange={(e) => setRegenCode(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-surface px-3 py-2 font-mono text-sm"
                  />
                </div>
              </div>
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-brand-600 px-4 py-2 text-xs font-semibold text-white hover:bg-brand-500 disabled:opacity-60"
              >
                {busy ? "Generating…" : "Confirm regeneration"}
              </button>
            </form>
          )}

          {showDisableConfirm && (
            <form onSubmit={handleDisableMfa} className="space-y-3 rounded-lg border border-risk-high/40 bg-risk-high/5 p-4">
              <h3 className="text-sm font-semibold text-risk-high">Confirm disabling 2FA</h3>
              <p className="text-xs text-slate-400">
                Disabling two-factor authentication lowers your Infora Security Score and revokes all other active sessions.
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs font-medium" htmlFor="disable-password">
                    Current password
                  </label>
                  <input
                    id="disable-password"
                    type="password"
                    required
                    value={disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-surface px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium" htmlFor="disable-code">
                    Authenticator or recovery code
                  </label>
                  <input
                    id="disable-code"
                    type="text"
                    required
                    placeholder="123456 or XXXXX-XXXXX"
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-surface px-3 py-2 font-mono text-sm"
                  />
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={busy}
                  className="rounded-lg bg-risk-high px-4 py-2 text-xs font-semibold text-white hover:opacity-90 disabled:opacity-60"
                >
                  {busy ? "Disabling…" : "Confirm Disable 2FA"}
                </button>
                <button
                  type="button"
                  onClick={() => setShowDisableConfirm(false)}
                  className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium hover:bg-slate-800"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}
    </Card>
  );
}
