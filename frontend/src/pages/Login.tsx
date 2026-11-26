import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { useAuth } from "@/context/AuthContext";
import { Card } from "@/components/Card";

export default function Login() {
  const { user, loading, login, completeMfaLogin } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaChallengeToken, setMfaChallengeToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!loading && user) {
      navigate("/dashboard", { replace: true });
    }
  }, [user, loading, navigate]);

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const result = await login(email, password);
      if (result.mfaRequired && result.challengeToken) {
        setMfaChallengeToken(result.challengeToken);
        setMfaCode("");
        return;
      }
      navigate("/dashboard");
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 423) setError("Account temporarily locked due to repeated failed attempts. Try again later.");
      else setError("Invalid email or password.");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleMfaSubmit(e: FormEvent) {
    e.preventDefault();
    if (!mfaChallengeToken) return;
    setError(null);
    setSubmitting(true);
    try {
      await completeMfaLogin(mfaChallengeToken, mfaCode.trim());
      navigate("/dashboard");
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 429) {
        setError("Too many verification attempts. Please wait a moment and try again.");
      } else {
        setError("Invalid or expired verification code.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  function handleBackToLogin() {
    setMfaChallengeToken(null);
    setMfaCode("");
    setError(null);
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-light px-4 dark:bg-surface">
      <Card className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-lg bg-brand-600 text-white font-bold">IS</div>
          <h1 className="text-xl font-semibold">
            {mfaChallengeToken ? "Two-Factor Verification" : "Infora Digital Shield"}
          </h1>
          <p className="text-sm text-slate-500">
            {mfaChallengeToken
              ? "Enter the 6-digit code from your authenticator app or a recovery code for your Infora account."
              : "Your Personal Digital Security Center"}
          </p>
        </div>

        {mfaChallengeToken ? (
          <form onSubmit={handleMfaSubmit} className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium" htmlFor="mfa-code">
                Verification or recovery code
              </label>
              <input
                id="mfa-code"
                type="text"
                required
                autoComplete="one-time-code"
                placeholder="123456 or XXXXX-XXXXX"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-center font-mono text-sm tracking-wider focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
              />
            </div>
            {error && <p className="text-sm text-risk-high" role="alert">{error}</p>}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-brand-600 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-500 disabled:opacity-60"
            >
              {submitting ? "Verifying…" : "Verify & Sign in"}
            </button>
            <button
              type="button"
              onClick={handleBackToLogin}
              className="w-full rounded-lg border border-slate-300 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              Back to sign in
            </button>
          </form>
        ) : (
          <form onSubmit={handlePasswordSubmit} className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium" htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium" htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500 dark:border-slate-700 dark:bg-surface"
              />
            </div>
            {error && <p className="text-sm text-risk-high" role="alert">{error}</p>}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-lg bg-brand-600 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-500 disabled:opacity-60"
            >
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}

        {!mfaChallengeToken && (
          <p className="mt-4 text-center text-sm text-slate-500">
            No account? <Link to="/register" className="font-medium text-brand-600">Create one</Link>
          </p>
        )}
      </Card>
    </div>
  );
}
