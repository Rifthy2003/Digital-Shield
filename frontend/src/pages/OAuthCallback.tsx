import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { completeGoogleOAuth } from "@/api/endpoints";
import { Card } from "@/components/Card";
import { useAuth } from "@/context/AuthContext";

export default function OAuthCallback() {
  const { user, loading: authLoading, restoreSession } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const capturedRef = useRef<{ code: string | null; state: string | null; error: string | null } | null>(null);
  const startedRef = useRef(false);

  if (capturedRef.current === null) {
    capturedRef.current = {
      code: searchParams.get("code"),
      state: searchParams.get("state"),
      error: searchParams.get("error"),
    };
  }

  const [statusMessage, setStatusMessage] = useState<string>("Completing Google account linking…");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Immediately strip sensitive query parameters from browser history
  useEffect(() => {
    if (window.location.search) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
    if (searchParams.toString()) {
      setSearchParams({}, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  useEffect(() => {
    if (authLoading || startedRef.current) return;
    startedRef.current = true;

    const { code, state, error } = capturedRef.current ?? { code: null, state: null, error: null };

    async function runCallback() {
      const activeUser = user ?? (await restoreSession());
      if (!activeUser) {
        setErrorMessage(
          "Your Infora session has expired or you are not signed in. Please sign in again to link your Google account."
        );
        return;
      }

      if (error) {
        setErrorMessage(
          error === "access_denied"
            ? "Google account linking was cancelled (access denied). No changes were made."
            : "Google returned an authorization error. Please try again."
        );
        return;
      }

      if (!code || !state) {
        setErrorMessage("Missing authorization parameters from Google callback. Please try again.");
        return;
      }

      try {
        const linked = await completeGoogleOAuth(code, state);
        setStatusMessage("Google account linked successfully. Redirecting…");
        navigate("/connected-accounts", {
          replace: true,
          state: {
            oauthSuccess: linked.provider_email
              ? `Connected Google account (${linked.provider_email}).`
              : "Google account connected successfully.",
          },
        });
      } catch (err: unknown) {
        const status = (err as { response?: { status?: number } })?.response?.status;
        const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
        if (status === 401) {
          setErrorMessage(
            "Your Infora session has expired. Please sign in again to link your Google account."
          );
        } else {
          setErrorMessage(detail ?? "Could not complete Google account linking. Please try again.");
        }
      }
    }

    runCallback();
  }, [authLoading, navigate, restoreSession, user]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-light p-4 dark:bg-surface">
      <Card className="w-full max-w-md space-y-4 text-center">
        <div className="mx-auto flex h-10 w-10 items-center justify-center rounded-lg bg-brand-600 text-white font-bold">
          IS
        </div>
        <h1 className="text-lg font-semibold">Google Account Linking</h1>

        {errorMessage ? (
          <div className="space-y-4">
            <div role="alert" className="rounded-lg bg-risk-high/10 px-4 py-3 text-sm text-risk-high">
              {errorMessage}
            </div>
            <div className="flex justify-center gap-3">
              {!user ? (
                <Link
                  to="/login"
                  className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
                >
                  Sign in
                </Link>
              ) : (
                <Link
                  to="/connected-accounts"
                  className="rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
                >
                  Back to Connected Accounts
                </Link>
              )}
            </div>
          </div>
        ) : (
          <p role="status" className="text-sm text-slate-600 dark:text-slate-300">
            {statusMessage}
          </p>
        )}
      </Card>
    </div>
  );
}
