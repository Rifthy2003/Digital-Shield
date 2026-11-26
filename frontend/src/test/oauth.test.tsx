import { StrictMode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as endpoints from "@/api/endpoints";
import type { ConnectedAccount, OAuthProviderInfo } from "@/api/types";
import App from "@/App";
import * as AuthCtx from "@/context/AuthContext";
import ConnectedAccounts from "@/pages/ConnectedAccounts";
import OAuthCallback from "@/pages/OAuthCallback";

vi.mock("@/api/endpoints", async () => {
  const actual = await vi.importActual<typeof import("@/api/endpoints")>("@/api/endpoints");
  return {
    ...actual,
    fetchOAuthProviders: vi.fn(),
    fetchConnectedAccounts: vi.fn(),
    startGoogleOAuth: vi.fn(),
    completeGoogleOAuth: vi.fn(),
    disconnectConnectedAccount: vi.fn(),
  };
});

const googleProvider: OAuthProviderInfo = {
  provider: "google",
  display_name: "Google",
  configured: true,
  scopes: ["openid", "email", "profile"],
};

const accountOne: ConnectedAccount = {
  id: "acc-1",
  provider: "google",
  provider_email: "personal@gmail.com",
  provider_email_verified: true,
  display_name: "Personal Gmail",
  avatar_url: null,
  scopes: ["openid", "email", "profile"],
  status: "active",
  created_at: "2026-11-25T10:00:00",
  updated_at: "2026-11-25T10:00:00",
  last_synced_at: "2026-11-25T10:00:00",
};

const accountTwo: ConnectedAccount = {
  id: "acc-2",
  provider: "google",
  provider_email: "work@gmail.com",
  provider_email_verified: true,
  display_name: "Work Gmail",
  avatar_url: null,
  scopes: ["openid", "email", "profile"],
  status: "active",
  created_at: "2026-11-25T11:00:00",
  updated_at: "2026-11-25T11:00:00",
  last_synced_at: "2026-11-25T11:00:00",
};

describe("Connected Accounts & OAuth Callback UI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    sessionStorage.clear();
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        full_name: "User",
        role: "citizen",
        is_email_verified: false,
        mfa_enabled: false,
      },
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: vi.fn(),
      refreshUser: vi.fn(),
    });
  });

  it("renders Connected Accounts page with loading and empty states", async () => {
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([googleProvider]);
    vi.mocked(endpoints.fetchConnectedAccounts).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <ConnectedAccounts />
      </MemoryRouter>
    );

    expect(screen.getByText("Connected Accounts")).toBeInTheDocument();
    expect(screen.getByText(/Loading connected accounts/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Connecting your Google account allows Infora to securely link your account identity/i)
    ).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("No Google accounts connected yet.")).toBeInTheDocument();
    });
    expect(screen.getByText("Microsoft")).toBeInTheDocument();
    expect(screen.getAllByText("Coming soon").length).toBeGreaterThan(0);
  });

  it("initiates Google OAuth authorization and prevents duplicate clicks", async () => {
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([googleProvider]);
    vi.mocked(endpoints.fetchConnectedAccounts).mockResolvedValue([]);
    let resolveAuth: (val: { provider: string; authorization_url: string; expires_at: string }) => void;
    vi.mocked(endpoints.startGoogleOAuth).mockImplementation(
      () =>
        new Promise((res) => {
          resolveAuth = res;
        })
    );
    const redirectSpy = vi.fn();

    render(
      <MemoryRouter>
        <ConnectedAccounts onRedirect={redirectSpy} />
      </MemoryRouter>
    );

    const btn = await screen.findByRole("button", { name: /Connect Google/i });
    await waitFor(() => expect(btn).not.toBeDisabled());

    fireEvent.click(btn);
    fireEvent.click(btn);
    expect(endpoints.startGoogleOAuth).toHaveBeenCalledTimes(1);

    resolveAuth!({
      provider: "google",
      authorization_url: "https://accounts.google.com/o/oauth2/v2/auth?state=abc",
      expires_at: "2026-11-25T12:00:00",
    });

    await waitFor(() => {
      expect(redirectSpy).toHaveBeenCalledWith(
        "https://accounts.google.com/o/oauth2/v2/auth?state=abc"
      );
    });
  });

  it("displays multiple connected Google accounts and handles disconnect confirmation", async () => {
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([googleProvider]);
    vi.mocked(endpoints.fetchConnectedAccounts)
      .mockResolvedValueOnce([accountOne, accountTwo])
      .mockResolvedValueOnce([accountTwo]);
    vi.mocked(endpoints.disconnectConnectedAccount).mockResolvedValue({
      message: "Connected account disconnected",
      disconnected_account_id: "acc-1",
      upstream_revocation_status: "revoked",
    });

    render(
      <MemoryRouter>
        <ConnectedAccounts />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("personal@gmail.com")).toBeInTheDocument();
      expect(screen.getByText("work@gmail.com")).toBeInTheDocument();
    });

    const disconnectButtons = screen.getAllByRole("button", { name: "Disconnect" });
    fireEvent.click(disconnectButtons[0]);

    // Cancel closes dialog without calling API
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(endpoints.disconnectConnectedAccount).not.toHaveBeenCalled();

    // Confirm disconnect calls API and refreshes list
    fireEvent.click(disconnectButtons[0]);
    fireEvent.click(screen.getByRole("button", { name: "Confirm disconnect" }));

    await waitFor(() => {
      expect(endpoints.disconnectConnectedAccount).toHaveBeenCalledWith("acc-1");
      expect(screen.getByText(/Google account disconnected and upstream access revoked/i)).toBeInTheDocument();
    });
    expect(screen.queryByText("personal@gmail.com")).not.toBeInTheDocument();
    expect(screen.getByText("work@gmail.com")).toBeInTheDocument();

    // No provider tokens stored in browser storage
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("shows API error and retry button when loading fails", async () => {
    vi.mocked(endpoints.fetchOAuthProviders).mockRejectedValue(new Error("network"));
    vi.mocked(endpoints.fetchConnectedAccounts).mockRejectedValue(new Error("network"));

    render(
      <MemoryRouter>
        <ConnectedAccounts />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/Unable to load connected accounts/i);
    });
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("handles OAuth callback success, scrubs URL params, and prevents duplicate calls in StrictMode", async () => {
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        full_name: "User",
        role: "citizen",
        is_email_verified: false,
        mfa_enabled: false,
      },
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: vi.fn(),
      refreshUser: vi.fn(),
    });
    vi.mocked(endpoints.completeGoogleOAuth).mockResolvedValue(accountOne);
    window.history.replaceState({}, "", "/oauth/google/callback?code=auth-code-1&state=state-token-123456");
    const replaceStateSpy = vi.spyOn(window.history, "replaceState");

    render(
      <StrictMode>
        <MemoryRouter initialEntries={["/oauth/google/callback?code=auth-code-1&state=state-token-123456"]}>
          <Routes>
            <Route path="/oauth/google/callback" element={<OAuthCallback />} />
            <Route path="/connected-accounts" element={<div>Connected Accounts Target</div>} />
          </Routes>
        </MemoryRouter>
      </StrictMode>
    );

    await waitFor(() => {
      expect(endpoints.completeGoogleOAuth).toHaveBeenCalledTimes(1);
      expect(endpoints.completeGoogleOAuth).toHaveBeenCalledWith("auth-code-1", "state-token-123456");
      expect(screen.getByText("Connected Accounts Target")).toBeInTheDocument();
    });
    expect(replaceStateSpy).toHaveBeenCalled();
    expect(window.location.search).toBe("");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("handles OAuth callback failure, access_denied, and expired session", async () => {
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "user@example.com",
        full_name: "User",
        role: "citizen",
        is_email_verified: false,
        mfa_enabled: false,
      },
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: vi.fn(),
      refreshUser: vi.fn(),
    });

    // access_denied
    const { unmount } = render(
      <MemoryRouter initialEntries={["/oauth/google/callback?error=access_denied"]}>
        <Routes>
          <Route path="/oauth/google/callback" element={<OAuthCallback />} />
        </Routes>
      </MemoryRouter>
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/access denied/i);
    expect(endpoints.completeGoogleOAuth).not.toHaveBeenCalled();
    unmount();

    // Backend callback error (never auto-retried)
    vi.mocked(endpoints.completeGoogleOAuth).mockRejectedValue({
      response: { status: 400, data: { detail: "Invalid, expired, or already used OAuth state" } },
    });
    const { unmount: unmount2 } = render(
      <MemoryRouter initialEntries={["/oauth/google/callback?code=c&state=s1234567890123456"]}>
        <Routes>
          <Route path="/oauth/google/callback" element={<OAuthCallback />} />
        </Routes>
      </MemoryRouter>
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/Invalid, expired, or already used OAuth state/i);
    expect(endpoints.completeGoogleOAuth).toHaveBeenCalledTimes(1);
    unmount2();

    // Expired Infora session
    const restoreFail = vi.fn().mockResolvedValue(null);
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: null,
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: restoreFail,
      refreshUser: vi.fn(),
    });
    render(
      <MemoryRouter initialEntries={["/oauth/google/callback?code=c&state=s1234567890123456"]}>
        <Routes>
          <Route path="/oauth/google/callback" element={<OAuthCallback />} />
        </Routes>
      </MemoryRouter>
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/session has expired/i);
    expect(restoreFail).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  });

  it("restores Infora session via refresh token when user is null on callback and completes linking", async () => {
    const restoredUser = {
      id: "u1",
      email: "user@example.com",
      full_name: "User",
      role: "citizen" as const,
      is_email_verified: false,
      mfa_enabled: false,
    };
    const restoreOk = vi.fn().mockResolvedValue(restoredUser);
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: null,
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: restoreOk,
      refreshUser: vi.fn(),
    });
    vi.mocked(endpoints.completeGoogleOAuth).mockResolvedValue(accountOne);

    render(
      <MemoryRouter initialEntries={["/oauth/google/callback?code=restored-code&state=restored-state-12345"]}>
        <Routes>
          <Route path="/oauth/google/callback" element={<OAuthCallback />} />
          <Route path="/connected-accounts" element={<div>Connected Accounts Restored</div>} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(restoreOk).toHaveBeenCalledTimes(1);
      expect(endpoints.completeGoogleOAuth).toHaveBeenCalledTimes(1);
      expect(endpoints.completeGoogleOAuth).toHaveBeenCalledWith("restored-code", "restored-state-12345");
      expect(screen.getByText("Connected Accounts Restored")).toBeInTheDocument();
    });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("deduplicates concurrent refreshAccessToken calls so rotating refresh tokens never collide", async () => {
    const axiosMod = await import("axios");
    const clientMod = await import("@/api/client");
    clientMod.setTokens("expired-access", "valid-refresh-1");

    const postSpy = vi.spyOn(axiosMod.default, "post").mockResolvedValue({
      data: { access_token: "new-access-2", refresh_token: "new-refresh-2" },
    });

    const [t1, t2] = await Promise.all([
      clientMod.refreshAccessToken(),
      clientMod.refreshAccessToken(),
    ]);

    expect(t1).toBe("new-access-2");
    expect(t2).toBe("new-access-2");
    expect(postSpy).toHaveBeenCalledTimes(1);
    expect(clientMod.getAccessToken()).toBe("new-access-2");
    expect(clientMod.getRefreshToken()).toBe("new-refresh-2");
    postSpy.mockRestore();
  });

  it("preserves existing App routes", () => {
    vi.restoreAllMocks();
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <App />
      </MemoryRouter>
    );
    expect(screen.getByRole("button", { name: /Sign in/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Infora Digital Shield/i })).toBeInTheDocument();
  });
});
