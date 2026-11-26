import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as endpoints from "@/api/endpoints";
import * as AuthCtx from "@/context/AuthContext";
import ConnectedAccounts from "@/pages/ConnectedAccounts";
import OAuthCallback from "@/pages/OAuthCallback";

vi.mock("@/api/endpoints", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/api/endpoints")>();
  return {
    ...actual,
    fetchOAuthProviders: vi.fn(),
    fetchConnectedAccounts: vi.fn(),
    startGoogleOAuth: vi.fn(),
    startMicrosoftOAuth: vi.fn(),
    completeMicrosoftOAuth: vi.fn(),
    disconnectConnectedAccount: vi.fn(),
  };
});

describe("Microsoft Personal OAuth Frontend (P1-C)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

  it("renders Microsoft Personal capabilities, limitation notice, and Connect Microsoft action", async () => {
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([
      {
        provider: "google",
        display_name: "Google",
        account_type: "personal",
        configured: true,
        scopes: ["openid", "email", "profile"],
      },
      {
        provider: "microsoft",
        display_name: "Microsoft",
        account_type: "personal",
        configured: true,
        scopes: ["openid", "profile", "email", "User.Read"],
        capabilities: {
          identity_verification: "supported",
          login_history: "requires_enterprise",
          device_session_visibility: "requires_enterprise",
          mfa_status: "requires_enterprise",
        },
        limitations: [
          "Microsoft does not expose private sign-in history, active devices, or Microsoft MFA enrollment status through these personal permissions.",
        ],
      },
    ]);
    vi.mocked(endpoints.fetchConnectedAccounts).mockResolvedValue([
      {
        id: "ms-acc-1",
        provider: "microsoft",
        provider_email: "alice@outlook.com",
        provider_email_verified: true,
        display_name: "Alice Outlook",
        avatar_url: null,
        scopes: ["openid", "profile", "email", "User.Read"],
        status: "active",
        created_at: "2026-11-26T10:00:00",
        updated_at: "2026-11-26T10:00:00",
        last_synced_at: "2026-11-26T10:00:00",
      },
    ]);
    vi.mocked(endpoints.startMicrosoftOAuth).mockResolvedValue({
      provider: "microsoft",
      authorization_url: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?state=s",
      expires_at: "2026-11-26T10:10:00",
    });

    const onRedirect = vi.fn();
    render(
      <MemoryRouter>
        <ConnectedAccounts onRedirect={onRedirect} />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("alice@outlook.com")).toBeInTheDocument();
    });
    expect(
      screen.getByText(/does not expose private sign-in history, active devices, or Microsoft MFA enrollment status/i)
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Connect Microsoft" }));
    await waitFor(() => {
      expect(onRedirect).toHaveBeenCalledWith(
        "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?state=s"
      );
    });
  });

  it("handles /oauth/microsoft/callback and links Microsoft account", async () => {
    vi.mocked(endpoints.completeMicrosoftOAuth).mockResolvedValue({
      id: "ms-acc-1",
      provider: "microsoft",
      provider_email: "alice@outlook.com",
      provider_email_verified: true,
      display_name: "Alice Outlook",
      avatar_url: null,
      scopes: ["openid", "profile", "email", "User.Read"],
      status: "active",
      created_at: "2026-11-26T10:00:00",
      updated_at: "2026-11-26T10:00:00",
      last_synced_at: "2026-11-26T10:00:00",
    });

    render(
      <MemoryRouter initialEntries={["/oauth/microsoft/callback?code=ms-code&state=ms-state-1234567890"]}>
        <Routes>
          <Route path="/oauth/microsoft/callback" element={<OAuthCallback />} />
          <Route path="/connected-accounts" element={<div>Microsoft Linked Target</div>} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(endpoints.completeMicrosoftOAuth).toHaveBeenCalledWith("ms-code", "ms-state-1234567890");
      expect(screen.getByText("Microsoft Linked Target")).toBeInTheDocument();
    });
  });
});
