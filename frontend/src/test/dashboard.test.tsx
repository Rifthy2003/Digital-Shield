import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as endpoints from "@/api/endpoints";
import type { ConnectedAccount, DashboardData, OAuthProviderInfo } from "@/api/types";
import { AppShell } from "@/components/AppShell";
import * as AuthCtx from "@/context/AuthContext";
import Dashboard from "@/pages/Dashboard";

vi.mock("@/api/endpoints", async () => {
  const actual = await vi.importActual<typeof import("@/api/endpoints")>("@/api/endpoints");
  return {
    ...actual,
    fetchDashboard: vi.fn(),
    fetchOAuthProviders: vi.fn(),
    fetchConnectedAccounts: vi.fn(),
  };
});

const mockDashboard: DashboardData = {
  score: 82,
  score_breakdown: {
    mfa: { points: 0, max_points: 20, reason: "MFA not enabled" },
    email_verification: { points: 20, max_points: 20, reason: "Email verified" },
    breach_monitoring: { points: 20, max_points: 20, reason: "No exposures found" },
  },
  alerts_summary: { high: 1, medium: 2, info: 3 },
  recent_alerts: [
    {
      id: "al-1",
      severity: "high",
      category: "url_check",
      title: "Suspicious link flagged",
      message: "High-risk phishing domain detected.",
      is_read: false,
      is_resolved: false,
      created_at: "2026-11-25T10:00:00",
    },
  ],
  recommendations: ["Enable MFA on your Infora account."],
  demo_data_notice: null,
};

const mockProvider: OAuthProviderInfo = {
  provider: "google",
  display_name: "Google",
  configured: true,
  scopes: ["openid", "email", "profile"],
};

const mockAccount: ConnectedAccount = {
  id: "acc-1",
  provider: "google",
  provider_email: "citizen@gmail.com",
  provider_email_verified: true,
  display_name: "Citizen Google",
  avatar_url: null,
  scopes: ["openid", "email", "profile"],
  status: "active",
  created_at: "2026-11-25T10:00:00",
  updated_at: "2026-11-25T10:00:00",
  last_synced_at: "2026-11-25T10:00:00",
};

describe("Upgraded Dashboard & AppShell Navigation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(AuthCtx, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "citizen@example.com",
        full_name: "Citizen User",
        role: "citizen",
        is_email_verified: true,
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

  it("renders Dashboard with real API data and Connected Accounts integration", async () => {
    vi.mocked(endpoints.fetchDashboard).mockResolvedValue(mockDashboard);
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([mockProvider]);
    vi.mocked(endpoints.fetchConnectedAccounts).mockResolvedValue([mockAccount]);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Security Dashboard")).toBeInTheDocument();
      expect(screen.getByText("82")).toBeInTheDocument();
    });

    expect(screen.getByText("Suspicious link flagged")).toBeInTheDocument();
    expect(screen.getByText("Enable MFA on your Infora account.")).toBeInTheDocument();
    expect(screen.getByText("citizen@gmail.com")).toBeInTheDocument();
    expect(screen.getByText(/1 connected provider · 1 Google account/i)).toBeInTheDocument();
    expect(screen.getByText(/Not yet checked/i)).toBeInTheDocument();
    expect(screen.getByText(/Not available via consumer OAuth APIs/i)).toBeInTheDocument();
  });

  it("shows honest empty state for Threat Activity when zero alerts exist", async () => {
    vi.mocked(endpoints.fetchDashboard).mockResolvedValue({
      ...mockDashboard,
      alerts_summary: { high: 0, medium: 0, info: 0 },
      recent_alerts: [],
      recommendations: [],
    });
    vi.mocked(endpoints.fetchOAuthProviders).mockResolvedValue([mockProvider]);
    vi.mocked(endpoints.fetchConnectedAccounts).mockResolvedValue([]);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/No open threat alerts recorded/i)).toBeInTheDocument();
    });
  });

  it("renders all required sidebar navigation items in AppShell", () => {
    render(
      <MemoryRouter initialEntries={["/dashboard"]}>
        <AppShell>
          <div>Content</div>
        </AppShell>
      </MemoryRouter>
    );

    const expectedLinks = [
      "Dashboard",
      "URL Checker",
      "Phishing Analyzer",
      "Breach Checker",
      "Password Health",
      "Connected Accounts",
      "Alerts",
      "Incident Reporting",
      "AI Assistant",
      "I've Been Hacked",
    ];
    for (const label of expectedLinks) {
      expect(screen.getAllByRole("link", { name: label }).length).toBeGreaterThan(0);
    }
  });
});
