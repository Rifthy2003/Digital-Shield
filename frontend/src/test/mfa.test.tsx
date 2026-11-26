import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as endpoints from "@/api/endpoints";
import { MfaSettings } from "@/components/MfaSettings";
import * as AuthContextModule from "@/context/AuthContext";
import Login from "@/pages/Login";

vi.mock("qrcode", () => ({
  default: {
    toDataURL: vi.fn().mockResolvedValue("data:image/png;base64,MOCK_QR"),
  },
}));

describe("Infora Account TOTP MFA Frontend (P1-B)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("enrolls TOTP, displays QR code + manual secret, and shows one-time recovery codes", async () => {
    const refreshUser = vi.fn().mockResolvedValue(null);
    vi.spyOn(AuthContextModule, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "alice@example.com",
        full_name: "Alice",
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
      refreshUser,
    });

    vi.spyOn(endpoints, "fetchMfaStatus").mockResolvedValue({
      mfa_enabled: false,
      recovery_codes_remaining: 0,
    });
    vi.spyOn(endpoints, "startMfaEnrollment").mockResolvedValue({
      provisioning_uri: "otpauth://totp/Infora%20Digital%20Shield:alice%40example.com?secret=JBSWY3DPEHPK3PXP",
      secret: "JBSWY3DPEHPK3PXP",
      issuer: "Infora Digital Shield",
      account_name: "alice@example.com",
    });
    vi.spyOn(endpoints, "verifyMfaEnrollment").mockResolvedValue({
      mfa_enabled: true,
      recovery_codes: ["ABCD2-EFGH3", "JKLM4-NPQR5"],
    });

    render(<MfaSettings />);

    expect(screen.getByText(/Protects your Infora Digital Shield sign-in only/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Enable 2FA/i }));

    await waitFor(() => {
      expect(screen.getByAltText("Infora TOTP QR Code")).toBeInTheDocument();
    });
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/Enter the 6-digit verification code/i), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Verify & Enable 2FA/i }));

    await waitFor(() => {
      expect(screen.getByText("Save your one-time recovery codes")).toBeInTheDocument();
    });
    expect(screen.getByText("ABCD2-EFGH3")).toBeInTheDocument();
    expect(screen.getByText("JKLM4-NPQR5")).toBeInTheDocument();
    expect(refreshUser).toHaveBeenCalled();
  });

  it("requires password and code confirmation to disable MFA", async () => {
    const refreshUser = vi.fn().mockResolvedValue(null);
    vi.spyOn(AuthContextModule, "useAuth").mockReturnValue({
      user: {
        id: "u1",
        email: "alice@example.com",
        full_name: "Alice",
        role: "citizen",
        is_email_verified: false,
        mfa_enabled: true,
      },
      loading: false,
      login: vi.fn(),
      completeMfaLogin: vi.fn(),
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: vi.fn(),
      refreshUser,
    });

    vi.spyOn(endpoints, "fetchMfaStatus").mockResolvedValue({
      mfa_enabled: true,
      recovery_codes_remaining: 8,
    });
    const disableSpy = vi.spyOn(endpoints, "disableMfa").mockResolvedValue({
      mfa_enabled: false,
      revoked_sessions_count: 1,
      message: "Multi-factor authentication has been disabled.",
    });

    render(<MfaSettings />);

    await waitFor(() => {
      expect(screen.getByText(/Recovery codes remaining: 8/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /Disable 2FA/i }));
    fireEvent.change(screen.getByLabelText(/Current password/i), {
      target: { value: "StrongPassword123!" },
    });
    fireEvent.change(screen.getByLabelText(/Authenticator or recovery code/i), {
      target: { value: "654321" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm Disable 2FA/i }));

    await waitFor(() => {
      expect(disableSpy).toHaveBeenCalledWith({
        current_password: "StrongPassword123!",
        code: "654321",
      });
    });
    expect(refreshUser).toHaveBeenCalled();
  });

  it("prompts for MFA verification step on Login when mfaRequired is returned", async () => {
    const loginMock = vi.fn().mockResolvedValue({
      mfaRequired: true,
      challengeToken: "challenge-token-abc",
    });
    const completeMfaMock = vi.fn().mockResolvedValue(undefined);

    vi.spyOn(AuthContextModule, "useAuth").mockReturnValue({
      user: null,
      loading: false,
      login: loginMock,
      completeMfaLogin: completeMfaMock,
      register: vi.fn(),
      logout: vi.fn(),
      restoreSession: vi.fn(),
      refreshUser: vi.fn(),
    });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: "alice@example.com" } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: "StrongPassword123!" } });
    fireEvent.click(screen.getByRole("button", { name: /Sign in/i }));

    await waitFor(() => {
      expect(screen.getByText("Two-Factor Verification")).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Verification or recovery code/i), {
      target: { value: "654321" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Verify & Sign in/i }));

    await waitFor(() => {
      expect(completeMfaMock).toHaveBeenCalledWith("challenge-token-abc", "654321");
    });
  });
});
