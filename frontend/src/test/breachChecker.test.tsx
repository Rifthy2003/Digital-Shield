import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { api } from "@/api/client";
import BreachChecker from "@/pages/BreachChecker";
import * as passwordStrength from "@/utils/passwordStrength";

describe("Data Breach Page — Password Breach Checker", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
    sessionStorage.clear();
  });

  it("renders Password Breach Checker below Email Breach Checker with privacy notice", () => {
    render(<BreachChecker />);

    const emailHeading = screen.getByText("Data Breach Monitoring");
    const pwHeading = screen.getByText("Password Breach Checker");
    expect(emailHeading).toBeInTheDocument();
    expect(pwHeading).toBeInTheDocument();
    expect(
      emailHeading.compareDocumentPosition(pwHeading) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();

    expect(
      screen.getByText(/Check whether your password has appeared in known data breaches\./i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Only the first five characters of its SHA-1 hash are sent to Have I Been Pwned/i)
    ).toBeInTheDocument();
  });

  it("toggles show/hide password and triggers no network requests while typing", () => {
    const checkSpy = vi.spyOn(passwordStrength, "checkPwnedPassword");
    const apiPostSpy = vi.spyOn(api, "post");

    render(<BreachChecker />);

    const input = screen.getByLabelText("Password to check") as HTMLInputElement;
    expect(input.type).toBe("password");

    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(input.type).toBe("text");

    fireEvent.click(screen.getByRole("button", { name: "Hide password" }));
    expect(input.type).toBe("password");

    fireEvent.change(input, { target: { value: "TypingDoesNotTriggerNetwork!" } });
    expect(checkSpy).not.toHaveBeenCalled();
    expect(apiPostSpy).not.toHaveBeenCalled();
  });

  it("invokes checkPwnedPassword, never posts password to Infora backend, shows no-match result, and clears password state", async () => {
    const apiPostSpy = vi.spyOn(api, "post");
    const checkSpy = vi.spyOn(passwordStrength, "checkPwnedPassword").mockResolvedValue({
      status: "safe",
      count: 0,
      message: "No match found in Have I Been Pwned breached passwords.",
    });

    render(<BreachChecker />);

    const input = screen.getByLabelText("Password to check") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "UniqueSafePassphrase!2026" } });
    fireEvent.click(screen.getByRole("button", { name: "Check Password" }));

    await waitFor(() => {
      expect(screen.getByText("No breach match found.")).toBeInTheDocument();
    });

    expect(checkSpy).toHaveBeenCalledTimes(1);
    expect(checkSpy).toHaveBeenCalledWith("UniqueSafePassphrase!2026");
    expect(apiPostSpy).not.toHaveBeenCalled();
    expect(input.value).toBe("");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("displays compromised password count and reuse recommendation", async () => {
    vi.spyOn(passwordStrength, "checkPwnedPassword").mockResolvedValue({
      status: "pwned",
      count: 4201,
      message: "Found in 4,201 known data breach records. Change this password anywhere it is reused.",
    });

    render(<BreachChecker />);

    fireEvent.change(screen.getByLabelText("Password to check"), {
      target: { value: "compromised-example" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Check Password" }));

    await waitFor(() => {
      expect(screen.getByText(/Compromised password detected/i)).toBeInTheDocument();
    });
    expect(screen.getByText(/4,201 known breach records/i)).toBeInTheDocument();
    expect(screen.getByText(/Change this password immediately everywhere it is reused/i)).toBeInTheDocument();
  });

  it("displays honest unavailable state on network failure without claiming password is safe", async () => {
    vi.spyOn(passwordStrength, "checkPwnedPassword").mockRejectedValue(new Error("Network error"));

    render(<BreachChecker />);

    fireEvent.change(screen.getByLabelText("Password to check"), {
      target: { value: "offline-test-password" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Check Password" }));

    await waitFor(() => {
      expect(screen.getByText("Breach check unavailable")).toBeInTheDocument();
    });
    expect(screen.queryByText(/No breach match found/i)).not.toBeInTheDocument();
  });

  it("prevents duplicate concurrent password checks", async () => {
    let resolveCheck!: (val: passwordStrength.PwnedCheckResult) => void;
    const checkSpy = vi.spyOn(passwordStrength, "checkPwnedPassword").mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCheck = resolve;
        })
    );

    render(<BreachChecker />);

    fireEvent.change(screen.getByLabelText("Password to check"), {
      target: { value: "ConcurrentCheck123!" },
    });

    const btn = screen.getByRole("button", { name: "Check Password" });
    fireEvent.click(btn);
    fireEvent.click(btn);

    expect(screen.getByText("Checking password...")).toBeInTheDocument();
    expect(checkSpy).toHaveBeenCalledTimes(1);

    resolveCheck({
      status: "safe",
      count: 0,
      message: "No match found in Have I Been Pwned breached passwords.",
    });

    await waitFor(() => {
      expect(screen.getByText("No breach match found.")).toBeInTheDocument();
    });
  });
});
