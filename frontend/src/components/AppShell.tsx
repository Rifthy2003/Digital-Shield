import { useState, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "@/context/AuthContext";

const PAGE_TITLES: Record<string, string> = {
  "/dashboard": "Security Dashboard",
  "/url-checker": "URL Threat Checker",
  "/message-checker": "Phishing Analyzer",
  "/breach-checker": "Breach Checker",
  "/password-health": "Password Health",
  "/connected-accounts": "Connected Accounts",
  "/alerts": "Security Alerts",
  "/incidents": "Incident Reporting",
  "/assistant": "AI Assistant",
  "/emergency": "Account Recovery",
  "/profile": "Profile & Settings",
  "/admin": "Admin Dashboard",
};

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/url-checker", label: "URL Checker" },
  { to: "/message-checker", label: "Phishing Analyzer" },
  { to: "/breach-checker", label: "Breach Checker" },
  { to: "/password-health", label: "Password Health" },
  { to: "/connected-accounts", label: "Connected Accounts" },
  { to: "/alerts", label: "Alerts" },
  { to: "/incidents", label: "Incident Reporting" },
  { to: "/assistant", label: "AI Assistant" },
  { to: "/emergency", label: "I've Been Hacked" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pageTitle = PAGE_TITLES[location.pathname] ?? "Security Operations Center";

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `flex items-center justify-between rounded-lg border-l-2 px-3 py-2 text-sm font-medium transition-colors ${
      isActive
        ? "border-brand-500 bg-brand-500/15 text-white"
        : "border-transparent text-slate-400 hover:bg-slate-800/70 hover:text-slate-100"
    }`;

  const sidebarContent = (
    <div className="flex h-full flex-col">
      <div className="mb-6 flex items-center gap-2.5 px-2">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600 font-bold text-white shadow-sm">
          IS
        </div>
        <div>
          <p className="text-sm font-semibold leading-tight text-slate-100">Infora Digital Shield</p>
          <p className="text-[11px] text-slate-400">Protect · Detect · Respond</p>
        </div>
      </div>

      <nav aria-label="Main navigation" className="flex-1 space-y-1">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            onClick={() => setMobileNavOpen(false)}
            className={navLinkClass}
          >
            <span>{item.label}</span>
          </NavLink>
        ))}
        {user?.role === "admin" && (
          <NavLink
            to="/admin"
            onClick={() => setMobileNavOpen(false)}
            className={navLinkClass}
          >
            <span>Admin Dashboard</span>
          </NavLink>
        )}
      </nav>

      <div className="mt-4 border-t border-slate-800/80 pt-3">
        <NavLink
          to="/profile"
          onClick={() => setMobileNavOpen(false)}
          className="block truncate rounded-lg px-3 py-2 text-sm text-slate-300 hover:bg-slate-800/70 hover:text-white"
        >
          {user?.full_name ?? user?.email}
        </NavLink>
        <button
          type="button"
          onClick={handleLogout}
          className="mt-1 w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-risk-high transition-colors hover:bg-risk-high/10"
        >
          Log out
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen bg-surface text-slate-100">
      {/* Desktop Sidebar */}
      <aside className="hidden w-64 shrink-0 border-r border-slate-800/80 bg-[#070d18] p-4 md:block">
        {sidebarContent}
      </aside>

      {/* Mobile Drawer */}
      {mobileNavOpen && (
        <div className="fixed inset-0 z-50 flex md:hidden">
          <div
            className="fixed inset-0 bg-black/60"
            onClick={() => setMobileNavOpen(false)}
          />
          <aside className="relative z-10 w-64 border-r border-slate-800 bg-[#070d18] p-4">
            {sidebarContent}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top Navigation Bar */}
        <header className="flex h-14 items-center justify-between border-b border-slate-800/80 bg-surface-raised/70 px-4 backdrop-blur md:px-8">
          <div className="flex items-center gap-3">
            <button
              type="button"
              aria-label="Open navigation menu"
              onClick={() => setMobileNavOpen(true)}
              className="rounded-lg border border-slate-700 px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 md:hidden"
            >
              Menu
            </button>
            <span className="text-sm font-semibold text-slate-100">{pageTitle}</span>
          </div>

          <div className="flex items-center gap-3">
            <NavLink
              to="/alerts"
              aria-label="Notifications and Alerts"
              className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-surface/80 px-3 py-1.5 text-xs font-medium text-slate-300 transition-colors hover:border-slate-700 hover:text-white"
            >
              <svg className="h-3.5 w-3.5 text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              <span>Alerts</span>
            </NavLink>
            <NavLink
              to="/profile"
              className="flex items-center gap-2 rounded-lg border border-slate-800 bg-surface/80 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-slate-700 hover:text-white"
            >
              <span className="h-2 w-2 rounded-full bg-risk-low" />
              <span className="max-w-[140px] truncate">{user?.full_name ?? user?.email ?? "Profile"}</span>
            </NavLink>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6 md:p-8">{children}</main>
      </div>
    </div>
  );
}
