import type { ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";

import { useAuth } from "@/context/AuthContext";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/url-checker", label: "URL Checker" },
  { to: "/message-checker", label: "Phishing Analyzer" },
  { to: "/breach-checker", label: "Breach Checker" },
  { to: "/password-health", label: "Password Health" },
  { to: "/alerts", label: "Alerts" },
  { to: "/incidents", label: "Incident Reporting" },
  { to: "/assistant", label: "AI Assistant" },
  { to: "/emergency", label: "I've Been Hacked" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <div className="flex min-h-screen bg-surface-light dark:bg-surface">
      <aside className="hidden w-64 shrink-0 flex-col border-r border-slate-200 bg-surface-light-raised p-4 dark:border-slate-800 dark:bg-surface-raised md:flex">
        <div className="mb-8 flex items-center gap-2 px-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-600 text-white font-bold">IS</div>
          <div>
            <p className="text-sm font-semibold leading-tight">Infora Digital Shield</p>
            <p className="text-xs text-slate-500">Protect · Detect · Respond</p>
          </div>
        </div>
        <nav className="flex-1 space-y-1">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-brand-500/10 text-brand-600 dark:text-brand-500"
                    : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
          {user?.role === "admin" && (
            <NavLink
              to="/admin"
              className={({ isActive }) =>
                `block rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
                  isActive ? "bg-brand-500/10 text-brand-600" : "text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
                }`
              }
            >
              Admin Dashboard
            </NavLink>
          )}
        </nav>
        <div className="border-t border-slate-200 pt-3 dark:border-slate-800">
          <NavLink to="/profile" className="block rounded-lg px-3 py-2 text-sm text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800">
            {user?.full_name ?? user?.email}
          </NavLink>
          <button
            onClick={handleLogout}
            className="mt-1 w-full rounded-lg px-3 py-2 text-left text-sm font-medium text-risk-high hover:bg-risk-high/10"
          >
            Log out
          </button>
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto p-6 md:p-10">{children}</main>
    </div>
  );
}
