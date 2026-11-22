import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";

import { useAuth } from "@/context/AuthContext";
import { AppShell } from "@/components/AppShell";

export function ProtectedRoute({ children, adminOnly = false }: { children: ReactNode; adminOnly?: boolean }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-surface-light dark:bg-surface text-slate-500">
        <div className="text-center">
          <div className="mx-auto mb-3 flex h-10 w-10 animate-pulse items-center justify-center rounded-lg bg-brand-600 text-white font-bold">
            IS
          </div>
          <p className="text-sm font-medium">Verifying session…</p>
        </div>
      </div>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  if (adminOnly && user.role !== "admin") {
    return <Navigate to="/dashboard" replace />;
  }
  return <AppShell>{children}</AppShell>;
}
