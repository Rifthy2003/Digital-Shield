import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { fetchCurrentUser, loginUser, logoutUser, registerUser } from "@/api/endpoints";
import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "@/api/client";
import type { User } from "@/api/types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      setLoading(false);
      return;
    }
    fetchCurrentUser()
      .then(setUser)
      .catch(() => clearTokens())
      .finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const tokens = await loginUser({ email, password });
    setTokens(tokens.access_token, tokens.refresh_token);
    const me = await fetchCurrentUser();
    setUser(me);
  }

  async function register(email: string, password: string, fullName?: string) {
    await registerUser({ email, password, full_name: fullName });
    await login(email, password);
  }

  async function logout() {
    const refreshToken = getRefreshToken();
    try {
      if (refreshToken) await logoutUser(refreshToken);
    } finally {
      clearTokens();
      setUser(null);
    }
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
