import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { fetchCurrentUser, loginUser, logoutUser, registerUser } from "@/api/endpoints";
import { clearTokens, getAccessToken, getRefreshToken, refreshAccessToken, setTokens } from "@/api/client";
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
    let isMounted = true;

    async function recoverSession() {
      const refreshToken = getRefreshToken();

      // If there is no refresh token, the user has no persistent session
      if (!refreshToken) {
        if (isMounted) setLoading(false);
        return;
      }

      try {
        const accessToken = getAccessToken();
        // If we have an access token, try to fetch current user
        if (accessToken) {
          try {
            const me = await fetchCurrentUser();
            if (isMounted) {
              setUser(me);
              setLoading(false);
              return;
            }
          } catch {
            // Access token expired; fall through to refresh
          }
        }

        // If access token was missing or expired, refresh it
        const newToken = await refreshAccessToken();
        if (newToken) {
          const me = await fetchCurrentUser();
          if (isMounted) setUser(me);
        } else {
          clearTokens();
          if (isMounted) setUser(null);
        }
      } catch {
        // Refresh token expired or session revoked on server
        clearTokens();
        if (isMounted) setUser(null);
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    recoverSession();

    return () => {
      isMounted = false;
    };
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
    } catch {
      // Server-side error or offline; proceed to clear local state
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
