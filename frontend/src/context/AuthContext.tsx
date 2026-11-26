import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

import { fetchCurrentUser, loginUser, logoutUser, registerUser, verifyMfaLogin } from "@/api/endpoints";
import { clearTokens, getAccessToken, getRefreshToken, refreshAccessToken, setTokens } from "@/api/client";
import type { User } from "@/api/types";

export interface LoginResult {
  mfaRequired: boolean;
  challengeToken?: string;
}

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  completeMfaLogin: (challengeToken: string, code: string) => Promise<void>;
  register: (email: string, password: string, fullName?: string) => Promise<void>;
  logout: () => Promise<void>;
  restoreSession: () => Promise<User | null>;
  refreshUser: () => Promise<User | null>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function restoreSession(): Promise<User | null> {
    const refreshToken = getRefreshToken();
    if (!refreshToken) {
      clearTokens();
      setUser(null);
      return null;
    }

    try {
      let accessToken = getAccessToken();
      if (!accessToken) {
        accessToken = await refreshAccessToken();
      }
      if (!accessToken) {
        clearTokens();
        setUser(null);
        return null;
      }
      // fetchCurrentUser automatically refreshes once via Axios 401 interceptor if expired.
      const me = await fetchCurrentUser();
      setUser(me);
      return me;
    } catch {
      clearTokens();
      setUser(null);
      return null;
    }
  }

  useEffect(() => {
    let isMounted = true;

    async function recoverSession() {
      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        if (isMounted) setLoading(false);
        return;
      }

      try {
        let accessToken = getAccessToken();
        if (!accessToken) {
          accessToken = await refreshAccessToken();
        }
        const me = await fetchCurrentUser();
        if (isMounted) setUser(me);
      } catch {
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

  async function login(email: string, password: string): Promise<LoginResult> {
    const tokens = await loginUser({ email, password });
    if (tokens.mfa_required && tokens.mfa_challenge_token) {
      return { mfaRequired: true, challengeToken: tokens.mfa_challenge_token };
    }
    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error("Incomplete authentication response");
    }
    setTokens(tokens.access_token, tokens.refresh_token);
    const me = await fetchCurrentUser();
    setUser(me);
    return { mfaRequired: false };
  }

  async function completeMfaLogin(challengeToken: string, code: string) {
    const tokens = await verifyMfaLogin({ challenge_token: challengeToken, code });
    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error("Incomplete MFA verification response");
    }
    setTokens(tokens.access_token, tokens.refresh_token);
    const me = await fetchCurrentUser();
    setUser(me);
  }

  async function refreshUser(): Promise<User | null> {
    try {
      const me = await fetchCurrentUser();
      setUser(me);
      return me;
    } catch {
      return null;
    }
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
    <AuthContext.Provider value={{ user, loading, login, completeMfaLogin, register, logout, restoreSession, refreshUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
