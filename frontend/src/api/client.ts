import axios, { type AxiosInstance } from "axios";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";

const ACCESS_TOKEN_KEY = "infora_access_token";
const REFRESH_TOKEN_KEY = "infora_refresh_token";

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(accessToken: string, refreshToken: string) {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export const api: AxiosInstance = axios.create({ baseURL: API_BASE_URL });

api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshInFlight: Promise<string> | null = null;

async function refreshAccessToken(): Promise<string> {
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    throw new Error("No refresh token available");
  }
  const resp = await axios.post(`${API_BASE_URL}/auth/refresh`, { refresh_token: refreshToken });
  setTokens(resp.data.access_token, resp.data.refresh_token);
  return resp.data.access_token as string;
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    // Never attempt to refresh the refresh/login/register calls themselves.
    const skipRefresh = ["/auth/refresh", "/auth/login", "/auth/register"].some((p) =>
      original?.url?.includes(p),
    );
    if (error.response?.status === 401 && !original._retried && !skipRefresh) {
      original._retried = true;
      try {
        refreshInFlight = refreshInFlight ?? refreshAccessToken();
        const newToken = await refreshInFlight;
        refreshInFlight = null;
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch {
        refreshInFlight = null;
        clearTokens();
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  },
);
