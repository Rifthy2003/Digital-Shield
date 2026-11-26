import { api } from "@/api/client";
import type {
  ActiveSession,
  Alert,
  AssistantResponse,
  BreachCheckResult,
  ConnectedAccount,
  DashboardData,
  DisconnectAccountResponse,
  IncidentReport,
  LogoutAllResponse,
  MessageCheckResult,
  MfaDisableResponse,
  MfaEnrollStartResponse,
  MfaEnrollVerifyResponse,
  MfaRecoveryCodesResponse,
  MfaStatus,
  OAuthAuthorizeResponse,
  OAuthProvidersResponse,
  TokenPair,
  UrlCheckResult,
  User,
} from "@/api/types";

// --- Auth ---
export const registerUser = (data: { email: string; password: string; full_name?: string }) =>
  api.post<User>("/auth/register", data).then((r) => r.data);

export const loginUser = (data: { email: string; password: string }) =>
  api.post<TokenPair>("/auth/login", data).then((r) => r.data);

export const logoutUser = (refresh_token: string) => api.post("/auth/logout", { refresh_token });

export const fetchCurrentUser = () => api.get<User>("/auth/me").then((r) => r.data);

export const fetchSessions = () => api.get<ActiveSession[]>("/auth/sessions").then((r) => r.data);

export const revokeSession = (sessionId: string) =>
  api.delete<{ message: string; revoked_session_id: string }>(`/auth/sessions/${sessionId}`).then((r) => r.data);

export const logoutAllOtherSessions = () =>
  api.post<LogoutAllResponse>("/auth/logout-all").then((r) => r.data);

export const fetchMfaStatus = () =>
  api.get<MfaStatus>("/auth/mfa/status").then((r) => r.data);

export const startMfaEnrollment = () =>
  api.post<MfaEnrollStartResponse>("/auth/mfa/enroll/start").then((r) => r.data);

export const verifyMfaEnrollment = (code: string) =>
  api.post<MfaEnrollVerifyResponse>("/auth/mfa/enroll/verify", { code }).then((r) => r.data);

export const verifyMfaLogin = (data: { challenge_token: string; code: string }) =>
  api.post<TokenPair>("/auth/mfa/login-verify", data).then((r) => r.data);

export const regenerateMfaRecoveryCodes = (data: { current_password: string; code: string }) =>
  api.post<MfaRecoveryCodesResponse>("/auth/mfa/recovery-codes/regenerate", data).then((r) => r.data);

export const disableMfa = (data: { current_password: string; code: string }) =>
  api.post<MfaDisableResponse>("/auth/mfa/disable", data).then((r) => r.data);

// --- Dashboard ---
export const fetchDashboard = () => api.get<DashboardData>("/dashboard").then((r) => r.data);

// --- URL Checker ---
export const checkUrl = (url: string) =>
  api.post<UrlCheckResult>("/url-checker/check", { url }).then((r) => r.data);

// --- Message Analyzer ---
export const checkMessage = (content: string) =>
  api.post<MessageCheckResult>("/message-checker/check", { content }).then((r) => r.data);

// --- Breach Checker ---
export const checkBreach = (email: string) =>
  api.post<BreachCheckResult>("/breach-checker/check", { email }).then((r) => r.data);

// --- Alerts ---
export const fetchAlerts = () => api.get<Alert[]>("/alerts").then((r) => r.data);
export const markAlertRead = (id: string) => api.post<Alert>(`/alerts/${id}/read`).then((r) => r.data);
export const resolveAlert = (id: string) => api.post<Alert>(`/alerts/${id}/resolve`).then((r) => r.data);

// --- Incident Reporting ---
export const submitIncident = (data: { category: string; description: string }) =>
  api.post<IncidentReport>("/incidents", data).then((r) => r.data);
export const fetchMyIncidents = () => api.get<IncidentReport[]>("/incidents").then((r) => r.data);

// --- AI Assistant ---
export const askAssistant = (question: string) =>
  api.post<AssistantResponse>("/assistant/ask", { question }).then((r) => r.data);

// --- Admin ---
export interface AdminStats {
  total_users: number;
  total_url_checks: number;
  total_incident_reports: number;
  open_incident_reports: number;
}
export const fetchAdminStats = () => api.get<AdminStats>("/admin/stats").then((r) => r.data);
export const fetchAllIncidents = () => api.get<IncidentReport[]>("/admin/incidents").then((r) => r.data);

// --- OAuth & Connected Accounts ---
export const fetchOAuthProviders = () =>
  api.get<OAuthProvidersResponse>("/oauth/providers").then((r) => r.data.providers);

export const fetchConnectedAccounts = () =>
  api.get<ConnectedAccount[]>("/oauth/accounts").then((r) => r.data);

export const startGoogleOAuth = () =>
  api.post<OAuthAuthorizeResponse>("/oauth/google/authorize").then((r) => r.data);

export const completeGoogleOAuth = (code: string, state: string) =>
  api.post<ConnectedAccount>("/oauth/google/callback", { code, state }).then((r) => r.data);

export const disconnectConnectedAccount = (accountId: string) =>
  api.delete<DisconnectAccountResponse>(`/oauth/accounts/${accountId}`).then((r) => r.data);
