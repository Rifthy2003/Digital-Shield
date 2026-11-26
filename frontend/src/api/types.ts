export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: "citizen" | "admin";
  is_email_verified: boolean;
  mfa_enabled: boolean;
}

export interface TokenPair {
  access_token: string | null;
  refresh_token: string | null;
  token_type: string;
  mfa_required?: boolean;
  mfa_challenge_token?: string | null;
}

export interface MfaStatus {
  mfa_enabled: boolean;
  recovery_codes_remaining: number;
}

export interface MfaEnrollStartResponse {
  provisioning_uri: string;
  secret: string;
  issuer: string;
  account_name: string;
}

export interface MfaEnrollVerifyResponse {
  mfa_enabled: boolean;
  recovery_codes: string[];
}

export interface MfaRecoveryCodesResponse {
  recovery_codes: string[];
}

export interface MfaDisableResponse {
  mfa_enabled: boolean;
  revoked_sessions_count: number;
  message: string;
}

export interface Indicator {
  key: string;
  weight: number;
  message: string;
  triggered: boolean;
  not_evaluated?: boolean;
}

export interface UrlCheckResult {
  url: string;
  domain: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high";
  indicators: Indicator[];
  checked_at: string;
}

export interface MessageCheckResult {
  risk_score: number;
  risk_level: "low" | "medium" | "high";
  indicators: Indicator[];
  links_found: string[];
  disclaimer: string;
}

export interface BreachCheckResult {
  configured: boolean;
  exposure_found: boolean;
  breach_count: number;
  message: string;
  recommended_actions: string[];
}

export interface PasswordStrengthResult {
  score: number;
  label: string;
  is_common: boolean;
  suggestions: string[];
}

export interface ScoreBreakdownItem {
  points: number;
  max_points: number;
  reason: string;
}

export interface Alert {
  id: string;
  severity: "high" | "medium" | "info";
  category: string;
  title: string;
  message: string;
  is_read: boolean;
  is_resolved: boolean;
  created_at: string;
}

export interface DashboardData {
  score: number;
  score_breakdown: Record<string, ScoreBreakdownItem>;
  alerts_summary: { high: number; medium: number; info: number };
  recent_alerts: Alert[];
  recommendations: string[];
  demo_data_notice: string | null;
}

export interface IncidentReport {
  report_id: string;
  category: string;
  description: string;
  status: "submitted" | "under_review" | "resolved";
  created_at: string;
}

export interface AssistantResponse {
  answer: string;
  mode: "ai_provider" | "rule_based_fallback";
}

export interface ActiveSession {
  id: string;
  device_name: string;
  client_type: string;
  ip_address: string | null;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  is_current: boolean;
}

export interface LogoutAllResponse {
  message: string;
  revoked_sessions_count: number;
}

export interface OAuthProviderInfo {
  provider: string;
  display_name: string;
  account_type?: string;
  configured: boolean;
  scopes: string[];
  capabilities?: Record<string, string>;
  required_permissions?: string[];
  enterprise_only_restrictions?: string[];
  limitations?: string[];
}

export interface OAuthProvidersResponse {
  providers: OAuthProviderInfo[];
}

export interface ConnectedAccount {
  id: string;
  provider: string;
  provider_email: string | null;
  provider_email_verified: boolean;
  display_name: string | null;
  avatar_url: string | null;
  scopes: string[];
  status: string;
  created_at: string;
  updated_at: string;
  last_synced_at: string | null;
}

export interface OAuthAuthorizeResponse {
  provider: string;
  authorization_url: string;
  expires_at: string;
}

export interface DisconnectAccountResponse {
  message: string;
  disconnected_account_id: string;
  upstream_revocation_status: string;
}
