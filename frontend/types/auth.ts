/**
 * Mirrors backend/app/schemas/auth.py (UserResponse, TokenResponse). Shared
 * by the transport layer (lib/api/session.ts) and the auth feature, so it
 * lives next to the response envelope types rather than inside a feature.
 */

export interface AuthUser {
  id: string;
  email: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  /** Access token lifetime in seconds. */
  expires_in: number;
  user: AuthUser;
}
