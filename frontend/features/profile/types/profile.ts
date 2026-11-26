/** Mirrors backend/app/schemas/auth.py (ChangePasswordRequest, ApiKey*). */

export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

/** app.core.enums.AIKeyProvider; OpenRouter is the only supported provider. */
export type AIKeyProvider = "openrouter";

export interface ApiKeyResponse {
  provider: AIKeyProvider;
  last4: string;
  updated_at: string;
}

export interface ApiKeyListResponse {
  keys: ApiKeyResponse[];
}

export interface SaveApiKeyRequest {
  api_key: string;
}

export interface ApiKeyTestResponse {
  valid: boolean;
  message: string;
}
