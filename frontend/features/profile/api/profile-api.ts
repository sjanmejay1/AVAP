import { apiClient } from "@/lib/api/client";
import { requestData, requestVoid } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";

import type {
  ApiKeyListResponse,
  ApiKeyResponse,
  ApiKeyTestResponse,
  ChangePasswordRequest,
  SaveApiKeyRequest,
} from "@/features/profile/types/profile";

const OPENROUTER_KEY_PATH = "/users/me/api-keys/openrouter";

/**
 * Typed wrappers around /api/v1/users/me/*. The saved key is write-only:
 * the backend returns its last 4 characters, never the key itself.
 */
export const profileApi = {
  changePassword: (body: ChangePasswordRequest) =>
    requestVoid(apiClient.post("/users/me/password", body)),

  getApiKeys: () =>
    requestData(apiClient.get<ApiSuccessEnvelope<ApiKeyListResponse>>("/users/me/api-keys")),

  saveOpenRouterKey: (body: SaveApiKeyRequest) =>
    requestData(apiClient.put<ApiSuccessEnvelope<ApiKeyResponse>>(OPENROUTER_KEY_PATH, body)),

  /** Checks the saved key with OpenRouter's key endpoint; runs no model. */
  testOpenRouterKey: () =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<ApiKeyTestResponse>>(`${OPENROUTER_KEY_PATH}/test`)
    ),

  deleteOpenRouterKey: () => requestVoid(apiClient.delete(OPENROUTER_KEY_PATH)),
};
