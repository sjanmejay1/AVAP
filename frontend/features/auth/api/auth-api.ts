import { apiClient } from "@/lib/api/client";
import { requestData, requestVoid } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";
import type { TokenResponse } from "@/types/auth";

import type { CredentialsRequest } from "@/features/auth/types/auth";

/**
 * Typed wrappers around POST /api/v1/auth/{login,register,logout}. The
 * refresh call is not here: it is a transport concern owned by
 * lib/api/session.ts so the Axios interceptor can use it.
 */
export const authApi = {
  login: (body: CredentialsRequest) =>
    requestData(apiClient.post<ApiSuccessEnvelope<TokenResponse>>("/auth/login", body)),

  register: (body: CredentialsRequest) =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<TokenResponse>>("/auth/register", body)
    ),

  logout: () => requestVoid(apiClient.post("/auth/logout")),
};
