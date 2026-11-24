import axios from "axios";

import { env } from "@/config/env";
import { authToken } from "@/lib/api/auth-token";
import { requestData } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";
import type { TokenResponse } from "@/types/auth";

/**
 * A separate Axios instance for the refresh call, with no auth interceptors,
 * so a failed refresh can never trigger another refresh. `withCredentials`
 * sends the httpOnly `avap_refresh` cookie (scoped to /api/v1/auth).
 */
export const sessionClient = axios.create({
  baseURL: `${env.apiBaseUrl}${env.apiVersionPrefix}`,
  timeout: 15_000,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

let inFlightRefresh: Promise<TokenResponse> | null = null;

/**
 * Exchanges the refresh cookie for a new access token. Single-flight:
 * concurrent callers (parallel 401s, React StrictMode's double effects)
 * share one request. The backend rotates the refresh cookie on every use,
 * so two parallel refreshes would present an already-rotated token.
 */
export function refreshSession(): Promise<TokenResponse> {
  if (!inFlightRefresh) {
    inFlightRefresh = requestData(
      sessionClient.post<ApiSuccessEnvelope<TokenResponse>>("/auth/refresh")
    )
      .then((tokens) => {
        authToken.set(tokens.access_token);
        return tokens;
      })
      .catch((error: unknown) => {
        authToken.clear();
        throw error;
      })
      .finally(() => {
        inFlightRefresh = null;
      });
  }
  return inFlightRefresh;
}

type SessionEndedListener = () => void;
const sessionEndedListeners = new Set<SessionEndedListener>();

/** Subscribe to "the session can no longer be refreshed". Returns an unsubscribe. */
export function onSessionEnded(listener: SessionEndedListener): () => void {
  sessionEndedListeners.add(listener);
  return () => {
    sessionEndedListeners.delete(listener);
  };
}

export function notifySessionEnded(): void {
  sessionEndedListeners.forEach((listener) => listener());
}
