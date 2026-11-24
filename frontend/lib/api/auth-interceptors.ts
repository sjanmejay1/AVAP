import axios, {
  type AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from "axios";

import { authToken } from "@/lib/api/auth-token";
import { notifySessionEnded, refreshSession } from "@/lib/api/session";

/**
 * Cookie-authenticated endpoints. They never carry the bearer token and a
 * 401 from them is a real answer (wrong password, no session), never a
 * reason to refresh. `/auth/me` is deliberately not listed: it is a normal
 * bearer-authenticated call.
 */
const SESSION_ENDPOINTS = ["/auth/login", "/auth/register", "/auth/refresh", "/auth/logout"];

export function isSessionEndpoint(url: string | undefined): boolean {
  if (!url) return false;
  const path = url.split("?")[0];
  return SESSION_ENDPOINTS.some((endpoint) => path.endsWith(endpoint));
}

interface RetriableRequestConfig extends InternalAxiosRequestConfig {
  _authRetried?: boolean;
}

/**
 * Transport-level auth only: attach the bearer token, and on a 401 refresh
 * once and replay the request once. Response unwrapping stays explicit in
 * `requestData`; these interceptors never touch response bodies.
 */
export function installAuthInterceptors(client: AxiosInstance): void {
  client.interceptors.request.use((config) => {
    const token = authToken.get();
    if (token && !isSessionEndpoint(config.url)) {
      config.headers.set("Authorization", `Bearer ${token}`);
    }
    return config;
  });

  client.interceptors.response.use(undefined, async (error: unknown) => {
    if (!axios.isAxiosError(error)) throw error;
    const config = (error as AxiosError).config as RetriableRequestConfig | undefined;

    const shouldRefresh =
      error.response?.status === 401 &&
      config !== undefined &&
      !config._authRetried &&
      !isSessionEndpoint(config.url);
    if (!shouldRefresh) throw error;

    config._authRetried = true;
    try {
      await refreshSession();
    } catch {
      notifySessionEnded();
      throw error;
    }
    return client.request(config);
  });
}
