import axios from "axios";

import { env } from "@/config/env";
import { installAuthInterceptors } from "@/lib/api/auth-interceptors";

/**
 * Single centralized Axios instance. Owns transport concerns only (base
 * URL, timeout, default headers, credentials, bearer token and one-time
 * refresh) — never business logic or response unwrapping. Every feature
 * service function calls this instance and unwraps its own response via
 * `requestData` (lib/api/request.ts).
 *
 * `withCredentials` is needed so the browser stores the refresh cookie set
 * by /auth/login and /auth/register; the backend allows credentials for its
 * explicit CORS origin list only.
 */
export const apiClient = axios.create({
  baseURL: `${env.apiBaseUrl}${env.apiVersionPrefix}`,
  timeout: 15_000,
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

installAuthInterceptors(apiClient);
