import { useMutation } from "@tanstack/react-query";
import { useContext } from "react";

import { authApi } from "@/features/auth/api/auth-api";
import { AuthContext, type AuthContextValue } from "@/features/auth/providers/auth-provider";
import type { CredentialsRequest } from "@/features/auth/types/auth";
import type { ApiError } from "@/lib/api/errors";
import type { TokenResponse } from "@/types/auth";

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used inside <AuthProvider>.");
  }
  return value;
}

/** No `retry`: a replayed login would count twice against the rate limit. */
export function useLogin() {
  const { startSession } = useAuth();
  return useMutation<TokenResponse, ApiError, CredentialsRequest>({
    mutationFn: (body) => authApi.login(body),
    onSuccess: (tokens) => startSession(tokens),
  });
}

/** No `retry`: registration is not idempotent. */
export function useRegister() {
  const { startSession } = useAuth();
  return useMutation<TokenResponse, ApiError, CredentialsRequest>({
    mutationFn: (body) => authApi.register(body),
    onSuccess: (tokens) => startSession(tokens),
  });
}

/**
 * Ends the local session even if the server call fails (offline, already
 * expired): signing out must never leave the token in memory.
 */
export function useLogout() {
  const { endSession } = useAuth();
  return useMutation<void, ApiError, void>({
    mutationFn: () => authApi.logout(),
    onSettled: () => endSession("signed-out"),
  });
}
