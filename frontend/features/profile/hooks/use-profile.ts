import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useAuth } from "@/features/auth/hooks/use-auth";
import { profileApi } from "@/features/profile/api/profile-api";
import type {
  ApiKeyResponse,
  ApiKeyTestResponse,
  ChangePasswordRequest,
} from "@/features/profile/types/profile";
import type { ApiError } from "@/lib/api/errors";

export const profileKeys = {
  all: ["profile"] as const,
  apiKeys: () => [...profileKeys.all, "api-keys"] as const,
};

/** The saved OpenRouter key's metadata (last 4 characters), or null. */
export function useOpenRouterKey() {
  return useQuery({
    queryKey: profileKeys.apiKeys(),
    queryFn: () => profileApi.getApiKeys(),
    select: (data): ApiKeyResponse | null =>
      data.keys.find((key) => key.provider === "openrouter") ?? null,
  });
}

/**
 * The backend revokes every refresh token on a password change, this
 * session's included, so the session is ended here and the user signs in
 * again with the new password.
 */
export function useChangePassword() {
  const { endSession } = useAuth();
  return useMutation<void, ApiError, ChangePasswordRequest>({
    mutationFn: (body) => profileApi.changePassword(body),
    onSuccess: () => endSession("password-changed"),
  });
}

export function useSaveOpenRouterKey() {
  const queryClient = useQueryClient();
  return useMutation<ApiKeyResponse, ApiError, string>({
    mutationFn: (apiKey) => profileApi.saveOpenRouterKey({ api_key: apiKey }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: profileKeys.apiKeys() }),
  });
}

export function useTestOpenRouterKey() {
  return useMutation<ApiKeyTestResponse, ApiError, void>({
    mutationFn: () => profileApi.testOpenRouterKey(),
  });
}

export function useDeleteOpenRouterKey() {
  const queryClient = useQueryClient();
  return useMutation<void, ApiError, void>({
    mutationFn: () => profileApi.deleteOpenRouterKey(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: profileKeys.apiKeys() }),
  });
}
