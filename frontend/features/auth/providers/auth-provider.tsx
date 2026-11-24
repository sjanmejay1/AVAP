"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useEffect, useMemo, useState } from "react";

import type { AuthStatus, SessionEndReason } from "@/features/auth/types/auth";
import { authToken } from "@/lib/api/auth-token";
import { onSessionEnded, refreshSession } from "@/lib/api/session";
import type { AuthUser, TokenResponse } from "@/types/auth";

export interface AuthContextValue {
  status: AuthStatus;
  user: AuthUser | null;
  endReason: SessionEndReason | null;
  /** Store a freshly issued token and mark the session signed in. */
  startSession: (tokens: TokenResponse) => void;
  /** Forget the token and every cached response from this account. */
  endSession: (reason: SessionEndReason) => void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

interface SessionState {
  status: AuthStatus;
  user: AuthUser | null;
  endReason: SessionEndReason | null;
}

/**
 * Restores the session on load (the access token never survives a reload,
 * by design) and clears the whole query cache whenever a session ends, so
 * nothing fetched for one account is ever shown to the next.
 */
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const [state, setState] = useState<SessionState>({
    status: "loading",
    user: null,
    endReason: null,
  });

  const endSession = useCallback(
    (reason: SessionEndReason) => {
      authToken.clear();
      queryClient.clear();
      setState({ status: "anonymous", user: null, endReason: reason });
    },
    [queryClient]
  );

  const startSession = useCallback((tokens: TokenResponse) => {
    authToken.set(tokens.access_token);
    setState({ status: "authenticated", user: tokens.user, endReason: null });
  }, []);

  useEffect(() => {
    let active = true;
    refreshSession()
      .then((tokens) => {
        if (active) setState({ status: "authenticated", user: tokens.user, endReason: null });
      })
      .catch(() => {
        if (active) setState({ status: "anonymous", user: null, endReason: null });
      });
    const unsubscribe = onSessionEnded(() => endSession("expired"));
    return () => {
      active = false;
      unsubscribe();
    };
  }, [endSession]);

  const value = useMemo<AuthContextValue>(
    () => ({ ...state, startSession, endSession }),
    [state, startSession, endSession]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
