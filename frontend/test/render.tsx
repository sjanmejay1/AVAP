import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { vi } from "vitest";

import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthContext, type AuthContextValue } from "@/features/auth/providers/auth-provider";

/** Fresh, retry-disabled QueryClient per test — no cross-test cache bleed. */
export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, refetchInterval: false },
    },
  });
}

/** Mirrors AppProviders' TooltipProvider ancestor — any shared component
 * that renders a Tooltip (e.g. table date columns) needs this context. */
export function renderWithQueryClient(ui: ReactElement) {
  const queryClient = createTestQueryClient();
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>{ui}</TooltipProvider>
      </QueryClientProvider>
    ),
  };
}

/** A signed-in auth context; override any field per test. */
export function fakeAuth(overrides: Partial<AuthContextValue> = {}): AuthContextValue {
  return {
    status: "authenticated",
    user: {
      id: "00000000-0000-0000-0000-000000000001",
      email: "analyst@example.com",
      created_at: "2026-11-01T09:00:00Z",
    },
    endReason: null,
    startSession: vi.fn(),
    endSession: vi.fn(),
    ...overrides,
  };
}

/** renderWithQueryClient plus an AuthContext, for components that call useAuth. */
export function renderWithAuth(ui: ReactElement, auth: AuthContextValue = fakeAuth()) {
  return {
    auth,
    ...renderWithQueryClient(<AuthContext.Provider value={auth}>{ui}</AuthContext.Provider>),
  };
}
