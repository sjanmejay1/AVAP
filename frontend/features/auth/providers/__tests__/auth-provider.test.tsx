import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import { useContext } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api/session", async () => {
  const listeners = new Set<() => void>();
  return {
    refreshSession: vi.fn(),
    onSessionEnded: (listener: () => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    notifySessionEnded: () => listeners.forEach((listener) => listener()),
  };
});

import { AuthContext, AuthProvider } from "@/features/auth/providers/auth-provider";
import { authToken } from "@/lib/api/auth-token";
import { notifySessionEnded, refreshSession } from "@/lib/api/session";
import { createTestQueryClient } from "@/test/render";

const mockedRefresh = vi.mocked(refreshSession);
const user = { id: "u1", email: "analyst@example.com", created_at: "2026-11-01T00:00:00Z" };

function Probe() {
  const auth = useContext(AuthContext);
  return (
    <div>
      <p data-testid="status">{auth?.status}</p>
      <p data-testid="reason">{auth?.endReason ?? "none"}</p>
      <p data-testid="email">{auth?.user?.email ?? "nobody"}</p>
      <button onClick={() => auth?.endSession("signed-out")}>sign out</button>
    </div>
  );
}

function renderProvider() {
  const queryClient = createTestQueryClient();
  queryClient.setQueryData(["targets", "list"], { secret: "previous account's data" });
  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Probe />
      </AuthProvider>
    </QueryClientProvider>
  );
  return queryClient;
}

describe("AuthProvider", () => {
  beforeEach(() => authToken.clear());

  it("restores the session from the refresh cookie on load", async () => {
    mockedRefresh.mockResolvedValue({
      access_token: "t",
      token_type: "bearer",
      expires_in: 900,
      user,
    });

    renderProvider();

    expect(screen.getByTestId("status")).toHaveTextContent("loading");
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));
    expect(screen.getByTestId("email")).toHaveTextContent("analyst@example.com");
  });

  it("is anonymous when there is no session to restore", async () => {
    mockedRefresh.mockRejectedValue(new Error("no cookie"));

    renderProvider();

    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("anonymous"));
    expect(screen.getByTestId("reason")).toHaveTextContent("none");
  });

  it("signing out forgets the token and every cached response", async () => {
    mockedRefresh.mockResolvedValue({ access_token: "t", token_type: "bearer", expires_in: 900, user });
    const queryClient = renderProvider();
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));
    authToken.set("t");

    act(() => screen.getByText("sign out").click());

    expect(screen.getByTestId("status")).toHaveTextContent("anonymous");
    expect(screen.getByTestId("reason")).toHaveTextContent("signed-out");
    expect(authToken.get()).toBeNull();
    expect(queryClient.getQueryData(["targets", "list"])).toBeUndefined();
  });

  it("marks the session expired when a refresh fails mid-session", async () => {
    mockedRefresh.mockResolvedValue({ access_token: "t", token_type: "bearer", expires_in: 900, user });
    renderProvider();
    await waitFor(() => expect(screen.getByTestId("status")).toHaveTextContent("authenticated"));

    act(() => notifySessionEnded());

    expect(screen.getByTestId("status")).toHaveTextContent("anonymous");
    expect(screen.getByTestId("reason")).toHaveTextContent("expired");
  });
});
