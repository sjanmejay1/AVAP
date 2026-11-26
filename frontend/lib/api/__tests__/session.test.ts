import { AxiosError, type AxiosAdapter } from "axios";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { authToken } from "@/lib/api/auth-token";
import {
  notifySessionEnded,
  onSessionEnded,
  refreshSession,
  sessionClient,
} from "@/lib/api/session";

const tokens = {
  access_token: "fresh-token",
  token_type: "bearer",
  expires_in: 900,
  user: { id: "u1", email: "analyst@example.com", created_at: "2026-11-01T00:00:00Z" },
};

describe("refreshSession", () => {
  const originalAdapter = sessionClient.defaults.adapter;

  beforeEach(() => authToken.clear());
  afterEach(() => {
    sessionClient.defaults.adapter = originalAdapter;
  });

  it("is single-flight: concurrent callers share one request (the cookie rotates on every use)", async () => {
    const adapter = vi.fn<AxiosAdapter>(async (config) => ({
      data: { success: true, data: tokens, error: null },
      status: 200,
      statusText: "OK",
      headers: {},
      config,
    }));
    sessionClient.defaults.adapter = adapter;

    const [first, second] = await Promise.all([refreshSession(), refreshSession()]);

    expect(adapter).toHaveBeenCalledTimes(1);
    expect(first).toEqual(tokens);
    expect(second).toEqual(tokens);
    expect(authToken.get()).toBe("fresh-token");
  });

  it("sends the refresh cookie (withCredentials) to POST /auth/refresh", async () => {
    const adapter = vi.fn<AxiosAdapter>(async (config) => ({
      data: { success: true, data: tokens, error: null },
      status: 200,
      statusText: "OK",
      headers: {},
      config,
    }));
    sessionClient.defaults.adapter = adapter;

    await refreshSession();

    const config = adapter.mock.calls[0][0];
    expect(config.url).toBe("/auth/refresh");
    expect(config.method).toBe("post");
    expect(config.withCredentials).toBe(true);
  });

  it("clears any token when the refresh is refused", async () => {
    authToken.set("stale");
    sessionClient.defaults.adapter = async (config) => {
      throw new AxiosError("unauthorized", "ERR_BAD_REQUEST", config, null, {
        data: {
          success: false,
          data: null,
          error: { code: "UNAUTHORIZED", message: "Session expired." },
        },
        status: 401,
        statusText: "",
        headers: {},
        config,
      });
    };

    await expect(refreshSession()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(authToken.get()).toBeNull();
  });
});

describe("onSessionEnded", () => {
  it("notifies subscribers until they unsubscribe", () => {
    const listener = vi.fn();
    const unsubscribe = onSessionEnded(listener);

    notifySessionEnded();
    unsubscribe();
    notifySessionEnded();

    expect(listener).toHaveBeenCalledTimes(1);
  });
});
