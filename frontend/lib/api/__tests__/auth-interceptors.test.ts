import axios, { AxiosError, type AxiosAdapter, type InternalAxiosRequestConfig } from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api/session", () => ({
  refreshSession: vi.fn(),
  notifySessionEnded: vi.fn(),
}));

import { installAuthInterceptors, isSessionEndpoint } from "@/lib/api/auth-interceptors";
import { authToken } from "@/lib/api/auth-token";
import { notifySessionEnded, refreshSession } from "@/lib/api/session";

const mockedRefresh = vi.mocked(refreshSession);
const mockedNotify = vi.mocked(notifySessionEnded);

function respond(config: InternalAxiosRequestConfig, status: number) {
  const response = { data: {}, status, statusText: "", headers: {}, config };
  if (status >= 400) {
    return Promise.reject(
      new AxiosError("failed", "ERR_BAD_RESPONSE", config, null, response)
    );
  }
  return Promise.resolve(response);
}

/** A client whose transport answers from `statuses` in order and records each request. */
function clientAnswering(statuses: number[]) {
  const seen: InternalAxiosRequestConfig[] = [];
  const adapter: AxiosAdapter = (config) => {
    seen.push(config);
    return respond(config, statuses[seen.length - 1] ?? 200);
  };
  const client = axios.create({ adapter });
  installAuthInterceptors(client);
  return { client, seen };
}

const authHeader = (config: InternalAxiosRequestConfig) => config.headers.get("Authorization");

describe("isSessionEndpoint", () => {
  it("matches the cookie-authenticated auth calls but not /auth/me", () => {
    expect(isSessionEndpoint("/auth/login")).toBe(true);
    expect(isSessionEndpoint("/auth/refresh?x=1")).toBe(true);
    expect(isSessionEndpoint("/auth/logout")).toBe(true);
    expect(isSessionEndpoint("/auth/me")).toBe(false);
    expect(isSessionEndpoint("/targets")).toBe(false);
    expect(isSessionEndpoint(undefined)).toBe(false);
  });
});

describe("auth interceptors", () => {
  beforeEach(() => {
    authToken.clear();
  });

  it("adds the bearer token to normal requests", async () => {
    authToken.set("access-1");
    const { client, seen } = clientAnswering([200]);

    await client.get("/targets");

    expect(authHeader(seen[0])).toBe("Bearer access-1");
  });

  it("never sends the bearer token to the cookie-authenticated session endpoints", async () => {
    authToken.set("access-1");
    const { client, seen } = clientAnswering([200]);

    await client.post("/auth/login", {});

    expect(authHeader(seen[0])).toBeFalsy();
  });

  it("on a 401 refreshes once and replays the request with the new token", async () => {
    authToken.set("expired");
    mockedRefresh.mockImplementation(async () => {
      authToken.set("access-2");
      return {} as never;
    });
    const { client, seen } = clientAnswering([401, 200]);

    const response = await client.get("/scans");

    expect(response.status).toBe(200);
    expect(mockedRefresh).toHaveBeenCalledTimes(1);
    expect(seen).toHaveLength(2);
    expect(authHeader(seen[1])).toBe("Bearer access-2");
  });

  it("does not loop: a replayed request that is still 401 fails without a second refresh", async () => {
    mockedRefresh.mockResolvedValue({} as never);
    const { client, seen } = clientAnswering([401, 401]);

    await expect(client.get("/scans")).rejects.toMatchObject({ response: { status: 401 } });

    expect(mockedRefresh).toHaveBeenCalledTimes(1);
    expect(seen).toHaveLength(2);
  });

  it("when refresh fails, reports the session as ended and rejects with the original 401", async () => {
    mockedRefresh.mockRejectedValue(new Error("no session"));
    const { client } = clientAnswering([401]);

    await expect(client.get("/scans")).rejects.toMatchObject({ response: { status: 401 } });

    expect(mockedNotify).toHaveBeenCalledTimes(1);
  });

  it("treats a 401 from login as the answer (wrong password), never as a reason to refresh", async () => {
    const { client } = clientAnswering([401]);

    await expect(client.post("/auth/login", {})).rejects.toBeInstanceOf(AxiosError);

    expect(mockedRefresh).not.toHaveBeenCalled();
  });

  it("does not refresh on other errors such as 403 or 500", async () => {
    const { client } = clientAnswering([500]);

    await expect(client.get("/scans")).rejects.toBeInstanceOf(AxiosError);

    expect(mockedRefresh).not.toHaveBeenCalled();
  });
});
