/**
 * The access token lives in this module's memory only: never localStorage,
 * sessionStorage or a readable cookie, so injected script cannot lift it
 * from storage. A page reload loses it by design; the httpOnly refresh
 * cookie restores the session (lib/api/session.ts).
 */
let accessToken: string | null = null;

export const authToken = {
  get(): string | null {
    return accessToken;
  },
  set(token: string): void {
    accessToken = token;
  },
  clear(): void {
    accessToken = null;
  },
};
