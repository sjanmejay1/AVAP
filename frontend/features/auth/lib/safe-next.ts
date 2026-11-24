export const DEFAULT_SIGNED_IN_PATH = "/targets";

const AUTH_PAGES = new Set(["/login", "/register"]);
const PROBE_ORIGIN = "http://avap.invalid";

/**
 * Returns `raw` only when it is a same-origin path, so a crafted
 * `/login?next=//evil.example` can never redirect off-site after sign-in.
 * Anything else (absolute URLs, protocol-relative, backslash tricks, the
 * auth pages themselves) falls back to the targets list.
 */
export function safeNextPath(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) {
    return DEFAULT_SIGNED_IN_PATH;
  }
  try {
    const url = new URL(raw, PROBE_ORIGIN);
    if (url.origin !== PROBE_ORIGIN || AUTH_PAGES.has(url.pathname)) {
      return DEFAULT_SIGNED_IN_PATH;
    }
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return DEFAULT_SIGNED_IN_PATH;
  }
}
