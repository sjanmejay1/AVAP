import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const replace = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace, push: vi.fn() }),
  usePathname: () => "/scans/abc",
}));

import { AuthGuard, loginRedirectUrl } from "@/features/auth/components/auth-guard";
import { GuestGuard } from "@/features/auth/components/guest-guard";
import { fakeAuth, renderWithAuth } from "@/test/render";

describe("loginRedirectUrl", () => {
  it("keeps where the visitor was going, and says why when the session expired", () => {
    expect(loginRedirectUrl("/scans/abc?tab=hosts", null)).toBe(
      "/login?next=%2Fscans%2Fabc%3Ftab%3Dhosts"
    );
    expect(loginRedirectUrl("/targets", "expired")).toBe(
      "/login?next=%2Ftargets&reason=expired"
    );
  });

  it("sends an explicit sign-out to a plain sign-in page", () => {
    expect(loginRedirectUrl("/targets", "signed-out")).toBe("/login");
    expect(loginRedirectUrl("/profile", "password-changed")).toBe(
      "/login?reason=password-changed"
    );
  });
});

describe("AuthGuard", () => {
  beforeEach(() => window.history.replaceState(null, "", "/scans/abc?tab=hosts"));

  it("renders the page only when signed in", () => {
    renderWithAuth(<AuthGuard>secret page</AuthGuard>);
    expect(screen.getByText("secret page")).toBeInTheDocument();
  });

  it("shows a loading state, not the page, while the session is restored", () => {
    renderWithAuth(<AuthGuard>secret page</AuthGuard>, fakeAuth({ status: "loading", user: null }));
    expect(screen.queryByText("secret page")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Checking your session");
  });

  it("redirects an anonymous visitor to sign in, carrying the current path", async () => {
    renderWithAuth(<AuthGuard>secret page</AuthGuard>, fakeAuth({ status: "anonymous", user: null }));
    expect(screen.queryByText("secret page")).not.toBeInTheDocument();
    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith("/login?next=%2Fscans%2Fabc%3Ftab%3Dhosts")
    );
  });
});

describe("GuestGuard", () => {
  it("shows the sign-in form to anonymous visitors", () => {
    renderWithAuth(<GuestGuard>login form</GuestGuard>, fakeAuth({ status: "anonymous", user: null }));
    expect(screen.getByText("login form")).toBeInTheDocument();
  });

  it("sends a signed-in visitor on to the safe next path", async () => {
    window.history.replaceState(null, "", "/login?next=%2Ftargets%2F42");
    renderWithAuth(<GuestGuard>login form</GuestGuard>);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/targets/42"));
  });

  it("never follows an off-site next parameter", async () => {
    window.history.replaceState(null, "", "/login?next=%2F%2Fevil.example");
    renderWithAuth(<GuestGuard>login form</GuestGuard>);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/targets"));
  });
});
