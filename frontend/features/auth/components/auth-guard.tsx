"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { SessionLoading } from "@/features/auth/components/session-loading";
import { useAuth } from "@/features/auth/hooks/use-auth";
import type { SessionEndReason } from "@/features/auth/types/auth";

/** Login URL for an anonymous visitor: carries where they were going and why. */
export function loginRedirectUrl(
  currentPath: string,
  reason: SessionEndReason | null
): string {
  if (reason === "signed-out") return "/login";
  if (reason === "password-changed") return "/login?reason=password-changed";
  const params = new URLSearchParams({ next: currentPath });
  if (reason === "expired") params.set("reason", "expired");
  return `/login?${params.toString()}`;
}

/**
 * Client-side guard for every signed-in page. The access token is in memory
 * only, so there is nothing a server-side check could read; the backend
 * still enforces auth (and ownership) on every request.
 */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const { status, endReason } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (status !== "anonymous") return;
    const currentPath = `${pathname}${window.location.search}`;
    router.replace(loginRedirectUrl(currentPath, endReason));
  }, [status, endReason, pathname, router]);

  if (status !== "authenticated") return <SessionLoading />;
  return <>{children}</>;
}
