"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { SessionLoading } from "@/features/auth/components/session-loading";
import { useAuth } from "@/features/auth/hooks/use-auth";
import { safeNextPath } from "@/features/auth/lib/safe-next";

/**
 * Wraps the sign-in and register pages. Once a session exists (restored on
 * load, or just started by the form) it sends the visitor on to the safe
 * `next` path. The forms themselves never navigate, so there is one
 * redirect decision, not two racing ones.
 */
export function GuestGuard({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status !== "authenticated") return;
    const next = new URLSearchParams(window.location.search).get("next");
    router.replace(safeNextPath(next));
  }, [status, router]);

  if (status !== "anonymous") return <SessionLoading />;
  return <>{children}</>;
}
