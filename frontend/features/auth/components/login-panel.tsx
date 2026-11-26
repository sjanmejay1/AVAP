"use client";

import { useSearchParams } from "next/navigation";

import { LoginForm } from "@/features/auth/components/login-form";

export const LOGIN_NOTICES: Record<string, string> = {
  expired: "Your session ended. Sign in again to continue.",
  "password-changed": "Password changed. Sign in with your new password.",
};

export function LoginPanel() {
  const reason = useSearchParams().get("reason");

  return (
    <section className="flex flex-col gap-6" aria-labelledby="login-heading">
      <h1 id="login-heading" className="text-h2">
        Sign in
      </h1>
      <LoginForm
        notice={reason && Object.hasOwn(LOGIN_NOTICES, reason) ? LOGIN_NOTICES[reason] : null}
      />
    </section>
  );
}
