"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";

import { FormError, FormField } from "@/components/shared/form-field";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useLogin } from "@/features/auth/hooks/use-auth";
import { loginSchema, type LoginFormValues } from "@/features/auth/schemas/auth-schema";
import type { ApiError } from "@/lib/api/errors";
import { fieldErrorsFrom } from "@/lib/api/field-errors";

/**
 * On success the GuestGuard around this page performs the redirect; the
 * form only reports errors. Wrong credentials (401), the rate limit (429)
 * and network failures are shown with the backend's sanitized message.
 */
export function LoginForm({ notice }: { notice?: string | null }) {
  const [formError, setFormError] = useState<string | null>(null);
  const { mutate, isPending } = useLogin();
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
  });

  function handleError(error: ApiError) {
    const fields = fieldErrorsFrom(error);
    if (fields.email) setError("email", { type: "server", message: fields.email });
    if (fields.password) setError("password", { type: "server", message: fields.password });
    if (!fields.email && !fields.password) setFormError(error.message);
  }

  function onSubmit(values: LoginFormValues) {
    setFormError(null);
    mutate(values, { onError: handleError });
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-5">
      {notice && (
        <p
          role="status"
          className="rounded-md border border-info-border bg-info-bg px-3 py-2 text-sm text-info"
        >
          {notice}
        </p>
      )}
      <FormError message={formError} />

      <FormField id="email" label="Email" error={errors.email?.message}>
        {(a11y) => (
          <Input
            {...a11y}
            type="email"
            autoComplete="email"
            autoFocus
            disabled={isPending}
            {...register("email")}
          />
        )}
      </FormField>

      <FormField id="password" label="Password" error={errors.password?.message}>
        {(a11y) => (
          <Input
            {...a11y}
            type="password"
            autoComplete="current-password"
            disabled={isPending}
            {...register("password")}
          />
        )}
      </FormField>

      <Button type="submit" size="lg" disabled={isPending}>
        {isPending ? "Signing in…" : "Sign in"}
      </Button>

      <p className="text-sm text-muted-foreground">
        New to AVAP?{" "}
        <Link href="/register" className="font-medium text-foreground underline underline-offset-4">
          Create an account
        </Link>
      </p>
    </form>
  );
}
