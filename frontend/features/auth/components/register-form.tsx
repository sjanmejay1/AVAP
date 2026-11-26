"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";

import { FormError, FormField } from "@/components/shared/form-field";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRegister } from "@/features/auth/hooks/use-auth";
import {
  MIN_PASSWORD_LENGTH,
  registerSchema,
  type RegisterFormValues,
} from "@/features/auth/schemas/auth-schema";
import type { ApiError } from "@/lib/api/errors";
import { fieldErrorsFrom } from "@/lib/api/field-errors";

export function RegisterForm() {
  const [formError, setFormError] = useState<string | null>(null);
  const { mutate, isPending } = useRegister();
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
  } = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: { email: "", password: "", confirmPassword: "" },
  });

  function handleError(error: ApiError) {
    const fields = fieldErrorsFrom(error);
    if (fields.email) setError("email", { type: "server", message: fields.email });
    if (fields.password) setError("password", { type: "server", message: fields.password });
    if (!fields.email && !fields.password) setFormError(error.message);
  }

  function onSubmit(values: RegisterFormValues) {
    setFormError(null);
    mutate({ email: values.email, password: values.password }, { onError: handleError });
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex flex-col gap-5">
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

      <FormField
        id="password"
        label="Password"
        error={errors.password?.message}
        hint={`At least ${MIN_PASSWORD_LENGTH} characters. A short sentence works well.`}
      >
        {(a11y) => (
          <Input
            {...a11y}
            type="password"
            autoComplete="new-password"
            disabled={isPending}
            {...register("password")}
          />
        )}
      </FormField>

      <FormField
        id="confirmPassword"
        label="Confirm password"
        error={errors.confirmPassword?.message}
      >
        {(a11y) => (
          <Input
            {...a11y}
            type="password"
            autoComplete="new-password"
            disabled={isPending}
            {...register("confirmPassword")}
          />
        )}
      </FormField>

      <Button type="submit" size="lg" disabled={isPending}>
        {isPending ? "Creating account…" : "Create account"}
      </Button>

      <p className="text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link href="/login" className="font-medium text-foreground underline underline-offset-4">
          Sign in
        </Link>
      </p>
    </form>
  );
}
