"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";

import { FormError, FormField } from "@/components/shared/form-field";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { MIN_PASSWORD_LENGTH } from "@/features/auth/schemas/auth-schema";
import { useChangePassword } from "@/features/profile/hooks/use-profile";
import {
  changePasswordSchema,
  type ChangePasswordFormValues,
} from "@/features/profile/schemas/profile-schema";
import type { ApiError } from "@/lib/api/errors";
import { fieldErrorsFrom } from "@/lib/api/field-errors";

export function PasswordSection() {
  const [formError, setFormError] = useState<string | null>(null);
  const { mutate, isPending } = useChangePassword();
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
  } = useForm<ChangePasswordFormValues>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: { currentPassword: "", newPassword: "", confirmPassword: "" },
  });

  function handleError(error: ApiError) {
    const fields = fieldErrorsFrom(error);
    // A wrong current password comes back as a 422 without field details;
    // its message is shown above the form rather than guessed onto a field.
    if (fields.new_password) {
      setError("newPassword", { type: "server", message: fields.new_password });
      return;
    }
    setFormError(error.message);
  }

  function onSubmit(values: ChangePasswordFormValues) {
    setFormError(null);
    mutate(
      { current_password: values.currentPassword, new_password: values.newPassword },
      { onError: handleError }
    );
  }

  return (
    <section aria-labelledby="password-heading" className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h2 id="password-heading" className="text-h3">
          Password
        </h2>
        <p className="text-sm text-muted-foreground">
          Changing it signs you out everywhere, including here.
        </p>
      </div>
      <form onSubmit={handleSubmit(onSubmit)} noValidate className="flex max-w-md flex-col gap-5">
        <FormError message={formError} />
        <FormField id="currentPassword" label="Current password" error={errors.currentPassword?.message}>
          {(a11y) => (
            <Input
              {...a11y}
              type="password"
              autoComplete="current-password"
              disabled={isPending}
              {...register("currentPassword")}
            />
          )}
        </FormField>
        <FormField
          id="newPassword"
          label="New password"
          error={errors.newPassword?.message}
          hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
        >
          {(a11y) => (
            <Input
              {...a11y}
              type="password"
              autoComplete="new-password"
              disabled={isPending}
              {...register("newPassword")}
            />
          )}
        </FormField>
        <FormField id="confirmPassword" label="Confirm new password" error={errors.confirmPassword?.message}>
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
        <div>
          <Button type="submit" disabled={isPending}>
            {isPending ? "Changing password…" : "Change password"}
          </Button>
        </div>
      </form>
    </section>
  );
}
