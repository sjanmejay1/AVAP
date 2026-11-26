import { z } from "zod";

import { MAX_PASSWORD_LENGTH, newPasswordSchema } from "@/features/auth/schemas/auth-schema";

/** Mirrors ChangePasswordRequest plus a confirm field and the backend's
 * "must differ from the current one" rule. */
export const changePasswordSchema = z
  .object({
    currentPassword: z
      .string()
      .min(1, "Enter your current password.")
      .max(MAX_PASSWORD_LENGTH, `Use ${MAX_PASSWORD_LENGTH} characters or fewer.`),
    newPassword: newPasswordSchema,
    confirmPassword: z.string().min(1, "Enter the new password again."),
  })
  .refine((values) => values.newPassword === values.confirmPassword, {
    path: ["confirmPassword"],
    message: "The passwords don't match.",
  })
  .refine((values) => values.newPassword !== values.currentPassword, {
    path: ["newPassword"],
    message: "Choose a password different from your current one.",
  });

/** Mirrors SaveApiKeyRequest: 8–512 characters, no spaces inside. */
export const apiKeySchema = z.object({
  apiKey: z
    .string()
    .trim()
    .min(8, "Paste your full OpenRouter key.")
    .max(512, "Keys are 512 characters or fewer.")
    .refine((value) => !/\s/.test(value), "API keys can't contain spaces."),
});

export type ChangePasswordFormValues = z.infer<typeof changePasswordSchema>;
export type ApiKeyFormValues = z.infer<typeof apiKeySchema>;
