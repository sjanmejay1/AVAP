import { z } from "zod";

/** Mirrors backend/app/schemas/auth.py MIN_PASSWORD_LENGTH / MAX_PASSWORD_LENGTH. */
export const MIN_PASSWORD_LENGTH = 12;
export const MAX_PASSWORD_LENGTH = 128;

/** Same rule as the backend's _normalize_email: trimmed, lowercased, one
 * "@", a non-empty local part, a dot in the domain and no spaces. */
export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(1, "Enter your email address.")
  .max(254, "Email must be 254 characters or fewer.")
  .refine((value) => {
    const at = value.indexOf("@");
    if (at <= 0 || value.includes(" ")) return false;
    return value.slice(at + 1).includes(".");
  }, "Enter a valid email address.");

export const newPasswordSchema = z
  .string()
  .min(MIN_PASSWORD_LENGTH, `Use at least ${MIN_PASSWORD_LENGTH} characters.`)
  .max(MAX_PASSWORD_LENGTH, `Use ${MAX_PASSWORD_LENGTH} characters or fewer.`);

export const loginSchema = z.object({
  email: emailSchema,
  password: z
    .string()
    .min(1, "Enter your password.")
    .max(MAX_PASSWORD_LENGTH, `Use ${MAX_PASSWORD_LENGTH} characters or fewer.`),
});

export const registerSchema = z
  .object({
    email: emailSchema,
    password: newPasswordSchema,
    confirmPassword: z.string().min(1, "Enter the password again."),
  })
  .refine((values) => values.password === values.confirmPassword, {
    path: ["confirmPassword"],
    message: "The passwords don't match.",
  });

export type LoginFormValues = z.infer<typeof loginSchema>;
export type RegisterFormValues = z.infer<typeof registerSchema>;
