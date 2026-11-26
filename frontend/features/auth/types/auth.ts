/** Mirrors backend/app/schemas/auth.py CredentialsRequest / LoginRequest. */
export interface CredentialsRequest {
  email: string;
  password: string;
}

export type AuthStatus = "loading" | "authenticated" | "anonymous";

/** Why the last session ended; drives the message on the sign-in page. */
export type SessionEndReason = "signed-out" | "expired" | "password-changed";
