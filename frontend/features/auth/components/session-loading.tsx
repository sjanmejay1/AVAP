import { Wordmark } from "@/components/shared/wordmark";

/** Quiet placeholder while the session is restored or a redirect runs. */
export function SessionLoading() {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-screen flex-col items-center justify-center gap-3"
    >
      <Wordmark />
      <p className="text-sm text-muted-foreground">Checking your session…</p>
    </div>
  );
}
