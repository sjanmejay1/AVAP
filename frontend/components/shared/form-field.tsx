import { Label } from "@/components/ui/label";

export interface FieldA11yProps {
  id: string;
  "aria-invalid": boolean;
  "aria-describedby": string | undefined;
}

/**
 * Label above, control, then either the error (in red, announced) or a
 * neutral hint. The render prop hands the control the ids it needs, so the
 * error is always tied to its field for screen readers.
 */
export function FormField({
  id,
  label,
  error,
  hint,
  children,
}: {
  id: string;
  label: string;
  error?: string;
  hint?: React.ReactNode;
  children: (a11y: FieldA11yProps) => React.ReactNode;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [errorId, hintId].filter(Boolean).join(" ") || undefined;

  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children({ id, "aria-invalid": Boolean(error), "aria-describedby": describedBy })}
      {error && (
        <p id={errorId} role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {hint && (
        <p id={hintId} className="text-sm text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

/** Form-level failure that isn't tied to one field (rate limit, network). */
export function FormError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p
      role="alert"
      className="rounded-md border border-destructive-border bg-destructive-bg px-3 py-2 text-sm text-destructive"
    >
      {message}
    </p>
  );
}
