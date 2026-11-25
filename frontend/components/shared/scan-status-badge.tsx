import type { ScanStatus } from "@/features/scans/types/scan";
import { cn } from "@/lib/utils";

/**
 * Symbolic colors (docs/design_system.md §3): yellow waiting, blue running,
 * green completed, red failed, grey cancelled.
 */
const STATUS_META: Record<ScanStatus, { label: string; className: string; pulse?: boolean }> = {
  PENDING: {
    label: "Pending",
    className: "border-warning-border bg-warning-bg text-warning",
  },
  RUNNING: {
    label: "Running",
    className: "border-info-border bg-info-bg text-info",
    pulse: true,
  },
  COMPLETED: {
    label: "Completed",
    className: "border-success-border bg-success-bg text-success",
  },
  FAILED: {
    label: "Failed",
    className: "border-destructive-border bg-destructive-bg text-destructive",
  },
  CANCELLED: {
    label: "Cancelled",
    className: "border-border bg-muted text-muted-foreground",
  },
};

/** Scan lifecycle status: an operational signal, not a security severity. */
export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus;
  className?: string;
}) {
  const meta = STATUS_META[status];

  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-sm border px-2 text-xs font-medium whitespace-nowrap",
        meta.className,
        className
      )}
    >
      <span
        className={cn(
          "size-1.5 shrink-0 rounded-full bg-current",
          meta.pulse && "animate-pulse motion-reduce:animate-none"
        )}
        aria-hidden="true"
      />
      {meta.label}
    </span>
  );
}
