import { SEVERITY_META, type SeverityKey } from "@/constants/severity";
import { cn } from "@/lib/utils";

/**
 * Renders a severity or risk level. Color is always paired with a text
 * label, never a color-only indicator.
 */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: SeverityKey;
  className?: string;
}) {
  const meta = SEVERITY_META[severity];

  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-sm border px-2 text-xs font-medium whitespace-nowrap",
        meta.bgClass,
        meta.textClass,
        meta.borderClass,
        className
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {meta.label}
    </span>
  );
}
