import { formatRiskScore } from "@/utils/format";
import { cn } from "@/lib/utils";

/**
 * Purely typographic numeric risk score (0.0–10.0). Deliberately not
 * color-coded — pair it with <RiskLevelBadge> for the categorical signal.
 */
export function RiskScore({
  score,
  className,
}: {
  score: number;
  className?: string;
}) {
  return (
    <span className={cn("text-sm font-semibold tabular-nums", className)}>
      {formatRiskScore(score)}
      <span className="ml-0.5 text-xs font-normal text-muted-foreground">/10</span>
    </span>
  );
}
