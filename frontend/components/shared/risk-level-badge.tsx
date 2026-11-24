import { SeverityBadge } from "@/components/shared/severity-badge";
import { riskLevelToSeverityKey } from "@/constants/severity";
import type { RiskLevel } from "@/features/risk/types/risk";

/**
 * Renders a deterministic RiskLevel. Same palette as SeverityBadge (both
 * share one five-value scale) but kept separate because RiskLevel and
 * severity_rating are distinct backend concepts.
 */
export function RiskLevelBadge({
  level,
  className,
}: {
  level: RiskLevel;
  className?: string;
}) {
  return <SeverityBadge severity={riskLevelToSeverityKey(level)} className={className} />;
}
