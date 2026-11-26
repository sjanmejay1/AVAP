"use client";

import { RiskLevelBadge } from "@/components/shared/risk-level-badge";
import { RiskScore } from "@/components/shared/risk-score";
import { Skeleton } from "@/components/ui/skeleton";
import { useScanRisk } from "@/features/risk/hooks/use-risk";
import type { ScanStatus } from "@/features/scans/types/scan";

/**
 * Compact risk for one scan: level badge plus score. Only completed scans
 * are scored, so nothing is requested for the others.
 */
export function ScanRiskCell({ scanId, status }: { scanId: string; status: ScanStatus }) {
  const isScorable = status === "COMPLETED";
  const { data, isPending, isError } = useScanRisk(scanId, isScorable);

  if (!isScorable) return <span className="text-sm text-muted-foreground">—</span>;
  if (isPending) return <Skeleton className="h-6 w-24" />;
  if (isError || !data) return <span className="text-sm text-muted-foreground">Not scored</span>;

  return (
    <span className="inline-flex items-center gap-2">
      <RiskLevelBadge level={data.risk_level} />
      <RiskScore score={data.risk_score} />
    </span>
  );
}
