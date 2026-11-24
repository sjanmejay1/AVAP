import { useMemo } from "react";

import { useRiskAssessments } from "@/features/risk/hooks/use-risk";
import { splitScanFindings } from "@/features/scans/lib/scan-findings";
import { useVulnerabilities } from "@/features/vulnerabilities/hooks/use-vulnerabilities";

/** The backend's maximum page size for both list endpoints. */
const FINDINGS_LIMIT = 200;

/**
 * One scan's findings, joined to their risk scores and split into
 * scanner-confirmed and AI-advisory. Two requests, both cached.
 */
export function useScanFindings(scanId: string, enabled = true) {
  const vulnerabilities = useVulnerabilities(
    { scan_id: scanId, limit: FINDINGS_LIMIT },
    enabled
  );
  const assessments = useRiskAssessments(
    { scan_id: scanId, scope: "VULNERABILITY", limit: FINDINGS_LIMIT },
    enabled
  );

  const findings = useMemo(
    () =>
      vulnerabilities.data && assessments.data
        ? splitScanFindings(
            vulnerabilities.data.vulnerabilities,
            assessments.data.risk_assessments
          )
        : undefined,
    [vulnerabilities.data, assessments.data]
  );

  return {
    findings,
    isPending: vulnerabilities.isPending || assessments.isPending,
    isError: vulnerabilities.isError || assessments.isError,
    refetch: () => {
      vulnerabilities.refetch();
      assessments.refetch();
    },
  };
}
