import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { riskApi } from "@/features/risk/api/risk-api";
import { riskKeys } from "@/features/risk/hooks/query-keys";
import type { RiskAssessmentResponse, RiskListFilters } from "@/features/risk/types/risk";
import type { ApiError } from "@/lib/api/errors";

/**
 * Risk assessments are deterministic, backend-calculated records — no
 * polling. Refresh is driven entirely by the calculation mutation's
 * targeted invalidation below, never by a timer.
 */
export function useRiskAssessments(
  params: { skip?: number; limit?: number } & RiskListFilters = {},
  enabled = true
) {
  const query = {
    skip: params.skip ?? 0,
    limit: params.limit ?? 50,
    scope: params.scope,
    risk_level: params.risk_level,
    scan_id: params.scan_id,
  };
  return useQuery({
    queryKey: riskKeys.list(query),
    queryFn: () => riskApi.getRiskAssessments(query),
    enabled,
  });
}

/** 404 NOT_FOUND means the scan has no score yet (still running, failed,
 * or the best-effort calculation did not run): a valid state, not a fault. */
export function useScanRisk(scanId: string, enabled = true) {
  return useQuery({
    queryKey: riskKeys.scan(scanId),
    queryFn: () => riskApi.getRiskByScan(scanId),
    enabled: Boolean(scanId) && enabled,
  });
}

/**
 * No `retry`: recalculation is a real backend write (upserts scope/entity
 * rows in place) — a transport failure after the backend already applied
 * it must not be silently replayed. Risk is normally calculated by the
 * backend when a scan completes; this is the manual fallback when that
 * best-effort step did not run.
 *
 * The AI feature's recommendation cache is not invalidated: no
 * AIRecommendation row is written. Freshness is recomputed from the
 * refetched assessment's `calculated_at`.
 */
export function useCalculateRiskForScan() {
  const queryClient = useQueryClient();
  return useMutation<RiskAssessmentResponse, ApiError, string>({
    mutationFn: (scanId: string) => riskApi.calculateRiskForScan(scanId),
    onSuccess: (data, scanId) => {
      queryClient.invalidateQueries({ queryKey: riskKeys.lists() });
      queryClient.setQueryData(riskKeys.scan(scanId), data);
    },
  });
}
