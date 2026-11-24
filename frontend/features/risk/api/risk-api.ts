import { apiClient } from "@/lib/api/client";
import { requestData } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";

import type {
  RiskAssessmentListResponse,
  RiskAssessmentResponse,
  RiskListFilters,
} from "@/features/risk/types/risk";

/**
 * Thin, typed wrappers around GET/POST /api/v1/risk/*. Sole caller of
 * `apiClient` for risk — hooks never call Axios directly. GET
 * /risk/assets/{id} is not wrapped: no page shows per-asset risk history.
 */
export const riskApi = {
  getRiskAssessments: (
    params: { skip?: number; limit?: number } & RiskListFilters = {}
  ) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<RiskAssessmentListResponse>>("/risk", {
        params,
      })
    ),

  getRiskByScan: (scanId: string) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<RiskAssessmentResponse>>(
        `/risk/scans/${scanId}`
      )
    ),

  calculateRiskForScan: (scanId: string) =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<RiskAssessmentResponse>>(
        `/risk/scans/${scanId}/calculate`
      )
    ),

};
