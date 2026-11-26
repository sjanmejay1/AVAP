import { apiClient } from "@/lib/api/client";
import { requestBlob, requestData, requestVoid } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";

import type {
  AIAnalysisResponse,
  CreateScanRequest,
  ScanHostListResponse,
  ScanListResponse,
  ScanResponse,
  ScanStatusResponse,
} from "@/features/scans/types/scan";

/**
 * Thin, typed wrappers around /api/v1/scans/*. Sole caller of `apiClient`
 * for scans — hooks never call Axios directly.
 */
export const scansApi = {
  getScans: (
    params: { skip?: number; limit?: number; target_id?: string } = {}
  ) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<ScanListResponse>>("/scans", { params })
    ),

  getScan: (scanId: string) =>
    requestData(apiClient.get<ApiSuccessEnvelope<ScanResponse>>(`/scans/${scanId}`)),

  getScanStatus: (scanId: string) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<ScanStatusResponse>>(
        `/scans/${scanId}/status`
      )
    ),

  getScanHosts: (scanId: string) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<ScanHostListResponse>>(`/scans/${scanId}/hosts`)
    ),

  createScan: (body: CreateScanRequest) =>
    requestData(apiClient.post<ApiSuccessEnvelope<ScanResponse>>("/scans", body)),

  cancelScan: (scanId: string) =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<ScanResponse>>(`/scans/${scanId}/cancel`)
    ),

  runAiAnalysis: (scanId: string) =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<AIAnalysisResponse>>(
        `/scans/${scanId}/ai-analysis`
      )
    ),

  deleteScan: (scanId: string) => requestVoid(apiClient.delete(`/scans/${scanId}`)),

  /** GET /scans/{id}/raw streams the Nmap XML as an attachment (no envelope). */
  downloadRawOutput: (scanId: string) =>
    requestBlob(apiClient.get<Blob>(`/scans/${scanId}/raw`, { responseType: "blob" })),
};
