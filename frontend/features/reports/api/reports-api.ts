import { apiClient } from "@/lib/api/client";
import { requestBlob, requestData } from "@/lib/api/request";
import type { ApiSuccessEnvelope } from "@/types/api";

import type {
  ReportListFilters,
  ReportListResponse,
  ReportResponse,
} from "@/features/reports/types/report";

/**
 * Thin, typed wrappers around /api/v1/reports/*. Sole caller of `apiClient`
 * for reports. Reports are generated for one scan on request and never
 * regenerated automatically. GET and DELETE /reports/{id} are not wrapped:
 * the scan page only lists, generates and downloads.
 */
export const reportsApi = {
  getReports: (params: { skip?: number; limit?: number } & ReportListFilters = {}) =>
    requestData(
      apiClient.get<ApiSuccessEnvelope<ReportListResponse>>("/reports", { params })
    ),

  generateReport: (scanId: string) =>
    requestData(
      apiClient.post<ApiSuccessEnvelope<ReportResponse>>("/reports", {
        scan_id: scanId,
      })
    ),

  /** GET /reports/{id}/download returns the PDF bytes (no envelope). */
  downloadReport: (reportId: string) =>
    requestBlob(
      apiClient.get<Blob>(`/reports/${reportId}/download`, { responseType: "blob" })
    ),
};
