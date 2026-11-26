import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { reportsApi } from "@/features/reports/api/reports-api";
import { reportKeys } from "@/features/reports/hooks/query-keys";
import type { ReportListFilters, ReportResponse } from "@/features/reports/types/report";
import type { ApiError } from "@/lib/api/errors";

/** Reports are immutable, generated-on-demand artifacts — no polling. */
export function useReports(
  params: { skip?: number; limit?: number } & ReportListFilters = {},
  enabled = true
) {
  const query = {
    skip: params.skip ?? 0,
    limit: params.limit ?? 50,
    scan_id: params.scan_id,
  };
  return useQuery({
    queryKey: reportKeys.list(query),
    queryFn: () => reportsApi.getReports(query),
    enabled,
  });
}

/**
 * No `retry`: every successful call creates a brand-new immutable report
 * row and file (never overwrites) — replaying a request whose response was
 * merely lost in transit would create a duplicate report, not recover one.
 * Report generation only writes the `reports` table, so only report lists
 * are re-read (never risk, AI, scans or findings).
 */
export function useGenerateReport() {
  const queryClient = useQueryClient();
  return useMutation<ReportResponse, ApiError, string>({
    mutationFn: (scanId: string) => reportsApi.generateReport(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportKeys.lists() });
    },
  });
}

/**
 * A user-triggered download action, not cacheable server state — modeled
 * as a mutation rather than a query. No cache effect.
 */
export function useDownloadReport() {
  return useMutation<Blob, ApiError, string>({
    mutationFn: (reportId: string) => reportsApi.downloadReport(reportId),
  });
}
