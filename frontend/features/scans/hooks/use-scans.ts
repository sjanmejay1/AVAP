import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";

import { reportKeys } from "@/features/reports/hooks/query-keys";
import { riskKeys } from "@/features/risk/hooks/query-keys";
import { scansApi } from "@/features/scans/api/scans-api";
import { scanKeys } from "@/features/scans/hooks/query-keys";
import type {
  AIAnalysisResponse,
  CreateScanRequest,
  ScanResponse,
  ScanStatus,
} from "@/features/scans/types/scan";
import { vulnerabilityKeys } from "@/features/vulnerabilities/hooks/query-keys";
import type { ApiError } from "@/lib/api/errors";

/**
 * Poll GET /scans/{id}/status (cheap, single-row lookup) rather than the
 * full GET /scans/{id}, every 10 seconds while a scan is active.
 */
export const SCAN_STATUS_POLL_INTERVAL_MS = 10_000;

export function isTerminalScanStatus(status: ScanStatus): boolean {
  return (
    status === "COMPLETED" || status === "FAILED" || status === "CANCELLED"
  );
}

/** Pure so the stop-on-terminal / poll-while-active decision is unit-testable. */
export function resolveScanStatusPollInterval(
  status: ScanStatus | undefined
): number | false {
  if (!status || isTerminalScanStatus(status)) return false;
  return SCAN_STATUS_POLL_INTERVAL_MS;
}

/** Same status-aware rule applied to a page of scans: poll only while at
 * least one row in the current page is still PENDING/RUNNING. */
export function resolveScanListPollInterval(
  scans: ScanResponse[] | undefined
): number | false {
  if (!scans || scans.length === 0) return false;
  const hasActiveScan = scans.some((scan) => !isTerminalScanStatus(scan.status));
  return hasActiveScan ? SCAN_STATUS_POLL_INTERVAL_MS : false;
}

export function useScans(
  params: { skip?: number; limit?: number; target_id?: string } = {}
) {
  const query = {
    skip: params.skip ?? 0,
    limit: params.limit ?? 50,
    target_id: params.target_id,
  };
  return useQuery({
    queryKey: scanKeys.list(query),
    queryFn: () => scansApi.getScans(query),
    refetchInterval: (state) => resolveScanListPollInterval(state.state.data?.scans),
  });
}

/** One-shot full detail fetch. Lifecycle observation is `useScanStatus`'s job. */
export function useScan(scanId: string) {
  return useQuery({
    queryKey: scanKeys.detail(scanId),
    queryFn: () => scansApi.getScan(scanId),
    enabled: Boolean(scanId),
  });
}

/** Status-aware polling of the lightweight status endpoint; stops once terminal. */
export function useScanStatus(scanId: string) {
  return useQuery({
    queryKey: scanKeys.status(scanId),
    queryFn: () => scansApi.getScanStatus(scanId),
    enabled: Boolean(scanId),
    refetchInterval: (state) => resolveScanStatusPollInterval(state.state.data?.status),
  });
}

/** Per-host detail (OS, MAC, uptime, traceroute, services with NSE output). */
export function useScanHosts(scanId: string, enabled = true) {
  return useQuery({
    queryKey: scanKeys.hosts(scanId),
    queryFn: () => scansApi.getScanHosts(scanId),
    enabled: Boolean(scanId) && enabled,
  });
}

/**
 * Re-reads everything a finished scan populated: the full record, hosts,
 * findings, risk and reports. Called once when polling sees a terminal
 * status. Never triggers server work itself.
 */
export function useRefreshFinishedScan() {
  const queryClient = useQueryClient();
  return useCallback(
    (scanId: string) => {
      queryClient.invalidateQueries({ queryKey: scanKeys.detail(scanId) });
      queryClient.invalidateQueries({ queryKey: scanKeys.hosts(scanId) });
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
      queryClient.invalidateQueries({ queryKey: vulnerabilityKeys.lists() });
      queryClient.invalidateQueries({ queryKey: riskKeys.all });
      queryClient.invalidateQueries({ queryKey: reportKeys.lists() });
    },
    [queryClient]
  );
}

/**
 * No `retry`: scan creation is not idempotent and the API contract offers
 * no idempotency key — a transport failure after the backend already
 * dispatched a scan must not be silently replayed.
 */
export function useCreateScan() {
  const queryClient = useQueryClient();
  return useMutation<ScanResponse, ApiError, CreateScanRequest>({
    mutationFn: (body: CreateScanRequest) => scansApi.createScan(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}

/** No `retry`: a replay could hit a scan that has since finished on its own. */
export function useCancelScan() {
  const queryClient = useQueryClient();
  return useMutation<ScanResponse, ApiError, string>({
    mutationFn: (scanId: string) => scansApi.cancelScan(scanId),
    onSuccess: (_data, scanId) => {
      queryClient.invalidateQueries({ queryKey: scanKeys.detail(scanId) });
      queryClient.invalidateQueries({ queryKey: scanKeys.status(scanId) });
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
    },
  });
}

/** No `retry`: delete is not safely replayable without idempotency support. */
export function useDeleteScan() {
  const queryClient = useQueryClient();
  return useMutation<void, ApiError, string>({
    mutationFn: (scanId: string) => scansApi.deleteScan(scanId),
    onSuccess: (_data, scanId) => {
      queryClient.invalidateQueries({ queryKey: scanKeys.lists() });
      queryClient.removeQueries({ queryKey: scanKeys.detail(scanId) });
      queryClient.removeQueries({ queryKey: scanKeys.status(scanId) });
      queryClient.removeQueries({ queryKey: scanKeys.hosts(scanId) });
    },
  });
}

/**
 * No `retry`: each run calls the user's OpenRouter key (rate-limited free
 * tier) and writes findings. The backend recalculates risk afterwards, so
 * findings and risk are re-read.
 */
export function useRunAiAnalysis() {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisResponse, ApiError, string>({
    mutationFn: (scanId: string) => scansApi.runAiAnalysis(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: vulnerabilityKeys.lists() });
      queryClient.invalidateQueries({ queryKey: riskKeys.all });
    },
  });
}

/** A user-triggered file download: a mutation, not cacheable server state. */
export function useDownloadRawOutput() {
  return useMutation<Blob, ApiError, string>({
    mutationFn: (scanId: string) => scansApi.downloadRawOutput(scanId),
  });
}
