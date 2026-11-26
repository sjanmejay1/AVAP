"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { PageSkeleton } from "@/components/shared/skeletons";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScanActions } from "@/features/scans/components/scan-actions";
import { ScanStatusBand } from "@/features/scans/components/scan-status-band";
import { AiTab } from "@/features/scans/components/tabs/ai-tab";
import { FindingsTab } from "@/features/scans/components/tabs/findings-tab";
import { HostsTab } from "@/features/scans/components/tabs/hosts-tab";
import { OverviewTab } from "@/features/scans/components/tabs/overview-tab";
import { PortsTab } from "@/features/scans/components/tabs/ports-tab";
import { RawTab } from "@/features/scans/components/tabs/raw-tab";
import { scanProfileLabel } from "@/features/scans/constants/scan-profiles";
import {
  isTerminalScanStatus,
  useRefreshFinishedScan,
  useScan,
  useScanStatus,
} from "@/features/scans/hooks/use-scans";
import type { ScanResponse, ScanStatus } from "@/features/scans/types/scan";
import { useTarget } from "@/features/targets/hooks/use-targets";
import { ApiError } from "@/lib/api/errors";
import { formatDateTime } from "@/utils/format";

export const SCAN_TABS = [
  { value: "overview", label: "Overview" },
  { value: "hosts", label: "Hosts" },
  { value: "ports", label: "Ports & services" },
  { value: "findings", label: "Findings" },
  { value: "ai", label: "AI advice" },
  { value: "raw", label: "Raw output" },
] as const;

export type ScanTab = (typeof SCAN_TABS)[number]["value"];

export function resolveScanTab(raw: string | null): ScanTab {
  return SCAN_TABS.some((tab) => tab.value === raw) ? (raw as ScanTab) : "overview";
}

function NoResults({ scan, status }: { scan: ScanResponse; status: ScanStatus }) {
  const message =
    status === "FAILED"
      ? "This scan failed, so there are no results."
      : status === "CANCELLED"
        ? "This scan was cancelled before it finished, so there are no results."
        : "Results appear here when the scan finishes.";
  return (
    <p className="rounded-lg border border-dashed border-border px-6 py-10 text-sm text-muted-foreground">
      {message}
      {status === "FAILED" && scan.failure_reason ? ` ${scan.failure_reason}` : ""}
    </p>
  );
}

/**
 * Watches the polled status and, the moment it turns terminal, re-reads
 * the full record and everything the finished scan populated.
 */
function useFinishWatcher(scanId: string, status: ScanStatus | undefined) {
  const refresh = useRefreshFinishedScan();
  const previous = useRef<ScanStatus | undefined>(undefined);

  useEffect(() => {
    if (!status) return;
    if (previous.current && previous.current !== status && isTerminalScanStatus(status)) {
      refresh(scanId);
    }
    previous.current = status;
  }, [status, scanId, refresh]);
}

export function ScanDetail({ scanId }: { scanId: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const tab = resolveScanTab(searchParams.get("tab"));

  const { data: scan, isPending, isError, error, refetch } = useScan(scanId);
  const { data: statusData } = useScanStatus(scanId);
  const { data: target } = useTarget(scan?.target_id ?? "");
  const status = statusData?.status ?? scan?.status;
  useFinishWatcher(scanId, statusData?.status);

  function selectTab(value: string) {
    const next = resolveScanTab(value);
    const params = new URLSearchParams(searchParams.toString());
    if (next === "overview") params.delete("tab");
    else params.set("tab", next);
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }

  if (isPending) return <PageSkeleton />;

  if (isError || !scan || !status) {
    const notFound = error instanceof ApiError && error.code === "NOT_FOUND";
    return (
      <div className="flex flex-col">
        <PageHeader title="Scan" breadcrumbs={[{ label: "Targets", href: "/targets" }]} />
        <ErrorState
          title={notFound ? "This scan doesn't exist" : "This scan couldn't be loaded"}
          description={
            notFound ? "It may have been deleted, or it belongs to another account." : undefined
          }
          onRetry={notFound ? undefined : () => refetch()}
        />
      </div>
    );
  }

  const targetLabel = target?.target ?? "Target";
  const isLive = !isTerminalScanStatus(status);
  const startedLabel = formatDateTime(scan.started_at ?? scan.created_at);
  const hasResults = status === "COMPLETED";
  const noResults = <NoResults scan={scan} status={status} />;

  return (
    <div className="flex flex-col">
      <PageHeader
        wide
        title={targetLabel}
        breadcrumbs={[
          { label: "Targets", href: "/targets" },
          { label: targetLabel, href: `/targets/${scan.target_id}` },
          { label: `Scan of ${startedLabel}` },
        ]}
        description={
          <span className="flex flex-wrap items-center gap-3">
            <ScanStatusBadge status={status} />
            <span>
              {scanProfileLabel(scan.scan_type)} scan, started {startedLabel}
            </span>
          </span>
        }
        actions={<ScanActions scan={{ ...scan, status }} targetId={scan.target_id} />}
      />

      {isLive && <ScanStatusBand scan={scan} status={status} />}

      {status === "FAILED" && scan.failure_reason && (
        <div
          role="alert"
          className="mb-8 rounded-lg border border-destructive-border bg-destructive-bg px-4 py-3 text-sm text-destructive"
        >
          <p className="font-medium">The scan failed.</p>
          <p className="mt-0.5">{scan.failure_reason}</p>
        </div>
      )}

      <Tabs value={tab} onValueChange={selectTab}>
        <TabsList aria-label="Scan sections">
          {SCAN_TABS.map((item) => (
            <TabsTrigger key={item.value} value={item.value}>
              {item.label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <OverviewTab scan={{ ...scan, status }} />
        </TabsContent>
        {/* Hosts, ports and findings only exist once a scan has completed. */}
        <TabsContent value="hosts">
          {hasResults ? <HostsTab scanId={scan.scan_id} /> : noResults}
        </TabsContent>
        <TabsContent value="ports">
          {hasResults ? <PortsTab scanId={scan.scan_id} /> : noResults}
        </TabsContent>
        <TabsContent value="findings">
          {hasResults ? <FindingsTab scan={scan} /> : noResults}
        </TabsContent>
        <TabsContent value="ai">
          <AiTab scan={{ ...scan, status }} />
        </TabsContent>
        <TabsContent value="raw">
          <RawTab scan={{ ...scan, status }} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
