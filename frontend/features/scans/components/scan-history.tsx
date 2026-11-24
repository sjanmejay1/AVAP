"use client";

import { MoreHorizontal, Radar, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScanRiskCell } from "@/features/risk/components/scan-risk-cell";
import { DeleteScanDialog } from "@/features/scans/components/delete-scan-dialog";
import { scanProfileLabel } from "@/features/scans/constants/scan-profiles";
import { isTerminalScanStatus, useScans } from "@/features/scans/hooks/use-scans";
import type { ScanResponse } from "@/features/scans/types/scan";
import { formatCount, formatDateTime, formatDuration } from "@/utils/format";

const HISTORY_LIMIT = 200;
const COLUMNS =
  "md:grid-cols-[minmax(0,1.6fr)_minmax(0,0.8fr)_minmax(0,1fr)_minmax(0,0.8fr)_minmax(0,1.2fr)_2.5rem]";

function ScanHistoryRow({
  scan,
  onDelete,
}: {
  scan: ScanResponse;
  onDelete: (scan: ScanResponse) => void;
}) {
  const isActive = !isTerminalScanStatus(scan.status);

  return (
    <li
      className={`relative grid grid-cols-[minmax(0,1fr)_2.5rem] items-center gap-x-4 gap-y-2 px-4 py-3.5 hover:bg-muted ${COLUMNS}`}
    >
      <Link
        href={`/scans/${scan.scan_id}`}
        className="text-sm font-medium text-foreground after:absolute after:inset-0 focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring focus-visible:after:ring-inset"
      >
        {formatDateTime(scan.started_at ?? scan.created_at)}
      </Link>
      <div className="col-start-1 flex flex-wrap items-center gap-x-4 gap-y-2 md:contents">
        <span className="text-sm">{scanProfileLabel(scan.scan_type)}</span>
        <span>
          <ScanStatusBadge status={scan.status} />
        </span>
        <span className="text-sm text-muted-foreground">
          {isActive ? "In progress" : formatDuration(scan.execution_duration)}
        </span>
        <ScanRiskCell scanId={scan.scan_id} status={scan.status} />
      </div>
      <div className="relative z-10 col-start-2 row-start-1 justify-self-end md:col-start-auto md:row-start-auto">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label="Scan actions">
              <MoreHorizontal aria-hidden="true" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuItem
              variant="destructive"
              disabled={scan.status === "RUNNING"}
              onSelect={() => onDelete(scan)}
            >
              <Trash2 aria-hidden="true" />
              Delete scan
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </li>
  );
}

/** Every scan of one target, newest first. Polls while any is still active. */
export function ScanHistory({
  targetId,
  emptyAction,
}: {
  targetId: string;
  emptyAction?: React.ReactNode;
}) {
  const [pendingDelete, setPendingDelete] = useState<ScanResponse | null>(null);
  const { data, isPending, isError, refetch } = useScans({
    target_id: targetId,
    limit: HISTORY_LIMIT,
  });

  if (isPending) return <ListRowsSkeleton rows={3} />;
  if (isError) {
    return <ErrorState title="Scan history couldn't be loaded" onRetry={() => refetch()} />;
  }
  if (data.scans.length === 0) {
    return (
      <EmptyState
        icon={Radar}
        title="No scans yet"
        description="Start a quick scan to see open ports and services in about a minute per host."
        action={emptyAction}
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="rounded-lg border border-border">
        <div
          className={`hidden gap-4 border-b border-border px-4 py-2.5 text-xs font-medium text-muted-foreground md:grid ${COLUMNS}`}
          aria-hidden="true"
        >
          <span>Started</span>
          <span>Type</span>
          <span>Status</span>
          <span>Duration</span>
          <span>Risk</span>
          <span />
        </div>
        <ul className="divide-y divide-border">
          {data.scans.map((scan) => (
            <ScanHistoryRow key={scan.scan_id} scan={scan} onDelete={setPendingDelete} />
          ))}
        </ul>
      </div>
      {data.total > data.scans.length && (
        <p className="text-sm text-muted-foreground">
          Showing the newest {formatCount(data.scans.length)} of {formatCount(data.total)} scans.
        </p>
      )}

      {pendingDelete && (
        <DeleteScanDialog
          scan={pendingDelete}
          open
          onOpenChange={(next) => {
            if (!next) setPendingDelete(null);
          }}
        />
      )}
    </div>
  );
}
