"use client";

import { MoreHorizontal, Play, Trash2 } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { ScanRiskCell } from "@/features/risk/components/scan-risk-cell";
import { NewScanDialog } from "@/features/scans/components/new-scan-dialog";
import { useScans } from "@/features/scans/hooks/use-scans";
import { TARGET_TYPE_LABELS, type TargetResponse } from "@/features/targets/types/target";
import { formatRelativeTime } from "@/utils/format";

/** Latest scan for one target: the newest row of GET /scans?target_id=… */
function LastScanCells({ targetId }: { targetId: string }) {
  const { data, isPending, isError } = useScans({ target_id: targetId, limit: 1 });

  if (isPending) {
    return (
      <>
        <Skeleton className="h-6 w-32" />
        <Skeleton className="h-6 w-24" />
      </>
    );
  }
  const latest = data?.scans[0];
  if (isError || !latest) {
    return (
      <>
        <span className="text-sm text-muted-foreground">
          {isError ? "Couldn't load" : "Not scanned yet"}
        </span>
        <span className="text-sm text-muted-foreground">—</span>
      </>
    );
  }
  return (
    <>
      <span className="flex flex-wrap items-center gap-2">
        <ScanStatusBadge status={latest.status} />
        <span className="text-sm text-muted-foreground">
          {formatRelativeTime(latest.started_at ?? latest.created_at)}
        </span>
      </span>
      <ScanRiskCell scanId={latest.scan_id} status={latest.status} />
    </>
  );
}

export function TargetRow({
  target,
  onDelete,
}: {
  target: TargetResponse;
  onDelete: (target: TargetResponse) => void;
}) {
  const [scanOpen, setScanOpen] = useState(false);

  return (
    <li className="relative grid grid-cols-[minmax(0,1fr)_2.5rem] items-center gap-x-4 gap-y-2 px-4 py-3.5 hover:bg-muted md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,1.2fr)_2.5rem]">
      <Link
        href={`/targets/${target.id}`}
        className="truncate font-mono text-sm font-medium text-foreground after:absolute after:inset-0 focus-visible:outline-none focus-visible:after:ring-2 focus-visible:after:ring-ring focus-visible:after:ring-inset"
      >
        {target.target}
      </Link>
      <span className="col-start-1 text-sm text-muted-foreground md:col-start-auto">
        {TARGET_TYPE_LABELS[target.target_type]}
      </span>
      <div className="col-span-1 col-start-1 flex flex-wrap items-center gap-x-4 gap-y-2 md:contents">
        <LastScanCells targetId={target.id} />
      </div>
      <div className="relative z-10 col-start-2 row-start-1 justify-self-end md:col-start-auto md:row-start-auto">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${target.target}`}>
              <MoreHorizontal aria-hidden="true" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuItem onSelect={() => setScanOpen(true)}>
              <Play aria-hidden="true" />
              New scan
            </DropdownMenuItem>
            <DropdownMenuItem variant="destructive" onSelect={() => onDelete(target)}>
              <Trash2 aria-hidden="true" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        <NewScanDialog target={target} open={scanOpen} onOpenChange={setScanOpen} />
      </div>
    </li>
  );
}
