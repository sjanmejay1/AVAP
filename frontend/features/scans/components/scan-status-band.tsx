"use client";

import { OctagonX } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button, buttonVariants } from "@/components/ui/button";
import { isScanProfile, SCAN_PROFILES } from "@/features/scans/constants/scan-profiles";
import { useCancelScan } from "@/features/scans/hooks/use-scans";
import type { ScanResponse, ScanStatus } from "@/features/scans/types/scan";
import { useNow } from "@/hooks/use-now";
import { formatElapsed } from "@/utils/format";

/** Seconds since the scan started, or null before Nmap has started. */
export function elapsedSeconds(startedAt: string | null, now: number): number | null {
  if (!startedAt) return null;
  return Math.max(0, (now - new Date(startedAt).getTime()) / 1000);
}

/**
 * Shown only while a scan is pending or running. Nmap reports no
 * percentage, so this shows a live elapsed clock and the expected time for
 * the profile instead of a made-up progress bar.
 */
export function ScanStatusBand({ scan, status }: { scan: ScanResponse; status: ScanStatus }) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const now = useNow(true);
  const { mutate: cancel, isPending: isCancelling } = useCancelScan();
  const elapsed = elapsedSeconds(scan.started_at, now);
  const profile = scan.scan_type.toUpperCase();
  const estimate = isScanProfile(profile) ? SCAN_PROFILES[profile].estimate : null;

  function handleCancel(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    if (isCancelling) return;
    cancel(scan.scan_id, {
      onSuccess: () => {
        toast.success("Scan cancelled");
        setConfirmOpen(false);
      },
      onError: (error) => {
        toast.error(error.message);
        setConfirmOpen(false);
      },
    });
  }

  return (
    <section
      aria-label="Scan progress"
      className="mb-8 flex flex-col gap-4 rounded-lg border border-info-border bg-info-bg p-4 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex flex-col gap-1.5" aria-live="polite">
        <div className="flex flex-wrap items-center gap-3">
          <ScanStatusBadge status={status} />
          <span className="text-title tabular-nums">
            {status === "PENDING" || elapsed === null
              ? "Waiting for Nmap to start"
              : `Running for ${formatElapsed(elapsed)}`}
          </span>
        </div>
        <p className="text-sm text-muted-foreground">
          Nmap doesn&apos;t report progress.
          {estimate ? ` ${estimate}.` : ""} This page updates by itself when the scan
          finishes.
        </p>
      </div>
      <Button
        variant="outline"
        onClick={() => setConfirmOpen(true)}
        disabled={isCancelling}
        className="shrink-0 bg-background"
      >
        <OctagonX aria-hidden="true" />
        Cancel scan
      </Button>

      <AlertDialog open={confirmOpen} onOpenChange={(next) => !isCancelling && setConfirmOpen(next)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancel this scan?</AlertDialogTitle>
            <AlertDialogDescription>
              Nmap is stopped and the scan is marked cancelled, so it won&apos;t be
              scored or reported. You can start a new scan at any time.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isCancelling}>Keep scanning</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCancel}
              disabled={isCancelling}
              className={buttonVariants({ variant: "destructive" })}
            >
              {isCancelling ? "Cancelling…" : "Cancel scan"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
