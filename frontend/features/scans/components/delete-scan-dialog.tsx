"use client";

import { toast } from "sonner";

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
import { buttonVariants } from "@/components/ui/button";
import { scanProfileLabel } from "@/features/scans/constants/scan-profiles";
import { useDeleteScan } from "@/features/scans/hooks/use-scans";
import type { ScanResponse } from "@/features/scans/types/scan";
import { formatDateTime } from "@/utils/format";

export function DeleteScanDialog({
  scan,
  open,
  onOpenChange,
  onDeleted,
}: {
  scan: ScanResponse;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called after a confirmed deletion — e.g. to navigate away from a detail page. */
  onDeleted?: () => void;
}) {
  const { mutate, isPending } = useDeleteScan();

  function handleConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault(); // wait for server confirmation before closing
    if (isPending) return;

    mutate(scan.scan_id, {
      onSuccess: () => {
        toast.success("Scan deleted");
        onOpenChange(false);
        onDeleted?.();
      },
      // The backend refuses to delete a running scan (409); its message is shown as-is.
      onError: (error) => toast.error(error.message),
    });
  }

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!isPending) onOpenChange(next);
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this scan?</AlertDialogTitle>
          <AlertDialogDescription>
            Its hosts, findings, AI advice, raw output and reports are deleted too. It
            can&apos;t be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <p className="rounded-md border border-border bg-muted px-3 py-2 text-sm text-foreground">
          {scanProfileLabel(scan.scan_type)} scan requested {formatDateTime(scan.created_at)}
        </p>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            disabled={isPending}
            className={buttonVariants({ variant: "destructive" })}
          >
            {isPending ? "Deleting…" : "Delete scan"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
