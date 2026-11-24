"use client";

import { FileDown, FileText, MoreHorizontal, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  useDownloadReport,
  useGenerateReport,
  useReports,
} from "@/features/reports/hooks/use-reports";
import { DeleteScanDialog } from "@/features/scans/components/delete-scan-dialog";
import { useDownloadRawOutput } from "@/features/scans/hooks/use-scans";
import { rawOutputFilename, reportFilename } from "@/features/scans/lib/download-names";
import type { ScanResponse } from "@/features/scans/types/scan";
import { triggerBrowserDownload } from "@/lib/download";

/**
 * Download PDF reuses the newest report for this scan, or generates the
 * first one. "Generate new PDF" always creates a fresh one, e.g. after
 * re-running AI analysis.
 */
export function ScanActions({ scan, targetId }: { scan: ScanResponse; targetId: string }) {
  const router = useRouter();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const isCompleted = scan.status === "COMPLETED";
  const reports = useReports({ scan_id: scan.scan_id, limit: 1 }, isCompleted);
  const generate = useGenerateReport();
  const download = useDownloadReport();
  const downloadRaw = useDownloadRawOutput();
  const isBusy = generate.isPending || download.isPending;

  async function saveReport(fresh: boolean) {
    try {
      const existing = fresh ? undefined : reports.data?.reports[0];
      const report = existing ?? (await generate.mutateAsync(scan.scan_id));
      const blob = await download.mutateAsync(report.id);
      triggerBrowserDownload(blob, reportFilename(report.id));
      toast.success(existing ? "PDF downloaded" : "PDF generated and downloaded");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "The PDF couldn't be downloaded.");
    }
  }

  function saveRawOutput() {
    downloadRaw.mutate(scan.scan_id, {
      onSuccess: (blob) => triggerBrowserDownload(blob, rawOutputFilename(scan.scan_id)),
      onError: (error) => toast.error(error.message),
    });
  }

  const pdfButton = (
    <Button onClick={() => saveReport(false)} disabled={!isCompleted || isBusy}>
      <FileDown aria-hidden="true" />
      {isBusy ? "Preparing PDF…" : "Download PDF"}
    </Button>
  );

  return (
    <>
      {isCompleted ? (
        pdfButton
      ) : (
        <Tooltip>
          <TooltipTrigger asChild>
            <span tabIndex={0} className="rounded-md">
              {pdfButton}
            </span>
          </TooltipTrigger>
          <TooltipContent>A PDF is available once the scan has completed.</TooltipContent>
        </Tooltip>
      )}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon" aria-label="More scan actions">
            <MoreHorizontal aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuItem disabled={!isCompleted || isBusy} onSelect={() => saveReport(true)}>
            <FileText aria-hidden="true" />
            Generate new PDF
          </DropdownMenuItem>
          <DropdownMenuItem
            disabled={!isCompleted || downloadRaw.isPending}
            onSelect={saveRawOutput}
          >
            <FileDown aria-hidden="true" />
            Download Nmap XML
          </DropdownMenuItem>
          <DropdownMenuItem
            variant="destructive"
            disabled={scan.status === "RUNNING"}
            onSelect={() => setDeleteOpen(true)}
          >
            <Trash2 aria-hidden="true" />
            Delete scan
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <DeleteScanDialog
        scan={scan}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => router.push(`/targets/${targetId}`)}
      />
    </>
  );
}
