"use client";

import { ChevronRight, FileDown } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useDownloadRawOutput } from "@/features/scans/hooks/use-scans";
import { rawOutputFilename } from "@/features/scans/lib/download-names";
import type { ScanResponse } from "@/features/scans/types/scan";
import { triggerBrowserDownload } from "@/lib/download";
import { cn } from "@/lib/utils";

function LogBlock({ title, text, tone }: { title: string; text: string; tone: "plain" | "error" }) {
  const [open, setOpen] = useState(false);
  return (
    <Collapsible open={open} onOpenChange={setOpen} className="rounded-lg border border-border">
      <CollapsibleTrigger className="flex w-full cursor-pointer items-center gap-2 px-4 py-3 text-left text-sm font-medium focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
        <ChevronRight
          className={cn("size-4 transition-transform", open && "rotate-90")}
          aria-hidden="true"
        />
        {title}
      </CollapsibleTrigger>
      <CollapsibleContent>
        <pre
          className={cn(
            "max-h-96 overflow-auto border-t border-border px-4 py-3 font-mono text-xs leading-relaxed whitespace-pre-wrap",
            tone === "error" ? "bg-destructive-bg text-destructive" : "bg-muted"
          )}
        >
          {text}
        </pre>
      </CollapsibleContent>
    </Collapsible>
  );
}

export function RawTab({ scan }: { scan: ScanResponse }) {
  const download = useDownloadRawOutput();
  const isCompleted = scan.status === "COMPLETED";

  function handleDownload() {
    download.mutate(scan.scan_id, {
      onSuccess: (blob) => triggerBrowserDownload(blob, rawOutputFilename(scan.scan_id)),
      onError: (error) => toast.error(error.message),
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <section className="flex flex-col items-start gap-3" aria-labelledby="raw-xml-heading">
        <h2 id="raw-xml-heading" className="text-h3">
          Nmap XML
        </h2>
        <p className="max-w-prose text-sm text-muted-foreground">
          The unmodified XML Nmap wrote for this scan. Every other tab is parsed from it.
          Open it in any XML viewer, or import it into other tools.
        </p>
        <Button onClick={handleDownload} disabled={!isCompleted || download.isPending}>
          <FileDown aria-hidden="true" />
          {download.isPending ? "Downloading…" : "Download Nmap XML"}
        </Button>
        {!isCompleted && (
          <p className="text-sm text-muted-foreground">Available once the scan has completed.</p>
        )}
      </section>

      {(scan.stdout_log || scan.stderr_log) && (
        <section className="flex flex-col gap-3" aria-labelledby="raw-logs-heading">
          <h2 id="raw-logs-heading" className="text-h3">
            Scanner logs
          </h2>
          {scan.stdout_log && <LogBlock title="Standard output" text={scan.stdout_log} tone="plain" />}
          {scan.stderr_log && <LogBlock title="Errors and warnings" text={scan.stderr_log} tone="error" />}
        </section>
      )}
    </div>
  );
}
