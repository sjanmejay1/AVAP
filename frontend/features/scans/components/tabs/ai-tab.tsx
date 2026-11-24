"use client";

import { Sparkles } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import { FindingRow } from "@/features/scans/components/finding-row";
import { useScanFindings } from "@/features/scans/hooks/use-scan-findings";
import { useRunAiAnalysis } from "@/features/scans/hooks/use-scans";
import type { ScanResponse } from "@/features/scans/types/scan";
import type { ApiError } from "@/lib/api/errors";

export const AI_KEY_REQUIRED_CODE = "AI_KEY_REQUIRED";

function AdvisoryBanner() {
  return (
    <div
      role="note"
      className="rounded-md border border-warning-border bg-warning-bg px-4 py-3 text-sm text-warning"
    >
      <p className="font-medium">AI advisory, unverified.</p>
      <p className="mt-0.5">
        These are guesses from service and version banners, made by a free OpenRouter
        model. They are not part of the risk score. Confirm each one before acting on it.
      </p>
    </div>
  );
}

function RunError({ error }: { error: ApiError }) {
  if (error.code === AI_KEY_REQUIRED_CODE) {
    return (
      <p role="alert" className="text-sm text-destructive">
        Add your OpenRouter key on your{" "}
        <Link href="/profile" className="font-medium underline underline-offset-4">
          profile
        </Link>{" "}
        to use AI analysis.
      </p>
    );
  }
  return (
    <p role="alert" className="text-sm text-destructive">
      {error.message}
    </p>
  );
}

export function AiTab({ scan }: { scan: ScanResponse }) {
  const isCompleted = scan.status === "COMPLETED";
  const { findings, isPending, isError, refetch } = useScanFindings(scan.scan_id, isCompleted);
  const run = useRunAiAnalysis();
  const [runError, setRunError] = useState<ApiError | null>(null);

  function handleRun() {
    setRunError(null);
    run.mutate(scan.scan_id, {
      onSuccess: (result) =>
        toast.success(
          result.findings_created === 1
            ? "AI analysis finished with 1 new finding"
            : `AI analysis finished with ${result.findings_created} new findings`
        ),
      onError: setRunError,
    });
  }

  const hasFindings = Boolean(findings && findings.advisory.length > 0);
  const runButton = (
    <Button
      variant={hasFindings ? "outline" : "default"}
      onClick={handleRun}
      disabled={!isCompleted || run.isPending}
    >
      <Sparkles aria-hidden="true" />
      {run.isPending ? "Analysing…" : hasFindings ? "Run AI analysis again" : "Run AI analysis"}
    </Button>
  );

  return (
    <div className="flex flex-col gap-5">
      <AdvisoryBanner />
      <div className="flex flex-col items-start gap-2">
        {runButton}
        {!isCompleted && (
          <p className="text-sm text-muted-foreground">Available once the scan has completed.</p>
        )}
        {runError && <RunError error={runError} />}
      </div>

      {isCompleted && isPending && <ListRowsSkeleton rows={3} />}
      {isCompleted && !isPending && (isError || !findings) && (
        <ErrorState title="AI findings couldn't be loaded" onRetry={refetch} />
      )}
      {findings && findings.advisory.length === 0 && (
        <EmptyState
          icon={Sparkles}
          title="No AI findings for this scan"
          description="Analysis runs automatically after a scan when your OpenRouter key is saved, or you can run it here."
        />
      )}
      {findings && findings.advisory.length > 0 && (
        <ul className="divide-y divide-border rounded-lg border border-border">
          {findings.advisory.map((finding) => (
            <FindingRow key={finding.vulnerability.id} finding={finding} showRemediation={false} />
          ))}
        </ul>
      )}
    </div>
  );
}
