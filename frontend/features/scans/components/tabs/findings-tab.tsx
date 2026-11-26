"use client";

import { ShieldCheck } from "lucide-react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { FindingRow } from "@/features/scans/components/finding-row";
import { useScanFindings } from "@/features/scans/hooks/use-scan-findings";
import type { ScanResponse } from "@/features/scans/types/scan";

/** Scanner-confirmed findings (Nmap NSE), highest risk first. */
export function FindingsTab({ scan }: { scan: ScanResponse }) {
  const { findings, isPending, isError, refetch } = useScanFindings(scan.scan_id);

  if (isPending) return <ListRowsSkeleton rows={4} />;
  if (isError || !findings) {
    return <ErrorState title="Findings couldn't be loaded" onRetry={refetch} />;
  }

  if (findings.confirmed.length === 0) {
    const isQuick = scan.scan_type.toUpperCase() === "QUICK";
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No confirmed vulnerabilities"
        description={
          isQuick
            ? "Quick scans don't run vulnerability scripts. Run a full scan to check services against Nmap's safe NSE scripts."
            : "Nmap's safe NSE scripts found no known vulnerabilities on this scan."
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted-foreground">
        Reported by Nmap&apos;s vulnerability scripts and scored by AVAP&apos;s deterministic
        risk engine. Scripts test how a service responds, so they can misfire (for example,
        an Apache check flagging nginx); check each finding before acting on it.
      </p>
      <ul className="divide-y divide-border rounded-lg border border-border">
        {findings.confirmed.map((finding) => (
          <FindingRow key={finding.vulnerability.id} finding={finding} showRemediation />
        ))}
      </ul>
    </div>
  );
}
