"use client";

import { toast } from "sonner";

import { RiskLevelBadge } from "@/components/shared/risk-level-badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { SEVERITY_META, severityRatingToKey, type SeverityKey } from "@/constants/severity";
import { useCalculateRiskForScan, useScanRisk } from "@/features/risk/hooks/use-risk";
import { scanProfileLabel } from "@/features/scans/constants/scan-profiles";
import { useScanFindings } from "@/features/scans/hooks/use-scan-findings";
import { useScanHosts } from "@/features/scans/hooks/use-scans";
import type { ScanFinding } from "@/features/scans/lib/scan-findings";
import type { ScanHostResponse, ScanResponse } from "@/features/scans/types/scan";
import { ApiError } from "@/lib/api/errors";
import { cn } from "@/lib/utils";
import { formatCount, formatDateTime, formatDuration, formatRiskScore } from "@/utils/format";

const BAR_ORDER: SeverityKey[] = ["critical", "high", "medium", "low", "informational"];

export function countOpenPorts(hosts: ScanHostResponse[]): number {
  return hosts.reduce(
    (total, host) =>
      total + host.details.services.filter((service) => service.state === "open").length,
    0
  );
}

export function severityCounts(findings: ScanFinding[]): Record<SeverityKey, number> {
  const counts: Record<SeverityKey, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    unknown: 0,
  };
  for (const finding of findings) {
    counts[severityRatingToKey(finding.vulnerability.severity_rating)] += 1;
  }
  return counts;
}

/** One stacked bar, with every count also written out so color is never the only signal. */
function SeverityBar({ counts }: { counts: Record<SeverityKey, number> }) {
  const keys = BAR_ORDER.filter((key) => counts[key] > 0);
  const total = keys.reduce((sum, key) => sum + counts[key], 0) + counts.unknown;

  if (total === 0) {
    return <p className="text-sm text-muted-foreground">No confirmed findings.</p>;
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex h-2.5 w-full overflow-hidden rounded-sm bg-muted" aria-hidden="true">
        {keys.map((key) => (
          <span
            key={key}
            className={SEVERITY_META[key].fillClass}
            style={{ width: `${(counts[key] / total) * 100}%` }}
          />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-5 gap-y-1.5 text-sm">
        {[...keys, ...(counts.unknown > 0 ? (["unknown"] as const) : [])].map((key) => (
          <li key={key} className="flex items-center gap-1.5">
            <span className={cn("size-2 rounded-full", SEVERITY_META[key].fillClass)} aria-hidden="true" />
            <span className="font-medium tabular-nums">{counts[key]}</span>
            <span className="text-muted-foreground">{SEVERITY_META[key].label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-title tabular-nums">{children}</dd>
    </div>
  );
}

function RiskSummary({ scan }: { scan: ScanResponse }) {
  const isCompleted = scan.status === "COMPLETED";
  const { data: risk, isPending, error } = useScanRisk(scan.scan_id, isCompleted);
  const calculate = useCalculateRiskForScan();

  if (!isCompleted) {
    return <p className="text-sm text-muted-foreground">Risk is scored when the scan completes.</p>;
  }
  if (isPending) return <Skeleton className="h-16 w-48" />;

  if (!risk) {
    const notScored = error instanceof ApiError && error.code === "NOT_FOUND";
    return (
      <div className="flex flex-col items-start gap-3">
        <p className="text-sm text-muted-foreground">
          {notScored
            ? "This scan hasn't been scored yet."
            : "The risk score couldn't be loaded."}
        </p>
        {notScored && (
          <Button
            variant="outline"
            size="sm"
            disabled={calculate.isPending}
            onClick={() =>
              calculate.mutate(scan.scan_id, { onError: (err) => toast.error(err.message) })
            }
          >
            {calculate.isPending ? "Calculating…" : "Calculate risk"}
          </Button>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline gap-3">
        <span className="type-wide text-display tabular-nums">{formatRiskScore(risk.risk_score)}</span>
        <span className="text-sm text-muted-foreground">out of 10</span>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <RiskLevelBadge level={risk.risk_level} />
        <span className="text-sm text-muted-foreground">
          The score of the riskiest confirmed finding (risk engine{" "}
          {risk.calculation_version})
        </span>
      </div>
    </div>
  );
}

export function OverviewTab({ scan }: { scan: ScanResponse }) {
  const isCompleted = scan.status === "COMPLETED";
  const hosts = useScanHosts(scan.scan_id, isCompleted);
  const { findings, isPending: findingsPending } = useScanFindings(scan.scan_id, isCompleted);

  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <section aria-labelledby="overview-risk" className="flex flex-col gap-4">
        <h2 id="overview-risk" className="text-h3">
          Risk
        </h2>
        <RiskSummary scan={scan} />
        <div className="flex flex-col gap-3 pt-2">
          <h3 className="text-title">Confirmed findings by severity</h3>
          {!isCompleted ? (
            <p className="text-sm text-muted-foreground">Findings appear when the scan completes.</p>
          ) : findingsPending || !findings ? (
            <Skeleton className="h-10 w-full" />
          ) : (
            <SeverityBar counts={severityCounts(findings.confirmed)} />
          )}
          {findings && findings.advisory.length > 0 && (
            <p className="text-sm text-muted-foreground">
              Plus {formatCount(findings.advisory.length)} AI advisory{" "}
              {findings.advisory.length === 1 ? "finding" : "findings"}, unverified and not
              scored.
            </p>
          )}
        </div>
      </section>

      <section aria-labelledby="overview-facts" className="flex flex-col gap-4">
        <h2 id="overview-facts" className="text-h3">
          Scan
        </h2>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-5">
          <Fact label="Type">{scanProfileLabel(scan.scan_type)}</Fact>
          <Fact label="Duration">{formatDuration(scan.execution_duration)}</Fact>
          <Fact label="Hosts up">
            {hosts.data ? formatCount(hosts.data.total) : isCompleted ? "…" : "—"}
          </Fact>
          <Fact label="Open ports">
            {hosts.data ? formatCount(countOpenPorts(hosts.data.hosts)) : isCompleted ? "…" : "—"}
          </Fact>
          <Fact label="Started">
            <span className="text-sm font-normal">
              {scan.started_at ? formatDateTime(scan.started_at) : "Not started"}
            </span>
          </Fact>
          <Fact label="Finished">
            <span className="text-sm font-normal">
              {scan.completed_at ? formatDateTime(scan.completed_at) : "—"}
            </span>
          </Fact>
        </dl>
      </section>
    </div>
  );
}
