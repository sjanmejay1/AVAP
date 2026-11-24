"use client";

import { ChevronRight, ExternalLink } from "lucide-react";
import { useState } from "react";

import { RiskScore } from "@/components/shared/risk-score";
import { SeverityBadge } from "@/components/shared/severity-badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { severityRatingToKey } from "@/constants/severity";
import { RecommendationPanel } from "@/features/ai/components/recommendation-panel";
import type { ScanFinding } from "@/features/scans/lib/scan-findings";
import { cn } from "@/lib/utils";

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

/** NVD link for a well-formed CVE id only; anything else is shown as text. */
export function nvdUrl(cve: string): string | null {
  return CVE_PATTERN.test(cve)
    ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.toUpperCase())}`
    : null;
}

/**
 * One finding. Expands to its description and, for scored findings, the
 * AI remediation panel (advisory, generated on request).
 */
export function FindingRow({
  finding,
  showRemediation,
}: {
  finding: ScanFinding;
  showRemediation: boolean;
}) {
  const [open, setOpen] = useState(false);
  const { vulnerability, assessment } = finding;
  const cveLink = vulnerability.cve ? nvdUrl(vulnerability.cve) : null;

  return (
    <li>
      <Collapsible open={open} onOpenChange={setOpen}>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
          <CollapsibleTrigger
            className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 rounded-md text-left focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
          >
            <ChevronRight
              className={cn("size-4 shrink-0 transition-transform", open && "rotate-90")}
              aria-hidden="true"
            />
            <SeverityBadge severity={severityRatingToKey(vulnerability.severity_rating)} />
            <span className="min-w-0 text-sm font-medium break-words">{vulnerability.name}</span>
          </CollapsibleTrigger>
          <div className="flex items-center gap-4 pl-7 sm:pl-0">
            {vulnerability.cve &&
              (cveLink ? (
                <a
                  href={cveLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 font-mono text-sm underline underline-offset-4"
                >
                  {vulnerability.cve}
                  <ExternalLink className="size-3.5" aria-hidden="true" />
                  <span className="sr-only">(opens NVD in a new tab)</span>
                </a>
              ) : (
                <span className="font-mono text-sm">{vulnerability.cve}</span>
              ))}
            {assessment ? (
              <RiskScore score={assessment.risk_score} />
            ) : (
              <span className="text-sm text-muted-foreground">Not scored</span>
            )}
          </div>
        </div>
        <CollapsibleContent className="flex flex-col gap-6 border-t border-border bg-muted/40 px-4 py-5 sm:pl-11">
          <p className="max-w-prose text-sm break-words whitespace-pre-line">
            {vulnerability.description || "No description was recorded for this finding."}
          </p>
          {showRemediation && assessment && (
            <section aria-label="AI remediation advice" className="flex flex-col gap-3">
              <h3 className="text-title">Remediation advice</h3>
              <p className="text-sm text-muted-foreground">
                AI advisory, unverified. Check each step before applying it.
              </p>
              <RecommendationPanel
                assessmentId={assessment.id}
                riskCalculatedAt={assessment.calculated_at}
              />
            </section>
          )}
        </CollapsibleContent>
      </Collapsible>
    </li>
  );
}
