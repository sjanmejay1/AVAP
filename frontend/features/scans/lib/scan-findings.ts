import type { RiskAssessmentResponse } from "@/features/risk/types/risk";
import type { VulnerabilityResponse } from "@/features/vulnerabilities/types/vulnerability";

/** Provenance value for AI-inferred findings (backend SOURCE_AI_INFERENCE). */
export const AI_INFERENCE_SOURCE = "AI_INFERENCE";

export interface ScanFinding {
  vulnerability: VulnerabilityResponse;
  /** The VULNERABILITY-scope assessment for this scan, when one was calculated. */
  assessment: RiskAssessmentResponse | null;
}

export interface SplitFindings {
  /** Scanner-confirmed (Nmap NSE), scored, highest risk first. */
  confirmed: ScanFinding[];
  /** AI-inferred and unverified; never part of the risk score. */
  advisory: ScanFinding[];
}

function byRiskThenSeverity(a: ScanFinding, b: ScanFinding): number {
  const riskA = a.assessment?.risk_score ?? -1;
  const riskB = b.assessment?.risk_score ?? -1;
  if (riskA !== riskB) return riskB - riskA;
  return b.vulnerability.severity_score - a.vulnerability.severity_score;
}

/**
 * Joins a scan's vulnerabilities to their VULNERABILITY-scope risk
 * assessments by `vulnerability_id`, then splits them by provenance. A fixed
 * order (highest risk first), not a user-configurable sort.
 */
export function splitScanFindings(
  vulnerabilities: VulnerabilityResponse[],
  assessments: RiskAssessmentResponse[]
): SplitFindings {
  const assessmentByVulnerability = new Map<string, RiskAssessmentResponse>();
  for (const assessment of assessments) {
    if (assessment.scope === "VULNERABILITY" && assessment.vulnerability_id) {
      assessmentByVulnerability.set(assessment.vulnerability_id, assessment);
    }
  }

  const confirmed: ScanFinding[] = [];
  const advisory: ScanFinding[] = [];
  for (const vulnerability of vulnerabilities) {
    const finding = {
      vulnerability,
      assessment: assessmentByVulnerability.get(vulnerability.id) ?? null,
    };
    if (vulnerability.source === AI_INFERENCE_SOURCE) advisory.push(finding);
    else confirmed.push(finding);
  }

  return {
    confirmed: confirmed.sort(byRiskThenSeverity),
    advisory: advisory.sort(byRiskThenSeverity),
  };
}
