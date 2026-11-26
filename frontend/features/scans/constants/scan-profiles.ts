import type { ScanProfile } from "@/features/scans/types/scan";

interface ScanProfileMeta {
  label: string;
  /** What Nmap does in this mode (app.core.enums.ScanProfile). */
  summary: string;
  /** Per-host expectation shown before starting and while running. */
  estimate: string;
}

export const SCAN_PROFILES: Record<ScanProfile, ScanProfileMeta> = {
  QUICK: {
    label: "Quick",
    summary: "Top 1,000 TCP ports, service versions and OS detection.",
    estimate: "About 1 minute per host",
  },
  FULL: {
    label: "Full",
    summary:
      "All 65,535 TCP ports, service versions, OS detection, traceroute and safe NSE vulnerability scripts.",
    estimate: "Up to about 90 minutes per host",
  },
};

export const SCAN_PROFILE_ORDER: ScanProfile[] = ["QUICK", "FULL"];

export function isScanProfile(value: string): value is ScanProfile {
  return value === "QUICK" || value === "FULL";
}

/** Display label for a scan's stored `scan_type`, including legacy values. */
export function scanProfileLabel(scanType: string): string {
  const upper = scanType.toUpperCase();
  if (isScanProfile(upper)) return SCAN_PROFILES[upper].label;
  return scanType.charAt(0).toUpperCase() + scanType.slice(1).toLowerCase();
}
