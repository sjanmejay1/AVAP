import { describe, expect, it } from "vitest";

import { nvdUrl, unwrapScannerText } from "@/features/scans/components/finding-row";
import { resolveScanTab } from "@/features/scans/components/scan-detail";
import { elapsedSeconds } from "@/features/scans/components/scan-status-band";
import { countOpenPorts, severityCounts } from "@/features/scans/components/tabs/overview-tab";
import { flattenPorts } from "@/features/scans/components/tabs/ports-tab";
import { scanProfileLabel } from "@/features/scans/constants/scan-profiles";
import { splitScanFindings } from "@/features/scans/lib/scan-findings";
import type { RiskAssessmentResponse } from "@/features/risk/types/risk";
import type { ScanHostResponse, ServiceDetails } from "@/features/scans/types/scan";
import type { VulnerabilityResponse } from "@/features/vulnerabilities/types/vulnerability";

function vuln(id: string, overrides: Partial<VulnerabilityResponse> = {}): VulnerabilityResponse {
  return {
    id,
    name: `Vuln ${id}`,
    severity_score: 5,
    severity_rating: "Medium",
    description: null,
    cve: null,
    source: "NMAP_NSE",
    created_at: "2026-11-20T00:00:00Z",
    updated_at: "2026-11-20T00:00:00Z",
    ...overrides,
  };
}

function assessment(vulnerabilityId: string, score: number): RiskAssessmentResponse {
  return {
    id: `ra-${vulnerabilityId}`,
    scope: "VULNERABILITY",
    risk_score: score,
    risk_level: "HIGH",
    calculation_version: "1.0.0",
    calculated_at: "2026-11-20T00:00:00Z",
    supporting_factors: {},
    scan_id: "s1",
    asset_id: null,
    vulnerability_id: vulnerabilityId,
    service_id: null,
  };
}

function service(port: number, overrides: Partial<ServiceDetails> = {}): ServiceDetails {
  return {
    port,
    protocol: "tcp",
    state: "open",
    service_name: "http",
    product: null,
    version: null,
    cpes: [],
    scripts: {},
    ...overrides,
  };
}

function host(ipv4: string, services: ServiceDetails[]): ScanHostResponse {
  return {
    asset_id: `a-${ipv4}`,
    ipv4,
    hostname: null,
    operating_system: null,
    details: {
      mac_address: null,
      mac_vendor: null,
      hostnames: [],
      os_matches: [],
      uptime_seconds: null,
      last_boot: null,
      network_distance: null,
      traceroute: [],
      closed_port_count: 0,
      filtered_port_count: 0,
      services,
    },
  };
}

describe("splitScanFindings", () => {
  it("separates AI-inferred findings from scanner-confirmed ones", () => {
    const result = splitScanFindings(
      [vuln("a"), vuln("b", { source: "AI_INFERENCE" }), vuln("c", { source: null })],
      []
    );
    expect(result.confirmed.map((f) => f.vulnerability.id)).toEqual(["a", "c"]);
    expect(result.advisory.map((f) => f.vulnerability.id)).toEqual(["b"]);
  });

  it("joins VULNERABILITY-scope risk by vulnerability id and orders highest risk first", () => {
    const result = splitScanFindings(
      [vuln("low"), vuln("high"), vuln("unscored", { severity_score: 9.8 })],
      [
        assessment("low", 2.1),
        assessment("high", 9.4),
        { ...assessment("high", 1), scope: "ASSET", id: "asset-row" },
      ]
    );
    expect(result.confirmed.map((f) => f.vulnerability.id)).toEqual(["high", "low", "unscored"]);
    expect(result.confirmed[0].assessment?.id).toBe("ra-high");
    expect(result.confirmed[2].assessment).toBeNull();
  });
});

describe("severityCounts", () => {
  it("buckets by intrinsic severity, with 'None' as informational", () => {
    const { confirmed } = splitScanFindings(
      [
        vuln("1", { severity_rating: "Critical" }),
        vuln("2", { severity_rating: "Critical" }),
        vuln("3", { severity_rating: "None" }),
        vuln("4", { severity_rating: "Odd" }),
      ],
      []
    );
    expect(severityCounts(confirmed)).toMatchObject({ critical: 2, informational: 1, unknown: 1, high: 0 });
  });
});

describe("flattenPorts and countOpenPorts", () => {
  const hosts = [
    host("10.0.0.20", [service(443), service(22)]),
    host("10.0.0.3", [service(80), service(25, { state: "filtered" })]),
  ];

  it("lists every service in a fixed order: host by address, then port", () => {
    expect(flattenPorts(hosts).map((row) => `${row.ipv4}:${row.service.port}`)).toEqual([
      "10.0.0.3:25",
      "10.0.0.3:80",
      "10.0.0.20:22",
      "10.0.0.20:443",
    ]);
  });

  it("counts only open ports", () => {
    expect(countOpenPorts(hosts)).toBe(3);
  });
});

describe("resolveScanTab", () => {
  it("accepts known tabs and falls back to the overview for anything else", () => {
    expect(resolveScanTab("ports")).toBe("ports");
    expect(resolveScanTab("ai")).toBe("ai");
    expect(resolveScanTab(null)).toBe("overview");
    expect(resolveScanTab("constructor")).toBe("overview");
  });
});

describe("elapsedSeconds", () => {
  it("is null before Nmap starts and never negative", () => {
    const start = "2026-11-21T10:00:00Z";
    expect(elapsedSeconds(null, Date.now())).toBeNull();
    expect(elapsedSeconds(start, new Date("2026-11-21T10:12:04Z").getTime())).toBe(724);
    expect(elapsedSeconds(start, new Date("2026-11-21T09:59:00Z").getTime())).toBe(0);
  });
});

describe("nvdUrl", () => {
  it("links only well-formed CVE ids", () => {
    expect(nvdUrl("cve-2014-0160")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2014-0160");
    expect(nvdUrl("CVE-2014-0160\"><script>")).toBeNull();
    expect(nvdUrl("OSVDB-1234")).toBeNull();
  });
});

describe("unwrapScannerText", () => {
  it("rejoins Nmap's hard-wrapped lines but keeps paragraph breaks", () => {
    const nse =
      "The Apache web server is vulnerable to a denial of service attack when numerous\n" +
      "      overlapping byte ranges are requested.\n\nDisclosure date: 2011-08-19";
    expect(unwrapScannerText(nse)).toBe(
      "The Apache web server is vulnerable to a denial of service attack when numerous " +
        "overlapping byte ranges are requested.\n\nDisclosure date: 2011-08-19"
    );
  });

  it("leaves single-line text alone", () => {
    expect(unwrapScannerText("  Plain sentence.  ")).toBe("Plain sentence.");
  });
});

describe("scanProfileLabel", () => {
  it("labels both profiles and keeps legacy values readable", () => {
    expect(scanProfileLabel("QUICK")).toBe("Quick");
    expect(scanProfileLabel("full")).toBe("Full");
    expect(scanProfileLabel("standard")).toBe("Standard");
  });
});
