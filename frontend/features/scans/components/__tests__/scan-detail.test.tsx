import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

const replace = vi.fn();
let search = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace }),
  usePathname: () => "/scans/s1",
  useSearchParams: () => search,
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/lib/download", () => ({ triggerBrowserDownload: vi.fn() }));
vi.mock("@/features/scans/api/scans-api", () => ({
  scansApi: {
    getScan: vi.fn(),
    getScanStatus: vi.fn(),
    getScanHosts: vi.fn(),
    getScans: vi.fn(),
    cancelScan: vi.fn(),
    runAiAnalysis: vi.fn(),
    downloadRawOutput: vi.fn(),
    deleteScan: vi.fn(),
  },
}));
vi.mock("@/features/targets/api/targets-api", () => ({
  targetsApi: { getTarget: vi.fn() },
}));
vi.mock("@/features/risk/api/risk-api", () => ({
  riskApi: { getRiskByScan: vi.fn(), getRiskAssessments: vi.fn(), calculateRiskForScan: vi.fn() },
}));
vi.mock("@/features/vulnerabilities/api/vulnerabilities-api", () => ({
  vulnerabilitiesApi: { getVulnerabilities: vi.fn() },
}));
vi.mock("@/features/reports/api/reports-api", () => ({
  reportsApi: { getReports: vi.fn(), generateReport: vi.fn(), downloadReport: vi.fn() },
}));
vi.mock("@/features/ai/api/ai-api", () => ({
  aiApi: { getRecommendation: vi.fn(), generateRecommendation: vi.fn() },
}));

import { reportsApi } from "@/features/reports/api/reports-api";
import { riskApi } from "@/features/risk/api/risk-api";
import { scansApi } from "@/features/scans/api/scans-api";
import { ScanDetail } from "@/features/scans/components/scan-detail";
import type { ScanHostListResponse, ScanResponse, ScanStatus } from "@/features/scans/types/scan";
import { targetsApi } from "@/features/targets/api/targets-api";
import { vulnerabilitiesApi } from "@/features/vulnerabilities/api/vulnerabilities-api";
import { ApiError } from "@/lib/api/errors";
import { triggerBrowserDownload } from "@/lib/download";
import { renderWithQueryClient } from "@/test/render";

function scan(status: ScanStatus, overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    scan_id: "s1",
    target_id: "t1",
    status,
    scan_type: "FULL",
    created_at: "2026-11-21T10:00:00Z",
    updated_at: "2026-11-21T10:00:00Z",
    started_at: "2026-11-21T10:00:00Z",
    completed_at: status === "COMPLETED" ? "2026-11-21T10:40:00Z" : null,
    execution_duration: status === "COMPLETED" ? 2400 : null,
    failure_reason: null,
    stdout_log: "Nmap done: 1 IP address (1 host up)",
    stderr_log: null,
    ...overrides,
  };
}

const HOSTS: ScanHostListResponse = {
  total: 1,
  hosts: [
    {
      asset_id: "a1",
      ipv4: "10.0.0.7",
      hostname: "web.lab",
      operating_system: "Linux 5.4",
      details: {
        mac_address: "00:11:22:33:44:55",
        mac_vendor: "Raspberry Pi Foundation",
        hostnames: ["web.lab"],
        os_matches: [{ name: "Linux 5.4", accuracy: 96, cpes: [] }],
        uptime_seconds: 90_000,
        last_boot: "Thu Nov 20 09:00:00 2026",
        network_distance: 2,
        traceroute: [
          { ttl: "1", ipaddr: "10.0.0.1", rtt: "0.40", host: "gateway" },
          { ttl: "2", ipaddr: "10.0.0.7", rtt: "1.10", host: null },
        ],
        closed_port_count: 997,
        filtered_port_count: 1,
        services: [
          {
            port: 443,
            protocol: "tcp",
            state: "open",
            service_name: "https",
            product: "nginx",
            version: "1.18.0",
            cpes: [],
            scripts: { "ssl-heartbleed": "VULNERABLE: The Heartbleed Bug" },
          },
          { port: 22, protocol: "tcp", state: "open", service_name: "ssh", product: "OpenSSH", version: "8.2", cpes: [], scripts: {} },
        ],
      },
    },
  ],
};

function mockCompletedBackend() {
  vi.mocked(scansApi.getScan).mockResolvedValue(scan("COMPLETED"));
  vi.mocked(scansApi.getScanStatus).mockResolvedValue({ scan_id: "s1", status: "COMPLETED", updated_at: "x" });
  vi.mocked(scansApi.getScanHosts).mockResolvedValue(HOSTS);
  vi.mocked(targetsApi.getTarget).mockResolvedValue({
    id: "t1",
    target: "10.0.0.0/24",
    target_type: "CIDR",
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
  });
  vi.mocked(riskApi.getRiskByScan).mockResolvedValue({
    id: "scan-risk",
    scope: "SCAN",
    risk_score: 9.4,
    risk_level: "CRITICAL",
    calculation_version: "1.0.0",
    calculated_at: "2026-11-21T10:40:00Z",
    supporting_factors: {},
    scan_id: "s1",
    asset_id: null,
    vulnerability_id: null,
    service_id: null,
  });
  vi.mocked(riskApi.getRiskAssessments).mockResolvedValue({
    total: 1,
    risk_assessments: [
      {
        id: "ra-heartbleed",
        scope: "VULNERABILITY",
        risk_score: 9.4,
        risk_level: "CRITICAL",
        calculation_version: "1.0.0",
        calculated_at: "2026-11-21T10:40:00Z",
        supporting_factors: {},
        scan_id: "s1",
        asset_id: "a1",
        vulnerability_id: "v-heartbleed",
        service_id: null,
      },
    ],
  });
  vi.mocked(vulnerabilitiesApi.getVulnerabilities).mockResolvedValue({
    total: 2,
    vulnerabilities: [
      {
        id: "v-heartbleed",
        name: "OpenSSL Heartbleed",
        severity_score: 7.5,
        severity_rating: "High",
        description: "Memory disclosure in the TLS heartbeat extension.",
        cve: "CVE-2014-0160",
        source: "NMAP_NSE",
        created_at: "2026-11-21T10:40:00Z",
        updated_at: "2026-11-21T10:40:00Z",
      },
      {
        id: "v-ai",
        name: "Possibly outdated nginx",
        severity_score: 5,
        severity_rating: "Medium",
        description: null,
        cve: null,
        source: "AI_INFERENCE",
        created_at: "2026-11-21T10:41:00Z",
        updated_at: "2026-11-21T10:41:00Z",
      },
    ],
  });
}

describe("ScanDetail", () => {
  beforeEach(() => {
    search = new URLSearchParams();
  });

  it("titles the page with the target and shows the overview by default", async () => {
    mockCompletedBackend();
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    expect(await screen.findByRole("heading", { level: 1, name: "10.0.0.0/24" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("9.4")).toBeInTheDocument();
    // Advisory findings are counted separately, never in the severity bar.
    expect(await screen.findByText(/Plus 1 AI advisory finding/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Scan progress" })).not.toBeInTheDocument();
  });

  it("opens the tab named in the URL and writes tab changes back to it", async () => {
    mockCompletedBackend();
    search = new URLSearchParams("tab=hosts");
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    const hostRegion = await screen.findByRole("region", { name: "Host 10.0.0.7" });
    expect(within(hostRegion).getByText("96%")).toBeInTheDocument();
    expect(within(hostRegion).getByText("00:11:22:33:44:55")).toBeInTheDocument();
    expect(within(hostRegion).getByText("1 day, 1 hour")).toBeInTheDocument();
    expect(within(hostRegion).getAllByRole("listitem").some((li) => li.textContent?.includes("gateway"))).toBe(true);

    await userEvent.setup().click(screen.getByRole("tab", { name: "Ports & services" }));
    expect(replace).toHaveBeenCalledWith("/scans/s1?tab=ports", { scroll: false });
  });

  it("expands NSE script output on the ports tab", async () => {
    mockCompletedBackend();
    search = new URLSearchParams("tab=ports");
    renderWithQueryClient(<ScanDetail scanId="s1" />);
    const user = userEvent.setup();

    const toggle = await screen.findByRole("button", { name: /Show 1 script result for port 443/ });
    expect(screen.queryByText(/The Heartbleed Bug/)).not.toBeInTheDocument();
    await user.click(toggle);

    expect(screen.getByText("ssl-heartbleed")).toBeInTheDocument();
    expect(screen.getByText(/The Heartbleed Bug/)).toBeInTheDocument();
    expect(toggle).toHaveAttribute("aria-expanded", "true");
  });

  it("lists only scanner-confirmed findings on the findings tab, with an NVD link", async () => {
    mockCompletedBackend();
    search = new URLSearchParams("tab=findings");
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    expect(await screen.findByText("OpenSSL Heartbleed")).toBeInTheDocument();
    expect(screen.queryByText("Possibly outdated nginx")).not.toBeInTheDocument();
    const link = screen.getByRole("link", { name: /CVE-2014-0160/ });
    expect(link).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("labels AI findings as advisory and points to the profile when no key is saved", async () => {
    mockCompletedBackend();
    vi.mocked(scansApi.runAiAnalysis).mockRejectedValue(
      new ApiError({ code: "AI_KEY_REQUIRED", message: "Add an OpenRouter key.", status: 409 })
    );
    search = new URLSearchParams("tab=ai");
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    expect(await screen.findByText("AI advisory, unverified.")).toBeInTheDocument();
    expect(await screen.findByText("Possibly outdated nginx")).toBeInTheDocument();
    expect(screen.queryByText("OpenSSL Heartbleed")).not.toBeInTheDocument();

    await userEvent.setup().click(screen.getByRole("button", { name: "Run AI analysis again" }));

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByRole("link", { name: "profile" })).toHaveAttribute("href", "/profile");
  });

  it("downloads the newest existing PDF instead of generating another", async () => {
    mockCompletedBackend();
    vi.mocked(reportsApi.getReports).mockResolvedValue({
      total: 1,
      reports: [{ id: "rep-1" } as never],
    });
    vi.mocked(reportsApi.downloadReport).mockResolvedValue(new Blob(["%PDF"]));
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    await screen.findByRole("heading", { level: 1, name: "10.0.0.0/24" });
    await waitFor(() => expect(reportsApi.getReports).toHaveBeenCalled());
    await userEvent.setup().click(screen.getByRole("button", { name: "Download PDF" }));

    await waitFor(() => expect(triggerBrowserDownload).toHaveBeenCalledWith(expect.any(Blob), "avap-report-rep-1.pdf"));
    expect(reportsApi.generateReport).not.toHaveBeenCalled();
  });

  it("generates the first PDF when the scan has none", async () => {
    mockCompletedBackend();
    vi.mocked(reportsApi.getReports).mockResolvedValue({ total: 0, reports: [] });
    vi.mocked(reportsApi.generateReport).mockResolvedValue({ id: "rep-new" } as never);
    vi.mocked(reportsApi.downloadReport).mockResolvedValue(new Blob(["%PDF"]));
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    await screen.findByRole("heading", { level: 1, name: "10.0.0.0/24" });
    await waitFor(() => expect(reportsApi.getReports).toHaveBeenCalled());
    await userEvent.setup().click(screen.getByRole("button", { name: "Download PDF" }));

    await waitFor(() => expect(reportsApi.generateReport).toHaveBeenCalledWith("s1"));
    await waitFor(() => expect(triggerBrowserDownload).toHaveBeenCalledWith(expect.any(Blob), "avap-report-rep-new.pdf"));
  });

  it("downloads the raw Nmap XML under the backend's filename", async () => {
    mockCompletedBackend();
    vi.mocked(scansApi.downloadRawOutput).mockResolvedValue(new Blob(["<nmaprun/>"]));
    search = new URLSearchParams("tab=raw");
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    await userEvent.setup().click(await screen.findByRole("button", { name: "Download Nmap XML" }));

    await waitFor(() => expect(triggerBrowserDownload).toHaveBeenCalledWith(expect.any(Blob), "nmap-s1.xml"));
  });

  it("shows a live status band while running, and cancels only after confirmation", async () => {
    mockCompletedBackend();
    vi.mocked(scansApi.getScan).mockResolvedValue(scan("RUNNING"));
    vi.mocked(scansApi.getScanStatus).mockResolvedValue({ scan_id: "s1", status: "RUNNING", updated_at: "x" });
    vi.mocked(scansApi.cancelScan).mockResolvedValue(scan("CANCELLED"));
    renderWithQueryClient(<ScanDetail scanId="s1" />);
    const user = userEvent.setup();

    const band = await screen.findByRole("region", { name: "Scan progress" });
    expect(within(band).getByText(/Running for/)).toBeInTheDocument();
    expect(within(band).getByText(/Up to about 90 minutes per host/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Download PDF" })).toBeDisabled();

    await user.click(within(band).getByRole("button", { name: "Cancel scan" }));
    expect(scansApi.cancelScan).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Cancel scan" }));

    await waitFor(() => expect(scansApi.cancelScan).toHaveBeenCalledWith("s1"));
  });

  it("explains a failed scan instead of showing empty tabs", async () => {
    mockCompletedBackend();
    vi.mocked(scansApi.getScan).mockResolvedValue(
      scan("FAILED", { failure_reason: "Nmap exited with status 1." })
    );
    vi.mocked(scansApi.getScanStatus).mockResolvedValue({ scan_id: "s1", status: "FAILED", updated_at: "x" });
    search = new URLSearchParams("tab=hosts");
    renderWithQueryClient(<ScanDetail scanId="s1" />);

    expect(await screen.findByText("The scan failed.")).toBeInTheDocument();
    expect(screen.getByText(/This scan failed, so there are no results/)).toBeInTheDocument();
    expect(scansApi.getScanHosts).not.toHaveBeenCalled();
  });

  it("says a missing scan doesn't exist, without a retry button", async () => {
    vi.mocked(scansApi.getScan).mockRejectedValue(
      new ApiError({ code: "NOT_FOUND", message: "Scan not found", status: 404 })
    );
    vi.mocked(scansApi.getScanStatus).mockRejectedValue(new Error("not found"));
    renderWithQueryClient(<ScanDetail scanId="missing" />);

    expect(await screen.findByText("This scan doesn't exist")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
  });
});
