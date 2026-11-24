import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));
vi.mock("@/features/targets/api/targets-api", () => ({
  targetsApi: { getTargets: vi.fn(), getTarget: vi.fn(), createTarget: vi.fn(), deleteTarget: vi.fn() },
}));
vi.mock("@/features/scans/api/scans-api", () => ({
  scansApi: { getScans: vi.fn(), createScan: vi.fn() },
}));
vi.mock("@/features/risk/api/risk-api", () => ({
  riskApi: { getRiskByScan: vi.fn(), getRiskAssessments: vi.fn(), calculateRiskForScan: vi.fn() },
}));

import { riskApi } from "@/features/risk/api/risk-api";
import { scansApi } from "@/features/scans/api/scans-api";
import type { ScanResponse } from "@/features/scans/types/scan";
import { targetsApi } from "@/features/targets/api/targets-api";
import { filterTargets, TargetList } from "@/features/targets/components/target-list";
import type { TargetResponse } from "@/features/targets/types/target";
import { renderWithQueryClient } from "@/test/render";

function target(id: string, value: string, type: TargetResponse["target_type"]): TargetResponse {
  return { id, target: value, target_type: type, created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00Z" };
}

function scan(overrides: Partial<ScanResponse>): ScanResponse {
  return {
    scan_id: "s1",
    target_id: "t1",
    status: "COMPLETED",
    scan_type: "QUICK",
    created_at: "2026-11-20T10:00:00Z",
    updated_at: "2026-11-20T10:01:00Z",
    started_at: "2026-11-20T10:00:00Z",
    completed_at: "2026-11-20T10:01:00Z",
    execution_duration: 60,
    failure_reason: null,
    stdout_log: null,
    stderr_log: null,
    ...overrides,
  };
}

const TARGETS = [
  target("t1", "10.0.0.0/24", "CIDR"),
  target("t2", "scanme.nmap.org", "HOSTNAME"),
  target("t3", "192.168.1.10", "IPV4"),
];

function mockBackend() {
  vi.mocked(targetsApi.getTargets).mockResolvedValue({ targets: TARGETS, total: 3 });
  vi.mocked(scansApi.getScans).mockImplementation(async (params) => {
    if (params?.target_id === "t1") return { scans: [scan({ scan_id: "s1", target_id: "t1" })], total: 1 };
    if (params?.target_id === "t2")
      return { scans: [scan({ scan_id: "s2", target_id: "t2", status: "RUNNING", completed_at: null })], total: 1 };
    return { scans: [], total: 0 };
  });
  vi.mocked(riskApi.getRiskByScan).mockResolvedValue({
    id: "r1",
    scope: "SCAN",
    risk_score: 8.4,
    risk_level: "HIGH",
    calculation_version: "1.0.0",
    calculated_at: "2026-11-20T10:01:00Z",
    supporting_factors: {},
    scan_id: "s1",
    asset_id: null,
    vulnerability_id: null,
    service_id: null,
  });
}

const rowFor = (text: string) => screen.getByText(text).closest("li") as HTMLElement;

describe("filterTargets", () => {
  it("matches case-insensitively on the target value and ignores surrounding spaces", () => {
    expect(filterTargets(TARGETS, "  SCANME ").map((t) => t.id)).toEqual(["t2"]);
    expect(filterTargets(TARGETS, "").map((t) => t.id)).toEqual(["t1", "t2", "t3"]);
  });
});

describe("TargetList", () => {
  it("shows each target's last scan and, for completed scans only, its risk", async () => {
    mockBackend();
    renderWithQueryClient(<TargetList />);

    await screen.findByText("10.0.0.0/24");
    await waitFor(() => expect(within(rowFor("10.0.0.0/24")).getByText("High")).toBeInTheDocument());
    expect(within(rowFor("10.0.0.0/24")).getByText("Completed")).toBeInTheDocument();
    expect(within(rowFor("10.0.0.0/24")).getByText("8.4")).toBeInTheDocument();

    await waitFor(() => expect(within(rowFor("scanme.nmap.org")).getByText("Running")).toBeInTheDocument());
    expect(await within(rowFor("192.168.1.10")).findByText("Not scanned yet")).toBeInTheDocument();
    // Risk is requested only for the completed scan, never for the running one.
    expect(riskApi.getRiskByScan).toHaveBeenCalledTimes(1);
    expect(riskApi.getRiskByScan).toHaveBeenCalledWith("s1");
  });

  it("filters the list as you type and says when nothing matches", async () => {
    mockBackend();
    renderWithQueryClient(<TargetList />);
    await screen.findByText("10.0.0.0/24");
    const user = userEvent.setup();

    await user.type(screen.getByRole("searchbox", { name: "Search targets" }), "192.168");
    await waitFor(() => expect(screen.queryByText("10.0.0.0/24")).not.toBeInTheDocument());
    expect(screen.getByText("192.168.1.10")).toBeInTheDocument();

    await user.clear(screen.getByRole("searchbox"));
    await user.type(screen.getByRole("searchbox"), "nothing-like-this");
    expect(await screen.findByText(/No targets match/)).toBeInTheDocument();
  });

  it("invites you to add a first target when there are none", async () => {
    vi.mocked(targetsApi.getTargets).mockResolvedValue({ targets: [], total: 0 });
    renderWithQueryClient(<TargetList />);

    expect(await screen.findByText("No targets yet")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Add target" }).length).toBeGreaterThan(0);
  });

  it("offers a retry when the list fails to load", async () => {
    vi.mocked(targetsApi.getTargets).mockRejectedValue(new Error("down"));
    renderWithQueryClient(<TargetList />);

    expect(await screen.findByText("Targets couldn't be loaded")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("links each row to its target page", async () => {
    mockBackend();
    renderWithQueryClient(<TargetList />);

    const link = await screen.findByRole("link", { name: "scanme.nmap.org" });
    expect(link).toHaveAttribute("href", "/targets/t2");
  });
});
