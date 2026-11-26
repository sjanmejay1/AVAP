import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push, replace: vi.fn() }) }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/features/scans/api/scans-api", () => ({
  scansApi: { createScan: vi.fn(), getScans: vi.fn() },
}));

import { NewScanDialog } from "@/features/scans/components/new-scan-dialog";
import { scansApi } from "@/features/scans/api/scans-api";
import type { TargetResponse } from "@/features/targets/types/target";
import { ApiError } from "@/lib/api/errors";
import { renderWithQueryClient } from "@/test/render";

const mockedCreate = vi.mocked(scansApi.createScan);

function target(value: string, type: TargetResponse["target_type"]): TargetResponse {
  return { id: "t1", target: value, target_type: type, created_at: "2026-11-01T00:00:00Z", updated_at: "2026-11-01T00:00:00Z" };
}

const started = {
  scan_id: "new-scan",
  target_id: "t1",
  status: "PENDING" as const,
  scan_type: "QUICK",
  created_at: "2026-11-21T10:00:00Z",
  updated_at: "2026-11-21T10:00:00Z",
  started_at: null,
  completed_at: null,
  execution_duration: null,
  failure_reason: null,
  stdout_log: null,
  stderr_log: null,
};

async function open(value = "10.0.0.5", type: TargetResponse["target_type"] = "IPV4") {
  const user = userEvent.setup();
  renderWithQueryClient(<NewScanDialog target={target(value, type)} />);
  await user.click(screen.getByRole("button", { name: "New scan" }));
  return user;
}

describe("NewScanDialog", () => {
  it("offers Quick and Full with their per-host estimates, Quick selected", async () => {
    await open();

    expect(screen.getByRole("radio", { name: "Quick scan" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Full scan" })).not.toBeChecked();
    expect(screen.getByText("About 1 minute per host")).toBeInTheDocument();
    expect(screen.getByText("Up to about 90 minutes per host")).toBeInTheDocument();
  });

  it("sends the chosen profile and opens the new scan", async () => {
    mockedCreate.mockResolvedValue({ ...started, scan_type: "FULL" });
    const user = await open();

    await user.click(screen.getByRole("radio", { name: "Full scan" }));
    await user.click(screen.getByRole("button", { name: "Start full scan" }));

    await waitFor(() =>
      expect(mockedCreate).toHaveBeenCalledWith({ target_id: "t1", scan_profile: "FULL" })
    );
    await waitFor(() => expect(push).toHaveBeenCalledWith("/scans/new-scan"));
  });

  it("explains range size for a CIDR target", async () => {
    await open("10.0.0.0/24", "CIDR");
    expect(screen.getByText(/This range has 256 addresses/)).toBeInTheDocument();
  });

  it("keeps the dialog open with the backend's reason when a scan is already running", async () => {
    mockedCreate.mockRejectedValue(
      new ApiError({ code: "CONFLICT", message: "A scan is already running for this target.", status: 409 })
    );
    const user = await open();

    await user.click(screen.getByRole("button", { name: "Start quick scan" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("A scan is already running");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(push).not.toHaveBeenCalled();
  });
});
