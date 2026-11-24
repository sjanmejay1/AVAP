import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { renderWithQueryClient } from "@/test/render";
import { ApiError } from "@/lib/api/errors";

vi.mock("@/features/targets/api/targets-api", () => ({
  targetsApi: {
    getTargets: vi.fn(),
    getTarget: vi.fn(),
    createTarget: vi.fn(),
    deleteTarget: vi.fn(),
  },
}));

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}));

import { targetsApi } from "@/features/targets/api/targets-api";
import { CreateTargetDialog } from "@/features/targets/components/create-target-dialog";
import { toast } from "sonner";

const mockedCreateTarget = vi.mocked(targetsApi.createTarget);

function created(target: string) {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    target,
    target_type: "IPV4" as const,
    created_at: "2026-07-15T00:00:00Z",
    updated_at: "2026-07-15T00:00:00Z",
  };
}

async function openDialogAndType(value: string) {
  const user = userEvent.setup();
  renderWithQueryClient(<CreateTargetDialog />);
  await user.click(screen.getByRole("button", { name: "Add target" }));
  const dialog = await screen.findByRole("dialog");
  await user.type(within(dialog).getByLabelText("Target"), value);
  return { user, dialog };
}

async function submit(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement) {
  await user.click(within(dialog).getByRole("button", { name: "Add target" }));
}

describe("CreateTargetDialog", () => {
  it("submits exactly {target} to the API and closes on success", async () => {
    mockedCreateTarget.mockResolvedValue(created("10.0.0.5"));

    const { user, dialog } = await openDialogAndType("10.0.0.5");
    await submit(user, dialog);

    await waitFor(() => expect(mockedCreateTarget).toHaveBeenCalledWith({ target: "10.0.0.5" }));
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith("Target added"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("describes what it recognised while typing", async () => {
    await openDialogAndType("10.0.0.0/24");
    expect(screen.getByText("CIDR range, 256 addresses.")).toBeInTheDocument();
  });

  it("rejects an obviously invalid value in the browser without calling the API", async () => {
    const { user, dialog } = await openDialogAndType("not a target");
    await submit(user, dialog);

    expect(await within(dialog).findByRole("alert")).toHaveTextContent(/Enter an IPv4 address/);
    expect(mockedCreateTarget).not.toHaveBeenCalled();
  });

  it("shows the backend's 422 message on the field when the server is stricter than the browser", async () => {
    // A /20 passes the browser's default /16 limit; a server configured with
    // MIN_CIDR_PREFIX_LENGTH=24 still refuses it, and its message must show.
    mockedCreateTarget.mockRejectedValue(
      new ApiError({
        code: "VALIDATION_ERROR",
        message: "CIDR range '10.0.0.0/20' is too broad; the narrowest allowed prefix is /24.",
        status: 422,
      })
    );

    const { user, dialog } = await openDialogAndType("10.0.0.0/20");
    await submit(user, dialog);

    expect(
      await within(dialog).findByText(
        "CIDR range '10.0.0.0/20' is too broad; the narrowest allowed prefix is /24."
      )
    ).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("surfaces a 409 duplicate as a field error, not a generic toast", async () => {
    mockedCreateTarget.mockRejectedValue(
      new ApiError({
        code: "CONFLICT",
        message: "Target 'duplicate.com' already exists.",
        status: 409,
      })
    );

    const { user, dialog } = await openDialogAndType("duplicate.com");
    await submit(user, dialog);

    expect(await screen.findByText("Target 'duplicate.com' already exists.")).toBeInTheDocument();
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("prevents duplicate submission: a second click while pending fires no second request", async () => {
    let resolveCreate: (value: ReturnType<typeof created>) => void = () => {};
    mockedCreateTarget.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCreate = resolve;
        })
    );

    const { user, dialog } = await openDialogAndType("10.0.0.5");
    const submitButton = within(dialog).getByRole("button", { name: "Add target" });
    await user.click(submitButton);
    await waitFor(() => expect(submitButton).toBeDisabled());
    await user.click(submitButton);

    expect(mockedCreateTarget).toHaveBeenCalledTimes(1);
    resolveCreate(created("10.0.0.5"));
  });
});
