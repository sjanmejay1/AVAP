import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/features/profile/api/profile-api", () => ({
  profileApi: {
    changePassword: vi.fn(),
    getApiKeys: vi.fn(),
    saveOpenRouterKey: vi.fn(),
    testOpenRouterKey: vi.fn(),
    deleteOpenRouterKey: vi.fn(),
  },
}));

import { profileApi } from "@/features/profile/api/profile-api";
import { OpenRouterKeySection } from "@/features/profile/components/openrouter-key-section";
import { PasswordSection } from "@/features/profile/components/password-section";
import { ProfileView } from "@/features/profile/components/profile-view";
import { ApiError } from "@/lib/api/errors";
import { renderWithAuth } from "@/test/render";

const savedKey = { provider: "openrouter" as const, last4: "9f2c", updated_at: "2026-11-20T10:00:00Z" };

describe("ProfileView", () => {
  it("shows the signed-in account", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [] });
    renderWithAuth(<ProfileView />);

    expect(screen.getByText("analyst@example.com")).toBeInTheDocument();
    expect(await screen.findByText("No key saved.")).toBeInTheDocument();
  });
});

describe("OpenRouterKeySection", () => {
  it("shows only the last 4 characters of a saved key and explains the free-tier limits", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [savedKey] });
    renderWithAuth(<OpenRouterKeySection />);

    expect(await screen.findByText("9f2c")).toBeInTheDocument();
    expect(screen.getByText(/20 requests a minute and 50 a day/)).toBeInTheDocument();
  });

  it("saves a key, clears the input and never echoes the key back", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [] });
    vi.mocked(profileApi.saveOpenRouterKey).mockResolvedValue(savedKey);
    renderWithAuth(<OpenRouterKeySection />);
    const user = userEvent.setup();

    const input = await screen.findByLabelText("API key");
    expect(input).toHaveAttribute("type", "password");
    await user.type(input, "sk-or-v1-secretvalue9f2c");
    await user.click(screen.getByRole("button", { name: "Save key" }));

    await waitFor(() =>
      expect(profileApi.saveOpenRouterKey).toHaveBeenCalledWith({ api_key: "sk-or-v1-secretvalue9f2c" })
    );
    await waitFor(() => expect(input).toHaveValue(""));
    expect(screen.queryByText("sk-or-v1-secretvalue9f2c")).not.toBeInTheDocument();
  });

  it("refuses a key with spaces before sending it", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [] });
    renderWithAuth(<OpenRouterKeySection />);
    const user = userEvent.setup();

    await user.type(await screen.findByLabelText("API key"), "sk-or with space");
    await user.click(screen.getByRole("button", { name: "Save key" }));

    expect(await screen.findByText("API keys can't contain spaces.")).toBeInTheDocument();
    expect(profileApi.saveOpenRouterKey).not.toHaveBeenCalled();
  });

  it("reports the result of testing the saved key", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [savedKey] });
    vi.mocked(profileApi.testOpenRouterKey).mockResolvedValue({
      valid: false,
      message: "OpenRouter rejected the API key.",
    });
    renderWithAuth(<OpenRouterKeySection />);

    await userEvent.setup().click(await screen.findByRole("button", { name: "Test key" }));

    expect(await screen.findByRole("status")).toHaveTextContent("OpenRouter rejected the API key.");
  });

  it("removes the key only after confirmation", async () => {
    vi.mocked(profileApi.getApiKeys).mockResolvedValue({ keys: [savedKey] });
    vi.mocked(profileApi.deleteOpenRouterKey).mockResolvedValue(undefined);
    renderWithAuth(<OpenRouterKeySection />);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Remove key" }));
    expect(profileApi.deleteOpenRouterKey).not.toHaveBeenCalled();
    await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Remove key" }));

    await waitFor(() => expect(profileApi.deleteOpenRouterKey).toHaveBeenCalledTimes(1));
  });
});

describe("PasswordSection", () => {
  async function fill(current: string, next: string, confirm: string) {
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Current password"), current);
    await user.type(screen.getByLabelText("New password"), next);
    await user.type(screen.getByLabelText("Confirm new password"), confirm);
    await user.click(screen.getByRole("button", { name: "Change password" }));
  }

  it("checks length, match and that the new password differs before sending", async () => {
    renderWithAuth(<PasswordSection />);

    await fill("old password value", "old password value", "something else");

    expect(await screen.findByText("Choose a password different from your current one.")).toBeInTheDocument();
    expect(screen.getByText("The passwords don't match.")).toBeInTheDocument();
    expect(profileApi.changePassword).not.toHaveBeenCalled();
  });

  it("changes the password, then ends this session so you sign in again", async () => {
    vi.mocked(profileApi.changePassword).mockResolvedValue(undefined);
    const { auth } = renderWithAuth(<PasswordSection />);

    await fill("old password value", "a brand new passphrase", "a brand new passphrase");

    await waitFor(() =>
      expect(profileApi.changePassword).toHaveBeenCalledWith({
        current_password: "old password value",
        new_password: "a brand new passphrase",
      })
    );
    await waitFor(() => expect(auth.endSession).toHaveBeenCalledWith("password-changed"));
  });

  it("shows the backend's message when the current password is wrong", async () => {
    vi.mocked(profileApi.changePassword).mockRejectedValue(
      new ApiError({ code: "VALIDATION_ERROR", message: "Current password is incorrect.", status: 422 })
    );
    const { auth } = renderWithAuth(<PasswordSection />);

    await fill("wrong password!", "a brand new passphrase", "a brand new passphrase");

    expect(await screen.findByRole("alert")).toHaveTextContent("Current password is incorrect.");
    expect(auth.endSession).not.toHaveBeenCalled();
  });
});
