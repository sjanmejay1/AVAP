import { expect, test } from "@playwright/test";

import { newUser, registerInBrowser, signInInBrowser } from "./support";

test.describe("profile", () => {
  test("an OpenRouter key is saved write-only and can be removed", async ({ page }) => {
    await registerInBrowser(page, newUser());
    await page.goto("/profile");
    await expect(page.getByText("No key saved.")).toBeVisible();

    // A fake key: saving never calls OpenRouter, and "Test key" is not used here.
    const fakeKey = "sk-or-v1-e2e-not-a-real-key-7a3f";
    const input = page.getByLabel("API key");
    await input.fill(fakeKey);
    await page.getByRole("button", { name: "Save key" }).click();

    await expect(page.getByText("7a3f", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Replace key")).toHaveValue("");
    await expect(page.getByText(fakeKey)).toHaveCount(0);

    await page.getByRole("button", { name: "Remove key" }).click();
    await page.getByRole("alertdialog").getByRole("button", { name: "Remove key" }).click();
    await expect(page.getByText("No key saved.")).toBeVisible();
  });

  test("changing the password signs you out; the new password works", async ({ page }) => {
    const user = newUser();
    await registerInBrowser(page, user);
    await page.goto("/profile");

    const newPassword = `${user.password}-changed`;
    await page.getByLabel("Current password").fill(user.password);
    await page.getByLabel("New password", { exact: true }).fill(newPassword);
    await page.getByLabel("Confirm new password").fill(newPassword);
    await page.getByRole("button", { name: "Change password" }).click();

    await expect(page).toHaveURL(/\/login\?reason=password-changed$/);
    await expect(page.getByRole("status")).toHaveText(/Password changed/);

    await signInInBrowser(page, { ...user, password: newPassword });
    await expect(page).toHaveURL(/\/targets$/);
  });
});
