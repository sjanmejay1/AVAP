import { expect, test } from "@playwright/test";

import { newUser, registerInBrowser, signInInBrowser, signOutInBrowser } from "./support";

test.describe("sign-in and session", () => {
  test("an anonymous visitor is sent to sign in, carrying where they were going", async ({ page }) => {
    await page.goto("/targets");
    await expect(page).toHaveURL(/\/login\?next=%2Ftargets$/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  });

  test("register, survive a reload, sign out, then sign back in", async ({ page }) => {
    const user = newUser();
    await registerInBrowser(page, user);
    await expect(page.getByText("No targets yet")).toBeVisible();

    // The access token is memory-only; the refresh cookie restores the session.
    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: "Targets" })).toBeVisible();

    await signOutInBrowser(page, user);
    await page.goto("/targets");
    await expect(page).toHaveURL(/\/login\?next=/);

    await signInInBrowser(page, user);
    await expect(page).toHaveURL(/\/targets$/);
  });

  test("a wrong password is refused with the backend's message", async ({ page }) => {
    const user = newUser();
    await registerInBrowser(page, user);
    await signOutInBrowser(page, user);

    await signInInBrowser(page, { ...user, password: "not-the-right-password" });

    await expect(page.getByRole("alert")).toBeVisible();
    await expect(page).toHaveURL(/\/login/);
  });

  test("registration checks length and matching passwords before sending", async ({ page }) => {
    await page.goto("/register");
    await page.getByLabel("Email").fill(newUser().email);
    await page.getByLabel("Password", { exact: true }).fill("short");
    await page.getByLabel("Confirm password").fill("different");
    await page.getByRole("button", { name: "Create account" }).click();

    await expect(page.getByText("Use at least 12 characters.")).toBeVisible();
    await expect(page.getByText("The passwords don't match.")).toBeVisible();
    await expect(page).toHaveURL(/\/register$/);
  });
});
