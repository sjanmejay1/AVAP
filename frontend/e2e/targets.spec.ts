import { expect, test } from "@playwright/test";

import { newUser, registerInBrowser } from "./support";

test.describe("targets", () => {
  test.beforeEach(async ({ page }) => {
    await registerInBrowser(page, newUser());
  });

  test("the add dialog explains what it recognised and refuses special addresses", async ({ page }) => {
    await page.getByRole("button", { name: "Add target" }).first().click();
    const dialog = page.getByRole("dialog");
    const field = dialog.getByLabel("Target");

    await field.fill("10.20.0.0/24");
    await expect(dialog.getByText("CIDR range, 256 addresses.")).toBeVisible();

    await field.fill("127.0.0.1");
    await dialog.getByRole("button", { name: "Add target" }).click();
    await expect(dialog.getByRole("alert")).toHaveText(/Loopback, multicast and unspecified/);

    await field.fill("10.0.0.0/8");
    await dialog.getByRole("button", { name: "Add target" }).click();
    await expect(dialog.getByRole("alert")).toHaveText(/too broad/);
  });

  test("add, search and delete targets", async ({ page }) => {
    for (const value of ["demo-web", "demo-cache"]) {
      await page.getByRole("button", { name: "Add target" }).first().click();
      const dialog = page.getByRole("dialog");
      await dialog.getByLabel("Target").fill(value);
      await dialog.getByRole("button", { name: "Add target" }).click();
      await expect(dialog).toBeHidden();
    }
    await expect(page.getByRole("link", { name: "demo-web", exact: true })).toBeVisible();
    await expect(page.getByText("2 targets")).toBeVisible();

    await page.getByRole("searchbox", { name: "Search targets" }).fill("cache");
    await expect(page.getByRole("link", { name: "demo-web", exact: true })).toBeHidden();
    await expect(page.getByRole("link", { name: "demo-cache", exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Actions for demo-cache" }).click();
    await page.getByRole("menuitem", { name: "Delete" }).click();
    await page.getByRole("alertdialog").getByRole("button", { name: "Delete target" }).click();
    await expect(page.getByRole("link", { name: "demo-cache", exact: true })).toBeHidden();
  });

  test("a duplicate target is refused by the backend on the field", async ({ page }) => {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await page.getByRole("button", { name: "Add target" }).first().click();
      const dialog = page.getByRole("dialog");
      await dialog.getByLabel("Target").fill("demo-web");
      await dialog.getByRole("button", { name: "Add target" }).click();
      if (attempt === 0) await expect(dialog).toBeHidden();
      else await expect(dialog.getByRole("alert")).toBeVisible();
    }
  });
});
