import { expect, test, type Page } from "@playwright/test";

import { addTargetInBrowser, newUser, registerInBrowser } from "./support";

async function expectNoSidewaysScroll(page: Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  expect(overflow).toBeLessThanOrEqual(0);
}

test("pages fit a phone screen without sideways scrolling", async ({ page }) => {
  await page.goto("/login");
  await expectNoSidewaysScroll(page);

  await registerInBrowser(page, newUser());
  await expectNoSidewaysScroll(page);

  await addTargetInBrowser(page, "demo-web");
  await expectNoSidewaysScroll(page);
  // The breadcrumb collapses to a back link on small screens.
  await expect(page.getByRole("link", { name: "Back to Targets" })).toBeVisible();

  await page.goto("/profile");
  await expectNoSidewaysScroll(page);
});
