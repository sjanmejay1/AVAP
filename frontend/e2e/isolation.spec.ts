import { expect, test } from "@playwright/test";

import { E2E_API_URL } from "../playwright.config";
import { createTargetViaApi, newUser, registerInBrowser, registerViaApi } from "./support";

test("one user can never see another user's targets", async ({ page, request }) => {
  const owner = newUser();
  const ownerToken = await registerViaApi(request, owner);
  const targetId = await createTargetViaApi(request, ownerToken, "demo-web");

  const other = newUser();
  await registerInBrowser(page, other);

  // Not in the list, and the direct URL reads as "doesn't exist".
  await expect(page.getByText("No targets yet")).toBeVisible();
  await page.goto(`/targets/${targetId}`);
  await expect(page.getByText("This target doesn't exist")).toBeVisible();

  // The API answers 404, not 403, so ids can't be probed.
  const otherToken = await registerViaApi(request, newUser());
  const response = await request.get(`${E2E_API_URL}/targets/${targetId}`, {
    headers: { Authorization: `Bearer ${otherToken}` },
  });
  expect(response.status()).toBe(404);

  // The owner still sees it.
  const own = await request.get(`${E2E_API_URL}/targets/${targetId}`, {
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  expect(own.status()).toBe(200);
});
