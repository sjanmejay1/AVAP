import { readFile } from "node:fs/promises";

import { expect, test, type Page } from "@playwright/test";

import { addTargetInBrowser, newUser, registerInBrowser } from "./support";

/** A quick scan of one container takes well under a minute; allow for slow machines. */
const SCAN_TIMEOUT_MS = 180_000;

async function startScan(page: Page, profile: "Quick" | "Full") {
  await page.getByRole("button", { name: "New scan" }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("radio", { name: `${profile} scan` }).click();
  await dialog.getByRole("button", { name: `Start ${profile.toLowerCase()} scan` }).click();
  await expect(page).toHaveURL(/\/scans\/[0-9a-f-]+$/);
}

async function readDownload(page: Page, trigger: () => Promise<void>) {
  const [download] = await Promise.all([page.waitForEvent("download"), trigger()]);
  const path = await download.path();
  return { name: download.suggestedFilename(), body: await readFile(path) };
}

test.describe("scanning a demo target", () => {
  test("quick scan: live status, every tab, downloads and history", async ({ page }) => {
    test.setTimeout(SCAN_TIMEOUT_MS + 120_000);
    await registerInBrowser(page, newUser());
    await addTargetInBrowser(page, "demo-web");
    await startScan(page, "Quick");

    // Live phase, then the page updates by itself when Nmap finishes.
    await expect(page.getByRole("heading", { level: 1, name: "demo-web" })).toBeVisible();
    await expect(page.getByText("Completed").first()).toBeVisible({ timeout: SCAN_TIMEOUT_MS });
    await expect(page.getByRole("region", { name: "Scan progress" })).toBeHidden();

    // Overview: a score and the counts.
    await expect(page.getByText("out of 10")).toBeVisible();
    await expect(page.getByText("Open ports")).toBeVisible();

    // Hosts.
    await page.getByRole("tab", { name: "Hosts" }).click();
    await expect(page).toHaveURL(/tab=hosts/);
    await expect(page.getByRole("region", { name: /^Host / })).toBeVisible();

    // Ports & services: nginx answers on 80.
    await page.getByRole("tab", { name: "Ports & services" }).click();
    const portRow = page.getByRole("row").filter({ hasText: "80/tcp" });
    await expect(portRow).toContainText("open");
    await expect(portRow).toContainText(/nginx/i);

    // The tab survives a reload (deep link).
    await page.reload();
    await expect(page.getByRole("tab", { name: "Ports & services" })).toHaveAttribute("aria-selected", "true");

    // Findings: quick scans run no vulnerability scripts.
    await page.getByRole("tab", { name: "Findings" }).click();
    await expect(page.getByText("Quick scans don't run vulnerability scripts.", { exact: false })).toBeVisible();

    // AI advice without a key: advisory label and a pointer to the profile.
    await page.getByRole("tab", { name: "AI advice" }).click();
    await expect(page.getByText("AI advisory, unverified.")).toBeVisible();
    await page.getByRole("button", { name: "Run AI analysis" }).click();
    const aiError = page.getByRole("alert").filter({ hasText: "OpenRouter key" });
    await expect(aiError.getByRole("link", { name: "profile" })).toHaveAttribute("href", "/profile");

    // Raw Nmap XML.
    await page.getByRole("tab", { name: "Raw output" }).click();
    const xml = await readDownload(page, () =>
      page.getByRole("button", { name: "Download Nmap XML" }).click()
    );
    expect(xml.name).toMatch(/^nmap-[0-9a-f-]+\.xml$/);
    expect(xml.body.toString("utf8")).toContain("<nmaprun");

    // PDF report: generated on first download.
    const pdf = await readDownload(page, () => page.getByRole("button", { name: "Download PDF" }).click());
    expect(pdf.name).toMatch(/^avap-report-[0-9a-f-]+\.pdf$/);
    expect(pdf.body.subarray(0, 5).toString("latin1")).toBe("%PDF-");

    // The target's history lists the scan as completed and scored.
    await page.getByRole("link", { name: "demo-web" }).first().click();
    const history = page.getByRole("listitem").filter({ hasText: "Quick" });
    await expect(history.getByText("Completed")).toBeVisible();
    await expect(history.getByText("/10")).toBeVisible();
  });

  test("a running scan can be cancelled after confirmation", async ({ page }) => {
    test.setTimeout(120_000);
    await registerInBrowser(page, newUser());
    await addTargetInBrowser(page, "demo-cache");
    await startScan(page, "Full");

    const band = page.getByRole("region", { name: "Scan progress" });
    await expect(band).toBeVisible();
    await band.getByRole("button", { name: "Cancel scan" }).click();
    await page.getByRole("alertdialog").getByRole("button", { name: "Cancel scan" }).click();

    await expect(page.getByText("Cancelled").first()).toBeVisible({ timeout: 60_000 });
    await expect(band).toBeHidden();
    await expect(page.getByRole("button", { name: "Download PDF" })).toBeDisabled();
  });
});
