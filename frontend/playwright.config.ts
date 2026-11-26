import { defineConfig, devices } from "@playwright/test";

/**
 * Browser tests against a real backend. Start the stack first:
 *   npm run e2e:stack:up   (backend on :18100, demo targets on an internal network)
 *   npm run test:e2e
 *   npm run e2e:stack:down
 * Playwright starts the Next.js dev server on :3100 itself, pointed at the
 * e2e backend, so it never touches a developer's own backend or .env.local.
 */
export const E2E_API_URL = "http://localhost:18100/api/v1";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.ts",
  // Scans share the backend's concurrent-scan cap; run one file at a time.
  workers: 1,
  fullyParallel: false,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  use: {
    baseURL: "http://localhost:3100",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] }, testIgnore: "**/mobile.spec.ts" },
    { name: "mobile", use: { ...devices["Pixel 7"] }, testMatch: "**/mobile.spec.ts" },
  ],
  webServer: {
    command: "npx next dev -p 3100",
    url: "http://localhost:3100/login",
    reuseExistingServer: false,
    timeout: 180_000,
    env: { NEXT_PUBLIC_API_BASE_URL: "http://localhost:18100" },
  },
});
