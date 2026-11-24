import { expect, type APIRequestContext, type Page } from "@playwright/test";
import { randomBytes } from "node:crypto";

import { E2E_API_URL } from "../playwright.config";

/** A unique, throwaway account per test; the e2e stack is deleted afterwards. */
export interface TestUser {
  email: string;
  password: string;
}

export function newUser(): TestUser {
  const id = randomBytes(6).toString("hex");
  return { email: `e2e-${id}@example.test`, password: `pw-${randomBytes(12).toString("hex")}` };
}

export async function registerInBrowser(page: Page, user: TestUser): Promise<void> {
  await page.goto("/register");
  await page.getByLabel("Email").fill(user.email);
  await page.getByLabel("Password", { exact: true }).fill(user.password);
  await page.getByLabel("Confirm password").fill(user.password);
  await page.getByRole("button", { name: "Create account" }).click();
  await expect(page).toHaveURL(/\/targets$/);
}

export async function signInInBrowser(page: Page, user: TestUser): Promise<void> {
  await page.getByLabel("Email").fill(user.email);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

export async function signOutInBrowser(page: Page, user: TestUser): Promise<void> {
  await page.getByRole("button", { name: user.email }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
}

/** Registers through the API and returns a bearer token, for fast setup. */
export async function registerViaApi(request: APIRequestContext, user: TestUser): Promise<string> {
  const response = await request.post(`${E2E_API_URL}/auth/register`, { data: user });
  expect(response.status(), await response.text()).toBe(201);
  return (await response.json()).data.access_token as string;
}

export async function createTargetViaApi(
  request: APIRequestContext,
  token: string,
  target: string
): Promise<string> {
  const response = await request.post(`${E2E_API_URL}/targets`, {
    data: { target },
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(response.status(), await response.text()).toBe(201);
  return (await response.json()).data.id as string;
}

/** Adds a target through the UI and opens its page. */
export async function addTargetInBrowser(page: Page, value: string): Promise<void> {
  await page.goto("/targets");
  await page.getByRole("button", { name: "Add target" }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Target").fill(value);
  await dialog.getByRole("button", { name: "Add target" }).click();
  await expect(dialog).toBeHidden();
  await page.getByRole("link", { name: value, exact: true }).click();
  await expect(page.getByRole("heading", { level: 1, name: value })).toBeVisible();
}
