import { describe, expect, it } from "vitest";

import { DEFAULT_SIGNED_IN_PATH, safeNextPath } from "@/features/auth/lib/safe-next";

describe("safeNextPath", () => {
  it("keeps same-origin paths with their query and hash", () => {
    expect(safeNextPath("/scans/abc?tab=hosts")).toBe("/scans/abc?tab=hosts");
    expect(safeNextPath("/targets/1#history")).toBe("/targets/1#history");
  });

  it.each([
    ["missing", null],
    ["empty", ""],
    ["absolute URL", "https://evil.example/steal"],
    ["protocol-relative", "//evil.example"],
    ["backslash trick", "/\\evil.example"],
    ["javascript scheme", "javascript:alert(1)"],
    ["relative without slash", "targets"],
    ["the login page itself", "/login"],
    ["the register page itself", "/register?next=/x"],
  ])("falls back to the targets list for %s", (_label, value) => {
    expect(safeNextPath(value)).toBe(DEFAULT_SIGNED_IN_PATH);
  });
});
