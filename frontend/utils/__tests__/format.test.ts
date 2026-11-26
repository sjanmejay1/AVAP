import { describe, expect, it } from "vitest";

import {
  formatCount,
  formatDuration,
  formatElapsed,
  formatRiskScore,
  formatUptime,
} from "@/utils/format";

describe("formatRiskScore", () => {
  it("always shows one decimal place across the 0.0-10.0 scale", () => {
    expect(formatRiskScore(0)).toBe("0.0");
    expect(formatRiskScore(9.5)).toBe("9.5");
    expect(formatRiskScore(10)).toBe("10.0");
  });
});


describe("formatCount", () => {
  it("groups large counts with locale separators", () => {
    expect(formatCount(1234)).toBe("1,234");
  });

  it("renders zero plainly (a valid empty-database state)", () => {
    expect(formatCount(0)).toBe("0");
  });
});

describe("formatDuration", () => {
  it("renders an em dash for a still-running scan with no duration yet, never a fabricated value", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(undefined)).toBe("—");
  });

  it("renders sub-minute durations in seconds", () => {
    expect(formatDuration(45)).toBe("45s");
  });

  it("renders sub-hour durations in minutes and seconds", () => {
    expect(formatDuration(150)).toBe("2m 30s");
  });

  it("renders hour-scale durations in hours and minutes", () => {
    expect(formatDuration(3725)).toBe("1h 2m");
  });
});

describe("formatElapsed", () => {
  it("ticks in a live-clock form with padded minutes and seconds", () => {
    expect(formatElapsed(45)).toBe("45s");
    expect(formatElapsed(724)).toBe("12m 04s");
    expect(formatElapsed(3729)).toBe("1h 02m 09s");
  });

  it("never shows a negative clock", () => {
    expect(formatElapsed(-5)).toBe("0s");
  });
});

describe("formatUptime", () => {
  it("shows the two largest units in words", () => {
    expect(formatUptime(3 * 86_400 + 4 * 3_600 + 59)).toBe("3 days, 4 hours");
    expect(formatUptime(3_600 + 5 * 60)).toBe("1 hour, 5 minutes");
    expect(formatUptime(40)).toBe("40 seconds");
    expect(formatUptime(0)).toBe("0 seconds");
  });
});
