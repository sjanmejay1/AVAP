import { describe, expect, it } from "vitest";

import {
  riskLevelToSeverityKey,
  severityRatingToKey,
  SEVERITY_META,
} from "@/constants/severity";

describe("riskLevelToSeverityKey", () => {
  it("maps every backend RiskLevel enum value to its severity key", () => {
    expect(riskLevelToSeverityKey("CRITICAL")).toBe("critical");
    expect(riskLevelToSeverityKey("HIGH")).toBe("high");
    expect(riskLevelToSeverityKey("MEDIUM")).toBe("medium");
    expect(riskLevelToSeverityKey("LOW")).toBe("low");
    expect(riskLevelToSeverityKey("INFORMATIONAL")).toBe("informational");
  });
});

describe("severityRatingToKey", () => {
  it("buckets the scanner's 'None' rating as informational, mirroring the backend rule", () => {
    expect(severityRatingToKey("None")).toBe("informational");
  });

  it("maps recognized title-case severity ratings case-insensitively", () => {
    expect(severityRatingToKey("Critical")).toBe("critical");
    expect(severityRatingToKey("High")).toBe("high");
    expect(severityRatingToKey("Medium")).toBe("medium");
    expect(severityRatingToKey("Low")).toBe("low");
  });

  it("buckets any unrecognized value as unknown rather than a known severity", () => {
    expect(severityRatingToKey("Weirdly Rated")).toBe("unknown");
    expect(severityRatingToKey("")).toBe("unknown");
  });
});

describe("SEVERITY_META", () => {
  it("never uses the neutral primary token for a severity color (color is reserved for meaning)", () => {
    for (const meta of Object.values(SEVERITY_META)) {
      expect(meta.fillClass).not.toContain("primary");
      expect(meta.textClass).not.toContain("primary");
    }
  });
});
