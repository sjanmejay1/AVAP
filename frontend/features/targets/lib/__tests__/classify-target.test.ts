import { describe, expect, it } from "vitest";

import {
  classifyTarget,
  describeClassification,
} from "@/features/targets/lib/classify-target";

/** Each case mirrors a rule in backend/app/core/security.py. */
describe("classifyTarget", () => {
  it.each([
    ["192.168.1.10", "IPV4", 1],
    ["  10.0.0.5  ", "IPV4", 1],
    ["8.8.8.8", "IPV4", 1],
    ["10.0.0.0/24", "CIDR", 256],
    ["10.0.0.5/24", "CIDR", 256],
    ["172.16.0.0/16", "CIDR", 65536],
    ["192.168.1.7/32", "CIDR", 1],
    ["10.0.0.0/255.255.255.0", "CIDR", 256],
    ["scanme.nmap.org", "HOSTNAME", null],
    ["Example.COM.", "HOSTNAME", null],
    ["fileserver", "HOSTNAME", null],
    ["a-b.example", "HOSTNAME", null],
  ])("accepts %s as %s", (value, type, addressCount) => {
    expect(classifyTarget(value)).toEqual({ ok: true, type, addressCount });
  });

  it.each([
    ["127.0.0.1", /Loopback/],
    ["224.0.0.1", /multicast/],
    ["0.0.0.0", /unspecified/],
    ["127.0.0.0/8", /too broad|Loopback/],
    ["127.0.0.0/24", /Loopback/],
    ["239.1.0.0/16", /multicast/],
    ["0.0.0.0/32", /unspecified/],
  ])("refuses the special address %s", (value, message) => {
    const result = classifyTarget(value);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toMatch(message);
  });

  it("refuses CIDR ranges broader than /16, the backend default", () => {
    const result = classifyTarget("10.0.0.0/15");
    expect(result).toEqual({
      ok: false,
      message: "This range is too broad. The widest allowed range is /16 (65,536 addresses).",
    });
  });

  it.each([
    "999.999.999.999",
    "1.2.3",
    "1.2.3.4.5",
    "01.2.3.4",
    "10.0.0.0/33",
    "10.0.0.0/255.0.255.0",
    "10.0.0.0/24/1",
    "-bad.example",
    "bad-.example",
    "under_score.example",
    "two..dots",
    "has space.example",
    "a".repeat(64) + ".example",
    "",
  ])("refuses the malformed value %j", (value) => {
    expect(classifyTarget(value).ok).toBe(false);
  });

  it("refuses hostnames longer than 253 characters", () => {
    const long = Array.from({ length: 5 }, () => "a".repeat(60)).join(".");
    expect(long.length).toBeGreaterThan(253);
    expect(classifyTarget(long).ok).toBe(false);
  });
});

describe("describeClassification", () => {
  it("describes what was recognised in plain words", () => {
    expect(describeClassification(classifyTarget("10.0.0.1"))).toBe("IPv4 address, 1 host.");
    expect(describeClassification(classifyTarget("10.0.0.0/16"))).toBe(
      "CIDR range, 65,536 addresses."
    );
    expect(describeClassification(classifyTarget("example.com"))).toMatch(/^Hostname/);
    expect(describeClassification(classifyTarget("nope nope"))).toBeNull();
  });
});
