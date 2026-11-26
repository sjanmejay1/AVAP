import type { TargetType } from "@/features/targets/types/target";

/**
 * Browser-side mirror of the backend's target rules
 * (backend/app/core/security.py and TargetService._determine_target_type),
 * used for instant feedback only. The backend stays the authority: it
 * re-validates every value, and its CIDR limit is configurable
 * (MIN_CIDR_PREFIX_LENGTH), so a 422 from the server is still shown on the
 * field.
 *
 * Order matches the backend: IPv4 address, then IPv4 CIDR, then hostname.
 */

/** Backend default for MIN_CIDR_PREFIX_LENGTH. */
export const MIN_CIDR_PREFIX_LENGTH = 16;
const HOSTNAME_MAX_LENGTH = 253;
const LABEL_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
const OCTET_PATTERN = /^(0|[1-9][0-9]{0,2})$/;

export type TargetClassification =
  | { ok: true; type: TargetType; addressCount: number | null }
  | { ok: false; message: string };

/** Python's IPv4Address rules: four decimal octets 0–255, no leading zeros. */
function parseIpv4(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!OCTET_PATTERN.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    result = result * 256 + octet;
  }
  return result;
}

const isLoopback = (address: number) => Math.floor(address / 2 ** 24) === 127;
const isMulticast = (address: number) => {
  const first = Math.floor(address / 2 ** 24);
  return first >= 224 && first <= 239;
};

/** "/24", or a dotted netmask ("/255.255.255.0") or hostmask ("/0.0.0.255"). */
function parsePrefix(mask: string): number | null {
  if (/^[0-9]+$/.test(mask)) {
    const prefix = Number(mask);
    return prefix <= 32 ? prefix : null;
  }
  const dotted = parseIpv4(mask);
  if (dotted === null) return null;
  const bits = dotted.toString(2).padStart(32, "0");
  if (/^1*0*$/.test(bits)) return bits.indexOf("0") === -1 ? 32 : bits.indexOf("0");
  if (/^0*1*$/.test(bits)) return bits.indexOf("1") === -1 ? 32 : bits.indexOf("1");
  return null;
}

function classifyCidr(value: string): TargetClassification | null {
  const slash = value.indexOf("/");
  if (slash === -1 || value.indexOf("/", slash + 1) !== -1) return null;
  const address = parseIpv4(value.slice(0, slash));
  const prefix = parsePrefix(value.slice(slash + 1));
  if (address === null || prefix === null) return null;

  const size = 2 ** (32 - prefix);
  const network = Math.floor(address / size) * size;
  const broadcast = network + size - 1;
  if (
    (isLoopback(network) && isLoopback(broadcast)) ||
    (isMulticast(network) && isMulticast(broadcast)) ||
    (prefix === 32 && network === 0)
  ) {
    return {
      ok: false,
      message: "Loopback, multicast and unspecified ranges can't be scanned.",
    };
  }
  if (prefix < MIN_CIDR_PREFIX_LENGTH) {
    return {
      ok: false,
      message: `This range is too broad. The widest allowed range is /${MIN_CIDR_PREFIX_LENGTH} (65,536 addresses).`,
    };
  }
  return { ok: true, type: "CIDR", addressCount: size };
}

function isValidHostname(value: string): boolean {
  if (value.length === 0 || value.length > HOSTNAME_MAX_LENGTH) return false;
  const labels = (value.endsWith(".") ? value.slice(0, -1) : value).split(".");
  if (!labels.every((label) => LABEL_PATTERN.test(label))) return false;
  // All-numeric multi-label values are attempted IP addresses, never hostnames.
  return !(labels.length > 1 && labels.every((label) => /^[0-9]+$/.test(label)));
}

/** "localhost" and "*.localhost" always resolve to loopback (RFC 6761). */
function isLoopbackName(value: string): boolean {
  const labels = (value.endsWith(".") ? value.slice(0, -1) : value).split(".");
  return labels[labels.length - 1] === "localhost";
}

export function classifyTarget(raw: string): TargetClassification {
  const value = raw.trim().toLowerCase();

  const address = parseIpv4(value);
  if (address !== null) {
    if (isLoopback(address) || isMulticast(address) || address === 0) {
      return {
        ok: false,
        message: "Loopback, multicast and unspecified addresses can't be scanned.",
      };
    }
    return { ok: true, type: "IPV4", addressCount: 1 };
  }

  const cidr = classifyCidr(value);
  if (cidr) return cidr;

  if (isLoopbackName(value)) {
    return { ok: false, message: "Loopback names such as localhost can't be scanned." };
  }

  if (isValidHostname(value)) return { ok: true, type: "HOSTNAME", addressCount: null };

  return {
    ok: false,
    message: "Enter an IPv4 address (192.168.1.10), a CIDR range (10.0.0.0/24) or a hostname (example.com).",
  };
}

/** Short description of what was recognised, shown under the field as you type. */
export function describeClassification(result: TargetClassification): string | null {
  if (!result.ok) return null;
  if (result.type === "IPV4") return "IPv4 address, 1 host.";
  if (result.type === "HOSTNAME") return "Hostname. It's resolved when the scan runs.";
  const count = result.addressCount ?? 0;
  return `CIDR range, ${count.toLocaleString("en-US")} addresses.`;
}
