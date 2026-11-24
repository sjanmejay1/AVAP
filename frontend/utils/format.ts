import { format, formatDistanceToNow } from "date-fns";

const numberFormatter = new Intl.NumberFormat("en-US");

export function formatCount(value: number): string {
  return numberFormatter.format(value);
}

/** Risk scores are always 0.0–10.0 per the Risk Engine contract. */
export function formatRiskScore(value: number): string {
  return value.toFixed(1);
}

export function formatDateTime(value: string | Date): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return format(date, "MMM d, yyyy 'at' HH:mm");
}

export function formatRelativeTime(value: string | Date): string {
  const date = typeof value === "string" ? new Date(value) : value;
  return formatDistanceToNow(date, { addSuffix: true });
}

/** Whole-second scan durations into a compact "1h 5m" form. */
export function formatDuration(totalSeconds: number | null | undefined): string {
  if (totalSeconds === null || totalSeconds === undefined) {
    return "—";
  }

  const seconds = Math.round(totalSeconds);
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const remainingSeconds = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${remainingSeconds}s`;
  }
  return `${remainingSeconds}s`;
}

/** Live elapsed clock: "45s", "12m 04s", "1h 02m 09s". Negative input is 0. */
export function formatElapsed(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  const pad = (value: number) => value.toString().padStart(2, "0");

  if (hours > 0) return `${hours}h ${pad(minutes)}m ${pad(rest)}s`;
  if (minutes > 0) return `${minutes}m ${pad(rest)}s`;
  return `${rest}s`;
}

/** Host uptime from Nmap: "3 days, 4 hours", "2 hours, 5 minutes", "40 seconds". */
export function formatUptime(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const units: [string, number][] = [
    ["day", 86_400],
    ["hour", 3_600],
    ["minute", 60],
    ["second", 1],
  ];
  const parts: string[] = [];
  let remaining = seconds;
  for (const [name, size] of units) {
    const count = Math.floor(remaining / size);
    remaining -= count * size;
    if (count > 0) parts.push(`${count} ${name}${count === 1 ? "" : "s"}`);
    if (parts.length === 2) break;
  }
  return parts.length > 0 ? parts.join(", ") : "0 seconds";
}
