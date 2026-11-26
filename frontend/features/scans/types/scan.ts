/**
 * Mirrors backend/app/schemas/scan.py and scan_host.py exactly (field
 * names, casing, nullability). Wire-contract types, not UI view models.
 */

export type ScanStatus =
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED";

/** app.core.enums.ScanProfile. Stored on the scan as `scan_type`. */
export type ScanProfile = "QUICK" | "FULL";

export interface ScanResponse {
  scan_id: string;
  target_id: string;
  status: ScanStatus;
  /** "QUICK" or "FULL" for new scans; older scans may hold other values. */
  scan_type: string;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  execution_duration: number | null;
  failure_reason: string | null;
  stdout_log: string | null;
  stderr_log: string | null;
}

export interface ScanListResponse {
  scans: ScanResponse[];
  total: number;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: ScanStatus;
  updated_at: string;
}

export interface CreateScanRequest {
  target_id: string;
  scan_profile: ScanProfile;
}

export interface AIAnalysisResponse {
  findings_created: number;
}

export interface ServiceDetails {
  port: number;
  protocol: string;
  state: string;
  service_name: string;
  product: string | null;
  version: string | null;
  cpes: string[];
  /** NSE script id → raw script output. */
  scripts: Record<string, string>;
}

export interface OsMatch {
  name: string;
  accuracy: number | null;
  cpes: string[];
}

export interface TracerouteHop {
  ttl: string;
  ipaddr: string | null;
  rtt: string | null;
  host: string | null;
}

export interface ScanHostDetails {
  mac_address: string | null;
  mac_vendor: string | null;
  hostnames: string[];
  os_matches: OsMatch[];
  uptime_seconds: number | null;
  last_boot: string | null;
  network_distance: number | null;
  traceroute: TracerouteHop[];
  closed_port_count: number;
  filtered_port_count: number;
  services: ServiceDetails[];
}

export interface ScanHostResponse {
  asset_id: string;
  ipv4: string;
  hostname: string | null;
  operating_system: string | null;
  details: ScanHostDetails;
}

export interface ScanHostListResponse {
  hosts: ScanHostResponse[];
  total: number;
}
