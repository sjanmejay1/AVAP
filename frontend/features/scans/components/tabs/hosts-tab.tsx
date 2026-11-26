"use client";

import { Server } from "lucide-react";

import { CopyableValue } from "@/components/shared/copyable-value";
import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { useScanHosts } from "@/features/scans/hooks/use-scans";
import type { OsMatch, ScanHostResponse, TracerouteHop } from "@/features/scans/types/scan";
import { formatCount, formatUptime } from "@/utils/format";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-sm break-words">{children}</dd>
    </div>
  );
}

function OsMatches({ matches }: { matches: OsMatch[] }) {
  if (matches.length === 0) {
    return <p className="text-sm text-muted-foreground">No OS match. Quick and full scans both try; it needs at least one open and one closed port.</p>;
  }
  return (
    <ul className="flex flex-col gap-2.5">
      {matches.slice(0, 5).map((match, index) => (
        <li key={`${match.name}-${index}`} className="flex flex-col gap-1">
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 break-words">{match.name}</span>
            <span className="shrink-0 tabular-nums text-muted-foreground">
              {match.accuracy === null ? "Accuracy unknown" : `${match.accuracy}%`}
            </span>
          </div>
          {match.accuracy !== null && (
            <div className="h-1 w-full rounded-full bg-muted" aria-hidden="true">
              <div
                className="h-1 rounded-full bg-foreground"
                style={{ width: `${Math.min(100, Math.max(0, match.accuracy))}%` }}
              />
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Hops are a real sequence (TTL order), so they are numbered. */
function Traceroute({ hops }: { hops: TracerouteHop[] }) {
  if (hops.length === 0) {
    return <p className="text-sm text-muted-foreground">No traceroute. Full scans record one.</p>;
  }
  return (
    <ol className="flex flex-col divide-y divide-border rounded-md border border-border">
      {hops.map((hop, index) => (
        <li
          key={`${hop.ttl}-${index}`}
          className="grid grid-cols-[2.5rem_minmax(0,1fr)_auto] items-center gap-3 px-3 py-2 text-sm"
        >
          <span className="tabular-nums text-muted-foreground">{hop.ttl}</span>
          <span className="min-w-0 truncate font-mono">
            {hop.ipaddr ?? "*"}
            {hop.host && <span className="ml-2 font-sans text-muted-foreground">{hop.host}</span>}
          </span>
          <span className="tabular-nums text-muted-foreground">{hop.rtt ? `${hop.rtt} ms` : "—"}</span>
        </li>
      ))}
    </ol>
  );
}

function HostSection({ host }: { host: ScanHostResponse }) {
  const { details } = host;
  const open = details.services.filter((service) => service.state === "open").length;
  const names = [host.hostname, ...details.hostnames].filter(
    (name, index, all): name is string => Boolean(name) && all.indexOf(name) === index
  );

  return (
    <section
      aria-label={`Host ${host.ipv4}`}
      className="flex flex-col gap-5 rounded-lg border border-border p-5"
    >
      <header className="flex flex-wrap items-baseline justify-between gap-3">
        <div className="flex flex-col gap-1">
          <CopyableValue value={host.ipv4} label="IP address" className="text-h3 font-semibold" />
          {names.length > 0 && <p className="text-sm text-muted-foreground">{names.join(", ")}</p>}
        </div>
        <p className="text-sm text-muted-foreground">
          {formatCount(open)} open, {formatCount(details.closed_port_count)} closed,{" "}
          {formatCount(details.filtered_port_count)} filtered
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="flex flex-col gap-3">
          <h3 className="text-title">Operating system</h3>
          <OsMatches matches={details.os_matches} />
        </div>
        <dl className="grid grid-cols-2 content-start gap-x-6 gap-y-4">
          <Field label="MAC address">
            {details.mac_address ? (
              <span className="font-mono">{details.mac_address}</span>
            ) : (
              <span className="text-muted-foreground">Not seen (only on the local network)</span>
            )}
          </Field>
          <Field label="Vendor">{details.mac_vendor ?? "—"}</Field>
          <Field label="Uptime">
            {details.uptime_seconds !== null ? formatUptime(details.uptime_seconds) : "—"}
          </Field>
          <Field label="Last boot">{details.last_boot ?? "—"}</Field>
          <Field label="Network distance">
            {details.network_distance !== null
              ? `${details.network_distance} ${details.network_distance === 1 ? "hop" : "hops"}`
              : "—"}
          </Field>
        </dl>
      </div>

      <div className="flex flex-col gap-3">
        <h3 className="text-title">Traceroute</h3>
        <Traceroute hops={details.traceroute} />
      </div>
    </section>
  );
}

export function HostsTab({ scanId }: { scanId: string }) {
  const { data, isPending, isError, refetch } = useScanHosts(scanId);

  if (isPending) return <ListRowsSkeleton rows={3} />;
  if (isError) return <ErrorState title="Hosts couldn't be loaded" onRetry={() => refetch()} />;
  if (data.hosts.length === 0) {
    return (
      <EmptyState
        icon={Server}
        title="No hosts were up"
        description="Nmap found no responding hosts. Check the target is online and reachable from the scanner."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {data.hosts.map((host) => (
        <HostSection key={host.asset_id} host={host} />
      ))}
    </div>
  );
}
