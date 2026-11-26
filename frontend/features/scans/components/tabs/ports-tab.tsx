"use client";

import { ChevronRight, Network } from "lucide-react";
import { Fragment, useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { useScanHosts } from "@/features/scans/hooks/use-scans";
import type { ScanHostResponse, ServiceDetails } from "@/features/scans/types/scan";
import { cn } from "@/lib/utils";

export interface PortRow {
  key: string;
  ipv4: string;
  service: ServiceDetails;
}

/** Every service across every host, in a fixed order: host, then port. */
export function flattenPorts(hosts: ScanHostResponse[]): PortRow[] {
  const rows = hosts.flatMap((host) =>
    host.details.services.map((service) => ({
      key: `${host.asset_id}-${service.protocol}-${service.port}`,
      ipv4: host.ipv4,
      service,
    }))
  );
  const ipKey = (ip: string) =>
    ip.split(".").reduce((total, octet) => total * 256 + Number(octet), 0);
  return rows.sort(
    (a, b) => ipKey(a.ipv4) - ipKey(b.ipv4) || a.service.port - b.service.port
  );
}

function stateClass(state: string): string {
  if (state === "open") return "text-success";
  if (state.includes("filtered")) return "text-warning";
  return "text-muted-foreground";
}

function ScriptOutput({ scripts }: { scripts: Record<string, string> }) {
  return (
    <div className="flex flex-col gap-3">
      {Object.entries(scripts).map(([id, output]) => (
        <div key={id} className="flex flex-col gap-1.5">
          <p className="font-mono text-xs font-semibold">{id}</p>
          <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap">
            {output}
          </pre>
        </div>
      ))}
    </div>
  );
}

export function PortsTab({ scanId }: { scanId: string }) {
  const { data, isPending, isError, refetch } = useScanHosts(scanId);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  if (isPending) return <ListRowsSkeleton rows={5} />;
  if (isError) return <ErrorState title="Ports couldn't be loaded" onRetry={() => refetch()} />;

  const rows = flattenPorts(data.hosts);
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No ports to show"
        description="Nmap reported no open or filtered ports on the hosts it reached."
      />
    );
  }

  function toggle(key: string) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full min-w-[640px] text-sm">
        <caption className="sr-only">Ports and services, ordered by host then port</caption>
        <thead>
          <tr className="border-b border-border text-left text-xs text-muted-foreground">
            <th scope="col" className="w-10 px-3 py-2.5 font-medium">
              <span className="sr-only">Script output</span>
            </th>
            <th scope="col" className="px-3 py-2.5 font-medium">Host</th>
            <th scope="col" className="px-3 py-2.5 font-medium">Port</th>
            <th scope="col" className="px-3 py-2.5 font-medium">State</th>
            <th scope="col" className="px-3 py-2.5 font-medium">Service</th>
            <th scope="col" className="px-3 py-2.5 font-medium">Product and version</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rows.map((row) => {
            const scriptCount = Object.keys(row.service.scripts).length;
            const isOpen = expanded.has(row.key);
            const product = [row.service.product, row.service.version].filter(Boolean).join(" ");
            return (
              <Fragment key={row.key}>
                <tr className={cn(isOpen && "bg-muted")}>
                  <td className="px-3 py-2">
                    {scriptCount > 0 && (
                      <button
                        type="button"
                        onClick={() => toggle(row.key)}
                        aria-expanded={isOpen}
                        aria-controls={isOpen ? `scripts-${row.key}` : undefined}
                        aria-label={`${isOpen ? "Hide" : "Show"} ${scriptCount} script ${scriptCount === 1 ? "result" : "results"} for port ${row.service.port}`}
                        className="flex size-8 cursor-pointer items-center justify-center rounded-md hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                      >
                        <ChevronRight
                          className={cn("size-4 transition-transform", isOpen && "rotate-90")}
                          aria-hidden="true"
                        />
                      </button>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono whitespace-nowrap">{row.ipv4}</td>
                  <td className="px-3 py-2 font-mono whitespace-nowrap">
                    {row.service.port}/{row.service.protocol}
                  </td>
                  <td className={cn("px-3 py-2 whitespace-nowrap", stateClass(row.service.state))}>
                    {row.service.state}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">{row.service.service_name || "—"}</td>
                  <td className="px-3 py-2">
                    {product || <span className="text-muted-foreground">—</span>}
                    {scriptCount > 0 && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {scriptCount} {scriptCount === 1 ? "script" : "scripts"}
                      </span>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr id={`scripts-${row.key}`} className="bg-muted/40">
                    <td />
                    <td colSpan={5} className="px-3 pt-1 pb-4">
                      <ScriptOutput scripts={row.service.scripts} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
