"use client";

import { Crosshair, Search } from "lucide-react";
import { useMemo, useState } from "react";

import { EmptyState } from "@/components/shared/empty-state";
import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { ListRowsSkeleton } from "@/components/shared/skeletons";
import { Input } from "@/components/ui/input";
import { CreateTargetDialog } from "@/features/targets/components/create-target-dialog";
import { DeleteTargetDialog } from "@/features/targets/components/delete-target-dialog";
import { TargetRow } from "@/features/targets/components/target-row";
import { useTargets } from "@/features/targets/hooks/use-targets";
import type { TargetResponse } from "@/features/targets/types/target";
import { useDebouncedValue } from "@/hooks/use-debounced-value";
import { formatCount } from "@/utils/format";

/** The backend's maximum page size for GET /targets. */
const TARGET_LIMIT = 200;

export function filterTargets(targets: TargetResponse[], query: string): TargetResponse[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return targets;
  return targets.filter((target) => target.target.toLowerCase().includes(needle));
}

export function TargetList() {
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search, 150);
  const [pendingDelete, setPendingDelete] = useState<TargetResponse | null>(null);
  const { data, isPending, isError, refetch } = useTargets({ limit: TARGET_LIMIT });

  const visible = useMemo(
    () => filterTargets(data?.targets ?? [], debouncedSearch),
    [data?.targets, debouncedSearch]
  );

  return (
    <div className="flex flex-col">
      <PageHeader
        title="Targets"
        description="Hosts and networks you scan. Open one to see its scan history."
        actions={<CreateTargetDialog />}
      />

      {isPending && <ListRowsSkeleton rows={5} />}

      {isError && (
        <ErrorState title="Targets couldn't be loaded" onRetry={() => refetch()} />
      )}

      {data && data.targets.length === 0 && (
        <EmptyState
          icon={Crosshair}
          title="No targets yet"
          description="Add an IP address, hostname or CIDR range to scan."
          action={<CreateTargetDialog />}
        />
      )}

      {data && data.targets.length > 0 && (
        <div className="flex flex-col gap-4">
          <div className="relative max-w-sm">
            <Search
              className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              type="search"
              aria-label="Search targets"
              placeholder="Search targets"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="pl-9"
            />
          </div>

          <div className="rounded-lg border border-border">
            <div
              className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,1.2fr)_2.5rem] gap-4 border-b border-border px-4 py-2.5 text-xs font-medium text-muted-foreground md:grid"
              aria-hidden="true"
            >
              <span>Target</span>
              <span>Type</span>
              <span>Last scan</span>
              <span>Risk</span>
              <span />
            </div>
            {visible.length === 0 ? (
              <p className="px-4 py-8 text-sm text-muted-foreground">
                No targets match &ldquo;{debouncedSearch.trim()}&rdquo;.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {visible.map((target) => (
                  <TargetRow key={target.id} target={target} onDelete={setPendingDelete} />
                ))}
              </ul>
            )}
          </div>

          <p className="text-sm text-muted-foreground">
            {data.total > data.targets.length
              ? `Showing the newest ${formatCount(data.targets.length)} of ${formatCount(data.total)} targets.`
              : `${formatCount(data.total)} ${data.total === 1 ? "target" : "targets"}`}
          </p>
        </div>
      )}

      {pendingDelete && (
        <DeleteTargetDialog
          target={pendingDelete}
          open
          onOpenChange={(next) => {
            if (!next) setPendingDelete(null);
          }}
        />
      )}
    </div>
  );
}
