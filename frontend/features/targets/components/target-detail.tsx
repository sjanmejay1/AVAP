"use client";

import { MoreHorizontal, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { ErrorState } from "@/components/shared/error-state";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/skeletons";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { NewScanDialog } from "@/features/scans/components/new-scan-dialog";
import { ScanHistory } from "@/features/scans/components/scan-history";
import { DeleteTargetDialog } from "@/features/targets/components/delete-target-dialog";
import { useTarget } from "@/features/targets/hooks/use-targets";
import { TARGET_TYPE_LABELS } from "@/features/targets/types/target";
import { ApiError } from "@/lib/api/errors";
import { formatDateTime } from "@/utils/format";

export function TargetDetail({ targetId }: { targetId: string }) {
  const router = useRouter();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const { data: target, isPending, isError, error, refetch } = useTarget(targetId);

  if (isPending) return <PageSkeleton />;

  if (isError || !target) {
    const notFound = error instanceof ApiError && error.code === "NOT_FOUND";
    return (
      <div className="flex flex-col">
        <PageHeader title="Target" breadcrumbs={[{ label: "Targets", href: "/targets" }]} />
        <ErrorState
          title={notFound ? "This target doesn't exist" : "This target couldn't be loaded"}
          description={
            notFound
              ? "It may have been deleted, or it belongs to another account."
              : undefined
          }
          onRetry={notFound ? undefined : () => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      <PageHeader
        wide
        title={target.target}
        breadcrumbs={[{ label: "Targets", href: "/targets" }, { label: target.target }]}
        description={`${TARGET_TYPE_LABELS[target.target_type]}, added ${formatDateTime(target.created_at)}`}
        actions={
          <>
            <NewScanDialog target={target} />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" aria-label="More target actions">
                  <MoreHorizontal aria-hidden="true" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuItem variant="destructive" onSelect={() => setDeleteOpen(true)}>
                  <Trash2 aria-hidden="true" />
                  Delete target
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        }
      />

      <section aria-labelledby="scan-history-heading" className="flex flex-col gap-4">
        <h2 id="scan-history-heading" className="text-h3">
          Scan history
        </h2>
        <ScanHistory targetId={target.id} emptyAction={<NewScanDialog target={target} />} />
      </section>

      <DeleteTargetDialog
        target={target}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => router.push("/targets")}
      />
    </div>
  );
}
