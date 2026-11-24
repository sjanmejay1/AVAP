"use client";

import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { buttonVariants } from "@/components/ui/button";
import { useDeleteTarget } from "@/features/targets/hooks/use-targets";
import type { TargetResponse } from "@/features/targets/types/target";

export function DeleteTargetDialog({
  target,
  open,
  onOpenChange,
  onDeleted,
}: {
  target: TargetResponse;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called after a confirmed deletion — e.g. to navigate away from a detail page. */
  onDeleted?: () => void;
}) {
  const { mutate, isPending } = useDeleteTarget();

  function handleConfirm(event: React.MouseEvent<HTMLButtonElement>) {
    // AlertDialogAction closes on click by default — keep it open, showing
    // a pending state, until the backend confirms the deletion.
    event.preventDefault();
    if (isPending) return;

    mutate(target.id, {
      onSuccess: () => {
        toast.success("Target deleted");
        onOpenChange(false);
        onDeleted?.();
      },
      onError: (error) => {
        toast.error(error.message);
        // Already gone server-side: nothing left to confirm.
        if (error.code === "NOT_FOUND") onOpenChange(false);
      },
    });
  }

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!isPending) onOpenChange(next);
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this target?</AlertDialogTitle>
          <AlertDialogDescription>
            This also deletes every scan of it, with their findings and reports. It
            can&apos;t be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <p className="truncate rounded-md border border-border bg-muted px-3 py-2 font-mono text-sm text-foreground">
          {target.target}
        </p>

        <AlertDialogFooter>
          <AlertDialogCancel disabled={isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            disabled={isPending}
            className={buttonVariants({ variant: "destructive" })}
          >
            {isPending ? "Deleting…" : "Delete target"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
