"use client";

import { Play } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { FormError } from "@/components/shared/form-field";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { RadioGroup, RadioGroupCard } from "@/components/ui/radio-group";
import {
  isScanProfile,
  SCAN_PROFILE_ORDER,
  SCAN_PROFILES,
} from "@/features/scans/constants/scan-profiles";
import { useCreateScan } from "@/features/scans/hooks/use-scans";
import type { ScanProfile } from "@/features/scans/types/scan";
import { classifyTarget } from "@/features/targets/lib/classify-target";
import type { TargetResponse } from "@/features/targets/types/target";
import { formatCount } from "@/utils/format";

/** Range size note for CIDR targets; hosts are scanned in parallel. */
function rangeNote(target: TargetResponse): string | null {
  if (target.target_type !== "CIDR") return null;
  const result = classifyTarget(target.target);
  if (!result.ok || result.addressCount === null) return null;
  return `This range has ${formatCount(result.addressCount)} addresses. Nmap scans live hosts in parallel, so the total isn't a simple multiple of the per-host time.`;
}

/**
 * Without `open` the dialog owns its state and renders a trigger (default:
 * a "New scan" button). With `open`/`onOpenChange` it is controlled, e.g.
 * from a row menu, which must not own a dialog that would unmount with it.
 */
export function NewScanDialog({
  target,
  open: controlledOpen,
  onOpenChange,
}: {
  target: TargetResponse;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const router = useRouter();
  const [ownOpen, setOwnOpen] = useState(false);
  const isControlled = controlledOpen !== undefined;
  const open = isControlled ? controlledOpen : ownOpen;
  const setOpen = (next: boolean) => (isControlled ? onOpenChange?.(next) : setOwnOpen(next));
  const [profile, setProfile] = useState<ScanProfile>("QUICK");
  const [formError, setFormError] = useState<string | null>(null);
  const { mutate, isPending } = useCreateScan();
  const note = rangeNote(target);

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    setOpen(next);
    if (!next) setFormError(null);
  }

  function handleStart() {
    setFormError(null);
    mutate(
      { target_id: target.id, scan_profile: profile },
      {
        onSuccess: (scan) => {
          toast.success("Scan started");
          setOpen(false);
          router.push(`/scans/${scan.scan_id}`);
        },
        // 409 (a scan of this target is already running) and 429 (the
        // concurrent-scan cap) carry messages the user can act on.
        onError: (error) => setFormError(error.message),
      }
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      {!isControlled && (
        <DialogTrigger asChild>
          <Button>
            <Play aria-hidden="true" />
            New scan
          </Button>
        </DialogTrigger>
      )}
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New scan</DialogTitle>
          <DialogDescription>
            Scan <span className="font-mono text-foreground">{target.target}</span> with Nmap.
          </DialogDescription>
        </DialogHeader>

        <RadioGroup
          value={profile}
          onValueChange={(value) => {
            if (isScanProfile(value)) setProfile(value);
          }}
          aria-label="Scan type"
          disabled={isPending}
        >
          {SCAN_PROFILE_ORDER.map((key) => {
            const meta = SCAN_PROFILES[key];
            return (
              <RadioGroupCard key={key} value={key} aria-label={`${meta.label} scan`}>
                <span className="text-title">{meta.label}</span>
                <span className="text-sm text-muted-foreground">{meta.summary}</span>
                <span className="text-sm font-medium">{meta.estimate}</span>
              </RadioGroupCard>
            );
          })}
        </RadioGroup>

        {note && <p className="text-sm text-muted-foreground">{note}</p>}
        <FormError message={formError} />

        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            onClick={() => handleOpenChange(false)}
            disabled={isPending}
          >
            Cancel
          </Button>
          <Button type="button" onClick={handleStart} disabled={isPending}>
            {isPending ? "Starting…" : `Start ${SCAN_PROFILES[profile].label.toLowerCase()} scan`}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
