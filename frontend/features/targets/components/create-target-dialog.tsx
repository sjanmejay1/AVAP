"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Plus } from "lucide-react";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";

import { FormField } from "@/components/shared/form-field";
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
import { Input } from "@/components/ui/input";
import { useCreateTarget } from "@/features/targets/hooks/use-targets";
import {
  classifyTarget,
  describeClassification,
} from "@/features/targets/lib/classify-target";
import {
  createTargetSchema,
  type CreateTargetFormValues,
} from "@/features/targets/schemas/target-schema";

/** Field-level backend failures a user can act on by editing the value. */
function isFieldLevelError(code: string): boolean {
  return code === "VALIDATION_ERROR" || code === "CONFLICT";
}

export function CreateTargetDialog({ trigger }: { trigger?: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const { mutate, isPending } = useCreateTarget();
  const {
    register,
    handleSubmit,
    reset,
    setError,
    control,
    formState: { errors },
  } = useForm<CreateTargetFormValues>({
    resolver: zodResolver(createTargetSchema),
    defaultValues: { target: "" },
  });
  const value = useWatch({ control, name: "target" });
  const hint = value.trim()
    ? describeClassification(classifyTarget(value))
    : "Only scan hosts and networks you own or are allowed to test.";

  function handleOpenChange(next: boolean) {
    if (isPending) return;
    setOpen(next);
    if (!next) reset();
  }

  function onSubmit(values: CreateTargetFormValues) {
    mutate(values, {
      onSuccess: () => {
        toast.success("Target added");
        reset();
        setOpen(false);
      },
      onError: (error) => {
        if (isFieldLevelError(error.code)) {
          setError("target", { type: "server", message: error.message });
          return;
        }
        toast.error(error.message);
      },
    });
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        {trigger ?? (
          <Button>
            <Plus aria-hidden="true" />
            Add target
          </Button>
        )}
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add a target</DialogTitle>
          <DialogDescription>
            An IPv4 address, a CIDR range up to /16, or a hostname.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-5" noValidate>
          <FormField
            id="target"
            label="Target"
            error={errors.target?.message}
            hint={errors.target ? undefined : hint}
          >
            {(a11y) => (
              <Input
                {...a11y}
                placeholder="192.168.1.10, 10.0.0.0/24 or example.com"
                autoComplete="off"
                spellCheck={false}
                autoFocus
                disabled={isPending}
                className="font-mono"
                {...register("target")}
              />
            )}
          </FormField>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleOpenChange(false)}
              disabled={isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending ? "Adding…" : "Add target"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
