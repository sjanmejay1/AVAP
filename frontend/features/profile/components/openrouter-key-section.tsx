"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircle2, XCircle } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";

import { ErrorState } from "@/components/shared/error-state";
import { FormField } from "@/components/shared/form-field";
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
import { Button, buttonVariants } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  useDeleteOpenRouterKey,
  useOpenRouterKey,
  useSaveOpenRouterKey,
  useTestOpenRouterKey,
} from "@/features/profile/hooks/use-profile";
import { apiKeySchema, type ApiKeyFormValues } from "@/features/profile/schemas/profile-schema";
import type { ApiKeyTestResponse } from "@/features/profile/types/profile";
import { fieldErrorsFrom } from "@/lib/api/field-errors";
import { formatRelativeTime } from "@/utils/format";

function TestResult({ result }: { result: ApiKeyTestResponse }) {
  const Icon = result.valid ? CheckCircle2 : XCircle;
  return (
    <p
      role="status"
      className={`flex items-center gap-2 text-sm ${result.valid ? "text-success" : "text-destructive"}`}
    >
      <Icon className="size-4 shrink-0" aria-hidden="true" />
      {result.message}
    </p>
  );
}

/**
 * Write-only key: once saved, only its last 4 characters are ever shown.
 * The input is cleared after every save.
 */
export function OpenRouterKeySection() {
  const { data: savedKey, isPending, isError, refetch } = useOpenRouterKey();
  const save = useSaveOpenRouterKey();
  const test = useTestOpenRouterKey();
  const remove = useDeleteOpenRouterKey();
  const [removeOpen, setRemoveOpen] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<ApiKeyFormValues>({
    resolver: zodResolver(apiKeySchema),
    defaultValues: { apiKey: "" },
  });

  function onSave(values: ApiKeyFormValues) {
    test.reset();
    save.mutate(values.apiKey, {
      onSuccess: () => {
        reset({ apiKey: "" });
        toast.success("OpenRouter key saved");
      },
      onError: (error) => {
        const message = fieldErrorsFrom(error).api_key ?? error.message;
        setError("apiKey", { type: "server", message });
      },
    });
  }

  function onRemove(event: React.MouseEvent<HTMLButtonElement>) {
    event.preventDefault();
    remove.mutate(undefined, {
      onSuccess: () => {
        test.reset();
        setRemoveOpen(false);
        toast.success("OpenRouter key removed");
      },
      onError: (error) => toast.error(error.message),
    });
  }

  return (
    <section aria-labelledby="openrouter-heading" className="flex flex-col gap-4">
      <div className="flex max-w-prose flex-col gap-1">
        <h2 id="openrouter-heading" className="text-h3">
          OpenRouter key
        </h2>
        <p className="text-sm text-muted-foreground">
          AI analysis and remediation advice use your own OpenRouter key. AVAP only calls
          free models (ids ending in <span className="font-mono">:free</span>), so nothing is
          billed. OpenRouter&apos;s free tier allows 20 requests a minute and 50 a day, or
          1,000 a day once you have bought at least 10 credits. Without a key, scans still
          run; only the AI steps are skipped.
        </p>
      </div>

      {isPending && <Skeleton className="h-16 w-full max-w-md" />}
      {isError && <ErrorState title="Your key status couldn't be loaded" onRetry={() => refetch()} />}

      {!isPending && !isError && (
        <div className="flex max-w-md flex-col gap-5">
          {savedKey ? (
            <div className="flex flex-col gap-3 rounded-lg border border-border p-4">
              <p className="text-sm">
                Key ending in <span className="font-mono font-semibold">{savedKey.last4}</span>,
                saved {formatRelativeTime(savedKey.updated_at)}.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={test.isPending}
                  onClick={() =>
                    test.mutate(undefined, { onError: (error) => toast.error(error.message) })
                  }
                >
                  {test.isPending ? "Testing…" : "Test key"}
                </Button>
                <Button variant="outline" size="sm" onClick={() => setRemoveOpen(true)}>
                  Remove key
                </Button>
              </div>
              {test.data && <TestResult result={test.data} />}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No key saved.</p>
          )}

          <form onSubmit={handleSubmit(onSave)} noValidate className="flex flex-col gap-4">
            <FormField
              id="apiKey"
              label={savedKey ? "Replace key" : "API key"}
              error={errors.apiKey?.message}
              hint="Create one at openrouter.ai under Keys. It's stored encrypted and never shown again."
            >
              {(a11y) => (
                <Input
                  {...a11y}
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="sk-or-v1-…"
                  disabled={save.isPending}
                  className="font-mono"
                  {...register("apiKey")}
                />
              )}
            </FormField>
            <div>
              <Button type="submit" disabled={save.isPending}>
                {save.isPending ? "Saving…" : "Save key"}
              </Button>
            </div>
          </form>
        </div>
      )}

      <AlertDialog open={removeOpen} onOpenChange={(next) => !remove.isPending && setRemoveOpen(next)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove your OpenRouter key?</AlertDialogTitle>
            <AlertDialogDescription>
              AI analysis and remediation advice stop until you save a key again. Your scans
              and existing findings are kept.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}>Keep key</AlertDialogCancel>
            <AlertDialogAction
              onClick={onRemove}
              disabled={remove.isPending}
              className={buttonVariants({ variant: "destructive" })}
            >
              {remove.isPending ? "Removing…" : "Remove key"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
