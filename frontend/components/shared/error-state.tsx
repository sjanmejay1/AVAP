"use client";

import { AlertTriangle } from "lucide-react";

import { Button } from "@/components/ui/button";

/**
 * Actionable, sanitized error surface: a fixed summary plus a retry action,
 * never a stack trace or raw transport detail.
 */
export function ErrorState({
  title = "This couldn't be loaded",
  description = "The request didn't complete. Check that the backend is running, then try again.",
  onRetry,
}: {
  title?: string;
  description?: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-col items-start gap-3 rounded-lg border border-destructive-border bg-destructive-bg px-6 py-6"
    >
      <div className="flex items-start gap-2 text-destructive">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium">{title}</p>
          <p className="mt-1 text-sm">{description}</p>
        </div>
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}
