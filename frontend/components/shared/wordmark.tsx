import { cn } from "@/lib/utils";

/** Text-only wordmark, set in Archivo at its widest. */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span
      className={cn("text-lg leading-none font-bold tracking-tight", className)}
      style={{ fontVariationSettings: '"wdth" 125' }}
    >
      AVAP
    </span>
  );
}
