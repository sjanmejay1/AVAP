import { Skeleton } from "@/components/ui/skeleton";

export function ListRowsSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="flex flex-col divide-y divide-border rounded-lg border border-border" aria-hidden="true">
      {Array.from({ length: rows }).map((_, index) => (
        <div key={index} className="flex items-center justify-between gap-3 px-4 py-4">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-4 w-20" />
        </div>
      ))}
    </div>
  );
}

export function PageSkeleton() {
  return (
    <div className="flex flex-col gap-6" role="status" aria-label="Loading">
      <Skeleton className="h-4 w-40" />
      <Skeleton className="h-10 w-2/3 max-w-md" />
      <ListRowsSkeleton rows={4} />
    </div>
  );
}
