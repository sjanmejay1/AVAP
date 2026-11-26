import type { Metadata } from "next";
import { Suspense } from "react";

import { PageSkeleton } from "@/components/shared/skeletons";
import { ScanDetail } from "@/features/scans/components/scan-detail";

export const metadata: Metadata = { title: "Scan" };

export default async function ScanPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;
  // ScanDetail reads ?tab= with useSearchParams, which needs a Suspense boundary.
  return (
    <Suspense fallback={<PageSkeleton />}>
      <ScanDetail scanId={scanId} />
    </Suspense>
  );
}
