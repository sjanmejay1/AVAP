import type { Metadata } from "next";

import { TargetDetail } from "@/features/targets/components/target-detail";

export const metadata: Metadata = { title: "Target" };

export default async function TargetPage({
  params,
}: {
  params: Promise<{ targetId: string }>;
}) {
  const { targetId } = await params;
  return <TargetDetail targetId={targetId} />;
}
