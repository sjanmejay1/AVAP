import type { Metadata } from "next";

import { TargetList } from "@/features/targets/components/target-list";

export const metadata: Metadata = { title: "Targets" };

export default function TargetsPage() {
  return <TargetList />;
}
