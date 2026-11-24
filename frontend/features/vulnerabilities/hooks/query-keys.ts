import type { VulnerabilityListFilters } from "@/features/vulnerabilities/types/vulnerability";

/** Deterministic query key factory for the Vulnerabilities feature. */
export const vulnerabilityKeys = {
  all: ["vulnerabilities"] as const,
  lists: () => [...vulnerabilityKeys.all, "list"] as const,
  list: (params: { skip: number; limit: number } & VulnerabilityListFilters) =>
    [...vulnerabilityKeys.lists(), params] as const,
};
