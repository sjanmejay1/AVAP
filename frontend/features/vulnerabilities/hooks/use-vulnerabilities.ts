import { useQuery } from "@tanstack/react-query";

import { vulnerabilityKeys } from "@/features/vulnerabilities/hooks/query-keys";
import { vulnerabilitiesApi } from "@/features/vulnerabilities/api/vulnerabilities-api";
import type { VulnerabilityListFilters } from "@/features/vulnerabilities/types/vulnerability";

/**
 * The Vulnerability catalog is a read-only reference/inventory resource —
 * no mutation hooks exist here (no endpoint to call), and no polling: the
 * scan page re-reads this list once, when a scan finishes.
 */
export function useVulnerabilities(
  params: { skip?: number; limit?: number } & VulnerabilityListFilters = {},
  enabled = true
) {
  const query = {
    skip: params.skip ?? 0,
    limit: params.limit ?? 50,
    severity_rating: params.severity_rating,
    cve: params.cve,
    target_id: params.target_id,
    scan_id: params.scan_id,
  };
  return useQuery({
    queryKey: vulnerabilityKeys.list(query),
    queryFn: () => vulnerabilitiesApi.getVulnerabilities(query),
    enabled,
  });
}
