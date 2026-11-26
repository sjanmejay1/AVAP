import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { aiApi } from "@/features/ai/api/ai-api";
import { aiKeys } from "@/features/ai/hooks/query-keys";
import type { AIRecommendationResponse } from "@/features/ai/types/ai";
import type { ApiError } from "@/lib/api/errors";

/**
 * A missing recommendation (404 NOT_FOUND) is a valid, expected product
 * state — not fetched again automatically (the global QueryClient default
 * already treats any 4xx as non-retryable; no override needed here). The
 * UI layer (RecommendationPanel) distinguishes "missing" from a genuine
 * failure by checking `error.code`, never by matching error text.
 */
export function useAiRecommendation(assessmentId: string) {
  return useQuery({
    queryKey: aiKeys.recommendation(assessmentId),
    queryFn: () => aiApi.getRecommendation(assessmentId),
    enabled: Boolean(assessmentId),
  });
}

/**
 * No `retry`: generation is an external-provider-backed mutation with real
 * side effects (a provider API call, a persisted row) — a transport
 * failure after the backend already completed it must not be replayed
 * automatically.
 *
 * On success, `setQueryData` applies the authoritative mutation response
 * directly (not optimistic — this is the real backend result), avoiding an
 * extra round-trip. Nothing is invalidated: generating a recommendation
 * does not write risk_assessments (app/services/ai_service.py only calls
 * risk_repository.get_by_id).
 */
export function useGenerateRecommendation() {
  const queryClient = useQueryClient();
  return useMutation<AIRecommendationResponse, ApiError, string>({
    mutationFn: (assessmentId: string) => aiApi.generateRecommendation(assessmentId),
    onSuccess: (data, assessmentId) => {
      queryClient.setQueryData(aiKeys.recommendation(assessmentId), data);
    },
  });
}

/**
 * Exact Module 07 freshness rule (app/services/ai_service.py:
 * `existing.generated_at >= risk_assessment.calculated_at`), reimplemented
 * only as a timestamp comparison — never a new algorithm, no grace period,
 * no client clock. Both timestamps are parsed to instants rather than
 * compared as strings to avoid ISO-format edge cases.
 */
export function isRecommendationFresh(
  generatedAt: string,
  riskCalculatedAt: string
): boolean {
  return new Date(generatedAt).getTime() >= new Date(riskCalculatedAt).getTime();
}
