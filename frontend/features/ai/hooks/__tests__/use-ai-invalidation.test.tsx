import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/features/ai/api/ai-api", () => ({
  aiApi: {
    getRecommendation: vi.fn(),
    generateRecommendation: vi.fn(),
  },
}));

import { aiApi } from "@/features/ai/api/ai-api";
import { useGenerateRecommendation } from "@/features/ai/hooks/use-ai";

const mockedGenerate = vi.mocked(aiApi.generateRecommendation);

function wrapper(queryClient: QueryClient) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
  };
}

describe("useGenerateRecommendation — cache invalidation map", () => {
  it("invalidates nothing — never any risk query — and applies the response with setQueryData", async () => {
    mockedGenerate.mockResolvedValue({
      id: "rec-1",
      vulnerability_id: "vuln-1",
      risk_assessment_id: "assessment-1",
      provider: "openrouter",
      model: "gpt-oss-20b",
      prompt_version: "1.0.0",
      summary: "Summary",
      explanation: "Explanation",
      remediation_steps: ["Step 1"],
      validation_steps: [],
      cautions: [],
      generated_at: "2026-07-15T10:00:00Z",
    });

    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    const { result } = renderHook(() => useGenerateRecommendation(), {
      wrapper: wrapper(queryClient),
    });

    result.current.mutate("assessment-1");
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    // The dashboard (the only other reader of AI coverage) was removed, so
    // nothing needs re-reading: the response itself is the new cache entry.
    expect(invalidateSpy).not.toHaveBeenCalled();

    // The mutation response is applied authoritatively via setQueryData.
    expect(queryClient.getQueryData(["ai", "recommendation", "assessment-1"])).toMatchObject({
      summary: "Summary",
    });
  });
});
