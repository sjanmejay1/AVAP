import { z } from "zod";

import { classifyTarget } from "@/features/targets/lib/classify-target";

/**
 * Mirrors the backend's CreateTargetRequest (1–253 characters) and its
 * target rules (see lib/classify-target.ts) for instant feedback. The
 * backend re-validates every value and remains the authority.
 */
export const createTargetSchema = z.object({
  target: z
    .string()
    .trim()
    .min(1, "Enter an IP address, CIDR range or hostname.")
    .max(253, "Targets must be 253 characters or fewer.")
    .superRefine((value, context) => {
      const result = classifyTarget(value);
      if (!result.ok) context.addIssue({ code: "custom", message: result.message });
    }),
});

export type CreateTargetFormValues = z.infer<typeof createTargetSchema>;
