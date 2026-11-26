import type { ApiError } from "@/lib/api/errors";

interface PydanticErrorItem {
  loc?: unknown;
  msg?: unknown;
}

/**
 * Maps a backend 422 `details.errors` list (Pydantic, with submitted values
 * already stripped server-side) to `{fieldName: message}` for forms. Only
 * body fields are mapped; anything else is left to the form-level message.
 */
export function fieldErrorsFrom(error: ApiError): Record<string, string> {
  const items = error.details?.errors;
  if (error.code !== "VALIDATION_ERROR" || !Array.isArray(items)) return {};

  const result: Record<string, string> = {};
  for (const item of items as PydanticErrorItem[]) {
    if (!Array.isArray(item.loc) || item.loc[0] !== "body" || typeof item.msg !== "string") {
      continue;
    }
    const field = item.loc[item.loc.length - 1];
    if (typeof field === "string" && !(field in result)) {
      result[field] = item.msg.replace(/^Value error, /, "");
    }
  }
  return result;
}
