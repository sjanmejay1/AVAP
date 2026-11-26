import type { AxiosResponse } from "axios";

import { normalizeApiError } from "@/lib/api/errors";
import type { ApiSuccessEnvelope } from "@/types/api";

/**
 * Explicit response-unwrapping helper used by every feature service
 * function — never a hidden Axios interceptor. Extracts `data.data` from
 * the standardized success envelope and converts any failure into a
 * normalized ApiError.
 */
export async function requestData<T>(
  requestPromise: Promise<AxiosResponse<ApiSuccessEnvelope<T>>>
): Promise<T> {
  try {
    const response = await requestPromise;
    return response.data.data;
  } catch (error) {
    throw normalizeApiError(error);
  }
}

/**
 * Same error normalization as `requestData`, for endpoints that return
 * `204 No Content` (no envelope body) — e.g. DELETE /targets/{id},
 * DELETE /scans/{id}.
 */
export async function requestVoid(
  requestPromise: Promise<AxiosResponse<unknown>>
): Promise<void> {
  try {
    await requestPromise;
  } catch (error) {
    throw normalizeApiError(error);
  }
}

/**
 * For endpoints that return a file (PDF report, raw Nmap XML) instead of an
 * envelope. With `responseType: "blob"` an error body also arrives as a
 * Blob, so it is parsed back into the envelope before normalizing; that
 * keeps the backend's sanitized message (e.g. "no raw output stored").
 */
export async function requestBlob(
  requestPromise: Promise<AxiosResponse<Blob>>
): Promise<Blob> {
  try {
    const response = await requestPromise;
    return response.data;
  } catch (error) {
    throw normalizeApiError(await withParsedBlobBody(error));
  }
}

async function withParsedBlobBody(error: unknown): Promise<unknown> {
  const response = (error as { response?: { data?: unknown } } | null)?.response;
  if (response && response.data instanceof Blob) {
    try {
      response.data = JSON.parse(await response.data.text());
    } catch {
      // Not JSON: normalizeApiError falls back to its generic message.
    }
  }
  return error;
}
