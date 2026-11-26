/**
 * Saves a Blob to the user's device using the standard temporary-anchor
 * pattern (native browser APIs only — no library). Callers pass the same
 * filename the backend's Content-Disposition uses (`avap-report-<id>.pdf`,
 * `nmap-<scan_id>.xml`) rather than inventing new ones.
 */
export function triggerBrowserDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
