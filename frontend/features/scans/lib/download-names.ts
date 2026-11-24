/** Same filenames the backend's Content-Disposition headers use. */
export function reportFilename(reportId: string): string {
  return `avap-report-${reportId}.pdf`;
}

export function rawOutputFilename(scanId: string): string {
  return `nmap-${scanId}.xml`;
}
