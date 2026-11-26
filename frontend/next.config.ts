import type { NextConfig } from "next";

// Baseline browser hardening for every page. A Content-Security-Policy is
// deliberately not set here: Next.js injects inline scripts, so a useful CSP
// needs nonce support and is its own piece of work.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=()",
  },
];

const nextConfig: NextConfig = {
  // Emit a self-contained server bundle (.next/standalone) so the Docker
  // runtime image ships only the compiled server + static assets, not the
  // full node_modules tree. Has no effect on `npm run dev`.
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
