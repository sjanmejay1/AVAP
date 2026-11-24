// Starts or stops the isolated stack the Playwright tests run against:
// PostgreSQL + backend (with Nmap) + the demo targets, as Docker Compose
// project "avap-e2e", with the backend on http://localhost:18100.
//
//   node e2e/stack.mjs up     build and start, wait until healthy
//   node e2e/stack.mjs down   stop and delete containers and volumes
//
// Secrets are generated fresh for each run and written to a temp file
// outside the repository; `down` deletes it. Nothing here is a real secret.
import { randomBytes } from "node:crypto";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const E2E_BACKEND_PORT = 18100;
export const E2E_FRONTEND_PORT = 3100;

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const envFile = join(tmpdir(), "avap-e2e.env");

function fernetKey() {
  return randomBytes(32).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
}

function writeEnvFile() {
  const lines = [
    `POSTGRES_PASSWORD=${randomBytes(18).toString("hex")}`,
    `JWT_SECRET_KEY=${randomBytes(48).toString("hex")}`,
    `APP_ENCRYPTION_KEY=${fernetKey()}`,
    `BACKEND_PORT=${E2E_BACKEND_PORT}`,
    `CORS_ALLOWED_ORIGINS=http://localhost:${E2E_FRONTEND_PORT}`,
    "ENVIRONMENT=production",
    // Every test registers fresh accounts from one IP; the default of 10 an
    // hour (unchanged everywhere else) would stop the suite part-way.
    "REGISTRATIONS_PER_IP_PER_HOUR=500",
  ];
  writeFileSync(envFile, `${lines.join("\n")}\n`, { mode: 0o600 });
}

function compose(args) {
  const result = spawnSync(
    "docker",
    [
      "compose",
      "-p",
      "avap-e2e",
      "-f",
      join(repoRoot, "docker-compose.yml"),
      "-f",
      join(repoRoot, "docker-compose.demo.yml"),
      "--env-file",
      envFile,
      ...args,
    ],
    { stdio: "inherit" }
  );
  if (result.status !== 0) {
    throw new Error(`docker compose ${args[0]} failed with exit code ${result.status}`);
  }
}

const command = process.argv[2];

if (command === "up") {
  writeEnvFile();
  compose(["up", "-d", "--build", "--wait", "db", "backend", "demo-web", "demo-cache"]);
} else if (command === "down") {
  // Compose still interpolates required variables on `down`.
  if (!existsSync(envFile)) writeEnvFile();
  compose(["down", "-v"]);
  rmSync(envFile, { force: true });
} else {
  console.error("Usage: node e2e/stack.mjs up|down");
  process.exit(2);
}
