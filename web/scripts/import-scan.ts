import { readFile } from "node:fs/promises";
import path from "node:path";

import { and, eq } from "drizzle-orm";
import { config as loadEnv } from "dotenv";

type ScanReport = {
  scan: {
    started_at: string;
    finished_at: string;
    input?: {
      targets?: string;
      ports?: string;
      scheme?: string;
      jobs?: number;
      timeout_seconds?: number;
      open_only?: boolean;
      capture_interface?: string | null;
    };
    host_discovery?: { tcp_fallback?: { port_count?: number } };
  };
  results: unknown[];
};

function validDate(value: unknown, field: string) {
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid ${field}`);
  return date;
}

async function main() {
  loadEnv({ path: ".env.local" });
  const inputPath = process.argv[2];
  if (!inputPath) throw new Error("Usage: npm run db:import-scan -- <scan-report.json>");

  const absolutePath = path.resolve(inputPath);
  const report = JSON.parse(await readFile(absolutePath, "utf8")) as ScanReport;
  if (!report?.scan || !Array.isArray(report.results)) {
    throw new Error("Invalid scan report: expected scan object and results array");
  }

  const startedAt = validDate(report.scan.started_at, "scan.started_at");
  const finishedAt = validDate(report.scan.finished_at, "scan.finished_at");
  const input = report.scan.input ?? {};
  const scanConfig = {
    targets: input.targets ?? "Not recorded",
    ports: input.ports ?? "Not recorded",
    interface: input.capture_interface ?? "Not recorded",
    arpInterval: 100,
    jobs: input.jobs ?? 1,
    timeout: input.timeout_seconds ?? 2,
    https: input.scheme === "https",
    openOnly: input.open_only ?? false,
    tcpFallback: (report.scan.host_discovery?.tcp_fallback?.port_count ?? 0) > 0,
    importSource: path.basename(absolutePath),
  };

  const [{ db }, { scanJobs }] = await Promise.all([
    import("../src/db"),
    import("../src/db/schema"),
  ]);
  const existing = await db.select({ id: scanJobs.id }).from(scanJobs).where(and(
    eq(scanJobs.trigger, "imported"),
    eq(scanJobs.startedAt, startedAt),
  )).limit(1);
  if (existing.length) {
    console.log(`Scan already imported as job #${existing[0].id}`);
    return;
  }

  const [job] = await db.insert(scanJobs).values({
    status: "completed",
    trigger: "imported",
    config: scanConfig,
    createdAt: startedAt,
    startedAt,
    finishedAt,
    result: report,
  }).returning({ id: scanJobs.id });
  const { storeScanDevices } = await import("./device-inventory.mjs");
  await storeScanDevices(db.$client, job.id, report, finishedAt);
  console.log(`Imported ${path.basename(absolutePath)} as scan job #${job.id}`);
}

main().then(() => process.exit(0)).catch((error) => {
  console.error(error);
  process.exit(1);
});
