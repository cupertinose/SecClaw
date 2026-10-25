import { cookies } from "next/headers";
import { desc, eq, sql } from "drizzle-orm";
import { NextResponse } from "next/server";

import { db } from "@/db";
import { scanJobs, scanSettings } from "@/db/schema";
import { sessionCookieName, verifySessionToken } from "@/lib/session";
import { defaultScanConfig, parseScanConfig } from "@/lib/scan-config";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type StoredScanResult = {
  scan?: { host_discovery?: { online_hosts?: string[] } };
  results?: { host?: string; port?: number; status?: string; models?: string[] }[];
};

function buildDeviceInventory(rows: { id: number; createdAt: Date; finishedAt: Date | null; result: unknown }[]) {
  const devices = new Map<string, {
    host: string;
    lastSeenAt: string;
    lastScanId: number;
    ports: Map<number, { port: number; status: string; models: string[]; lastSeenAt: string; scanId: number }>;
  }>();

  // Rows are newest first, so the first observation is the one displayed.
  for (const row of rows) {
    const result = row.result as StoredScanResult | null;
    const seenAt = (row.finishedAt ?? row.createdAt).toISOString();
    const hosts = new Set(result?.scan?.host_discovery?.online_hosts ?? []);
    for (const service of result?.results ?? []) {
      if (service.host) hosts.add(service.host);
    }
    for (const host of hosts) {
      if (!devices.has(host)) {
        devices.set(host, { host, lastSeenAt: seenAt, lastScanId: row.id, ports: new Map() });
      }
    }
    for (const service of result?.results ?? []) {
      if (!service.host || !Number.isInteger(service.port)) continue;
      const device = devices.get(service.host);
      if (!device || device.ports.has(service.port!)) continue;
      device.ports.set(service.port!, {
        port: service.port!,
        status: service.status ?? "unknown",
        models: service.models ?? [],
        lastSeenAt: seenAt,
        scanId: row.id,
      });
    }
  }

  return [...devices.values()]
    .map(({ ports, ...device }) => ({ ...device, ports: [...ports.values()].sort((a, b) => a.port - b.port) }))
    .sort((a, b) => a.host.localeCompare(b.host, undefined, { numeric: true }));
}

async function adminSession() {
  const token = (await cookies()).get(sessionCookieName)?.value;
  if (!token) return null;
  try {
    const session = await verifySessionToken(token);
    return session.role === "sys_admin" ? session : null;
  } catch {
    return null;
  }
}

function sameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || new URL(origin).host === request.headers.get("host");
}

export async function GET() {
  if (!(await adminSession())) return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  const [settings] = await db.select().from(scanSettings).where(eq(scanSettings.id, 1));
  const jobs = await db.select().from(scanJobs).orderBy(desc(scanJobs.id));
  const inventoryRows = await db.select({
    id: scanJobs.id,
    createdAt: scanJobs.createdAt,
    finishedAt: scanJobs.finishedAt,
    result: scanJobs.result,
  }).from(scanJobs).where(eq(scanJobs.status, "completed")).orderBy(desc(scanJobs.id));
  return NextResponse.json({
    defaults: defaultScanConfig,
    settings: settings ?? { enabled: false, intervalMinutes: 60, nextRunAt: null, config: defaultScanConfig },
    jobs,
    devices: buildDeviceInventory(inventoryRows),
  });
}

export async function POST(request: Request) {
  const session = await adminSession();
  if (!session) return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  if (!sameOrigin(request)) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });

  let config;
  try {
    const body = await request.json();
    config = parseScanConfig(body.config);
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Invalid scan parameters" }, { status: 400 });
  }
  const inserted = await db.execute(sql`
    insert into scan_jobs (status, trigger, requested_by, config)
    select 'queued', 'manual', ${session.userId}, ${JSON.stringify(config)}::jsonb
    where not exists (select 1 from scan_jobs where status in ('queued', 'running'))
    returning id
  `);
  if (!inserted.length) return NextResponse.json({ error: "A scan is already queued or running" }, { status: 409 });
  return NextResponse.json({ id: inserted[0].id }, { status: 202 });
}

export async function PUT(request: Request) {
  if (!(await adminSession())) return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  if (!sameOrigin(request)) return NextResponse.json({ error: "Invalid origin" }, { status: 403 });

  let body: { enabled?: unknown; intervalMinutes?: unknown; config?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  if (typeof body.enabled !== "boolean" || !Number.isInteger(body.intervalMinutes) ||
      (body.intervalMinutes as number) < 15 || (body.intervalMinutes as number) > 10080) {
    return NextResponse.json({ error: "Interval must be 15–10080 minutes" }, { status: 400 });
  }
  const intervalMinutes = body.intervalMinutes as number;
  let config;
  try {
    config = parseScanConfig(body.config);
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Invalid scan parameters" }, { status: 400 });
  }
  const nextRunAt = body.enabled ? new Date(Date.now() + intervalMinutes * 60_000) : null;
  await db.insert(scanSettings).values({ id: 1, enabled: body.enabled, intervalMinutes, nextRunAt, config })
    .onConflictDoUpdate({ target: scanSettings.id, set: { enabled: body.enabled, intervalMinutes, nextRunAt, config } });
  return NextResponse.json({ enabled: body.enabled, intervalMinutes, nextRunAt, config });
}
