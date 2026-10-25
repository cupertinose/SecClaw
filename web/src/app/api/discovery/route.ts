import { cookies } from "next/headers";
import { desc, sql } from "drizzle-orm";
import { NextResponse } from "next/server";

import { db } from "@/db";
import { discoveryJobs } from "@/db/schema";
import { sessionCookieName, verifySessionToken } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function isAdmin() {
  const token = (await cookies()).get(sessionCookieName)?.value;
  if (!token) return false;
  try {
    return (await verifySessionToken(token)).role === "sys_admin";
  } catch {
    return false;
  }
}

export async function GET() {
  if (!(await isAdmin())) return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  const jobs = await db.select().from(discoveryJobs).orderBy(desc(discoveryJobs.id)).limit(10);
  return NextResponse.json({ jobs });
}

export async function POST(request: Request) {
  if (!(await isAdmin())) return NextResponse.json({ error: "Admin access required" }, { status: 403 });
  const origin = request.headers.get("origin");
  if (origin && new URL(origin).host !== request.headers.get("host")) {
    return NextResponse.json({ error: "Invalid origin" }, { status: 403 });
  }
  const inserted = await db.execute(sql`
    insert into discovery_jobs (status) select 'queued'
    where not exists (select 1 from discovery_jobs where status in ('queued', 'running'))
    returning id
  `);
  if (!inserted.length) return NextResponse.json({ error: "Discovery is already in progress" }, { status: 409 });
  return NextResponse.json({ id: inserted[0].id }, { status: 202 });
}
