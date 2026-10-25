import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { sessionCookieName, verifySessionToken } from "@/lib/session";
import ScanPanel from "./scan-panel";

export default async function DashboardPage() {
  const token = (await cookies()).get(sessionCookieName)?.value;
  if (!token) redirect("/login");

  let session;
  try {
    session = await verifySessionToken(token);
  } catch {
    redirect("/login");
  }

  return (
    <main className="min-h-screen bg-slate-950 p-8 text-slate-100">
      <div className="mx-auto max-w-4xl rounded-2xl border border-slate-800 bg-slate-900 p-8">
        <p className="text-sm font-semibold tracking-widest text-cyan-400">SecClaw</p>
        <h1 className="mt-3 text-3xl font-semibold">Welcome, {session.name}</h1>
        <p className="mt-2 text-slate-400">{session.email} · {session.role}</p>
        {session.role === "sys_admin" && <ScanPanel />}
        <form action="/api/auth/logout" method="post" className="mt-8">
          <button className="rounded-lg border border-slate-700 px-4 py-2 hover:border-slate-500">Sign out</button>
        </form>
      </div>
    </main>
  );
}
