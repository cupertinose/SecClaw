"use client";

import { useCallback, useEffect, useState } from "react";

type Device = { ip: string; hostname: string | null; names: string[]; services: string[] };
type DiscoveryJob = {
  id: number;
  status: string;
  createdAt: string;
  finishedAt: string | null;
  error: string | null;
  result: { source: string; interface: string; devices: Device[] } | null;
};

export default function DeviceDiscovery() {
  const [jobs, setJobs] = useState<DiscoveryJob[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/discovery", { cache: "no-store" });
      if (!response.ok) throw new Error("Could not load device discovery");
      const data = await response.json();
      setJobs(data.jobs);
      setSelected((current) => current ?? data.jobs[0]?.id ?? null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function start() {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/discovery", { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not start discovery");
      setSelected(data.id);
      await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  const active = jobs.some((item) => item.status === "queued" || item.status === "running");
  const job = jobs.find((item) => item.id === selected) ?? jobs[0];
  const devices = job?.result?.devices ?? [];

  return <div className="space-y-5">
    <div className="rounded-xl border border-slate-700 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">Device discovery</h2>
          <p className="mt-1 text-sm text-slate-400">Find devices advertising mDNS services on the host Wi-Fi interface.</p>
        </div>
        <button disabled={busy || active} onClick={() => void start()}
          className="rounded-lg bg-cyan-600 px-4 py-2 font-medium hover:bg-cyan-500 disabled:opacity-50">
          {active ? "Discovering…" : "Discover now"}
        </button>
      </div>
      <p className="mt-3 text-sm text-slate-400">These are visible service announcements. They may include wired devices and other subnets, and do not represent every connected Wi-Fi client.</p>
    </div>

    {error && <p role="alert" className="rounded-lg bg-red-950 p-3 text-red-200">{error}</p>}

    <div className="rounded-xl border border-slate-700 p-5">
      <h2 className="text-xl font-semibold">Discovery results</h2>
      <div className="mt-3 flex flex-wrap gap-2">
        {jobs.map((item) => <button key={item.id} onClick={() => setSelected(item.id)}
          className={`rounded-lg border px-3 py-2 text-sm ${job?.id === item.id ? "border-cyan-400" : "border-slate-700"}`}>
          #{item.id} · {item.status === "completed" ? "Completed" : item.status === "running" ? "Running" : item.status === "queued" ? "Queued" : "Failed"}
        </button>)}
      </div>
      {!job && <p className="mt-3 text-slate-400">No discoveries yet.</p>}
      {job && <div className="mt-4 text-sm">
        <p>Discovery #{job.id} · {new Date(job.createdAt).toLocaleString()}{job.finishedAt ? ` · Finished ${new Date(job.finishedAt).toLocaleString()}` : ""}</p>
        {(job.status === "running" || job.status === "queued") && <p className="mt-2 text-cyan-300">Discovery in progress. Results refresh automatically.</p>}
        {job.error && <p className="mt-2 text-red-300">{job.error}</p>}
        {job.result && <>
          <p className="mt-3">{devices.length} unique IP addresses observed on {job.result.interface}.</p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-slate-700 text-slate-400"><tr><th className="p-2">IP address</th><th className="p-2">Device</th><th className="p-2">Services</th></tr></thead>
              <tbody>{devices.map((device) => <tr key={device.ip} className="border-b border-slate-800 align-top">
                <td className="p-2 font-mono">{device.ip}</td>
                <td className="p-2">{device.hostname || device.names[0] || "Unknown"}</td>
                <td className="p-2 text-slate-400">{device.services.join(", ")}</td>
              </tr>)}</tbody>
            </table>
          </div>
        </>}
      </div>}
    </div>
  </div>;
}
