"use client";

import { useCallback, useEffect, useState } from "react";
import DeviceDiscovery from "./device-discovery";

type Config = {
  targets: string; ports: string; interface: string; arpInterval: number;
  jobs: number; timeout: number; https: boolean; openOnly: boolean; tcpFallback: boolean;
  importSource?: string;
};

type Job = {
  id: number;
  status: string;
  trigger: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  config: Config | null;
  result: {
    scan?: { host_discovery?: { online_hosts?: string[] }; result_count?: number; duration_seconds?: number };
    results?: { host: string; port: number; status: string; models?: string[]; detail?: unknown }[];
  } | null;
};
type Device = {
  host: string;
  lastSeenAt: string;
  lastScanId: number;
  ports: { port: number; status: string; models: string[]; lastSeenAt: string; scanId: number }[];
};

export default function ScanPanel() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [defaults, setDefaults] = useState<Config | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"devices" | "scans" | "discovery">("devices");
  const [deviceFilter, setDeviceFilter] = useState("");
  const [createPeriod, setCreatePeriod] = useState("once");

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/scans", { cache: "no-store" });
      if (!response.ok) throw new Error("Could not load scan status");
      const data = await response.json();
      setJobs(data.jobs);
      setDevices(data.devices ?? []);
      setDefaults(data.defaults);
      setSelected((current) => current ?? data.jobs[0]?.id ?? null);
    } catch (cause) {
      setError(String(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function update(method: "POST" | "PUT", body?: object) {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/scans", {
        method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body ?? {}),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Action failed");
      await refresh();
      if (method === "POST") {
        setSelected(data.id);
        setTab("scans");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  const active = jobs.some((job) => job.status === "queued" || job.status === "running");
  const job = jobs.find((item) => item.id === selected) ?? jobs[0];
  const hosts = job?.result?.scan?.host_discovery?.online_hosts ?? [];
  const results = job?.result?.results ?? [];
  const statusLabel = (status: string) => status === "queued" ? "Queued" : status === "running" ? "Running" : status === "completed" ? "Completed" : "Failed";
  const statusColor = (status: string) => status === "completed" ? "bg-emerald-950 text-emerald-300" : status === "failed" ? "bg-red-950 text-red-300" : "bg-cyan-950 text-cyan-300";
  const visibleDevices = devices.filter((device) => {
    const query = deviceFilter.trim().toLowerCase();
    return !query || device.host.toLowerCase().includes(query) || device.ports.some((port) =>
      String(port.port).includes(query) || port.status.toLowerCase().includes(query) || port.models.some((model) => model.toLowerCase().includes(query))
    );
  });
  function createScan() {
    if (!defaults) return;
    if (createPeriod === "once") {
      void update("POST", { config: defaults });
      return;
    }
    void update("PUT", { enabled: true, intervalMinutes: Number(createPeriod), config: defaults });
  }

  return (
    <section className="mt-8 space-y-6">
      <div role="tablist" aria-label="Scan sections" className="flex flex-wrap gap-2 border-b border-slate-700 pb-3">
        {([ ["devices", "Dashboard"], ["scans", "Scans"], ["discovery", "Devices"] ] as const).map(([key, label]) =>
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={`rounded-lg px-4 py-2 ${tab === key ? "bg-cyan-700 text-white" : "bg-slate-800 text-slate-300 hover:bg-slate-700"}`}>
            {label}{key === "scans" && active ? " · In progress" : ""}
          </button>)}
      </div>
      {error && <p role="alert" className="rounded-lg bg-red-950 p-3 text-red-200">{error}</p>}

      {tab === "devices" && <div className="rounded-xl border border-slate-700 p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold">Scanned devices and ports</h2>
            <p className="mt-1 text-sm text-slate-400">
              {devices.length} {devices.length === 1 ? "device" : "devices"} found across all completed scans. Latest result shown per port.
            </p>
          </div>
          <label className="text-sm text-slate-300">Filter devices or ports
            <input value={deviceFilter} onChange={(event) => setDeviceFilter(event.target.value)} placeholder="IP, port, status, or model"
              className="mt-1 block w-64 max-w-full rounded border border-slate-600 bg-slate-800 p-2" />
          </label>
        </div>
        <div className="mt-5 space-y-3">
          {visibleDevices.map((device) => <article key={device.host} className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="font-mono text-base font-semibold text-cyan-300">{device.host}</h3>
              <p className="text-xs text-slate-400">Last seen {new Date(device.lastSeenAt).toLocaleString()} · Scan #{device.lastScanId}</p>
            </div>
            {device.ports.length ? <div className="mt-3 overflow-x-auto">
              <table className="w-full min-w-lg text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-slate-500">
                  <tr><th className="pb-2 pr-4">Port</th><th className="pb-2 pr-4">Status</th><th className="pb-2 pr-4">Detected models</th><th className="pb-2">Last scan</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {device.ports.map((port) => <tr key={port.port}>
                    <td className="py-2 pr-4 font-mono text-slate-100">{port.port}</td>
                    <td className="py-2 pr-4"><span className={`rounded-full px-2 py-1 text-xs ${port.status === "open" ? "bg-emerald-950 text-emerald-300" : "bg-slate-800 text-slate-300"}`}>{port.status}</span></td>
                    <td className="py-2 pr-4 text-slate-300">{port.models.length ? port.models.join(", ") : "—"}</td>
                    <td className="py-2 text-slate-400">#{port.scanId} · {new Date(port.lastSeenAt).toLocaleString()}</td>
                  </tr>)}
                </tbody>
              </table>
            </div> : <p className="mt-3 text-sm text-slate-400">No open ports were recorded for this device.</p>}
          </article>)}
          {!visibleDevices.length && <p className="rounded-lg bg-slate-950 p-4 text-sm text-slate-400">
            {devices.length ? "No devices match this filter." : "No scanned devices yet. Run or import a completed scan to populate this view."}
          </p>}
        </div>
      </div>}

      {tab === "scans" && <div className="rounded-xl border border-slate-700 p-5">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div><h2 className="text-xl font-semibold">Scans</h2><p className="mt-1 text-sm text-slate-400">All network scans and their results.</p></div>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-sm text-slate-300">Period
              <select value={createPeriod} onChange={(event) => setCreatePeriod(event.target.value)}
                className="mt-1 block rounded border border-slate-600 bg-slate-800 px-3 py-2">
                <option value="once">Once</option>
                <option value="15">Every 15 minutes</option>
                <option value="30">Every 30 minutes</option>
                <option value="60">Every hour</option>
                <option value="360">Every 6 hours</option>
                <option value="720">Every 12 hours</option>
                <option value="1440">Every day</option>
                <option value="10080">Every week</option>
              </select>
            </label>
            <button disabled={busy || !defaults || (createPeriod === "once" && active)} onClick={createScan}
              className="rounded-lg bg-cyan-600 px-4 py-2 font-medium hover:bg-cyan-500 disabled:opacity-50">
              {createPeriod === "once" && active ? "Scan in progress" : "Create"}
            </button>
            <button onClick={() => void refresh()} className="rounded-lg border border-slate-600 px-3 py-2 text-sm hover:border-cyan-400">Refresh</button>
          </div>
        </div>
        {!jobs.length ? <p className="mt-5 text-sm text-slate-400">No scans yet.</p> : <div className="mt-4 overflow-x-auto rounded-lg border border-slate-700">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead className="bg-slate-950 text-xs uppercase tracking-wide text-slate-400"><tr>
              <th className="px-3 py-3">Scan</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Type</th><th className="px-3 py-3">Target</th><th className="px-3 py-3">Started</th><th className="px-3 py-3 text-right">Results</th>
            </tr></thead>
            <tbody className="divide-y divide-slate-800">{jobs.map((item) => <tr key={item.id} onClick={() => setSelected(item.id)}
              className={`cursor-pointer hover:bg-slate-800/70 ${job?.id === item.id ? "bg-cyan-950/40" : ""}`}>
              <td className="px-3 py-3 font-medium text-cyan-300">#{item.id}</td>
              <td className="px-3 py-3"><span className={`rounded-full px-2 py-1 text-xs font-medium ${statusColor(item.status)}`}>{statusLabel(item.status)}</span></td>
              <td className="px-3 py-3 capitalize text-slate-300">{item.trigger}</td>
              <td className="max-w-52 truncate px-3 py-3 text-slate-300">{item.config?.targets ?? "—"}</td>
              <td className="px-3 py-3 text-slate-400">{new Date(item.startedAt ?? item.createdAt).toLocaleString()}</td>
              <td className="px-3 py-3 text-right">{item.result?.scan?.result_count ?? item.result?.results?.length ?? 0}</td>
            </tr>)}</tbody>
          </table>
        </div>}
        {job && <div className="mt-6 border-t border-slate-700 pt-5 text-sm">
          <div className="flex flex-wrap items-center gap-3"><h3 className="text-lg font-semibold">Scan #{job.id} results</h3><span className={`rounded-full px-2 py-1 text-xs font-medium ${statusColor(job.status)}`}>{statusLabel(job.status)}</span></div>
          <p className="mt-2 text-slate-400">{job.trigger === "manual" ? "Manual" : job.trigger === "imported" ? "Imported" : "Scheduled"} · {new Date(job.createdAt).toLocaleString()}{job.result?.scan?.duration_seconds != null ? ` · ${job.result.scan.duration_seconds.toFixed(1)} seconds` : ""}</p>
          {job.config?.importSource && <p className="mt-1 text-slate-400">Source file: {job.config.importSource}</p>}
          {job.config && <p className="mt-1 text-slate-400">{job.config.targets} · {job.config.interface} · Ports {job.config.ports}</p>}
          {(job.status === "running" || job.status === "queued") && <p className="mt-3 text-cyan-300">{job.status === "queued" ? "Waiting to start…" : "Scanning now. Results will appear here when complete…"}</p>}
          {job.error && <p className="mt-3 rounded-lg bg-red-950 p-3 text-red-200">{job.error}</p>}
          {job.result && <>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg bg-slate-950 p-4"><p className="text-2xl font-semibold">{hosts.length}</p><p className="text-slate-400">Responding devices</p></div>
              <div className="rounded-lg bg-slate-950 p-4"><p className="text-2xl font-semibold">{job.result.scan?.result_count ?? results.length}</p><p className="text-slate-400">Service results</p></div>
            </div>
            <h4 className="mt-5 font-semibold">Responding devices</h4>
            <div className="mt-2 max-h-40 overflow-auto whitespace-pre-line rounded-lg bg-slate-950 p-3 font-mono text-xs">{hosts.length ? hosts.join("\n") : "No devices found"}</div>
            <h4 className="mt-5 font-semibold">Service results</h4>
            {!results.length ? <p className="mt-2 text-slate-400">No service results.</p> : <div className="mt-2 overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full min-w-[520px] text-left"><thead className="bg-slate-950 text-xs uppercase text-slate-400"><tr><th className="px-3 py-2">Host</th><th className="px-3 py-2">Port</th><th className="px-3 py-2">Status</th><th className="px-3 py-2">Models</th></tr></thead>
                <tbody className="divide-y divide-slate-800">{results.map((result, index) => <tr key={`${result.host}:${result.port}:${index}`}><td className="px-3 py-2 font-mono">{result.host}</td><td className="px-3 py-2 font-mono">{result.port}</td><td className="px-3 py-2 capitalize text-emerald-300">{result.status}</td><td className="px-3 py-2 text-slate-300">{result.models?.length ? result.models.join(", ") : "—"}</td></tr>)}</tbody>
              </table>
            </div>}
          </>}
        </div>}
      </div>}
      {tab === "discovery" && <DeviceDiscovery />}
    </section>
  );
}
