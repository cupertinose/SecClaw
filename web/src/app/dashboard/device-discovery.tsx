"use client";

import { useCallback, useEffect, useState } from "react";

type DiscoveredService = string | { name: string; port: number };
type Device = { ip: string; hostname: string | null; names: string[]; services: DiscoveredService[] };
type ScannedDevice = {
  host: string;
  hostname: string | null;
  ports: { port: number; status: string }[];
};
type DiscoveryJob = {
  id: number;
  status: string;
  createdAt: string;
  finishedAt: string | null;
  error: string | null;
  result: { source: string; interface: string; devices: Device[] } | null;
};

type Props = {
  scannedDevices: ScannedDevice[];
  sshTargetIp: string | null;
  remediationBusyHost: string | null;
  sshBusyHost: string | null;
  onSendRemediation: (host: string) => void;
  onGenerateSecurityReport: (host: string) => void;
};

function formatService(service: DiscoveredService) {
  return typeof service === "string" ? service : `${service.name} (${service.port})`;
}

export default function DeviceDiscovery({
  scannedDevices,
  sshTargetIp,
  remediationBusyHost,
  sshBusyHost,
  onSendRemediation,
  onGenerateSecurityReport,
}: Props) {
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
      <h2 className="text-xl font-semibold">Scanned device actions</h2>
      <p className="mt-1 text-sm text-slate-400">{scannedDevices.length} devices across completed scans and discoveries. Generate reports or send remediation guidance for devices with observed open ports.</p>
      <div className="mt-4 space-y-3">{scannedDevices.map((device) => {
        const openPorts = device.ports.filter((port) => port.status === "open");
        const canGenerateSecurityReport = device.host === sshTargetIp && openPorts.some((port) => port.port === 22);
        return <div key={device.host} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
          <div><p className="font-mono text-cyan-300">{device.host}</p>{device.hostname && <p className="mt-1 text-xs text-slate-300">{device.hostname}</p>}<p className="mt-1 text-xs text-slate-400">{openPorts.length ? `Open ports: ${openPorts.map((port) => port.port).join(", ")}` : "No observed open ports"}</p></div>
          <div className="flex flex-wrap gap-2">
            {!!openPorts.length && <button disabled={remediationBusyHost !== null} onClick={() => onSendRemediation(device.host)}
              className="rounded border border-amber-600 px-3 py-1 text-xs text-amber-200 hover:bg-amber-950 disabled:opacity-50">
              {remediationBusyHost === device.host ? "Generating and sending…" : "Send remediation"}
            </button>}
            {canGenerateSecurityReport && <button disabled={sshBusyHost !== null} onClick={() => onGenerateSecurityReport(device.host)}
              className="rounded border border-cyan-600 px-3 py-1 text-xs text-cyan-200 hover:bg-cyan-950 disabled:opacity-50">
              {sshBusyHost === device.host ? "Generating report…" : "OpenShell security report"}
            </button>}
          </div>
        </div>;
      })}</div>
      {!scannedDevices.length && <p className="mt-4 text-sm text-slate-400">No scanned devices yet.</p>}
    </div>

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
                  <td className="p-2 text-slate-400">{device.services.map(formatService).join(", ")}</td>
                </tr>)}</tbody>
            </table>
          </div>
        </>}
      </div>}
    </div>
  </div>;
}
