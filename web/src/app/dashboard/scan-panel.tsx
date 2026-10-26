"use client";

import { useCallback, useEffect, useState } from "react";
import DashboardCharts from "./dashboard-charts";
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
  hostname: string | null;
  names: string[];
  lastSeenAt: string;
  lastScanId: number;
  ports: { port: number; status: string; models: string[]; lastSeenAt: string; scanId: number }[];
};
type SshReport = { id: number; host: string; createdAt: string; evidence: string; analysis: string | null; analysisError: string | null };
type SecurityScores = {
  overallScore: number;
  overallSummary: string;
  devices: { host: string; score: number; riskLevel: string; summary: string; recommendations: string[] }[];
};
type PendingScan = { config: Config; period: string };
type OpenShellRuntime = {
  available: boolean;
  gateway: string | null;
  server: string | null;
  status: string | null;
  authentication: string | null;
  version: string | null;
  checkedAt: string;
  error: string | null;
  sandboxes: {
    id: string; name: string; phase: string; workspace: string; createdAt: string | null;
    policyVersion: number | null; configurationState: string | null; ready: boolean;
  }[];
};

export default function ScanPanel() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [defaults, setDefaults] = useState<Config | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"devices" | "scans" | "discovery" | "openshell">("devices");
  const [deviceFilter, setDeviceFilter] = useState("");
  const [createPeriod, setCreatePeriod] = useState("once");
  const [sshBusyHost, setSshBusyHost] = useState<string | null>(null);
  const [sshResult, setSshResult] = useState("");
  const [sshReports, setSshReports] = useState<SshReport[]>([]);
  const [sshTargetIp, setSshTargetIp] = useState<string | null>(null);
  const [remediationBusyHost, setRemediationBusyHost] = useState<string | null>(null);
  const [remediationResult, setRemediationResult] = useState("");
  const [securityScores, setSecurityScores] = useState<SecurityScores | null>(null);
  const [securityScoresBusy, setSecurityScoresBusy] = useState(false);
  const [pendingScan, setPendingScan] = useState<PendingScan | null>(null);
  const [openShellRuntime, setOpenShellRuntime] = useState<OpenShellRuntime | null>(null);

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/scans", { cache: "no-store" });
      if (!response.ok) throw new Error("Could not load scan status");
      const data = await response.json();
      setJobs(data.jobs);
      setDevices(data.devices ?? []);
      setDefaults(data.defaults);
      const reportResponse = await fetch("/api/openshell", { cache: "no-store" });
      if (reportResponse.ok) {
        const reportData = await reportResponse.json();
        setSshReports(reportData.reports ?? []);
        setSshTargetIp(reportData.targetIp ?? null);
        setOpenShellRuntime(reportData.runtime ?? null);
      }
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
    setPendingScan({ config: { ...defaults }, period: createPeriod });
  }
  function updatePendingConfig<K extends keyof Config>(field: K, value: Config[K]) {
    setPendingScan((current) => current ? {
      ...current,
      config: { ...current.config, [field]: value },
    } : null);
  }
  function confirmScan() {
    if (!pendingScan) return;
    const { config, period } = pendingScan;
    setPendingScan(null);
    if (period === "once") {
      void update("POST", { config });
      return;
    }
    void update("PUT", { enabled: true, intervalMinutes: Number(period), config });
  }

  async function verifySsh(host: string) {
    setSshBusyHost(host);
    setSshResult("");
    try {
      const response = await fetch("/api/openshell", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host }),
      });
      const data = await response.json();
      setSshResult(response.ok ? `${host}: Security report generated` : `${host}: ${data.error}`);
      if (response.ok) await refresh();
    } catch {
      setSshResult(`${host}: Could not contact the web server`);
    } finally {
      setSshBusyHost(null);
    }
  }

  async function sendRemediation(host: string) {
    setRemediationBusyHost(host);
    setRemediationResult("");
    try {
      const response = await fetch("/api/remediation", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ host }),
      });
      const data = await response.json();
      setRemediationResult(response.ok ? `${host}: Remediation steps sent to Discord (${data.messagesSent} message${data.messagesSent === 1 ? "" : "s"}).` : `${host}: ${data.error}`);
    } catch {
      setRemediationResult(`${host}: Could not contact the web server`);
    } finally {
      setRemediationBusyHost(null);
    }
  }

  async function generateSecurityScores() {
    setSecurityScoresBusy(true);
    setError("");
    try {
      const response = await fetch("/api/security-scores", { method: "POST" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not generate security scores");
      setSecurityScores(data);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSecurityScoresBusy(false);
    }
  }

  return (
    <section className="mt-8 space-y-6">
      <div role="tablist" aria-label="Scan sections" className="flex flex-wrap gap-2 border-b border-slate-700 pb-3">
        {([ ["devices", "Dashboard"], ["scans", "Scans"], ["discovery", "Devices"], ["openshell", "OpenShell"] ] as const).map(([key, label]) =>
          <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
            className={`rounded-lg px-4 py-2 ${tab === key ? "bg-cyan-700 text-white" : "bg-slate-800 text-slate-300 hover:bg-slate-700"}`}>
            {label}{key === "scans" && active ? " · In progress" : ""}
          </button>)}
      </div>
      {error && <p role="alert" className="rounded-lg bg-red-950 p-3 text-red-200">{error}</p>}
      {sshResult && <p role="status" className="rounded-lg bg-slate-800 p-3 text-slate-100">{sshResult}</p>}
      {remediationResult && <p role="status" className="rounded-lg bg-slate-800 p-3 text-slate-100">{remediationResult}</p>}

      {pendingScan && <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="presentation">
        <form role="dialog" aria-modal="true" aria-labelledby="scan-confirm-title"
          onSubmit={(event) => { event.preventDefault(); confirmScan(); }}
          className="w-full max-w-lg rounded-xl border border-slate-600 bg-slate-900 p-6 shadow-2xl">
          <h2 id="scan-confirm-title" className="text-xl font-semibold">Confirm scan parameters</h2>
          <p className="mt-2 text-sm text-slate-400">Review or change these settings before the scan action is created.</p>
          <div className="mt-4 rounded-lg bg-slate-950/70 p-3 text-sm text-slate-300">
            <span className="text-slate-500">Action</span><span className="ml-3">{pendingScan.period === "once" ? "Run one scan · Once" : `Create recurring scan · Every ${pendingScan.period} minutes`}</span>
          </div>
          <div className="mt-4 grid max-h-[60vh] gap-4 overflow-y-auto pr-1 sm:grid-cols-2">
            <label className="text-sm text-slate-300 sm:col-span-2">Target
              <input autoFocus required value={pendingScan.config.targets}
                onChange={(event) => updatePendingConfig("targets", event.target.value)}
                placeholder="192.168.32.0/20"
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2 font-mono" />
              <span className="mt-1 block text-xs text-slate-500">IPv4 addresses or CIDRs, separated by commas</span>
            </label>
            <label className="text-sm text-slate-300 sm:col-span-2">Ports
              <input required value={pendingScan.config.ports}
                onChange={(event) => updatePendingConfig("ports", event.target.value)}
                placeholder="8000 or 8000-8010,8080"
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2 font-mono" />
            </label>
            <label className="text-sm text-slate-300">Interface
              <input required value={pendingScan.config.interface}
                onChange={(event) => updatePendingConfig("interface", event.target.value)}
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2 font-mono" />
            </label>
            <label className="text-sm text-slate-300">ARP interval (ms)
              <input required type="number" min="1" max="1000" value={pendingScan.config.arpInterval}
                onChange={(event) => updatePendingConfig("arpInterval", event.target.valueAsNumber)}
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2" />
            </label>
            <label className="text-sm text-slate-300">Workers
              <input required type="number" min="1" max="128" step="1" value={pendingScan.config.jobs}
                onChange={(event) => updatePendingConfig("jobs", event.target.valueAsNumber)}
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2" />
            </label>
            <label className="text-sm text-slate-300">Timeout (seconds)
              <input required type="number" min="0.1" max="60" step="0.1" value={pendingScan.config.timeout}
                onChange={(event) => updatePendingConfig("timeout", event.target.valueAsNumber)}
                className="mt-1 block w-full rounded border border-slate-600 bg-slate-800 p-2" />
            </label>
            <fieldset className="sm:col-span-2">
              <legend className="text-sm text-slate-300">Options</legend>
              <div className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-sm">
                <label className="flex items-center gap-2"><input type="checkbox" checked={pendingScan.config.https}
                  onChange={(event) => updatePendingConfig("https", event.target.checked)} /> HTTPS</label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={pendingScan.config.openOnly}
                  onChange={(event) => updatePendingConfig("openOnly", event.target.checked)} /> Open ports only</label>
                <label className="flex items-center gap-2"><input type="checkbox" checked={pendingScan.config.tcpFallback}
                  onChange={(event) => updatePendingConfig("tcpFallback", event.target.checked)} /> TCP fallback</label>
              </div>
            </fieldset>
          </div>
          <div className="mt-6 flex justify-end gap-3">
            <button type="button" onClick={() => setPendingScan(null)}
              className="rounded-lg border border-slate-600 px-4 py-2 hover:border-slate-400">Cancel</button>
            <button type="submit"
              className="rounded-lg bg-cyan-600 px-4 py-2 font-medium hover:bg-cyan-500">
              {pendingScan.period === "once" ? "Confirm and run" : "Confirm schedule"}
            </button>
          </div>
        </form>
      </div>}

      {tab === "devices" && <div className="rounded-xl border border-slate-700 p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h2 className="text-xl font-semibold">Scanned devices and ports</h2>
            <p className="mt-1 text-sm text-slate-400">
              {devices.length} {devices.length === 1 ? "device" : "devices"} found across completed scans and discoveries. Latest result shown per port.
            </p>
          </div>
          <label className="text-sm text-slate-300">Filter devices or ports
            <input value={deviceFilter} onChange={(event) => setDeviceFilter(event.target.value)} placeholder="IP, port, status, or model"
              className="mt-1 block w-64 max-w-full rounded border border-slate-600 bg-slate-800 p-2" />
          </label>
        </div>
        <div className="mt-5">
          <DashboardCharts devices={devices} jobs={jobs} securityScores={securityScores} />
        </div>
        <div className="mt-4 rounded-lg border border-slate-700 bg-slate-950/60 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="font-semibold">vLLM security scores</h3>
              <p className="mt-1 text-sm text-slate-400">AI-assisted posture estimates based only on the latest stored scan observations.</p>
            </div>
            <button disabled={securityScoresBusy || !devices.length} onClick={() => void generateSecurityScores()}
              className="rounded-lg bg-violet-700 px-4 py-2 text-sm font-medium hover:bg-violet-600 disabled:opacity-50">
              {securityScoresBusy ? "Generating scores…" : securityScores ? "Refresh scores" : "Generate security scores"}
            </button>
          </div>
          {securityScores && <div className="mt-4 space-y-3">
            <div className="flex items-center gap-4">
              <span className="text-3xl font-bold text-violet-300">{securityScores.overallScore}/10</span>
              <p className="text-sm text-slate-300">{securityScores.overallSummary}</p>
            </div>
            <div className="grid gap-3 lg:grid-cols-2">{securityScores.devices.map((score) => <div key={score.host} className="rounded-lg border border-slate-800 p-3">
              <div className="flex items-center justify-between gap-2"><span className="font-mono text-cyan-300">{score.host}</span><span className="font-semibold">{score.score}/10 · {score.riskLevel}</span></div>
              <p className="mt-2 text-sm text-slate-300">{score.summary}</p>
              {!!score.recommendations.length && <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-400">{score.recommendations.map((item) => <li key={item}>{item}</li>)}</ul>}
            </div>)}</div>
            <p className="text-xs text-slate-500">These scores are advisory estimates, not vulnerability findings.</p>
          </div>}
        </div>
        <div className="mt-5 space-y-3">
          {visibleDevices.map((device) => <article key={device.host} className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div><h3 className="font-mono text-base font-semibold text-cyan-300">{device.host}</h3>
                {device.hostname && <p className="mt-1 text-sm text-slate-400">{device.hostname}</p>}
              </div>
              <div className="flex items-center gap-3">
                <p className="text-xs text-slate-400">Last seen {new Date(device.lastSeenAt).toLocaleString()} · Scan #{device.lastScanId}</p>
              </div>
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
            {sshReports.filter((report) => report.host === device.host).slice(0, 1).map((report) =>
              <div key={report.id} className="mt-4 space-y-3 rounded-lg border border-slate-700 p-4 text-sm">
                <h4 className="font-semibold">安全报告 #{report.id} · {new Date(report.createdAt).toLocaleString()}</h4>
                <details><summary className="cursor-pointer text-cyan-300">查看 OpenShell 原始观测</summary>
                  <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-slate-900 p-3">{report.evidence}</pre></details>
                <div className="whitespace-pre-wrap text-slate-200">{report.analysis ?? `模型分析不可用：${report.analysisError ?? "未知错误"}`}</div>
              </div>)}
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
      {tab === "openshell" && <div className="space-y-5 rounded-xl border border-slate-700 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold">OpenShell runtime</h2>
            <p className="mt-1 text-sm text-slate-400">Live gateway and sandbox state. Refreshed every five seconds.</p>
          </div>
          <button onClick={() => void refresh()} className="rounded-lg border border-slate-600 px-3 py-2 text-sm hover:border-cyan-400">Refresh</button>
        </div>
        {!openShellRuntime ? <p className="rounded-lg bg-slate-950 p-4 text-slate-400">Loading OpenShell status…</p> : <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg bg-slate-950 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Gateway</p><p className="mt-2 font-semibold">{openShellRuntime.gateway ?? "—"}</p></div>
            <div className="rounded-lg bg-slate-950 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Status</p><p className={`mt-2 font-semibold ${openShellRuntime.available ? "text-emerald-300" : "text-red-300"}`}>{openShellRuntime.status ?? "Unknown"}</p></div>
            <div className="rounded-lg bg-slate-950 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Version</p><p className="mt-2 font-semibold">{openShellRuntime.version ?? "—"}</p></div>
            <div className="rounded-lg bg-slate-950 p-4"><p className="text-xs uppercase tracking-wide text-slate-500">Sandboxes</p><p className="mt-2 text-2xl font-semibold">{openShellRuntime.sandboxes.length}</p></div>
          </div>
          <dl className="grid gap-3 rounded-lg border border-slate-700 p-4 text-sm sm:grid-cols-[10rem_1fr]">
            <dt className="text-slate-400">Server</dt><dd className="break-all font-mono">{openShellRuntime.server ?? "—"}</dd>
            <dt className="text-slate-400">Authentication</dt><dd>{openShellRuntime.authentication ?? "—"}</dd>
            <dt className="text-slate-400">Configured SSH target</dt><dd className="font-mono">{sshTargetIp ?? "Not configured"}</dd>
            <dt className="text-slate-400">Last checked</dt><dd>{new Date(openShellRuntime.checkedAt).toLocaleString()}</dd>
          </dl>
          {openShellRuntime.error && <p role="alert" className="rounded-lg bg-red-950 p-3 text-red-200">{openShellRuntime.error}</p>}
          <div>
            <h3 className="font-semibold">Running sandboxes</h3>
            {!openShellRuntime.sandboxes.length ? <p className="mt-3 rounded-lg bg-slate-950 p-4 text-sm text-slate-400">No sandboxes found.</p> :
              <div className="mt-3 overflow-x-auto rounded-lg border border-slate-700">
                <table className="w-full min-w-[680px] text-left text-sm">
                  <thead className="bg-slate-950 text-xs uppercase tracking-wide text-slate-400"><tr><th className="px-3 py-3">Name</th><th className="px-3 py-3">Phase</th><th className="px-3 py-3">Ready</th><th className="px-3 py-3">Workspace</th><th className="px-3 py-3">Policy</th><th className="px-3 py-3">Created</th></tr></thead>
                  <tbody className="divide-y divide-slate-800">{openShellRuntime.sandboxes.map((sandbox) => <tr key={sandbox.id || sandbox.name}>
                    <td className="px-3 py-3 font-mono text-cyan-300">{sandbox.name}</td>
                    <td className="px-3 py-3"><span className={`rounded-full px-2 py-1 text-xs ${sandbox.phase === "Ready" ? "bg-emerald-950 text-emerald-300" : "bg-amber-950 text-amber-300"}`}>{sandbox.phase}</span></td>
                    <td className="px-3 py-3">{sandbox.ready ? "Yes" : "No"}</td>
                    <td className="px-3 py-3">{sandbox.workspace}</td>
                    <td className="px-3 py-3">v{sandbox.policyVersion ?? "—"} · {sandbox.configurationState ?? "unknown"}</td>
                    <td className="px-3 py-3 text-slate-400">{sandbox.createdAt ? new Date(`${sandbox.createdAt}Z`).toLocaleString() : "—"}</td>
                  </tr>)}</tbody>
                </table>
              </div>}
          </div>
          <div>
            <h3 className="font-semibold">Recent SSH reports</h3>
            <p className="mt-2 text-sm text-slate-400">{sshReports.length ? `${sshReports.length} stored report${sshReports.length === 1 ? "" : "s"}.` : "No successful SSH reports yet."}</p>
          </div>
        </>}
      </div>}
      {tab === "discovery" && <DeviceDiscovery
        scannedDevices={devices}
        sshTargetIp={sshTargetIp}
        remediationBusyHost={remediationBusyHost}
        sshBusyHost={sshBusyHost}
        onSendRemediation={(host) => void sendRemediation(host)}
        onGenerateSecurityReport={(host) => void verifySsh(host)}
      />}
    </section>
  );
}
