"use client";

type ChartDevice = {
  host: string;
  ports: { port: number; status: string }[];
};

type ChartJob = {
  id: number;
  status: string;
  createdAt: string;
  result: {
    scan?: { result_count?: number; duration_seconds?: number };
    results?: { status: string }[];
  } | null;
};

type SecurityScores = {
  overallScore: number;
  devices: { host: string; score: number; riskLevel: string }[];
} | null;

const CHART_WIDTH = 520;

export default function DashboardCharts({
  devices,
  jobs,
  securityScores,
}: {
  devices: ChartDevice[];
  jobs: ChartJob[];
  securityScores: SecurityScores;
}) {
  const portCounts = new Map<number, number>();
  for (const device of devices) {
    for (const port of device.ports) {
      if (port.status === "open") portCounts.set(port.port, (portCounts.get(port.port) ?? 0) + 1);
    }
  }
  const topPorts = [...portCounts.entries()]
    .map(([port, count]) => ({ port, count }))
    .sort((a, b) => b.count - a.count || a.port - b.port)
    .slice(0, 6);

  const recentScans = jobs
    .filter((job) => job.status === "completed")
    .slice(0, 8)
    .reverse()
    .map((job) => ({
      id: job.id,
      date: new Date(job.createdAt),
      findings: job.result?.scan?.result_count ?? job.result?.results?.filter((item) => item.status === "open").length ?? 0,
    }));

  return (
    <div className="grid gap-4 xl:grid-cols-2" aria-label="Network security charts">
      <PortExposureChart ports={topPorts} deviceCount={devices.length} />
      {securityScores?.devices.length ? (
        <SecurityScoreChart scores={securityScores.devices} overall={securityScores.overallScore} />
      ) : (
        <ScanCoverageChart scans={recentScans} />
      )}
    </div>
  );
}

function PortExposureChart({ ports, deviceCount }: { ports: { port: number; count: number }[]; deviceCount: number }) {
  const height = 76 + Math.max(ports.length, 1) * 42;
  const max = Math.max(...ports.map((item) => item.count), 1);
  const plotLeft = 72;
  const plotWidth = CHART_WIDTH - plotLeft - 44;

  return (
    <figure className="rounded-xl border border-slate-700 bg-slate-950/55 p-5">
      <figcaption>
        <h3 className="font-semibold text-slate-100">Open-port exposure</h3>
        <p className="mt-1 text-sm text-slate-400">Most common open ports across {deviceCount} scanned {deviceCount === 1 ? "device" : "devices"}.</p>
      </figcaption>
      {ports.length ? (
        <svg className="mt-4 h-auto w-full" viewBox={`0 0 ${CHART_WIDTH} ${height}`} role="img" aria-label="Horizontal bar chart of devices by open port">
          {ports.map((item, index) => {
            const y = 18 + index * 42;
            const width = (item.count / max) * plotWidth;
            return (
              <g key={item.port}>
                <text x="0" y={y + 17} fill="currentColor" className="fill-slate-300 font-mono text-xs">:{item.port}</text>
                <rect x={plotLeft} y={y} width={plotWidth} height="22" rx="6" className="fill-slate-800" />
                <rect x={plotLeft} y={y} width={width} height="22" rx="6" className="fill-cyan-500" />
                <text x={Math.min(plotLeft + width + 9, CHART_WIDTH - 28)} y={y + 16} className="fill-slate-200 text-xs font-medium">{item.count}</text>
              </g>
            );
          })}
          <text x={plotLeft} y={height - 8} className="fill-slate-500 text-[11px]">Devices</text>
        </svg>
      ) : <EmptyChart message="No open ports recorded yet." />}
    </figure>
  );
}

function ScanCoverageChart({ scans }: { scans: { id: number; date: Date; findings: number }[] }) {
  const height = 250;
  const left = 40;
  const top = 24;
  const bottom = 48;
  const right = 18;
  const plotWidth = CHART_WIDTH - left - right;
  const plotHeight = height - top - bottom;
  const max = Math.max(...scans.map((scan) => scan.findings), 1);
  const x = (index: number) => left + (scans.length === 1 ? plotWidth / 2 : index * plotWidth / (scans.length - 1));
  const y = (value: number) => top + plotHeight - (value / max) * plotHeight;
  const points = scans.map((scan, index) => `${x(index)},${y(scan.findings)}`).join(" ");

  return (
    <figure className="rounded-xl border border-slate-700 bg-slate-950/55 p-5">
      <figcaption>
        <h3 className="font-semibold text-slate-100">Recent scan coverage</h3>
        <p className="mt-1 text-sm text-slate-400">Open results reported by the latest completed scans.</p>
      </figcaption>
      {scans.length ? (
        <svg className="mt-4 h-auto w-full" viewBox={`0 0 ${CHART_WIDTH} ${height}`} role="img" aria-label="Line chart of open results in recent scans">
          {[0, 0.5, 1].map((ratio) => {
            const gridY = top + plotHeight * ratio;
            return <line key={ratio} x1={left} x2={CHART_WIDTH - right} y1={gridY} y2={gridY} className="stroke-slate-800" />;
          })}
          {scans.length > 1 && <polyline points={points} fill="none" className="stroke-violet-400" strokeWidth="4" strokeLinejoin="round" strokeLinecap="round" />}
          {scans.map((scan, index) => <g key={scan.id}>
            <circle cx={x(index)} cy={y(scan.findings)} r="6" className="fill-violet-400 stroke-slate-950" strokeWidth="3" />
            <text x={x(index)} y={Math.max(y(scan.findings) - 12, 12)} textAnchor="middle" className="fill-slate-200 text-xs font-medium">{scan.findings}</text>
            <text x={x(index)} y={height - 26} textAnchor="middle" className="fill-slate-500 text-[11px]">#{scan.id}</text>
          </g>)}
          <text x={left} y={height - 7} className="fill-slate-500 text-[11px]">Scan</text>
        </svg>
      ) : <EmptyChart message="Complete a scan to see coverage over time." />}
    </figure>
  );
}

function SecurityScoreChart({ scores, overall }: { scores: { host: string; score: number; riskLevel: string }[]; overall: number }) {
  const visible = [...scores].sort((a, b) => a.score - b.score).slice(0, 6);
  const height = 76 + visible.length * 42;
  const plotLeft = 128;
  const plotWidth = CHART_WIDTH - plotLeft - 44;
  return (
    <figure className="rounded-xl border border-slate-700 bg-slate-950/55 p-5">
      <figcaption className="flex items-start justify-between gap-4">
        <div>
          <h3 className="font-semibold text-slate-100">Device security posture</h3>
          <p className="mt-1 text-sm text-slate-400">Lowest-scoring devices, ranked by generated score.</p>
        </div>
        <span className="shrink-0 rounded-full bg-violet-950 px-3 py-1 text-sm font-semibold text-violet-300">{overall}/100</span>
      </figcaption>
      <svg className="mt-4 h-auto w-full" viewBox={`0 0 ${CHART_WIDTH} ${height}`} role="img" aria-label="Horizontal bar chart of device security scores">
        {visible.map((item, index) => {
          const y = 18 + index * 42;
          return <g key={item.host}>
            <text x="0" y={y + 16} className="fill-slate-300 font-mono text-[11px]">{shortHost(item.host)}</text>
            <rect x={plotLeft} y={y} width={plotWidth} height="22" rx="6" className="fill-slate-800" />
            <rect x={plotLeft} y={y} width={plotWidth * item.score / 100} height="22" rx="6"
              className={item.score < 50 ? "fill-red-500" : item.score < 75 ? "fill-amber-400" : "fill-emerald-400"} />
            <text x={CHART_WIDTH - 4} y={y + 16} textAnchor="end" className="fill-slate-200 text-xs font-medium">{item.score}</text>
          </g>;
        })}
        <text x={plotLeft} y={height - 8} className="fill-slate-500 text-[11px]">Security score</text>
      </svg>
    </figure>
  );
}

function EmptyChart({ message }: { message: string }) {
  return <div className="mt-4 flex min-h-52 items-center justify-center rounded-lg bg-slate-900/70 px-6 text-center text-sm text-slate-500">{message}</div>;
}

function shortHost(host: string) {
  return host.length > 16 ? `${host.slice(0, 13)}…` : host;
}
