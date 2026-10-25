import { isIP } from "node:net";

export type ScanConfig = {
  targets: string;
  ports: string;
  interface: string;
  arpInterval: number;
  jobs: number;
  timeout: number;
  https: boolean;
  openOnly: boolean;
  tcpFallback: boolean;
};

export const defaultScanConfig: ScanConfig = {
  targets: process.env.SCAN_TARGETS || "192.168.32.0/20",
  ports: process.env.SCAN_PORTS || "8000",
  interface: process.env.SCAN_INTERFACE || "wlP9s9",
  arpInterval: Number(process.env.SCAN_ARP_INTERVAL || 100),
  jobs: 32,
  timeout: 2,
  https: false,
  openOnly: false,
  tcpFallback: false,
};

export function parseScanConfig(value: unknown): ScanConfig {
  if (!value || typeof value !== "object") throw new Error("Missing scan parameters");
  const config = value as Record<string, unknown>;
  if (typeof config.targets !== "string" || !config.targets.trim()) throw new Error("Enter a target range");
  const targets = config.targets.split(",").map((part) => part.trim());
  let hostCount = 0;
  for (const target of targets) {
    const [address, mask, extra] = target.split("/");
    if (extra || isIP(address) !== 4 || (mask !== undefined && (!/^\d+$/.test(mask) || Number(mask) > 32))) {
      throw new Error("Targets must be IPv4 addresses or CIDRs separated by commas");
    }
    hostCount += mask === undefined ? 1 : 2 ** (32 - Number(mask));
  }
  if (hostCount > 4096) throw new Error("At most 4096 target addresses are allowed");

  if (typeof config.ports !== "string" || !config.ports.trim()) throw new Error("Enter TCP ports");
  const portParts = config.ports.split(",").map((part) => part.trim());
  let portCount = 0;
  for (const part of portParts) {
    const match = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!match) throw new Error("Ports must be numbers or ranges separated by commas");
    const first = Number(match[1]);
    const last = match[2] ? Number(match[2]) : first;
    if (first < 1 || last > 65535 || last < first) throw new Error("Invalid port range");
    portCount += last - first + 1;
  }
  if (portCount > 65535) throw new Error("Too many ports");
  if (typeof config.interface !== "string" || !/^[a-zA-Z0-9_.:-]{1,32}$/.test(config.interface)) {
    throw new Error("Invalid network interface");
  }
  if (!Number.isInteger(config.arpInterval) || (config.arpInterval as number) < 1 || (config.arpInterval as number) > 1000) {
    throw new Error("ARP interval must be 1–1000 ms");
  }
  if (!Number.isInteger(config.jobs) || (config.jobs as number) < 1 || (config.jobs as number) > 128) {
    throw new Error("Concurrent checks must be 1–128");
  }
  if (typeof config.timeout !== "number" || config.timeout <= 0 || config.timeout > 60) {
    throw new Error("Timeout must be greater than 0 and at most 60 seconds");
  }
  for (const field of ["https", "openOnly", "tcpFallback"] as const) {
    if (typeof config[field] !== "boolean") throw new Error(`Invalid ${field} option`);
  }
  return {
    targets: targets.join(","), ports: portParts.join(","), interface: config.interface,
    arpInterval: config.arpInterval as number, jobs: config.jobs as number,
    timeout: config.timeout, https: config.https as boolean, openOnly: config.openOnly as boolean,
    tcpFallback: config.tcpFallback as boolean,
  };
}
