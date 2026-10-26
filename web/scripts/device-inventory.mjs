function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length))];
}

export async function storeScanDevices(db, jobId, result, seenAt = new Date()) {
  const byIp = new Map();
  for (const ip of result?.scan?.host_discovery?.online_hosts ?? []) {
    if (ip) byIp.set(ip, { ports: [] });
  }
  for (const service of result?.results ?? []) {
    if (!service?.host) continue;
    const device = byIp.get(service.host) ?? { ports: [] };
    if (Number.isInteger(service.port)) device.ports.push({
      port: service.port,
      status: service.status ?? "unknown",
      models: uniqueStrings(service.models ?? []),
    });
    byIp.set(service.host, device);
  }
  for (const [ip, device] of byIp) {
    const observation = { source: "scan", jobId, seenAt: seenAt.toISOString(), ports: device.ports };
    await db`
      insert into devices (ip, ports, observations, first_seen_at, last_seen_at, last_scan_id)
      values (${ip}, ${db.json(device.ports)}, ${db.json([observation])}, ${seenAt}, ${seenAt}, ${jobId})
      on conflict (ip) do update set
        ports = excluded.ports,
        observations = devices.observations || excluded.observations,
        last_seen_at = greatest(devices.last_seen_at, excluded.last_seen_at),
        last_scan_id = excluded.last_scan_id
    `;
  }
}

export async function storeDiscoveredDevices(db, jobId, result, seenAt = new Date()) {
  for (const discovered of result?.devices ?? []) {
    if (!discovered?.ip) continue;
    const names = uniqueStrings(discovered.names ?? []);
    const services = (discovered.services ?? []).filter(Boolean);
    const ports = services.flatMap((service) =>
      typeof service === "object" && Number.isInteger(service.port)
        ? [{ port: service.port, status: "advertised", models: service.name ? [service.name] : [] }]
        : []);
    const observation = { source: "discovery", jobId, seenAt: seenAt.toISOString(), hostname: discovered.hostname ?? null, names, services };
    await db`
      insert into devices (ip, hostname, names, ports, services, observations, first_seen_at, last_seen_at, last_discovery_id)
      values (${discovered.ip}, ${discovered.hostname ?? null}, ${db.json(names)}, ${db.json(ports)}, ${db.json(services)}, ${db.json([observation])}, ${seenAt}, ${seenAt}, ${jobId})
      on conflict (ip) do update set
        hostname = coalesce(excluded.hostname, devices.hostname),
        names = excluded.names,
        services = excluded.services,
        ports = case when jsonb_array_length(devices.ports) = 0 then excluded.ports else devices.ports end,
        observations = devices.observations || excluded.observations,
        last_seen_at = greatest(devices.last_seen_at, excluded.last_seen_at),
        last_discovery_id = excluded.last_discovery_id
    `;
  }
}
