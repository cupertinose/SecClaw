import { spawn } from "node:child_process";
import { readFile, unlink } from "node:fs/promises";
import postgres from "postgres";

const db = postgres(process.env.DATABASE_URL, { max: 1 });
const script = process.env.SCAN_SCRIPT || "/scripts/vllm_scan.sh";

async function runScan(id, config) {
  const output = `/tmp/secclaw-scan-${id}.json`;
  const args = [script, "-t", config.targets, "-p", config.ports,
    "--interface", config.interface, "--arp-interval", String(config.arpInterval),
    "--jobs", String(config.jobs), "--timeout", String(config.timeout), "-o", output];
  if (!config.tcpFallback) args.push("--no-tcp-fallback");
  if (config.https) args.push("--https");
  if (config.openOnly) args.push("--open-only");
  let log = "";
  try {
    const code = await new Promise((resolve, reject) => {
      const child = spawn("bash", args, { stdio: ["ignore", "ignore", "pipe"] });
      child.stderr.on("data", (chunk) => { log = (log + chunk.toString()).slice(-4000); });
      child.on("error", reject);
      child.on("close", resolve);
    });
    if (code !== 0) throw new Error(log.trim() || `Scanner exited with code ${code}`);
    const result = JSON.parse(await readFile(output, "utf8"));
    await db`update scan_jobs set status = 'completed', finished_at = now(), result = ${db.json(result)} where id = ${id}`;
  } catch (error) {
    await db`update scan_jobs set status = 'failed', finished_at = now(), error = ${String(error).slice(0, 4000)} where id = ${id}`;
  } finally {
    await unlink(output).catch(() => {});
  }
}

async function tick() {
  await db`insert into scan_settings (id, enabled, interval_minutes) values (1, false, 60) on conflict (id) do nothing`;
  await db`
    update scan_settings set next_run_at = now() + interval_minutes * interval '1 minute'
    where id = 1 and enabled and next_run_at is null
  `;
  const due = await db`
    update scan_settings set next_run_at = now() + interval_minutes * interval '1 minute'
    where id = 1 and enabled and next_run_at <= now()
      and not exists (select 1 from scan_jobs where status in ('queued', 'running'))
    returning id
  `;
  if (due.length) await db`
    insert into scan_jobs (status, trigger, config)
    select 'queued', 'scheduled', config from scan_settings where id = 1
  `;

  const jobs = await db`
    update scan_jobs set status = 'running', started_at = now()
    where id = (select id from scan_jobs where status = 'queued' order by id limit 1)
    returning id, config
  `;
  if (jobs.length) await runScan(jobs[0].id, jobs[0].config);
}

let recovered = false;
for (;;) {
  try {
    if (!recovered) {
      await db`update scan_jobs set status = 'failed', finished_at = now(), error = 'Scanner worker restarted' where status = 'running'`;
      recovered = true;
    }
    await tick();
  } catch (error) {
    console.error("scan worker:", error);
  }
  await new Promise((resolve) => setTimeout(resolve, 5000));
}
