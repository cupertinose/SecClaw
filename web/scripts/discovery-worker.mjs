import { spawn } from "node:child_process";
import { config } from "dotenv";
import postgres from "postgres";
import { storeDiscoveredDevices } from "./device-inventory.mjs";

config({ path: ".env.local", quiet: true });
const db = postgres(process.env.DATABASE_URL, { max: 1 });
const iface = process.env.DISCOVERY_INTERFACE || "wlP9s9";

async function runDiscovery(id) {
  let stdout = "";
  let stderr = "";
  try {
    const code = await new Promise((resolve, reject) => {
      const child = spawn("/usr/bin/python3", ["scripts/discover-mdns.py", "--interface", iface, "--seconds", "8"],
        { stdio: ["ignore", "pipe", "pipe"] });
      child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
      child.stderr.on("data", (chunk) => { stderr = (stderr + chunk.toString()).slice(-4000); });
      child.on("error", reject);
      child.on("close", resolve);
    });
    if (code !== 0) throw new Error(stderr.trim() || `Discovery exited with code ${code}`);
    const result = JSON.parse(stdout);
    const finishedAt = new Date();
    await db.begin(async (tx) => {
      await storeDiscoveredDevices(tx, id, result, finishedAt);
      await tx`update discovery_jobs set status = 'completed', finished_at = ${finishedAt}, result = ${tx.json(result)} where id = ${id}`;
    });
  } catch (error) {
    await db`update discovery_jobs set status = 'failed', finished_at = now(), error = ${String(error).slice(0, 4000)} where id = ${id}`;
  }
}

let recovered = false;
for (;;) {
  try {
    if (!recovered) {
      await db`update discovery_jobs set status = 'failed', finished_at = now(), error = 'Discovery worker restarted' where status = 'running'`;
      recovered = true;
    }
    const jobs = await db`
      update discovery_jobs set status = 'running', started_at = now()
      where id = (select id from discovery_jobs where status = 'queued' order by id limit 1)
      returning id
    `;
    if (jobs.length) await runDiscovery(jobs[0].id);
  } catch (error) {
    console.error("discovery worker:", error);
  }
  await new Promise((resolve) => setTimeout(resolve, 5000));
}
