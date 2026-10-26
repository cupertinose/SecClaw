import { config } from "dotenv";
import postgres from "postgres";
import { storeDiscoveredDevices, storeScanDevices } from "./device-inventory.mjs";

config({ path: ".env.local", quiet: true });
const db = postgres(process.env.DATABASE_URL, { max: 1 });

try {
  const observations = await db`
    select 'scan' as source, id, coalesce(finished_at, created_at) as seen_at, result
      from scan_jobs where status = 'completed' and result is not null
    union all
    select 'discovery' as source, id, coalesce(finished_at, created_at) as seen_at, result
      from discovery_jobs where status = 'completed' and result is not null
    order by seen_at asc
  `;
  await db`truncate table devices`;
  for (const observation of observations) {
    if (observation.source === "scan") {
      await storeScanDevices(db, observation.id, observation.result, observation.seen_at);
    } else {
      await storeDiscoveredDevices(db, observation.id, observation.result, observation.seen_at);
    }
  }
  const [{ count }] = await db`select count(*)::int as count from devices`;
  console.log(`Backfilled ${count} devices from ${observations.length} completed jobs.`);
} finally {
  await db.end();
}
