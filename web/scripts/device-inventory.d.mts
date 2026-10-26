import type postgres from "postgres";

type Sql = ReturnType<typeof postgres>;
export function storeScanDevices(db: Sql, jobId: number, result: unknown, seenAt?: Date): Promise<void>;
export function storeDiscoveredDevices(db: Sql, jobId: number, result: unknown, seenAt?: Date): Promise<void>;
