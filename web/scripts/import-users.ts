import { readFile } from "node:fs/promises";
import path from "node:path";

import { hash } from "bcryptjs";
import { parse } from "csv-parse/sync";
import { config } from "dotenv";

type CsvUser = {
  name: string;
  email: string;
  pass: string;
  role: string;
};

async function main() {
  config({ path: ".env.local" });
  const [{ db }, { users }] = await Promise.all([
    import("../src/db"),
    import("../src/db/schema"),
  ]);
  const csvPath =
    process.env.USER_CSV_PATH ?? path.join(process.cwd(), "../data/users.csv");
  const csv = await readFile(csvPath, "utf8");
  const records = parse(csv, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
  }) as CsvUser[];

  for (const record of records) {
    if (!record.name || !record.email || !record.pass || !record.role) {
      throw new Error(`Invalid user row for ${record.email || "unknown email"}`);
    }

    const passwordHash = await hash(record.pass, 12);
    const email = record.email.toLowerCase();

    await db
      .insert(users)
      .values({
        name: record.name,
        email,
        passwordHash,
        role: record.role,
      })
      .onConflictDoUpdate({
        target: users.email,
        set: {
          name: record.name,
          passwordHash,
          role: record.role,
        },
      });
  }

  console.log(`Imported ${records.length} user(s) from ${csvPath}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
