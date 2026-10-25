# SecClaw Web

Next.js application backed by PostgreSQL through Drizzle ORM.

## Local development

From the repository root, start the Docker services:

```bash
./scripts/start-db.sh   # PostgreSQL only
./scripts/start-web.sh  # Web and its PostgreSQL dependency
./scripts/start-all.sh  # Entire stack
```

The web container applies the Drizzle schema and imports `data/users.csv` every
time it starts. CSV passwords are hashed with bcrypt before they are stored.

For development without the web container:

```bash
cd web
npm install
npm run db:push
npm run dev
```

Open <http://localhost:3000>. The database health endpoint is available at
<http://localhost:3000/api/health>.

The login page is at <http://localhost:3000/login>. Set a strong, unique
`SESSION_SECRET` before deploying outside local development.

## Network scanner

Start the web app, scanner, and mDNS discovery worker with
`./scripts/start-web.sh` from the repository root. The discovery worker runs
as a systemd user service so it can read the host's Avahi service cache.
The scanner container uses the Linux host network and `NET_RAW` capability so
it can send ARP requests through `wlP9s9`. The scan form is prefilled with
`192.168.32.0/20`, interface `wlP9s9`, and TCP port `8000`; an admin can edit
these values for each manual scan or saved schedule.
The signed-in `sys_admin` dashboard can queue one scan and configure a schedule
from 15 minutes to 7 days. Jobs and results are stored in PostgreSQL, and
the separate scanner service keeps schedules running while the page is closed.

The **Device discovery** tab browses mDNS/Bonjour announcements on `wlP9s9`
and lists unique advertised IPv4 addresses, names, and services. It can find
devices on other routed subnets, but the list is not a complete count of
connected Wi-Fi clients. Set `DISCOVERY_INTERFACE` for the user service if needed.

Import an existing scanner JSON report as a completed dashboard job with:

```bash
cd web
DATABASE_URL=postgresql://secclaw:secclaw_dev@127.0.0.1:5432/secclaw \
  npm run db:import-scan -- ../scan_20261025_141359.json
```

Re-importing a report with the same scan start time does not create a duplicate.

## Database commands

```bash
npm run db:generate  # generate SQL migrations from src/db/schema.ts
npm run db:migrate   # apply generated migrations
npm run db:push      # sync schema directly during local development
npm run db:studio    # open Drizzle Studio
```

Copy `.env.example` to `.env.local` when setting up a fresh checkout. Node.js
20.19 or newer is recommended.
