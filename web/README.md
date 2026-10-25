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

## Discord remediation messages

Set `SECCLAW_DISCORD_WEBHOOK` in the web server environment to a Discord channel
webhook URL. Set `VLLM_HOST` (default `http://127.0.0.1:8000`) and `VLLM_MODEL`
(default `gpt-oss-120b`) so the web server can reach the local vLLM API. The
**Send remediation** button on a scanned device with an open port generates
defensive steps from its latest per-port observations and sends them to that
Discord channel. Only `sys_admin` users can use it. The webhook URL stays on
the server and is never returned to the browser. Configure it in an untracked
environment file or service environment, not in source control.
For Docker Compose, put it in a root `.env` file or export it before running
`./scripts/start-web.sh`; Compose forwards it into the web container and uses
`host.docker.internal:8000` for host-run vLLM by default.

The message is advisory. It does not change device settings or assert that an
open port is a confirmed vulnerability.

## OpenShell SSH reports

The dashboard offers **OpenShell 生成安全报告** for scanned devices with port 22
open. The action is restricted to `sys_admin` and to the single IP configured in
`OPENSHELL_SSH_TARGET_IP`. A Python SSH client runs inside an OpenShell sandbox,
checks the pinned SSH host key, logs in as `dell`, and runs a fixed set of
read-only inventory commands. The web server stores the evidence, sends it to
the local vLLM model, and displays the model's suggested remediation and
validation steps. It never applies those steps automatically.

The local setup uses [OpenShell](https://github.com/NVIDIA/OpenShell) 0.1.5,
the `secclaw-ssh` sandbox, [Dockerfile.openshell-ssh](Dockerfile.openshell-ssh),
and [openshell-ssh-policy.yaml](openshell-ssh-policy.yaml). Build the web image
first, then build the sandbox image and create the sandbox:

```bash
docker compose build web
docker build -t secclaw-openshell-ssh:local -f web/Dockerfile.openshell-ssh web
openshell sandbox create --name secclaw-ssh --from secclaw-openshell-ssh:local \
  --policy web/openshell-ssh-policy.yaml --detach
```

OpenShell's native TCP policy requires a DNS hostname. This configuration uses
an exact `sslip.io` name and pins its resolved address to `192.168.43.161/32`.
For another target, update both the policy and `compose.override.yaml`, and
pin that target's verified SSH host key fingerprint. The policy permits only
the sandbox's Python binary to reach TCP port 22.

The Compose override mounts the host OpenShell CLI and client configuration
into the web container and uses host networking for the local gateway and
vLLM. Set `OPENSHELL_SSH_PASSWORD` in the ignored root `.env` file. Never commit
the password. A failed SSH authentication produces no report.

## Database commands

```bash
npm run db:generate  # generate SQL migrations from src/db/schema.ts
npm run db:migrate   # apply generated migrations
npm run db:push      # sync schema directly during local development
npm run db:studio    # open Drizzle Studio
```

Copy `.env.example` to `.env.local` when setting up a fresh checkout. Node.js
20.19 or newer is recommended.
