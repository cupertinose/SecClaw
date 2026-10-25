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

## Database commands

```bash
npm run db:generate  # generate SQL migrations from src/db/schema.ts
npm run db:migrate   # apply generated migrations
npm run db:push      # sync schema directly during local development
npm run db:studio    # open Drizzle Studio
```

Copy `.env.example` to `.env.local` when setting up a fresh checkout. Node.js
20.19 or newer is recommended.
