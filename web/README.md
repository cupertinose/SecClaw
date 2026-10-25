# SecClaw Web

Next.js application backed by PostgreSQL through Drizzle ORM.

## Local development

From the repository root, start PostgreSQL:

```bash
docker compose up -d postgres
```

Then start Next.js:

```bash
cd web
npm install
npm run db:push
npm run dev
```

Open <http://localhost:3000>. The database health endpoint is available at
<http://localhost:3000/api/health>.

## Database commands

```bash
npm run db:generate  # generate SQL migrations from src/db/schema.ts
npm run db:migrate   # apply generated migrations
npm run db:push      # sync schema directly during local development
npm run db:studio    # open Drizzle Studio
```

Copy `.env.example` to `.env.local` when setting up a fresh checkout. Node.js
20.19 or newer is recommended.
