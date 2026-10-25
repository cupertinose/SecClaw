import { boolean, integer, jsonb, pgTable, serial, text, timestamp } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("user"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .defaultNow()
    .notNull(),
});

export const scanJobs = pgTable("scan_jobs", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("queued"),
  trigger: text("trigger").notNull(),
  requestedBy: integer("requested_by"),
  config: jsonb("config"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  error: text("error"),
  result: jsonb("result"),
});

export const scanSettings = pgTable("scan_settings", {
  id: integer("id").primaryKey(),
  enabled: boolean("enabled").notNull().default(false),
  intervalMinutes: integer("interval_minutes").notNull().default(60),
  config: jsonb("config"),
  nextRunAt: timestamp("next_run_at", { withTimezone: true }),
});

export const discoveryJobs = pgTable("discovery_jobs", {
  id: serial("id").primaryKey(),
  status: text("status").notNull().default("queued"),
  requestedBy: integer("requested_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  error: text("error"),
  result: jsonb("result"),
});

export const sshReports = pgTable("ssh_reports", {
  id: serial("id").primaryKey(),
  host: text("host").notNull(),
  requestedBy: integer("requested_by").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  evidence: text("evidence").notNull(),
  analysis: text("analysis"),
  analysisError: text("analysis_error"),
});
