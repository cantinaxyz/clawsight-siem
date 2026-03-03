/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/prisma.ts.
 */
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@prisma/client";
import { Pool } from "pg";

const globalForPrisma = globalThis as unknown as {
  __clawsightPrisma?: PrismaClient;
  __clawsightPgPool?: Pool;
  __clawsightPgAdapter?: PrismaPg;
};

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error("Missing DATABASE_URL for Prisma client initialization.");
}

const pool =
  globalForPrisma.__clawsightPgPool ??
  new Pool({
    connectionString,
  });

const adapter =
  globalForPrisma.__clawsightPgAdapter ??
  new PrismaPg(pool);

export const prisma =
  globalForPrisma.__clawsightPrisma ??
  new PrismaClient({
    adapter,
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.__clawsightPrisma = prisma;
  globalForPrisma.__clawsightPgPool = pool;
  globalForPrisma.__clawsightPgAdapter = adapter;
}
