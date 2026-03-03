/**
 * @fileoverview ClawSight SIEM module: platform/src/lib/prisma.ts.
 */
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  __clawsightPrisma?: PrismaClient;
};

export const prisma =
  globalForPrisma.__clawsightPrisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.__clawsightPrisma = prisma;
}
