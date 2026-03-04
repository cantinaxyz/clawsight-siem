import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const repoRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@": path.join(repoRoot, "src"),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["node_modules/**", ".next/**"],
  },
});
