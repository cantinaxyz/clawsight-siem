# Repository Guidelines

## Project Scope

This guide applies to the `platform/` project (ClawSight SIEM).

## Project Structure and Module Organization

- `src/app/`: Next.js App Router pages and route handlers.
- `src/app/api/`: HTTP API surface (telemetry ingest, events, executions, traces, alerts, safety, agents).
- `src/lib/`: shared server logic (normalization, detection, policy, intent, Prisma, query mappers).
- `src/components/`: reusable UI components used across pages.
- `prisma/schema.prisma`: database schema and indexes.
- `docs/`: product and operational documentation.

Keep changes localized. Do not edit generated artifacts (`.next/`, `node_modules/`, `*.tsbuildinfo`).

## Build, Test, and Development Commands

Run from repo root with `pnpm -C platform ...` or from inside `platform/`.

- `pnpm -C platform dev`: start local Next.js server.
- `pnpm -C platform lint`: run ESLint with zero warnings.
- `pnpm -C platform typecheck`: run `tsc --noEmit`.
- `pnpm -C platform build`: Prisma generate + production build.
- `pnpm -C platform exec next typegen`: regenerate route types after route changes.

## Coding Style and Naming Conventions

- Use strict TypeScript patterns; prefer explicit types at API boundaries.
- Use `camelCase` for variables/functions and `PascalCase` for types/components.
- Keep route handlers in `route.ts` files.
- Keep telemetry field names stable (`requestId`, `category`, `action`, `severity`, `result`, `outcome`).
- Prefer small, pure helpers in `src/lib/` over duplicating route-level logic.

## Testing Guidelines

- Minimum quality gate: `lint` and `typecheck`.
- For API behavior changes, include a simple manual smoke example in PR notes (for example ingest payload and expected response).

## Commit and Pull Request Guidelines

- Keep commits focused and descriptive.
- Conventional commit style is recommended:
  - `feat(siem): add agent filter to executions query`
  - `fix(api): handle SSE cursor tie-break ordering`
  - `docs(readme): update clawsight install command`
- PRs should include:
  - concise problem statement,
  - implemented solution summary,
  - touched paths,
  - validation commands run.

## Security and Configuration Tips

- Never commit secrets; use `.env` and SIEM token variables (`SIEM_API_TOKEN` or `CLAWSIGHT_API_TOKEN`).
- Preserve telemetry redaction/sanitization behavior when changing ingest/display flows.
- If API contracts or operational setup change, update `platform/README.md` and relevant `platform/docs/*` in the same PR.
