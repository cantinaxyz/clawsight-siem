/**
 * @fileoverview ClawSight SIEM module: platform/src/app/sessions/[sessionKey]/page.tsx.
 */
import { redirect } from "next/navigation";

type ParamsInput = { sessionKey: string };

async function resolveParams(params: ParamsInput | Promise<ParamsInput>): Promise<ParamsInput> {
  return Promise.resolve(params);
}

export default async function SessionDetailPage({
  params,
}: {
  params: ParamsInput | Promise<ParamsInput>;
}) {
  const resolved = await resolveParams(params);
  redirect(`/executions?search=${encodeURIComponent(decodeURIComponent(String(resolved.sessionKey || "")))}`);
}
