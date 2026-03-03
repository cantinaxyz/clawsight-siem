/**
 * @fileoverview ClawSight SIEM module: platform/src/app/traces/page.tsx.
 */
import { redirect } from "next/navigation";

export default function TracesPage() {
  redirect("/executions");
}
