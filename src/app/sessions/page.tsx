/**
 * @fileoverview ClawSight SIEM module: platform/src/app/sessions/page.tsx.
 */
import { redirect } from "next/navigation";

export default function SessionsPage() {
  redirect("/executions");
}
