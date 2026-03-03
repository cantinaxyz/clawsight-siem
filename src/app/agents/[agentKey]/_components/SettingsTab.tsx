/**
 * @fileoverview ClawSight SIEM module: platform/src/app/agents/[agentKey]/_components/SettingsTab.tsx.
 */
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

type SettingsTabProps = {
  agentKey: string;
  displayName: string;
  notes: string;
  policyProfile: string;
  updateAgentAction: (formData: FormData) => Promise<void>;
  deleteAgentAction: (formData: FormData) => Promise<void>;
};

export default function SettingsTab({
  agentKey,
  displayName,
  notes,
  policyProfile,
  updateAgentAction,
  deleteAgentAction,
}: SettingsTabProps) {
  return (
    <div className="flex max-w-2xl flex-col gap-6 p-4 md:p-8">
      <form action={updateAgentAction} className="flex flex-col gap-6">
        <input type="hidden" name="agentKey" value={agentKey} />
        <input type="hidden" name="policyProfile" value={policyProfile} />

        <Card className="border-border">
          <CardContent className="flex flex-col gap-4 p-5">
            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-foreground">Display Name</label>
              <Input name="displayName" defaultValue={displayName} placeholder="Agent display name" />
              <p className="text-xs text-muted-foreground">
                Override the default discovered name shown in the agent registry.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border">
          <CardContent className="flex flex-col gap-4 p-5">
            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-foreground">Notes</label>
              <textarea
                name="notes"
                defaultValue={notes}
                placeholder="Internal notes about this agent"
                rows={4}
                className="min-h-[96px] resize-none rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground"
              />
              <p className="text-xs text-muted-foreground">
                Internal notes only. Not sent to the agent.
              </p>
            </div>
          </CardContent>
        </Card>

        <div className="flex items-center gap-3">
          <Button type="submit">Save Settings</Button>
        </div>
      </form>

      <Card className="border-destructive/40 bg-destructive/5">
        <CardContent className="flex flex-col gap-4 p-5">
          <div className="flex flex-col gap-1">
            <h3 className="text-sm font-semibold text-foreground">Delete agent</h3>
            <p className="text-xs text-muted-foreground">
              This permanently removes the agent card and all stored telemetry scoped to this agent.
            </p>
          </div>
        </CardContent>
      </Card>

      <form action={deleteAgentAction} className="flex flex-col gap-3">
        <input type="hidden" name="agentKey" value={agentKey} />
        <label htmlFor="confirm-delete-agent" className="text-xs text-muted-foreground">
          Type <span className="font-semibold text-foreground">DELETE</span> to confirm
        </label>
        <Input
          id="confirm-delete-agent"
          name="confirm"
          required
          pattern="DELETE"
          placeholder="DELETE"
          className="max-w-[240px]"
        />
        <div className="flex items-center gap-3">
          <Button type="submit" variant="destructive">
            Delete Agent
          </Button>
        </div>
      </form>
    </div>
  );
}
