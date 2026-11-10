// SPDX-License-Identifier: AGPL-3.0-or-later
import { useQuery } from "@tanstack/react-query";
import { Network } from "lucide-react";
import { VarlatchApiError, type MachineReach, type OrgIdentity, type ReachAction } from "@varlatch/sdk";
import { useSession } from "../../lib/session";
import { Badge, Button, Spinner } from "../../components/ui";
import { errorMessage } from "../../shell/Shell";

/**
 * A machine's reach (ADR-0054 Decision 8): what its Grants allow, per
 * project and environment, with the Tailnet Requirements that would
 * constrain an action shown as conditions. Nothing here is checked against
 * a device: a condition is never a denial. Read-only, fetched on opening.
 */

function ActionBadge({ action, conditioned }: { action: ReachAction; conditioned: boolean }) {
  return (
    <Badge
      tone={conditioned ? "info" : "mono"}
      className="font-mono"
      data-reach-action={action.action}
      title={conditioned ? "Only from a device that meets the conditions below" : undefined}
    >
      {conditioned && <Network size={11} aria-label="conditional" />}
      {action.action}
    </Badge>
  );
}

function ActionList({ actions }: { actions: ReachAction[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {actions.map((a) => (
        <ActionBadge key={a.action} action={a} conditioned={a.conditions.length > 0} />
      ))}
    </span>
  );
}

const STATE_WORDS: Record<MachineReach["identity"]["state"], string> = {
  live: "live",
  disabled: "disabled",
  retired: "retired",
};

export function MachineReachPanel({ org, identity }: { org: string; identity: OrgIdentity }) {
  const { api } = useSession();
  const reach = useQuery({
    queryKey: ["machine-reach", org, identity.id],
    queryFn: () => api.machineReach(org, identity.id),
    retry: false,
  });
  const denied = reach.error instanceof VarlatchApiError && reach.error.status === 403;
  const data = reach.data;
  const condition = (id: string) => data?.requirements.find((r) => r.id === id)?.condition ?? `Requirement ${id}`;
  return (
    <div className="rounded-lg border border-bd bg-raised" data-testid={`reach-panel-${identity.id}`}>
      <div className="flex items-center justify-between gap-3 border-b border-bd px-4 py-2.5">
        <div>
          <p className="text-[13px] font-semibold">Reach</p>
          <p className="text-xs text-muted">
            What its grants allow. Conditions are network requirements a request must meet; they are listed here, not checked.
          </p>
        </div>
        {data && (
          <span className="flex shrink-0 items-center gap-2 text-xs text-muted" data-testid="reach-state">
            <Badge tone={data.identity.state === "live" ? "neutral" : "danger"}>
              {data.identity.disabledReason === "organization-deletion" ? "disabled by deletion" : STATE_WORDS[data.identity.state]}
            </Badge>
            {data.identity.liveCredentials} live credential{data.identity.liveCredentials === 1 ? "" : "s"}
          </span>
        )}
      </div>
      {reach.isLoading ? (
        <div className="px-4 py-3">
          <Spinner />
        </div>
      ) : reach.error ? (
        <div className="flex items-center justify-between gap-3 px-4 py-3 text-[13px]" data-testid="reach-error">
          <span className="text-muted">
            {denied ? "Seeing a machine's reach needs permission to read identities and policy." : `Could not load its reach: ${errorMessage(reach.error)}`}
          </span>
          {!denied && (
            <Button size="sm" variant="secondary" onClick={() => void reach.refetch()}>
              Try again
            </Button>
          )}
        </div>
      ) : data ? (
        <div className="space-y-3 px-4 py-3 text-[13px]">
          {data.organizationActions.length > 0 && (
            <div className="flex flex-wrap items-center gap-2" data-testid="reach-organization">
              <span className="text-muted">Whole organization</span>
              <ActionList actions={data.organizationActions} />
            </div>
          )}
          {data.projects.length === 0 && data.organizationActions.length === 0 && (
            <p className="text-muted" data-testid="reach-empty">
              No grant allows it anything yet.
            </p>
          )}
          {data.projects.map((p) => (
            <div key={p.id} data-reach-project={p.slug}>
              <p className="font-medium">{p.name}</p>
              <ul className="mt-1 space-y-1.5 border-l border-bd pl-3">
                {p.actions.length > 0 && (
                  <li className="flex flex-wrap items-center gap-2">
                    <span className="text-muted">project</span>
                    <ActionList actions={p.actions} />
                  </li>
                )}
                {p.environments.map((e) => {
                  const conditions = [...new Set(e.actions.flatMap((a) => a.conditions))];
                  return (
                    <li key={e.id} data-reach-environment={e.name}>
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[12.5px]">{e.name}</span>
                        <ActionList actions={e.actions} />
                      </span>
                      {conditions.length > 0 && (
                        <span className="mt-1 flex flex-wrap gap-1" data-testid="reach-conditions">
                          {conditions.map((id) => (
                            <Badge key={id} tone="info" data-reach-condition={id} title="Value reads here need a device that meets this">
                              {condition(id)}
                            </Badge>
                          ))}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          {data.notes.map((n) => (
            <p key={n} className="text-xs text-muted" data-testid="reach-note">
              {n}
            </p>
          ))}
        </div>
      ) : null}
    </div>
  );
}
