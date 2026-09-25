// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { Circle, CircleCheck } from "lucide-react";
import type { Project } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Card, Mono, cn } from "../../components/ui";

/**
 * Getting-started checklist (design R2 §Onboarding): CLI-native and
 * snippet-forward, every checkmark derived from authoritative /v1 state on
 * render — no stored click-state anywhere. Branches git-vs-managed contract
 * instructions after project creation. Workload connection and invitations
 * are recommended, never required: a solo org with values set is a complete
 * onboarding state and the card disappears on its own.
 */

function Snippet({ lines }: { lines: string[] }) {
  return (
    <pre className="rounded-md border border-bd bg-inset px-3 py-2 font-mono text-[12.5px] leading-relaxed overflow-x-auto">
      {lines.join("\n")}
    </pre>
  );
}

function Step({
  id,
  done,
  recommended,
  title,
  children,
}: {
  id: string;
  done: boolean;
  recommended?: boolean;
  title: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div
      data-testid={`onboarding-${id}`}
      data-done={done}
      className="flex gap-3 py-2.5 border-t border-bd/60 first:border-t-0"
    >
      {done ? (
        <CircleCheck size={16} className="text-allow mt-0.5 shrink-0" />
      ) : (
        <Circle size={16} className="text-muted/50 mt-0.5 shrink-0" />
      )}
      <div className="flex-1 space-y-1.5 min-w-0">
        <p className={cn("text-sm font-medium", done && "text-muted")}>
          {title}
          {recommended && (
            <span className="ml-2 align-middle text-[10px] uppercase tracking-wide text-muted border border-bd rounded-full px-1.5 py-0.5">
              recommended
            </span>
          )}
        </p>
        {!done && children}
      </div>
    </div>
  );
}

export function OnboardingChecklist({ org, projects }: { org: string; projects: Project[] }) {
  const { api } = useSession();
  // The founding project drives the git-vs-managed branch; once several
  // projects exist the org is past hand-holding and the card is long gone.
  const target = projects[0] ?? null;

  const envs = useQuery({
    queryKey: ["environments", org, target?.slug],
    queryFn: () => api.listEnvironments(org, (target as Project).slug),
    enabled: target !== null,
  });
  const contract = useQuery({
    queryKey: ["contract", org, target?.slug],
    queryFn: () => api.getActiveContract(org, (target as Project).slug).catch(() => null),
    enabled: target !== null,
  });
  // Access metadata may be beyond this caller's authority; a failure hides
  // the workload/invite steps rather than dead-ending onboarding.
  const identities = useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org).catch(() => null),
  });
  const roots = (envs.data?.items ?? []).filter((e) => !e.parentEnvironmentId);
  const presence = useQueries({
    queries: roots.map((env) => ({
      queryKey: ["effective-meta", org, target?.slug, env.name],
      queryFn: () =>
        api
          .effectiveConfiguration(org, (target as Project).slug, env.name)
          .catch(() => null),
    })),
  });

  const projectDone = target !== null;
  const contractDone = Boolean(contract.data);
  const envsDone = roots.length > 0;
  const valuesDone = presence.some((q) => (q.data?.items?.length ?? 0) > 0);
  const machineDone = (identities.data?.items ?? []).some(
    (i) => i.kind !== "human" && !i.disabled,
  );
  const inviteDone = (identities.data?.items ?? []).filter((i) => i.kind === "human").length > 1;

  // Required loop: project → contract → environments → values. Complete →
  // render nothing; recommended steps never keep the card alive.
  if (projectDone && contractDone && envsDone && valuesDone) return null;
  // Avoid a checked→unchecked flash while the underlying queries settle.
  if (target && (envs.isPending || contract.isPending || presence.some((q) => q.isPending))) {
    return null;
  }

  const doneCount = [projectDone, contractDone, envsDone, valuesDone].filter(Boolean).length;
  const origin = window.location.origin;
  const slug = target?.slug ?? "<project>";
  const git = target?.contractAuthority !== "managed";

  return (
    <Card data-testid="onboarding">
      <div className="flex items-baseline justify-between mb-1">
        <h2 className="font-semibold">Getting started</h2>
        <span className="text-xs text-muted" data-testid="onboarding-progress">
          {doneCount} of 4
        </span>
      </div>
      <Step id="project" done={projectDone} title="Create a project">
        <p className="text-muted text-sm">
          Use the form above. Pick <Mono>git</Mono> if the configuration contract lives as{" "}
          <Mono>.env.schema</Mono> in your repository, <Mono>managed</Mono> to edit it here.
        </p>
      </Step>
      <Step
        id="contract"
        done={contractDone}
        title={git ? "Push and activate your contract" : "Define and activate your contract"}
      >
        {target &&
          (git ? (
            <>
              <Snippet
                lines={[
                  `varlatch login --server ${origin}`,
                  `varlatch init --org ${org} --project ${slug}`,
                  "varlatch contract push --schema .env.schema",
                ]}
              />
              <p className="text-muted text-sm">
                Push prints the revision to pass to <Mono>varlatch contract activate</Mono>. If it
                reports unmapped <Mono>forEnv</Mono> names, map them under{" "}
                <Link className="text-accent hover:underline" to={`/o/${org}/p/${slug}/contract`}>
                  Contract
                </Link>{" "}
                → Varlock mapping first.
              </p>
            </>
          ) : (
            <p className="text-muted text-sm">
              Open the{" "}
              <Link className="text-accent hover:underline" to={`/o/${org}/p/${slug}/contract`}>
                Contract tab
              </Link>
              , add your config items, review the diff, and activate the revision.
            </p>
          ))}
      </Step>
      <Step id="environments" done={envsDone} title="Create environments">
        {target && (
          <p className="text-muted text-sm">
            Add them on the project card below — typically <Mono>development</Mono>,{" "}
            <Mono>staging</Mono>, and <Mono>production</Mono>, each with its tier.
          </p>
        )}
      </Step>
      <Step id="values" done={valuesDone} title="Set your first values">
        {target && (
          <>
            <p className="text-muted text-sm">
              Open{" "}
              <Link className="text-accent hover:underline" to={`/o/${org}/p/${slug}`}>
                the project matrix
              </Link>{" "}
              and pick an environment, or from your repo:
            </p>
            <Snippet lines={["varlatch values set DATABASE_URL <value>"]} />
          </>
        )}
      </Step>
      {identities.data && (
        <Step id="workload" done={machineDone} recommended title="Connect a workload">
          <p className="text-muted text-sm">
            Create a machine identity under{" "}
            <Link className="text-accent hover:underline" to={`/o/${org}/access`}>
              Access
            </Link>{" "}
            → Machines and grant it read, then run your app with its values:
          </p>
          <Snippet
            lines={[
              `varlatch login --server ${origin} --token <credential>`,
              "varlatch run -- <your command>",
            ]}
          />
        </Step>
      )}
      {identities.data && (
        <Step id="invite" done={inviteDone} recommended title="Invite a teammate">
          <p className="text-muted text-sm">
            Create an invitation under{" "}
            <Link className="text-accent hover:underline" to={`/o/${org}/access`}>
              Access
            </Link>{" "}
            → People. Varlatch sends no email — share the one-time link through a trusted channel.
            Working solo is a complete setup; this never blocks anything.
          </p>
        </Step>
      )}
    </Card>
  );
}
