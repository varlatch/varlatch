// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bot, Check, ChevronDown, ChevronRight, Plus, UserPlus } from "lucide-react";
import type { Environment, Project, Tier } from "@varlatch/protocol";
import { useSession } from "../../lib/session";
import { Button, cn } from "../../components/ui";
import { CodeBlock } from "../../components/CodeBlock";
import { useToast } from "../../components/Toast";
import { errorMessage } from "../../shell/Shell";
import { contractItems } from "./health";
import { keys, sortEnvironments } from "./hooks";
import { NewEnvironmentDialog } from "./NewEnvironmentDialog";

/**
 * Getting started (design R2 §Onboarding): CLI-native and snippet-forward,
 * every check derived from authoritative /v1 state on render, never from
 * stored click-state. The contract step branches on git vs managed. Workload
 * connection and invitations are recommended, never required: a solo org
 * with values set is complete, and the steps disappear on their own.
 */

const STANDARD: Tier[] = ["development", "staging", "production"];
type StepId = "project" | "contract" | "environments" | "values";

export type OnboardingState = {
  /** The required loop is unfinished and the checks have settled. */
  visible: boolean;
  /** Checks have settled at least once; until then render nothing, to avoid a flash. */
  ready: boolean;
  target: Project | null;
  done: Record<StepId, boolean>;
  doneCount: number;
  environments: Environment[];
  roots: Environment[];
  itemNames: string[];
  /** Null when the caller may not list identities: the recommended steps hide. */
  people: { workload: boolean; invite: boolean } | null;
};

export function useOnboarding(org: string, projects: Project[] | undefined): OnboardingState {
  const { api } = useSession();
  // The founding project drives the steps and the git-vs-managed branch.
  const target = projects?.[0] ?? null;
  const slug = target?.slug ?? "";
  const envs = useQuery({
    queryKey: keys.environments(org, slug),
    queryFn: () => api.listEnvironments(org, slug),
    enabled: target !== null,
  });
  // No active revision: nothing to fetch (the project list refreshes on contract events).
  const hasContract = target !== null && target.activeContractRevisionId !== null;
  const contract = useQuery({
    queryKey: keys.contract(org, slug),
    queryFn: () => api.getActiveContract(org, slug),
    enabled: hasContract,
    retry: false,
  });
  // Access metadata may be beyond this caller's authority; a failure hides
  // the recommended steps rather than dead-ending onboarding.
  const identities = useQuery({
    queryKey: ["identities", org],
    queryFn: () => api.listIdentities(org),
    retry: false,
  });
  const environments = sortEnvironments(envs.data?.items ?? []);
  const roots = environments.filter((e) => !e.parentEnvironmentId);
  const presence = useQueries({
    queries: roots.map((env) => ({
      queryKey: keys.effectiveMeta(org, slug, env.name),
      queryFn: () => api.effectiveConfiguration(org, slug, env.name),
      enabled: target !== null,
      retry: false,
    })),
  });

  const done: Record<StepId, boolean> = {
    project: target !== null,
    contract: hasContract && Boolean(contract.data),
    environments: roots.length > 0,
    values: presence.some((q) => (q.data?.items.length ?? 0) > 0),
  };
  const doneCount = Object.values(done).filter(Boolean).length;
  const settling =
    projects === undefined ||
    (target !== null && (envs.isPending || (hasContract && contract.isPending) || presence.some((q) => q.isPending)));
  const people = identities.data
    ? {
        workload: identities.data.items.some((i) => i.kind !== "human" && !i.disabled),
        invite: identities.data.items.filter((i) => i.kind === "human").length > 1,
      }
    : null;
  // While new checks load (a project or environment just appeared), keep
  // showing the last settled state instead of flashing unchecked steps.
  const last = useRef<{ org: string; state: OnboardingState } | null>(null);
  if (settling) {
    return last.current?.org === org ? last.current.state : { ...EMPTY, ready: false };
  }
  const state: OnboardingState = {
    visible: doneCount < 4,
    ready: true,
    target,
    done,
    doneCount,
    environments,
    roots,
    itemNames: hasContract ? contractItems(contract.data?.contract).map((i) => i.name) : [],
    people,
  };
  last.current = { org, state };
  return state;
}

const EMPTY: OnboardingState = {
  visible: false,
  ready: false,
  target: null,
  done: { project: false, contract: false, environments: false, values: false },
  doneCount: 0,
  environments: [],
  roots: [],
  itemNames: [],
  people: null,
};

export function Onboarding({
  org,
  state,
  variant,
  onNewProject,
}: {
  org: string;
  state: OnboardingState;
  /** "page": the steps are the page (new organization); "card": above the project list. */
  variant: "page" | "card";
  onNewProject: () => void;
}) {
  const { done, target } = state;
  const order: StepId[] = ["project", "contract", "environments", "values"];
  const current = order.find((s) => !done[s]) ?? null;
  // Open steps: the current one unless the reader chose others.
  const [toggled, setToggled] = useState<Partial<Record<StepId, boolean>>>({});
  const isOpen = (s: StepId) => toggled[s] ?? s === current;
  const toggle = (s: StepId) => setToggled((t) => ({ ...t, [s]: !isOpen(s) }));
  const [addingEnv, setAddingEnv] = useState(false);
  const navigate = useNavigate();

  const origin = window.location.origin;
  const slug = target?.slug ?? "<project>";
  const git = target?.contractAuthority !== "managed";
  const firstItem = state.itemNames[0] ?? "DATABASE_URL";
  const firstEnv = state.roots[0]?.name;

  const progress = (
    <div className="flex items-center gap-4">
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-hover"
        role="progressbar"
        aria-label="Getting started"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={state.doneCount}
      >
        <div
          className="h-full rounded-full bg-accent transition-[width] duration-500"
          style={{ width: `${Math.max(state.doneCount / 4, 0.02) * 100}%` }}
        />
      </div>
      <span className="shrink-0 text-[13px] tabular-nums text-muted" data-testid="onboarding-progress">
        {state.doneCount} of 4
      </span>
    </div>
  );

  const steps = (
    <ol className="overflow-hidden rounded-xl border border-bd bg-raised">
      <Step
        id="project"
        n={1}
        done={done.project}
        current={current === "project"}
        open={isOpen("project")}
        onToggle={() => toggle("project")}
        last={false}
        title="Create a project"
        summary={
          target ? (
            <>
              <span className="font-mono">{target.slug}</span> · {target.contractAuthority} contract
            </>
          ) : (
            "A project holds one contract and the environments that use it."
          )
        }
      >
        {target ? (
          <p className="text-[13px] text-muted">
            <Link className="link" to={`/o/${org}/p/${target.slug}`}>
              Open {target.slug}
            </Link>{" "}
            or{" "}
            <button type="button" className="link cursor-pointer" onClick={onNewProject}>
              create another project
            </button>
            .
          </p>
        ) : (
          <div className="space-y-3">
            <p className="text-[13px] text-muted">
              Choose whether its contract lives in your repository as <InlineCode>.env.schema</InlineCode> or is edited
              here, and which environments to start with.
            </p>
            <Button variant="primary" icon={<Plus size={15} />} onClick={onNewProject} data-testid="onboarding-new-project">
              New project
            </Button>
          </div>
        )}
      </Step>

      <Step
        id="contract"
        n={2}
        done={done.contract}
        current={current === "contract"}
        open={isOpen("contract")}
        onToggle={() => toggle("contract")}
        last={false}
        title={git ? "Push your contract" : "Define your contract"}
        summary={
          done.contract ? (
            `${state.itemNames.length} config item${state.itemNames.length === 1 ? "" : "s"}, active`
          ) : git ? (
            <>
              From your repository with <InlineCode>varlatch contract push</InlineCode>
            </>
          ) : (
            "Add config items on the Contract tab and activate them"
          )
        }
      >
        {target &&
          (git ? (
            <div className="space-y-3">
              <p className="text-[13px] text-muted">
                Your schema lives in the repo as <InlineCode>.env.schema</InlineCode>. Push it, then activate the revision
                the push prints.
              </p>
              <CodeBlock
                numbered
                lines={[
                  `varlatch login --server ${origin}`,
                  `varlatch init --org ${org} --project ${slug}`,
                  "varlatch contract push --schema .env.schema",
                  "varlatch contract activate <revision>",
                ]}
              />
              {!done.contract && <Waiting>Waiting for an active contract…</Waiting>}
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-[13px] text-muted">
                Add your config items, review the change and activate the revision. Varlatch is the source of truth for
                this contract.
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <Button icon={<ChevronRight size={15} />} onClick={() => navigate(`/o/${org}/p/${slug}/contract`)}>
                  Open the contract
                </Button>
                {!done.contract && <Waiting>Waiting for an active contract…</Waiting>}
              </div>
            </div>
          ))}
      </Step>

      <Step
        id="environments"
        n={3}
        done={done.environments}
        current={current === "environments"}
        open={isOpen("environments")}
        onToggle={() => toggle("environments")}
        last={false}
        title="Create environments"
        summary={
          done.environments
            ? state.roots.map((e) => e.name).join(", ")
            : "development, staging and production, in one click"
        }
        action={
          target && !done.environments && !isOpen("environments") ? (
            <CreateStandardEnvironments org={org} project={target.slug} existing={state.environments} />
          ) : undefined
        }
      >
        {target && (
          <div className="space-y-3">
            <p className="text-[13px] text-muted">
              Each environment has a tier. Production-tier saves always ask for an explicit acknowledgement.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <CreateStandardEnvironments org={org} project={target.slug} existing={state.environments} />
              <Button variant="ghost" icon={<Plus size={15} />} onClick={() => setAddingEnv(true)}>
                Another environment…
              </Button>
            </div>
          </div>
        )}
      </Step>

      <Step
        id="values"
        n={4}
        done={done.values}
        current={current === "values"}
        open={isOpen("values")}
        onToggle={() => toggle("values")}
        last
        title="Set your first values"
        summary={
          done.values ? (
            "Values are set"
          ) : (
            <>
              In the dashboard or with <InlineCode>varlatch values set</InlineCode>
            </>
          )
        }
      >
        {target && (
          <div className="space-y-3">
            <p className="text-[13px] text-muted">
              Fill in the{" "}
              <Link className="link" to={`/o/${org}/p/${slug}`}>
                values of {slug}
              </Link>
              , or from your repository. The CLI asks for the value without showing it:
            </p>
            <CodeBlock lines={[`varlatch values set ${firstItem}${firstEnv ? ` -e ${firstEnv}` : ""}`]} />
          </div>
        )}
      </Step>
    </ol>
  );

  return (
    <div data-testid="onboarding" className={cn("space-y-4", variant === "card" && "mb-10")}>
      {variant === "page" ? (
        <>
          <div className="-mt-1">{progress}</div>
          {steps}
        </>
      ) : (
        <section className="space-y-3">
          <div className="flex items-center gap-4">
            <h2 className="shrink-0 text-[15px] font-semibold">Getting started</h2>
            <div className="flex-1">{progress}</div>
          </div>
          {steps}
        </section>
      )}
      {state.people && <Recommended org={org} people={state.people} />}
      {addingEnv && target && (
        <NewEnvironmentDialog
          org={org}
          project={target.slug}
          environments={state.environments}
          open
          onClose={() => setAddingEnv(false)}
        />
      )}
    </div>
  );
}

function Step({
  id,
  n,
  done,
  current,
  open,
  onToggle,
  last,
  title,
  summary,
  action,
  children,
}: {
  id: StepId;
  n: number;
  done: boolean;
  current: boolean;
  open: boolean;
  onToggle: () => void;
  last: boolean;
  title: React.ReactNode;
  summary: React.ReactNode;
  action?: React.ReactNode | undefined;
  children?: React.ReactNode;
}) {
  const bodyId = `onboarding-${id}-body`;
  return (
    <li
      data-testid={`onboarding-${id}`}
      data-done={done}
      data-current={current || undefined}
      className={cn("relative border-b border-bd last:border-b-0", current && "bg-hover/40")}
    >
      <span
        aria-hidden="true"
        className={cn(
          "absolute left-[37px] border-l border-dashed border-bd-strong",
          n === 1 ? "top-[34px]" : "top-0",
          last ? "h-[34px]" : "bottom-0",
        )}
      />
      <div className="flex items-center gap-4 px-5 py-4">
        <span
          aria-hidden="true"
          className={cn(
            "relative z-[1] flex size-9 shrink-0 items-center justify-center rounded-full text-sm font-semibold",
            done
              ? "bg-accent text-accent-fg"
              : current
                ? "border-2 border-accent bg-raised text-fg"
                : "border border-bd-strong bg-raised text-muted",
          )}
        >
          {done ? <Check size={17} strokeWidth={2.5} /> : n}
        </span>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={onToggle}
          className="min-w-0 flex-1 cursor-pointer text-left"
        >
          <span className={cn("block text-base font-semibold", done ? "text-fg/75" : "text-fg")}>
            {title}
            <span className="sr-only">{done ? " (done)" : " (to do)"}</span>
          </span>
          {!(open && !done) && <span className="mt-0.5 block truncate text-[13px] text-muted">{summary}</span>}
        </button>
        {action}
        <button
          type="button"
          aria-label={open ? "Collapse" : "Expand"}
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={onToggle}
          className="flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg"
        >
          {open ? <ChevronDown size={17} /> : <ChevronRight size={17} />}
        </button>
      </div>
      {open && (
        <div id={bodyId} className="pb-5 pl-[76px] pr-5">
          {children}
        </div>
      )}
    </li>
  );
}

/** Creates whichever of development, staging and production are missing. */
function CreateStandardEnvironments({ org, project, existing }: { org: string; project: string; existing: Environment[] }) {
  const { api } = useSession();
  const qc = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const missing = STANDARD.filter((t) => !existing.some((e) => e.name === t));
  if (missing.length === 0) return null;
  const create = async () => {
    setBusy(true);
    const made: string[] = [];
    try {
      for (const tier of missing) {
        await api.createEnvironment(org, project, { name: tier, tier });
        made.push(tier);
      }
      toast.success(`Created ${made.join(", ")}`, { description: `in ${project}` });
    } catch (err) {
      toast.error(made.length ? `Created ${made.join(", ")}, then stopped` : "Could not create the environments", {
        description: errorMessage(err),
      });
    } finally {
      setBusy(false);
      await qc.invalidateQueries({ queryKey: keys.environments(org, project) });
    }
  };
  return (
    <Button loading={busy} onClick={() => void create()} data-testid="onboarding-create-environments">
      {missing.length === 3 ? "Create all three" : `Create ${missing.join(" and ")}`}
    </Button>
  );
}

function Recommended({ org, people }: { org: string; people: { workload: boolean; invite: boolean } }) {
  const rows = [
    {
      id: "workload",
      done: people.workload,
      icon: <Bot size={20} />,
      title: "Connect a workload",
      text: "Deploy from your CI, server, or cloud provider with a machine identity.",
      to: `/o/${org}/access?tab=machines`,
    },
    {
      id: "invite",
      done: people.invite,
      icon: <UserPlus size={20} />,
      title: "Invite a teammate",
      text: "Give your team access to this organization. Working solo is a complete setup.",
      to: `/o/${org}/access?tab=members`,
    },
  ];
  return (
    <section data-testid="onboarding-recommended" className="rounded-xl border border-bd bg-raised px-5 pb-2 pt-4">
      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-subtle">Recommended</h3>
      <ul className="mt-1">
        {rows.map((r) => (
          <li key={r.id} data-testid={`onboarding-${r.id}`} data-done={r.done} className="border-b border-bd last:border-b-0">
            <Link to={r.to} className="group -mx-2 flex items-center gap-4 rounded-lg px-2 py-3 hover:bg-hover/50">
              <span className={cn("shrink-0", r.done ? "text-accent" : "text-muted group-hover:text-fg")}>
                {r.done ? <Check size={20} /> : r.icon}
              </span>
              <span className="min-w-0 flex-1">
                <span className={cn("block text-[14px] font-semibold", r.done ? "text-fg/75" : "text-fg")}>{r.title}</span>
                <span className="block text-[13px] text-muted">{r.text}</span>
              </span>
              <ChevronRight size={17} className="shrink-0 text-muted group-hover:text-fg" />
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}

function Waiting({ children }: { children: React.ReactNode }) {
  return (
    <span
      data-testid="onboarding-waiting"
      className="inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/[0.07] px-3 py-1 text-[12.5px] text-fg/90"
    >
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-accent opacity-60" />
        <span className="relative inline-flex size-2 rounded-full bg-accent" />
      </span>
      {children}
    </span>
  );
}

function InlineCode({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded border border-bd bg-inset px-1.5 py-px font-mono text-[12px] text-fg">{children}</code>
  );
}
