// SPDX-License-Identifier: AGPL-3.0-or-later
import { Link, Outlet, useNavigate, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Ellipsis, KeyRound, Layers, RefreshCw, ScrollText, ShieldOff, Trash2 } from "lucide-react";
import type { Tier } from "@varlatch/protocol";
import { useOrgRealtime } from "../../lib/realtime";
import { useSession } from "../../lib/session";
import { EmptyState, TierChip, TierDot } from "../../components/ui";
import { Menu } from "../../components/Select";
import { useConfirm } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { PageHeader, Tabs } from "../../components/PageHeader";
import { FullPageLoading } from "../../shell/AuthScreens";
import { errorMessage } from "../../shell/Shell";
import {
  keys,
  sortEnvironments,
  useEnvironments,
  useOrgName,
  useProject,
  type EnvironmentContext,
} from "../projects/hooks";
import { cellStateOf, contractItemsOf, envPath, listNames, plural } from "../values/model";
import { usePlatformConnections } from "../values/queries";
import { TailnetOnlyBadge } from "../values/TailnetOnly";
import { isTailnetOnly } from "../../lib/tailnet";
import { targetLabel } from "../sync/syncStatus";

/**
 * One environment: header (breadcrumbs, tier, kind, item health, actions)
 * and the tabs Values / Integrations / Activity. Child routes render content
 * only and read the environment from `useEnvironmentContext()`.
 */
export function EnvironmentLayout() {
  const { org, project: slug, env } = useParams() as { org: string; project: string; env: string };
  const envName = decodeURIComponent(env);
  useOrgRealtime(
    org,
    // "requirement": a Tailnet Requirement changes environments' tailnetRequired.
    ["environment", "sync", "value", "contract", "requirement"],
    [keys.environments(org, slug), keys.syncTargets(org, slug, envName), ["effective-meta", org, slug], ["requirements", org]],
  );
  const orgName = useOrgName(org);
  const { api } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const toast = useToast();
  const navigate = useNavigate();
  const { project, isLoading } = useProject(org, slug);
  const envs = useEnvironments(org, slug);
  const targets = useQuery({
    queryKey: keys.syncTargets(org, slug, envName),
    queryFn: () => api.listSyncTargets(org, slug, envName),
    retry: false,
  });
  const connections = usePlatformConnections(org);
  // Metadata only: item count and what is missing, for the header.
  const meta = useQuery({
    queryKey: keys.effectiveMeta(org, slug, envName),
    queryFn: () => api.effectiveConfiguration(org, slug, envName),
    retry: false,
  });
  const contract = useQuery({
    queryKey: keys.contract(org, slug),
    queryFn: () => api.getActiveContract(org, slug),
    retry: false,
  });

  if (isLoading || envs.isLoading) return <FullPageLoading />;
  const environment = envs.data?.items.find((e) => e.name === envName);
  if (!project || !environment) {
    return (
      <EmptyState
        title="Environment not found"
        description={`There is no environment “${envName}” in ${slug}, or you cannot see it.`}
      />
    );
  }
  const tier = environment.tier as Tier;
  const parent = environment.parentEnvironmentId
    ? envs.data?.items.find((e) => e.id === environment.parentEnvironmentId)
    : undefined;
  const children = (envs.data?.items ?? []).filter((e) => e.parentEnvironmentId === environment.id);
  const base = `/o/${org}/p/${slug}/e/${encodeURIComponent(envName)}`;
  const targetCount = targets.data?.items.length ?? 0;
  const context: EnvironmentContext = {
    org,
    project,
    environments: sortEnvironments(envs.data?.items ?? []),
    environment,
  };

  const items = meta.data?.items;
  const contractItems = contractItemsOf(contract.data);
  const missing = items
    ? contractItems.filter((c) => cellStateOf(items.find((i) => i.name === c.name), c, environment) === "missing_required").length
    : 0;
  const itemCount = items ? new Set([...items.map((i) => i.name), ...contractItems.map((c) => c.name)]).size : undefined;

  const deleteEnvironment = async () => {
    if (children.length > 0) {
      // The server deletes an environment only once nothing derives from it.
      const open = await confirm({
        title: `Delete the derived environments first`,
        description: `${plural(children.length, "environment")} derive${children.length === 1 ? "s" : ""} from ${envName}. Delete ${children.length === 1 ? "it" : "them"}, then ${envName}.`,
        consequences: children.map((c) => ({
          icon: <Layers size={15} />,
          text: (
            <span>
              <span className="font-mono">{c.name}</span> <span className="text-muted">({c.kind})</span>
            </span>
          ),
        })),
        confirmLabel: `Open ${children[0]!.name}`,
        cancelLabel: "Close",
      });
      if (open) navigate(envPath(org, slug, children[0]!.name));
      return;
    }
    const current = await api.effectiveConfiguration(org, slug, envName).catch(() => null);
    const own = (current?.items ?? []).filter((i) => i.source === "self");
    const secrets = own.filter((i) => i.sensitive).length;
    const stopping = targets.data?.items ?? [];
    const rootProduction = tier === "production" && !environment.parentEnvironmentId;
    const ok = await confirm({
      tone: "danger",
      title: `Delete ${envName}?`,
      description: (
        <span>
          <span className="font-mono">
            {slug} / {envName}
          </span>{" "}
          · this cannot be undone
        </span>
      ),
      consequences: [
        {
          icon: <KeyRound size={15} />,
          text: current
            ? own.length === 0
              ? "It holds no values of its own."
              : `${plural(own.length, "value")}${secrets > 0 ? `, including ${plural(secrets, "secret")},` : ""} ${own.length === 1 ? "is" : "are"} deleted.`
            : "Its values are deleted.",
        },
        ...(stopping.length > 0
          ? [
              {
                icon: <RefreshCw size={15} />,
                text: `${plural(stopping.length, "integration")} stop${stopping.length === 1 ? "s" : ""} pushing: ${listNames(
                  stopping.map((t) => targetLabel(t, connections.data?.items)),
                )}.`,
              },
            ]
          : []),
        { icon: <ShieldOff size={15} />, text: "Capabilities issued for it are revoked." },
        { icon: <ScrollText size={15} />, text: "Audit history is kept." },
      ],
      confirmLabel: "Delete environment",
      ...(rootProduction ? { typeToConfirm: envName } : {}),
    });
    if (!ok) return;
    try {
      await api.deleteEnvironment(org, slug, envName);
      await qc.invalidateQueries({ queryKey: keys.environments(org, slug) });
      void qc.invalidateQueries({ queryKey: keys.projects(org) });
      void qc.invalidateQueries({ queryKey: keys.orgSyncTargets(org) });
      toast.success(`Deleted ${envName}`, { description: slug });
      navigate(`/o/${org}/p/${slug}`);
    } catch (err) {
      toast.error(`Could not delete ${envName}`, { description: errorMessage(err) });
    }
  };

  return (
    <>
      <PageHeader
        breadcrumbs={[
          { label: orgName, to: `/o/${org}/projects` },
          { label: "Projects", to: `/o/${org}/projects` },
          { label: project.slug, to: `/o/${org}/p/${slug}` },
          { label: environment.name },
        ]}
        title={
          <span className="inline-flex items-center gap-3">
            <TierDot tier={tier} className="size-3" />
            <span className="font-mono" data-testid="environment-name">
              {environment.name}
            </span>
          </span>
        }
        badges={
          <span className="inline-flex flex-wrap items-center gap-2">
            <TierChip tier={tier} />
            {isTailnetOnly(environment) && (
              <TailnetOnlyBadge org={org} project={project} env={environment} environments={envs.data?.items ?? []} />
            )}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>{environment.kind}</span>
            {parent && (
              <>
                <span aria-hidden="true">·</span>
                <span>
                  derived from{" "}
                  <Link to={envPath(org, slug, parent.name)} className="font-mono text-fg hover:text-accent">
                    {parent.name}
                  </Link>
                </span>
              </>
            )}
            {itemCount !== undefined && (
              <>
                <span aria-hidden="true">·</span>
                <span>{plural(itemCount, "item")}</span>
                <span aria-hidden="true">·</span>
                {missing > 0 ? (
                  <span className="text-deny" data-testid="environment-health">
                    {missing} missing
                  </span>
                ) : (
                  <span className="text-allow" data-testid="environment-health" title="Every required item has a value or a contract default">
                    valid
                  </span>
                )}
              </>
            )}
          </span>
        }
        actions={
          <Menu
            label={`${envName} actions`}
            data-testid="environment-menu"
            buttonClassName="size-8 justify-center border border-bd bg-raised hover:border-bd-strong"
            items={[
              {
                label: "Delete environment…",
                icon: <Trash2 size={14} />,
                danger: true,
                onSelect: () => void deleteEnvironment(),
                "data-testid": "menu-delete-environment",
              },
            ]}
          >
            <Ellipsis size={16} />
          </Menu>
        }
        tabs={
          <Tabs
            aria-label="Environment sections"
            items={[
              { key: "values", label: "Values", to: base, end: true, "data-testid": "env-tab-values" },
              {
                key: "integrations",
                label: "Integrations",
                to: `${base}/integrations`,
                ...(targetCount > 0 ? { count: targetCount } : {}),
                "data-testid": "integrations-link",
              },
              { key: "activity", label: "Activity", to: `${base}/activity`, "data-testid": "env-tab-activity" },
            ]}
          />
        }
      />
      <Outlet context={context} />
    </>
  );
}
