// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import { Bot, Box, Building2, Server, Shuffle, Sparkles, User, Users, UsersRound, type LucideIcon } from "lucide-react";
import type { Environment, Grant, GrantScope, Project, Tier } from "@varlatch/protocol";
import type { OrgIdentity } from "@varlatch/sdk";
import { PRESETS } from "./shared";

/**
 * Plain-English vocabulary for the access model: what an action means, how a
 * permission set reads as a phrase, and how a scope reads as a sentence.
 * Presets and phrases are presentation only; the stored Grant is the truth.
 */

export type ActionGroup = "Organization" | "Configuration" | "Secrets" | "Contract" | "Access" | "Audit" | "Sync";

export const ACTION_INFO: Record<string, { label: string; group: ActionGroup; description: string }> = {
  "organization.read": { label: "See the organization", group: "Organization", description: "Read organization details and its member list." },
  "organization.manage": { label: "Administer the organization", group: "Organization", description: "Change organization settings and administration." },
  "project.read": { label: "See projects", group: "Configuration", description: "List projects and read their settings." },
  "project.manage": { label: "Manage projects", group: "Configuration", description: "Create, rename and configure projects." },
  "environment.read": { label: "See environments", group: "Configuration", description: "List environments and their tiers." },
  "environment.manage": { label: "Manage environments", group: "Configuration", description: "Create and delete environments." },
  "config.metadata.read": { label: "Read item names", group: "Configuration", description: "Which items exist and whether they are set, without values." },
  "config.value.read": { label: "Read values", group: "Configuration", description: "Read non-secret values." },
  "config.value.write": { label: "Write values", group: "Configuration", description: "Set, change, rotate and delete values, including secrets (blind overwrite)." },
  "contract.read": { label: "Read the contract", group: "Contract", description: "See the active contract and its revisions." },
  "contract.submit": { label: "Push contract revisions", group: "Contract", description: "Store new contract revisions (not activate them)." },
  "contract.activate": { label: "Activate contracts", group: "Contract", description: "Make a stored revision the active contract." },
  "secret.use": { label: "Use secrets", group: "Secrets", description: "Retrieve secret material for running software (varlatch run, brokers)." },
  "secret.reveal": { label: "Reveal secrets", group: "Secrets", description: "See secret plaintext in tools. Every reveal is audited." },
  "identity.read": { label: "See people and machines", group: "Access", description: "List identities and their credentials metadata." },
  "identity.manage": { label: "Manage people and machines", group: "Access", description: "Invite people, create and retire machines, manage credentials." },
  "policy.read": { label: "See grants and roles", group: "Access", description: "Read grants, roles, groups, teams and requirements." },
  "policy.manage": { label: "Manage grants and roles", group: "Access", description: "Create and change grants, roles, groups, teams and requirements." },
  "audit.read": { label: "Read the audit log", group: "Audit", description: "Read and export audit events and manage audit webhooks." },
  "config.sync.manage": { label: "Manage integrations", group: "Sync", description: "Create and change sync targets and platform connections." },
};

export const ACTION_GROUPS: ActionGroup[] = ["Configuration", "Secrets", "Contract", "Access", "Audit", "Sync", "Organization"];

export function actionLabel(action: string): string {
  return ACTION_INFO[action]?.label ?? action;
}

/** A short phrase for a permission: a preset name when it matches one exactly. */
export function permissionPhrase(actions: string[] | null | undefined, roleName?: string | null): string {
  if (roleName) return roleName;
  const set = new Set(actions ?? []);
  const preset = PRESETS.find((p) => p.actions.length === set.size && p.actions.every((a) => set.has(a)));
  if (preset) return preset.label;
  if (set.size === 0) return "No actions";
  // Lead with the strongest abilities a reader cares about.
  const key = ["organization.manage", "policy.manage", "secret.reveal", "secret.use", "config.value.write", "config.value.read", "audit.read", "identity.manage", "config.sync.manage", "contract.activate"];
  const top = key.filter((a) => set.has(a)).slice(0, 2).map(actionLabel);
  if (top.length === 0) return `${set.size} action${set.size === 1 ? "" : "s"}`;
  const rest = set.size - top.length;
  return `${top.join(" + ")}${rest > 0 ? ` +${rest}` : ""}`;
}

export type Names = {
  project: (id: string) => Project | undefined;
  environment: (id: string) => Environment | undefined;
  team: (id: string) => string | undefined;
};

/** Where a grant applies, as chips: [project, environments] / [whole organization] / [team's projects]. */
export function scopeParts(scope: GrantScope, names: Names): { label: string; tier?: Tier; mono?: boolean }[] {
  if (scope.kind === "organization") return [{ label: "whole organization" }];
  if (scope.kind === "team") return [{ label: `${names.team(scope.teamId) ?? "a team"}'s projects` }];
  const project = names.project(scope.projectId);
  const projectLabel = project?.slug ?? "an unknown project";
  if (scope.kind === "project") return [{ label: projectLabel, mono: true }, { label: "all environments" }];
  if (scope.selector.kind === "tier") return [{ label: projectLabel, mono: true }, { label: scope.selector.tier, tier: scope.selector.tier }];
  const envs = scope.selector.environmentIds.map((id) => names.environment(id));
  return [
    { label: projectLabel, mono: true },
    ...envs.map((e, i) =>
      e ? { label: e.name, tier: e.tier as Tier, mono: true } : { label: `environment ${i + 1}` },
    ),
  ];
}

/** Plain-text version of a grant, for `title` attributes and tests. */
export function grantSentence(grant: Grant, subject: string, permission: string, names: Names): string {
  const parts = scopeParts(grant.scope, names).map((p) => p.label);
  const where =
    grant.scope.kind === "organization" || grant.scope.kind === "team"
      ? `on ${parts.join(" ")}`
      : `on ${parts[0]} in ${parts.slice(1).join(", ")}`;
  return `${subject} can ${permission} ${where}`;
}

export type SubjectKind = OrgIdentity["kind"] | "group" | "team";

const KIND_ICONS: Record<SubjectKind, LucideIcon> = {
  human: User,
  service: Server,
  workload: Box,
  ci: Bot,
  broker: Shuffle,
  agent: Sparkles,
  group: Users,
  team: UsersRound,
};

export function KindIcon({ kind, size = 18, className }: { kind: SubjectKind; size?: number | undefined; className?: string | undefined }) {
  const Icon = KIND_ICONS[kind] ?? Building2;
  return <Icon size={size} {...(className ? { className } : {})} />;
}

export const KIND_LABEL: Record<SubjectKind, string> = {
  human: "person",
  service: "service",
  workload: "workload",
  ci: "ci",
  broker: "broker",
  agent: "agent",
  group: "group",
  team: "team",
};

/** How a machine kind authenticates, in words. */
export const KIND_AUTH: Record<Exclude<OrgIdentity["kind"], "human">, string> = {
  service: "Long-lived token",
  workload: "Long-lived token",
  ci: "OIDC federation, no stored secret",
  broker: "Token; mediates secret use for agents",
  agent: "Secrets via a broker only",
};

export const KIND_HELP: Record<Exclude<OrgIdentity["kind"], "human">, string> = {
  service: "A server or app that runs continuously. Gets a token, shown once.",
  workload: "A job or container. Gets a token, shown once; give it an expiry or use budget.",
  ci: "A CI pipeline that signs in with its platform's OIDC token. No stored secret at all.",
  broker: "Issues short-lived capabilities so AI agents can use secrets without seeing them.",
  agent: "An AI agent. Never holds a token; uses secrets only through a broker.",
};
