// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Plain-English audit lines. Each event becomes an icon, a short title and a
 * sentence that follows the actor's name ("Dev Admin" + "revealed 2 secrets
 * in api / production"). Pure, so every event type is tested without
 * rendering. Names come from a resolver; when no name is known the sentence
 * falls back to a neutral noun, never to a raw ID.
 */

export type AuditEventLike = {
  eventId: string;
  eventType: string;
  occurredAt: string;
  decision: string;
  actorIdentityId?: string | null;
  credentialId?: string | null;
  /** The acting request's client, as the server summarized its User-Agent. */
  client?: string | null;
  action?: string | null;
  resource?: unknown;
  metadata?: unknown;
  authorization?: unknown;
  requestId?: string | null;
};

/** A sentence is text plus highlighted pieces: item names, places, people. */
export type Segment =
  | string
  | { kind: "mono"; text: string }
  | { kind: "place"; text: string }
  | { kind: "name"; text: string };

export type EventIcon =
  | "eye"
  | "file"
  | "shield"
  | "pencil"
  | "trash"
  | "rotate"
  | "user-plus"
  | "user"
  | "key"
  | "git"
  | "plug"
  | "upload"
  | "webhook"
  | "login"
  | "folder"
  | "layers"
  | "users"
  | "settings"
  | "alert"
  | "check"
  | "pause"
  | "play"
  | "mail"
  | "network"
  | "dot";

export interface Described {
  icon: EventIcon;
  /** Short heading for the detail panel, e.g. "Access denied". */
  title: string;
  segments: Segment[];
}

export interface NameResolver {
  identity(id: string | null | undefined): string | undefined;
  project(id: string | null | undefined): string | undefined;
  environment(id: string | null | undefined): { name: string; projectId: string } | undefined;
  connection(id: string | null | undefined): string | undefined;
  /** Destination label of a sync target, e.g. "GitHub Actions acme-org/api". */
  target(id: string | null | undefined): string | undefined;
  role(id: string | null | undefined): string | undefined;
  group(id: string | null | undefined): string | undefined;
}

export const emptyResolver: NameResolver = {
  identity: () => undefined,
  project: () => undefined,
  environment: () => undefined,
  connection: () => undefined,
  target: () => undefined,
  role: () => undefined,
  group: () => undefined,
};

type Rec = Record<string, unknown>;

function rec(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

/** "A@ver,B@ver+old" -> ["A", "B"]. */
export function listedItems(meta: Rec): string[] {
  const raw = str(meta.items);
  if (!raw) return [];
  return raw
    .split(",")
    .map((entry) => entry.split("@")[0]!.trim())
    .filter(Boolean);
}

/** Readable names of actions, used in grants and denials. */
export const ACTION_LABELS: Record<string, string> = {
  "organization.read": "View the organization",
  "organization.manage": "Manage the organization",
  "project.read": "View projects",
  "project.manage": "Manage projects",
  "environment.read": "View environments",
  "environment.manage": "Manage environments",
  "config.metadata.read": "See item names",
  "config.value.read": "Read values",
  "config.value.write": "Write values",
  "secret.reveal": "Reveal secrets",
  "secret.use": "Use secrets",
  "contract.read": "View the contract",
  "contract.submit": "Push contract revisions",
  "contract.activate": "Activate contract revisions",
  "identity.read": "View identities",
  "identity.manage": "Manage identities",
  "policy.read": "View access",
  "policy.manage": "Manage access",
  "audit.read": "Read the audit log",
  "config.sync.manage": "Manage integrations",
};

const PLATFORM_LABELS: Record<string, string> = {
  "github-actions": "GitHub Actions",
  coolify: "Coolify",
  convex: "Convex",
};

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Item names when there are one or two of them, otherwise a count. */
function itemsPhrase(names: string[], noun: string, nouns = `${noun}s`): Segment[] {
  if (names.length === 0) return [nouns];
  if (names.length <= 2) {
    const out: Segment[] = [];
    names.forEach((n, i) => {
      if (i > 0) out.push(" and ");
      out.push({ kind: "mono", text: n });
    });
    return out;
  }
  return [plural(names.length, noun, nouns)];
}

/** "api / production", "api", or a neutral noun when nothing resolves. */
export function placeOf(resource: Rec, names: NameResolver): string | undefined {
  const env = names.environment(str(resource.environmentId));
  const projectId = str(resource.projectId) ?? env?.projectId;
  const project = names.project(projectId) ?? str(resource.projectSlug);
  const envName = env?.name ?? str(resource.environmentName);
  if (project && envName) return `${project} / ${envName}`;
  if (envName) return envName;
  return project;
}

function inPlace(resource: Rec, names: NameResolver, prep = "in"): Segment[] {
  const place = placeOf(resource, names);
  return place ? [` ${prep} `, { kind: "place", text: place }] : [];
}

function who(id: unknown, names: NameResolver, fallback = "an identity"): Segment {
  const name = names.identity(str(id));
  return name ? { kind: "name", text: name } : fallback;
}

function actionText(action: string | null | undefined): Segment {
  return { kind: "mono", text: action ?? "an action" };
}

/** Human summary of the decision recorded in `authorization`. */
export function authorizationSummary(event: AuditEventLike): string | undefined {
  const authz = rec(event.authorization);
  const denial = str(authz.denial);
  const action = event.action ?? "this action";
  if (event.decision === "deny") {
    if (denial === "no-grant") return `No grant covers ${action} here.`;
    if (denial === "requirement-failed") {
      const reqs = Array.isArray(authz.requirements) ? (authz.requirements as Rec[]) : [];
      const failed = reqs.find((r) => r.satisfied === false);
      const reason = str(failed?.reason);
      if (reason === "no-tailnet-context") return "A network requirement applies and the request did not come from the tailnet.";
      if (reason === "tailnet-mismatch") return "A network requirement applies and the request came from a different tailnet.";
      if (reason === "selector-mismatch") return "A network requirement applies and the device does not match it.";
      return "A network requirement was not met.";
    }
    const metaReason = str(rec(event.metadata).reason);
    if (metaReason) return `Refused: ${metaReason.replace(/[-_]/g, " ")}.`;
    return "The request was refused.";
  }
  if (event.decision === "allow") {
    const applied = Array.isArray(authz.applied) ? authz.applied.length : 0;
    const grants = Array.isArray(authz.grantIds) ? authz.grantIds.length : 0;
    const n = applied || grants;
    if (n > 0) return `Allowed by ${plural(n, "grant")}.`;
    if (str(authz.role)) return `Allowed as organization ${str(authz.role)}.`;
    return "Allowed.";
  }
  return undefined;
}

/**
 * The sentence for one event. Falls back to the event type itself for types
 * this dashboard does not know yet.
 */
export function describeEvent(event: AuditEventLike, names: NameResolver = emptyResolver): Described {
  const r = rec(event.resource);
  const m = rec(event.metadata);
  const t = event.eventType;
  const items = listedItems(m);
  const item = str(r.itemName);
  const target = names.target(str(r.targetId));
  const dest: Segment = target ? { kind: "name", text: target } : "an integration";

  switch (t) {
    // ---- values and secrets
    case "value.written":
      return {
        icon: "pencil",
        title: r.previousVersionId ? "Value changed" : "Value set",
        segments: [r.previousVersionId ? "changed " : "set ", { kind: "mono", text: item ?? "an item" }, ...inPlace(r, names)],
      };
    case "value.deleted":
      return { icon: "trash", title: "Value removed", segments: ["removed ", { kind: "mono", text: item ?? "an item" }, ...inPlace(r, names, "from")] };
    case "value.rotation_started":
      return { icon: "rotate", title: "Rotation started", segments: ["started rotating ", { kind: "mono", text: item ?? "a secret" }, ...inPlace(r, names)] };
    case "value.rotation_completed":
      return { icon: "rotate", title: "Rotation finished", segments: ["finished rotating ", { kind: "mono", text: item ?? "a secret" }, ...inPlace(r, names)] };
    case "value.disclosed": {
      const mode = str(m.mode);
      const verb = mode === "reference-expansion" ? "read referenced " : "read ";
      const withheld = typeof m.withheld === "number" && m.withheld > 0 ? [`, ${m.withheld} withheld`] : [];
      return {
        icon: "file",
        title: "Values read",
        segments: [verb, ...itemsPhrase(items, "value"), ...inPlace(r, names), ...withheld],
      };
    }
    case "secret.disclosed":
      return {
        icon: "eye",
        title: "Secrets revealed",
        segments: [str(m.mode) === "strict-retrieval" ? "received " : "revealed ", ...itemsPhrase(items, "secret"), ...inPlace(r, names)],
      };
    case "secret.validated":
    case "value.validated":
      return {
        icon: "check",
        title: "Values checked",
        segments: ["checked ", ...itemsPhrase(items, t === "secret.validated" ? "secret" : "value"), ...inPlace(r, names), " without disclosing them"],
      };

    // ---- access decisions
    case "authorization.denied":
      return { icon: "shield", title: "Access denied", segments: ["was denied ", actionText(event.action), ...inPlace(r, names, "on")] };
    case "authentication.failed":
      return {
        icon: "shield",
        title: "Sign-in failed",
        segments: [
          str(m.method) === "oidc"
            ? "failed to sign in with OIDC"
            : str(m.method) === "device-approval"
              ? "failed to confirm a CLI sign-in with a passkey"
              : "failed to sign in",
          ...(str(m.reason) ? [` (${str(m.reason)!.replace(/[-_]/g, " ")})`] : []),
        ],
      };
    case "authentication.passkey_enrollment_started":
      return { icon: "key", title: "Passkey enrollment", segments: ["started adding a passkey"] };
    // ---- device sign-in (a CLI signs in after a person approves its code)
    case "authentication.device_requested":
      return { icon: "login", title: "CLI sign-in requested", segments: ["a CLI asked to sign in with a code"] };
    case "authentication.device_approved":
      return { icon: "login", title: "CLI sign-in approved", segments: ["approved a CLI sign-in with a passkey"] };
    case "authentication.device_denied":
      return { icon: "shield", title: "CLI sign-in denied", segments: ["denied a CLI sign-in"] };
    case "authentication.device_collected":
      return { icon: "key", title: "CLI signed in", segments: ["signed in a CLI with an approved code"] };
    case "authentication.device_code_rejected":
      return { icon: "shield", title: "Wrong sign-in code", segments: ["entered a sign-in code that matches no pending sign-in"] };
    case "authentication.device_code_locked":
      return {
        icon: "alert",
        title: "Sign-in code entry paused",
        segments: [
          str(m.scope) === "global"
            ? "reached the limit of wrong sign-in codes for everyone; code entry is paused"
            : str(m.scope) === "peer"
              ? "reached the limit of wrong sign-in codes from one address; code entry from it is paused"
              : "entered too many wrong sign-in codes; their code entry is paused",
        ],
      };
    case "capability.issued":
      return {
        icon: "key",
        title: "Capability issued",
        segments: ["let ", who(r.agentIdentityId, names, "an agent"), " use ", ...itemsPhrase(items, "secret"), ...inPlace(r, names)],
      };
    case "capability.exercised":
      return {
        icon: "key",
        title: "Capability used",
        segments: ["used ", ...itemsPhrase(items, "secret"), " for ", who(r.agentIdentityId, names, "an agent"), ...inPlace(r, names)],
      };
    case "capability.denied":
      return { icon: "shield", title: "Capability refused", segments: ["was refused a capability use", ...inPlace(r, names)] };
    case "capability.revoked":
      return { icon: "trash", title: "Capability revoked", segments: ["revoked a capability", ...inPlace(r, names)] };
    case "credential.issued": {
      const kind = str(m.kind);
      const self = str(r.identityId) === event.actorIdentityId;
      return {
        icon: "key",
        title: "Credential issued",
        segments: self
          ? [`signed in${kind ? ` (${kind === "cli" ? "CLI" : kind})` : ""}`]
          : [`issued a ${kind ? `${kind === "cli" ? "CLI" : kind} ` : ""}credential for `, who(r.identityId, names)],
      };
    }
    case "credential.revoked": {
      const self = str(r.identityId) === event.actorIdentityId;
      return {
        icon: "trash",
        title: "Credential revoked",
        segments: self ? ["revoked one of their credentials"] : ["revoked a credential of ", who(r.identityId, names)],
      };
    }

    // ---- grants, roles, groups
    case "grant.created": {
      const role = names.role(str(m.roleId));
      const actions = (str(m.actions) ?? "").split(",").filter(Boolean);
      const what: Segment[] = role
        ? [{ kind: "name", text: role }]
        : actions.length > 0 && actions.length <= 2
          ? actions.flatMap((a, i) => [...(i > 0 ? [" and "] : []), ACTION_LABELS[a] ?? a])
          : [plural(actions.length, "permission")];
      const subject = r.subjectGroupId ? { kind: "name" as const, text: names.group(str(r.subjectGroupId)) ?? "a group" } : who(r.subjectIdentityId, names);
      return { icon: "user-plus", title: m.replaces ? "Grant replaced" : "Grant created", segments: ["granted ", ...what, " to ", subject] };
    }
    case "grant.revoked":
      return { icon: "trash", title: "Grant revoked", segments: [m.replacedBy ? "replaced a grant" : "revoked a grant"] };
    case "role.created":
      return { icon: "users", title: "Role created", segments: ["created role ", { kind: "name", text: str(m.name) ?? names.role(str(r.roleId)) ?? "a role" }] };
    case "role.updated":
      return { icon: "users", title: "Role updated", segments: ["updated role ", { kind: "name", text: str(m.newName) ?? names.role(str(r.roleId)) ?? "a role" }] };
    case "role.deleted":
      return { icon: "trash", title: "Role deleted", segments: ["deleted a role"] };
    case "group.created":
    case "team.created":
      return { icon: "users", title: `${cap(t.split(".")[0]!)} created`, segments: [`created ${t.split(".")[0]} `, { kind: "name", text: str(m.name) ?? "a group" }] };
    case "group.updated":
    case "team.updated":
      return { icon: "users", title: `${cap(t.split(".")[0]!)} renamed`, segments: [`renamed ${t.split(".")[0]} `, { kind: "name", text: str(m.oldName) ?? "" }, " to ", { kind: "name", text: str(m.newName) ?? "" }] };
    case "group.deleted":
    case "team.deleted":
      return { icon: "trash", title: `${cap(t.split(".")[0]!)} deleted`, segments: [`deleted a ${t.split(".")[0]}`] };
    case "group.member_added":
    case "team.member_added":
      return {
        icon: "user-plus",
        title: "Member added",
        segments: ["added ", who(r.identityId, names), ` to ${t.split(".")[0]} `, { kind: "name", text: names.group(str(r.groupId)) ?? t.split(".")[0]! }],
      };
    case "group.member_removed":
    case "team.member_removed":
      return {
        icon: "user",
        title: "Member removed",
        segments: ["removed ", who(r.identityId, names), ` from ${t.split(".")[0]} `, { kind: "name", text: names.group(str(r.groupId)) ?? t.split(".")[0]! }],
      };
    case "team.project_added":
      return { icon: "folder", title: "Team project added", segments: ["gave team ", { kind: "name", text: names.group(str(r.groupId)) ?? "a team" }, " project ", { kind: "place", text: names.project(str(r.projectId)) ?? "a project" }] };
    case "team.project_removed":
      return { icon: "folder", title: "Team project removed", segments: ["removed project ", { kind: "place", text: names.project(str(r.projectId)) ?? "a project" }, " from team ", { kind: "name", text: names.group(str(r.groupId)) ?? "a team" }] };
    case "requirement.created":
      return { icon: "network", title: "Network requirement added", segments: ["added a network requirement", ...(str(m.tailnet) ? [" for tailnet ", { kind: "mono" as const, text: str(m.tailnet)! }] : [])] };
    case "requirement.updated":
      return { icon: "network", title: "Network requirement changed", segments: ["changed a network requirement"] };
    case "requirement.revoked":
      return { icon: "trash", title: "Network requirement removed", segments: ["removed a network requirement"] };

    // ---- identities and invitations
    case "identity.created":
      return { icon: "user-plus", title: "Identity created", segments: [`created ${str(m.kind) ? `${str(m.kind)} ` : ""}identity `, who(r.identityId, names)] };
    case "identity.renamed":
      return { icon: "user", title: "Identity renamed", segments: ["renamed ", { kind: "name", text: str(m.previousName) ?? "an identity" }, " to ", { kind: "name", text: str(m.name) ?? "" }] };
    case "identity.retired":
      return { icon: "user", title: "Identity retired", segments: ["retired ", who(r.identityId, names)] };
    case "identity.reactivated":
      return { icon: "user", title: "Identity reactivated", segments: ["reactivated ", who(r.identityId, names)] };
    case "identity.profile_updated":
      return { icon: "user", title: "Profile updated", segments: ["updated their profile"] };
    case "invitation.issued":
      return { icon: "mail", title: "Invitation sent", segments: ["invited ", { kind: "name", text: str(m.inviteeName) ?? "someone" }, ...(str(m.role) ? [` as ${str(m.role)}`] : [])] };
    case "invitation.revoked":
      return { icon: "trash", title: "Invitation revoked", segments: ["revoked the invitation for ", { kind: "name", text: str(m.inviteeName) ?? "someone" }] };
    case "invitation.accepted":
      return { icon: "user-plus", title: "Invitation accepted", segments: ["joined through an invitation"] };
    case "oidc_binding.created":
      return { icon: "key", title: "OIDC sign-in added", segments: ["let ", who(r.identityId, names), " sign in with OIDC", ...(str(m.issuer) ? [" from ", { kind: "mono" as const, text: str(m.issuer)! }] : [])] };
    case "oidc_binding.revoked":
      return { icon: "trash", title: "OIDC sign-in removed", segments: ["removed an OIDC sign-in from ", who(r.identityId, names)] };

    // ---- projects, environments, contracts
    case "organization.created":
      return { icon: "settings", title: "Organization created", segments: ["created the organization"] };
    case "organization.renamed":
      return { icon: "settings", title: "Organization renamed", segments: ["renamed the organization to ", { kind: "name", text: str(m.name) ?? "" }] };
    case "project.created":
      return { icon: "folder", title: "Project created", segments: ["created project ", { kind: "place", text: str(r.projectSlug) ?? names.project(str(r.projectId)) ?? "a project" }] };
    case "project.renamed":
      return { icon: "folder", title: "Project renamed", segments: ["renamed project ", { kind: "place", text: str(r.projectSlug) ?? "a project" }, " to ", { kind: "name", text: str(m.name) ?? "" }] };
    case "environment.created":
      return { icon: "layers", title: "Environment created", segments: ["created environment ", ...placeSegment(r, names)] };
    case "environment.deleted":
      return { icon: "trash", title: "Environment deleted", segments: ["deleted environment ", ...placeSegment(r, names)] };
    case "contract.revision_pushed":
      return {
        icon: "git",
        title: "Contract revision pushed",
        segments: [
          "pushed a contract revision",
          ...inPlace(r, names, "for"),
          ...(typeof m.itemCount === "number" ? [` (${plural(m.itemCount, "item")})`] : []),
        ],
      };
    case "contract.activated":
      return {
        icon: "check",
        title: "Contract activated",
        segments: ["activated a contract revision", ...inPlace(r, names, "for"), ...(m.securityRelevant ? [" with security-relevant changes"] : [])],
      };

    // ---- integrations
    case "sync.connection_created":
      return {
        icon: "plug",
        title: "Connection created",
        segments: ["connected ", PLATFORM_LABELS[str(m.platform) ?? ""] ?? "a platform", ...(str(m.baseIdentity) ? [" ", { kind: "mono" as const, text: str(m.baseIdentity)! }] : [])],
      };
    case "sync.connection_checked": {
      const status = str(m.status);
      const where = str(m.destination) ?? str(m.baseIdentity);
      return {
        icon: status === "ok" ? "check" : "alert",
        title: "Access checked",
        segments: [
          "checked access to ",
          PLATFORM_LABELS[str(m.platform) ?? ""] ?? "a platform",
          ...(where ? [" ", { kind: "mono" as const, text: where }] : []),
          ...(status && status !== "ok" ? [`: ${status.replace(/-/g, " ")}`] : []),
        ],
      };
    }
    case "sync.connection_credential_replaced":
      return { icon: "key", title: "Credential replaced", segments: ["replaced the credential of ", { kind: "name", text: names.connection(str(r.connectionId)) ?? "a connection" }] };
    case "sync.connection_revoked":
      return { icon: "trash", title: "Connection revoked", segments: ["revoked connection ", { kind: "name", text: names.connection(str(r.connectionId)) ?? "a connection" }] };
    case "sync.target_created":
      return { icon: "upload", title: "Integration added", segments: ["added an integration", ...inPlace(r, names, "from"), ...(str(m.destination) ? [" to ", { kind: "mono" as const, text: str(m.destination)! }] : [])] };
    case "sync.target_updated":
      return { icon: "upload", title: "Integration changed", segments: ["changed ", dest, ...inPlace(r, names, "for")] };
    case "sync.target_paused":
      return { icon: "pause", title: "Integration paused", segments: ["paused ", dest, ...inPlace(r, names, "for")] };
    case "sync.target_resumed":
      return { icon: "play", title: "Integration resumed", segments: ["resumed ", dest, ...inPlace(r, names, "for")] };
    case "sync.target_revoked":
      return { icon: "trash", title: "Integration revoked", segments: ["revoked ", dest, ...inPlace(r, names, "for")] };
    case "sync.target_disabled":
      return { icon: "alert", title: "Integration stopped", segments: ["stopped ", dest, " after repeated failures"] };
    case "sync.values_decrypted":
      return { icon: "file", title: "Values prepared for push", segments: ["prepared ", ...itemsPhrase(items, "value"), ...inPlace(r, names, "from"), " for ", dest] };
    case "sync.push_attempted":
      return {
        icon: "upload",
        title: "Push started",
        segments: [
          "started pushing ",
          ...itemsPhrase(items, "value"),
          ...inPlace(r, names, "from"),
          " to ",
          target ? dest : str(m.destination) ? { kind: "mono", text: str(m.destination)! } : dest,
        ],
      };
    case "sync.push_result": {
      const failed = typeof m.failed === "number" ? m.failed : 0;
      const written = typeof m.written === "number" ? m.written : 0;
      return {
        icon: failed > 0 ? "alert" : "check",
        title: failed > 0 ? "Push degraded" : "Push finished",
        segments: [failed > 0 ? `pushed ${written}, ${failed} failed, to ` : `pushed ${plural(written, "value")} to `, dest],
      };
    }

    // ---- webhooks and installation
    case "webhook.created":
      return { icon: "webhook", title: "Webhook registered", segments: ["registered an audit webhook", ...(str(m.url) ? [" ", { kind: "mono" as const, text: str(m.url)! }] : [])] };
    case "webhook.updated":
      return { icon: "webhook", title: "Webhook changed", segments: ["changed an audit webhook"] };
    case "webhook.revoked":
      return { icon: "trash", title: "Webhook revoked", segments: ["revoked an audit webhook"] };
    case "bootstrap.completed":
      return { icon: "login", title: "Installation bootstrapped", segments: ["set up this installation"] };
    case "recovery.completed":
      return { icon: "login", title: "Recovery completed", segments: ["recovered access"] };
  }

  // Unknown or rare types: the type itself, readable, plus the place.
  const [domain, verb] = t.split(".");
  return {
    icon: event.decision === "deny" ? "shield" : "dot",
    title: cap(`${domain ?? t} ${(verb ?? "").replace(/_/g, " ")}`.trim()),
    segments: [{ kind: "mono", text: t }, ...inPlace(r, names)],
  };
}

function placeSegment(r: Rec, names: NameResolver): Segment[] {
  const place = placeOf(r, names);
  return [{ kind: "place", text: place ?? "an environment" }];
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Plain text of a sentence, for filtering and accessible labels. */
export function segmentsText(segments: Segment[]): string {
  return segments.map((s) => (typeof s === "string" ? s : s.text)).join("");
}
