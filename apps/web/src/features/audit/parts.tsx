// SPDX-License-Identifier: AGPL-3.0-or-later
import React from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  CircleDot,
  Eye,
  FileText,
  Folder,
  GitBranch,
  HelpCircle,
  KeyRound,
  Layers,
  LogIn,
  Mail,
  Network,
  Pause,
  Pencil,
  Play,
  Plug,
  RefreshCw,
  Server,
  Settings,
  ShieldAlert,
  Sparkles,
  Trash2,
  Upload,
  User,
  UserPlus,
  Users,
  Webhook,
  Workflow,
} from "lucide-react";
import type { AuditCredential, OrgIdentity } from "@varlatch/sdk";
import { shortId } from "../../lib/identity";
import { Avatar, Badge, cn } from "../../components/ui";
import type { AuditEventLike, EventIcon, Segment } from "./describe";

/** Small pieces shared by the audit timeline and its detail panel. */

export type AuditEvent = AuditEventLike & Record<string, unknown>;

const ICONS: Record<EventIcon, React.ComponentType<{ size?: number; className?: string }>> = {
  eye: Eye,
  file: FileText,
  shield: ShieldAlert,
  pencil: Pencil,
  trash: Trash2,
  rotate: RefreshCw,
  "user-plus": UserPlus,
  user: User,
  key: KeyRound,
  git: GitBranch,
  plug: Plug,
  upload: Upload,
  webhook: Webhook,
  login: LogIn,
  folder: Folder,
  layers: Layers,
  users: Users,
  settings: Settings,
  alert: AlertTriangle,
  check: Check,
  pause: Pause,
  play: Play,
  mail: Mail,
  network: Network,
  dot: CircleDot,
};

export function EventIconGlyph({ icon, deny, size = 15 }: { icon: EventIcon; deny?: boolean; size?: number }) {
  const Icon = ICONS[icon];
  return <Icon size={size} className={cn("shrink-0", deny ? "text-deny" : "text-muted")} aria-hidden="true" />;
}

/** The audit listing's credentials sidecar, merged across loaded pages. */
export type AuditCredentials = Record<string, AuditCredential>;

/** The actor filter's value for Varlatch's own events (`actor=varlatch`); never an identity ID. */
export const VARLATCH_ACTOR = "varlatch";

/**
 * Events whose credentialId is the credential they are about, not the one
 * that acted: its name says nothing about how the actor connected.
 */
const SUBJECT_CREDENTIAL_EVENTS = new Set(["credential.issued", "credential.revoked", "authentication.device_collected"]);

export type Actor = {
  name: string;
  known: boolean;
  kind: string;
  identity?: OrgIdentity | undefined;
  /** How the actor connected: the request's client, else the acting credential's name. */
  via?: string | undefined;
  /** The event's credential, as the sidecar describes it. */
  credential?: (AuditCredential & { id: string }) | undefined;
};

/** Actor display: name plus avatar (people) or a kind glyph (machines, the system), and how they connected. */
export function actorOf(
  event: AuditEventLike,
  identityById: Map<string, OrgIdentity>,
  credentials: AuditCredentials = {},
): Actor {
  const id = event.actorIdentityId;
  if (!id) {
    if (event.eventType.startsWith("authentication.")) return { name: "Unknown", known: false, kind: "unknown" };
    return { name: "Varlatch", known: true, kind: "system" };
  }
  const described = event.credentialId ? credentials[event.credentialId] : undefined;
  const credential = described && event.credentialId ? { ...described, id: event.credentialId } : undefined;
  const acting = SUBJECT_CREDENTIAL_EVENTS.has(event.eventType) ? undefined : credential;
  const via = event.client || acting?.name || acting?.client || undefined;
  const identity = identityById.get(id);
  if (identity) return { name: identity.name, known: true, kind: identity.kind, identity, via, credential };
  return { name: shortId(id), known: false, kind: "unknown", via, credential };
}

/** True for Varlatch's own events, as `actor=varlatch` selects them on the server. */
export function isVarlatchEvent(event: AuditEventLike): boolean {
  return !event.actorIdentityId && !event.eventType.startsWith("authentication.");
}

/** The kinds the actor filter groups identities by, in order. */
const ACTOR_GROUPS: { label: string; kinds: OrgIdentity["kind"][] }[] = [
  { label: "People", kinds: ["human"] },
  { label: "Agents", kinds: ["agent"] },
  { label: "CI", kinds: ["ci"] },
  { label: "Machines", kinds: ["service", "workload", "broker"] },
];

/**
 * The actor filter's options: anyone, Varlatch itself, then identities by
 * group, each sorted by name, retired ones marked.
 */
export function actorOptions(identities: OrgIdentity[]): { value: string; label: string; group?: string }[] {
  return [
    { value: "", label: "anyone" },
    { value: VARLATCH_ACTOR, label: "Varlatch" },
    ...ACTOR_GROUPS.flatMap(({ label, kinds }) =>
      identities
        .filter((i) => kinds.includes(i.kind))
        .sort((a, b) => a.name.localeCompare(b.name))
        .map((i) => ({ value: i.id, label: i.disabled ? `${i.name} (retired)` : i.name, group: label })),
    ),
  ];
}

/** Merge each loaded page's credentials sidecar: a page describes only its own events. */
export function mergeCredentials(pages: { credentials?: AuditCredentials | undefined }[]): AuditCredentials {
  return Object.assign({}, ...pages.map((p) => p.credentials ?? {})) as AuditCredentials;
}

const KIND_ICONS: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  agent: Sparkles,
  ci: Workflow,
  service: Bot,
  workload: Bot,
  broker: KeyRound,
  system: Server,
  unknown: HelpCircle,
};

export function ActorMark({ actor, size = "sm" }: { actor: Actor; size?: "xs" | "sm" | "md" }) {
  if (actor.kind === "human") return <Avatar name={actor.name} image={actor.identity?.image} size={size} />;
  const Icon = KIND_ICONS[actor.kind] ?? Bot;
  const box = size === "md" ? "size-8" : size === "xs" ? "size-5" : "size-6";
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-full border border-bd bg-inset",
        actor.kind === "agent" ? "text-warn" : "text-muted",
        box,
      )}
      title={actor.kind === "system" ? "Varlatch itself" : actor.kind}
    >
      <Icon size={size === "md" ? 15 : 12} />
    </span>
  );
}

export function SentenceText({ segments, className }: { segments: Segment[]; className?: string }) {
  return (
    <span className={className}>
      {segments.map((s, i) =>
        typeof s === "string" ? (
          <React.Fragment key={i}>{s}</React.Fragment>
        ) : s.kind === "name" ? (
          <span key={i} className="font-medium text-fg">
            {s.text}
          </span>
        ) : (
          <span key={i} className={cn("font-mono text-[12.5px] text-fg", s.kind === "place" && "whitespace-nowrap")}>
            {s.text}
          </span>
        ),
      )}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const tone = decision === "deny" ? "danger" : decision === "allow" ? "accent" : "info";
  return (
    <Badge tone={tone} className="font-mono" data-decision={decision}>
      {decision}
    </Badge>
  );
}


/** Events of one automatic push: same target and generation, no actor. */
export function sameDelivery(a: AuditEventLike, b: AuditEventLike): boolean {
  if (a.actorIdentityId || b.actorIdentityId) return false;
  if (!a.eventType.startsWith("sync.") || !b.eventType.startsWith("sync.")) return false;
  const ra = (a.resource ?? {}) as Record<string, unknown>;
  const rb = (b.resource ?? {}) as Record<string, unknown>;
  const ga = (a.metadata as Record<string, unknown> | undefined)?.generation;
  const gb = (b.metadata as Record<string, unknown> | undefined)?.generation;
  return Boolean(ra.targetId) && ra.targetId === rb.targetId && ga !== undefined && ga === gb;
}

/** 24-hour clock, like the rest of the log. */
export function clock(iso: string, seconds = false): string {
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    ...(seconds ? { second: "2-digit" } : {}),
    hourCycle: "h23",
  });
}

