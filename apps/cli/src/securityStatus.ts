// SPDX-License-Identifier: Apache-2.0
import {
  VarlatchApiError,
  type ApprovalKeys,
  type AuditExportStatus,
  type CredentialReview,
  type IncidentFreeze,
  type SecurityControl,
  type SecurityControlCounts,
  type SecurityControlList,
  type SecurityControlMode,
  type SecurityControlName,
  type SecurityReportEntry,
  type VarlatchClient,
} from "@varlatch/sdk";
import type { Requirement } from "@varlatch/protocol";
import { enforceable, lifetime } from "./securityControls.js";
import { ago, expiryLine, usagePolicyLine } from "./securityReport.js";
import { statusLines as auditExportLines } from "./auditExport.js";

/**
 * `varlatch security status` (ADR-0054 Decision 11): what the dashboard's
 * Security page shows, as text or one JSON document. The Organization's
 * Security Controls with what each one counts in report mode and what
 * enforce would change, their counts of the last 30 days, the approval keys
 * of the admins, the credential review with expiry warnings, the Tailnet
 * Requirements, the audit export (ADR-0056 Decision 11), and a short
 * checklist with links to the docs.
 *
 * Read-only. Each part needs its own permission: the controls need
 * organization.read (every member); the counts and approval keys
 * organization.manage; the credential review identity.manage; Requirements
 * policy.read. A part the caller cannot read, or the server cannot answer,
 * is left out and named in `unavailable`; only the controls are required.
 * Where the server reports the caller's own permissions
 * (organizations.permissions), parts they do not hold are not asked for.
 */

export const SECURITY_STATUS_USAGE = "Usage: varlatch security status [--json] [--org <organization>] [--server <url>]";

export const DOCS = "https://docs.varlatch.com";

const CONTROL_ORDER: readonly SecurityControlName[] = ["requirement-protection", "admin-step-up", "passkey-verification", "credential-lifetime"];

/** What each control counts in report mode, and what enforce would change. Same words as the Security page. */
export const CONTROL_EXPLANATIONS: Record<SecurityControlName, { report: string; enforce: string }> = {
  "requirement-protection": {
    report: "Counts each edit or revocation of a Tailnet Requirement made without an approval. Creating one is not counted: it only restricts.",
    enforce: "Editing or revoking a Tailnet Requirement would need an approval with a trusted passkey, so a stolen admin sign-in cannot remove one from off the tailnet.",
  },
  "admin-step-up": {
    report:
      "Counts each administrative change made without an approval: machine identities and credentials, grants, roles, groups and teams, admins and members, integrations, deletion, and .env export.",
    enforce: "Those changes would need an approval with a trusted passkey. A machine credential can never give one, so it would be refused.",
  },
  "passkey-verification": {
    report:
      "Counts requests by a person's dashboard or CLI sign-in that was not made with a trusted passkey that verified them (PIN, fingerprint or face). Only requests that were allowed and succeeded count, and machine credentials never do. Access counts are best-effort: a busy server can drop some, so a count is a lower bound.",
    enforce: "Such sign-ins would be refused in this organization until the person signs in again with a trusted passkey and a PIN, fingerprint or face.",
  },
  "credential-lifetime": {
    report:
      "Counts machine credentials issued without a lifetime (they would get the default) and with one above the maximum (they would be refused). OIDC and agent-run credentials are not counted.",
    enforce: "Machine credentials would get the default lifetime when none is given, and longer ones would be refused. Existing credentials never change.",
  },
};

export interface ChecklistItem {
  id: string;
  title: string;
  why: string;
  url: string;
}

/** A short checklist; each item links to its docs page. */
export const CHECKLIST: readonly ChecklistItem[] = [
  {
    id: "report-mode",
    title: "Try each control in report mode",
    why: "Report refuses nothing; its counts show what enforce would stop before you decide.",
    url: `${DOCS}/reference/security-controls/`,
  },
  {
    id: "trusted-passkeys",
    title: "Give every admin a trusted passkey",
    why: "Only a trusted passkey can approve turning a control down or off.",
    url: `${DOCS}/getting-started/#your-passkeys`,
  },
  {
    id: "find-files",
    title: "Find copies of secrets on disk",
    why: "varlatch scan --find-files lists .env and key files that a stolen laptop would give away.",
    url: `${DOCS}/reference/secret-scanning/#finding-copies-of-secrets`,
  },
  {
    id: "backup-object-lock",
    title: "Keep backups where the host cannot erase them",
    why: "With Object Lock on the bucket, a compromised host cannot delete or overwrite archives.",
    url: `${DOCS}/operations/backup/#scoping-destination-credentials-per-provider`,
  },
  {
    id: "threat-model",
    title: "Read the threat model",
    why: "What Varlatch protects against, and what it leaves to whoever runs the host.",
    url: `${DOCS}/threat-model/`,
  },
];

export type StatusSection = "controlReport" | "approvalKeys" | "credentialReview" | "requirements";
export type Unavailable = { section: StatusSection; reason: "not-permitted" | "not-supported" };

export interface StatusControl extends SecurityControl {
  explanation: { report: string; enforce: string };
  /** The control's counts in the window; null when the counts are unavailable. */
  counts: Pick<SecurityControlCounts, "total" | "currentHour" | "pending" | "entries"> | null;
}

export interface SecurityStatus {
  organization: string;
  /** The open incident freeze (ADR-0055), or null; null too where the server has none. */
  incidentFreeze: IncidentFreeze | null;
  /** Whether this server can enforce any control. */
  enforceAvailable: boolean;
  /** The controls this server can enforce (each item's availableModes says the same). */
  enforceable: SecurityControlName[];
  controls: {
    availableModes: SecurityControlMode[];
    /** The counts' window; null when the counts are unavailable. */
    window: { days: number; since: string; generatedAt: string } | null;
    items: StatusControl[];
  };
  approvalKeys: ApprovalKeys | null;
  credentialReview: CredentialReview | null;
  requirements: { count: number; protectedBy: "requirement-protection"; items: Requirement[] } | null;
  /**
   * The audit export and the installation switch (capability
   * audit.storage-export), for whoever may manage the organization; null
   * otherwise. Not listed in `unavailable`: a member's text is unchanged,
   * and their JSON gains only this key, as null.
   */
  auditExport: AuditExportStatus | null;
  checklist: readonly ChecklistItem[];
  unavailable: Unavailable[];
}

export type SecurityStatusApi = Pick<
  VarlatchClient,
  "meta" | "myOrganizationPermissions" | "listSecurityControls" | "securityControlReport" | "securityApprovalKeys" | "credentialReview" | "listRequirements"
> & Partial<Pick<VarlatchClient, "incidentFreeze" | "getAuditExport">>;

/** The server cannot answer at all: it has no Security Controls. */
export class SecurityStatusUnsupportedError extends Error {
  override name = "SecurityStatusUnsupportedError";
}

/** The caller may not read it: refused (403) or hidden (404). */
function notPermitted(err: unknown): boolean {
  return err instanceof VarlatchApiError && (err.status === 403 || err.status === 404);
}

export async function fetchSecurityStatus(api: SecurityStatusApi, organization: string): Promise<SecurityStatus> {
  const meta = await api.meta();
  if (!meta.capabilities.includes("security.controls")) {
    throw new SecurityStatusUnsupportedError(
      `varlatch security status: this server (${meta.serverVersion}) has no security controls ` +
        "(it lacks the security.controls capability); upgrade the server.",
    );
  }
  const has = (cap: string) => meta.capabilities.includes(cap);
  const unavailable: Unavailable[] = [];
  // Errors other than "not yours to read" fail the whole command.
  // The caller's own permissions, where the server can say: parts they do not
  // allow are never asked for, so the command records no refusals.
  const held = has("organizations.permissions") ? new Set<string>((await api.myOrganizationPermissions(organization)).actions) : null;
  async function part<T>(section: StatusSection, capability: string | null, load: () => Promise<T>): Promise<T | null> {
    if (capability && !has(capability)) {
      unavailable.push({ section, reason: "not-supported" });
      return null;
    }
    if (held && !held.has(NEEDS[section])) {
      unavailable.push({ section, reason: "not-permitted" });
      return null;
    }
    try {
      return await load();
    } catch (err) {
      if (!notPermitted(err)) throw err;
      unavailable.push({ section, reason: "not-permitted" });
      return null;
    }
  }

  // Every member reads the freeze (organization.read), as the controls.
  const incidentFreeze = has("organizations.incident-freeze") && api.incidentFreeze ? (await api.incidentFreeze(organization)).freeze : null;
  const list: SecurityControlList = await api.listSecurityControls(organization);
  const report = await part("controlReport", "security.report", () => api.securityControlReport(organization, { days: 30 }));
  // The approval keys need what the counts need: no second refusal when the counts were refused.
  const keys =
    report === null && unavailable.some((u) => u.section === "controlReport" && u.reason === "not-permitted")
      ? (unavailable.push({ section: "approvalKeys", reason: "not-permitted" }), null)
      : await part("approvalKeys", "security.approval-keys", () => api.securityApprovalKeys(organization));
  const review = await part("credentialReview", "security.credential-review", () => api.credentialReview(organization));
  const requirements = await part("requirements", null, () => api.listRequirements(organization));
  // The audit export: asked only where the server has it and the caller may manage the organization.
  const mayManage = held ? held.has("organization.manage") : true;
  let auditExport: AuditExportStatus | null = null;
  if (has("audit.storage-export") && api.getAuditExport && mayManage) {
    try {
      auditExport = await api.getAuditExport(organization);
    } catch (err) {
      if (!notPermitted(err)) throw err;
    }
  }

  const items = [...list.items]
    .sort((a, b) => CONTROL_ORDER.indexOf(a.control) - CONTROL_ORDER.indexOf(b.control))
    .map((c): StatusControl => {
      const counts = report?.controls.find((r) => r.control === c.control);
      return {
        ...c,
        explanation: CONTROL_EXPLANATIONS[c.control],
        counts: counts ? { total: counts.total, currentHour: counts.currentHour, pending: counts.pending, entries: counts.entries } : null,
      };
    });
  return {
    organization,
    enforceAvailable: enforceable(list).length > 0,
    enforceable: enforceable(list),
    controls: {
      availableModes: list.availableModes,
      window: report ? { days: report.days, since: report.since, generatedAt: report.generatedAt } : null,
      items,
    },
    approvalKeys: keys,
    credentialReview: review,
    requirements: requirements ? { count: requirements.items.length, protectedBy: "requirement-protection", items: requirements.items } : null,
    checklist: CHECKLIST,
    unavailable,
    incidentFreeze,
    // Last, so every earlier key keeps its place.
    auditExport,
  };
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** "in 3 days", "within a day": how long until an expiry, rounded up to whole days. */
export function until(at: string, now: number): string {
  const days = Math.ceil((Date.parse(at) - now) / 86_400_000);
  return days <= 1 ? "within a day" : `in ${days} days`;
}

function entryLine(e: SecurityReportEntry): string {
  const who = e.actor.name ?? e.actor.id;
  return `      ${e.operation}  ${e.reason}  by ${who}${e.actor.kind && e.actor.kind !== "human" ? ` (${e.actor.kind})` : ""}: ${e.count}`;
}

/** How many entries per control the text shows; --json has them all. */
export const TEXT_ENTRIES = 3;

const SECTION_WORDS: Record<StatusSection, string> = {
  controlReport: "counts of the controls",
  approvalKeys: "admins' approval keys",
  credentialReview: "credential review",
  requirements: "Tailnet Requirements",
};
const NEEDS: Record<StatusSection, string> = {
  controlReport: "organization.manage",
  approvalKeys: "organization.manage",
  credentialReview: "identity.manage",
  requirements: "policy.read",
};

/** The human format: grouped and short. */
export function securityStatusLines(s: SecurityStatus, now: number): string[] {
  const lines: string[] = [`Security for ${s.organization}`];
  if (s.incidentFreeze) {
    const f = s.incidentFreeze;
    lines.push(
      `FROZEN for an incident since ${f.frozenAt} by ${f.frozenBy.name ?? f.frozenBy.id}: ${f.reason}`,
      `  Every read and write is refused except inspection, audit and recovery. Lift it: varlatch org unfreeze ${s.organization}`,
    );
  }
  const on = s.controls.items.filter((c) => c.mode !== "off");
  lines.push(
    on.length === 0
      ? "Every control is off, as it is by default: nothing is counted, refused or changed."
      : `Every control is off by default. Turned on here: ${on.map((c) => `${c.control} (${c.mode})`).join(", ")}.`,
  );

  // Controls.
  const width = Math.max(...s.controls.items.map((c) => c.control.length));
  lines.push("", s.controls.window ? `Controls (counts of the last ${s.controls.window.days} days)` : "Controls");
  for (const c of s.controls.items) {
    const facts: string[] = [];
    if (c.config) facts.push(`default ${lifetime(c.config.defaultTtlSeconds)}, at most ${lifetime(c.config.maxTtlSeconds)}`);
    if (c.counts) {
      facts.push(
        c.counts.total === 0
          ? "nothing counted"
          : `${c.counts.total} counted${c.counts.currentHour > 0 ? `, ${c.counts.currentHour} this hour` : ""}`,
      );
    }
    lines.push(`  ${c.control.padEnd(width)}  ${c.mode.padEnd(6)}${facts.length ? `  ${facts.join("; ")}` : ""}`);
    if (c.counts && c.control === "passkey-verification" && c.mode !== "off") {
      lines.push("      only allowed, successful requests count; access counts are best-effort, so this is a lower bound");
    }
    for (const e of c.counts?.entries.slice(0, TEXT_ENTRIES) ?? []) lines.push(entryLine(e));
    const more = (c.counts?.entries.length ?? 0) - TEXT_ENTRIES;
    if (more > 0) lines.push(`      and ${plural(more, "more entry", "more entries")} (--json lists all)`);
  }
  lines.push(
    s.enforceable.length > 0
      ? `  Modes: ${s.controls.availableModes.join(", ")}, and enforce for ${s.enforceable.join(", ")}.` +
          (s.enforceable.length < s.controls.items.length ? " Enforce for the others: coming in a later release." : "")
      : `  Modes: ${s.controls.availableModes.join(", ")}. Enforce: coming in a later release.`,
    "  Report counts what a control would have done, without refusing or changing anything.",
    "  Turning a control down or off, or a lifetime up, needs your approval with a trusted passkey.",
  );

  // Approval keys.
  if (s.approvalKeys) {
    lines.push("", "Approval keys of the admins (only a trusted passkey can approve)");
    for (const a of s.approvalKeys.items) {
      const counts = `${a.trusted} trusted, ${a.unconfirmed} unconfirmed`;
      lines.push(`  ${a.identity.name}  ${counts}${a.trusted === 0 ? ": cannot approve anything yet" : ""}`);
    }
    if (s.approvalKeys.summary.withoutTrustedKey > 0) {
      lines.push(
        "  Confirm a passkey with a trusted one under Account, Security in the dashboard. Without any trusted one,",
        "  ask whoever runs the server: varlatch admin reenroll --identity <id>.",
      );
    }
  }

  // Credentials.
  const review = s.credentialReview;
  if (review) {
    const { summary } = review;
    lines.push("", "Machine credentials", `  ${usagePolicyLine(review)}`);
    const expiry = review.expiry;
    if (expiry) {
      lines.push(`  ${expiryLine(expiry)}`);
      for (const c of expiry.items) {
        const when = !c.expiresAt ? "" : c.state === "expired" ? `expired ${ago(c.expiresAt, now)}` : `expires ${until(c.expiresAt, now)} (${c.expiresAt})`;
        lines.push(`  ${c.id}  ${c.name ?? "unnamed"}  for ${c.identity.name}: ${when}`);
      }
    }
    if (review.summary.listed > 0 || (expiry?.items.length ?? 0) > 0) {
      lines.push("  Details: varlatch security report. Revoke or replace them in the dashboard under Access, Machines.");
    }
  }

  // Requirements.
  if (s.requirements) {
    const protection = s.controls.items.find((c) => c.control === "requirement-protection")?.mode ?? "off";
    lines.push(
      "",
      "Tailnet Requirements",
      `  ${s.requirements.count === 0 ? "None" : plural(s.requirements.count, "requirement", "requirements")}. requirement-protection is ${protection}.`,
      "  Edit them in the dashboard under Access, Advanced, or list them: varlatch tailnet requirements.",
    );
  }

  // The audit export.
  if (s.auditExport) {
    const e = s.auditExport.export;
    const shown = e && (e.state === "active" || e.state === "draining");
    lines.push("", "Audit export");
    if (!shown) {
      if (!s.auditExport.enabled) lines.push("  Stopped by the host operator on this installation (VARLATCH_AUDIT_EXPORT=off).");
      lines.push(
        `  Not set up${e ? `; the last export was ${e.state}` : ""}. The audit log stays in this installation only.`,
        "  Copy it to a bucket you control: varlatch audit-export create (see varlatch audit-export --help).",
      );
    } else {
      // The same lines as varlatch audit-export show, under this heading.
      for (const line of auditExportLines(s.organization, s.auditExport)) lines.push(line.startsWith("  ") ? line : `  ${line}`);
      lines.push(
        "  Checklist: compliance retention for at least 400 days; a bucket in an account the host operator does not control;",
        "  someone watching the heartbeat. Details: varlatch audit-export show.",
      );
    }
  }

  // Checklist.
  lines.push("", "Checklist");
  for (const item of s.checklist) lines.push(`  - ${item.title}: ${item.why}`, `    ${item.url}`);

  if (s.unavailable.length > 0) {
    lines.push("", "Not shown");
    for (const u of s.unavailable) {
      lines.push(
        u.reason === "not-supported"
          ? `  ${SECTION_WORDS[u.section]}: this server does not offer it; upgrade the server.`
          : `  ${SECTION_WORDS[u.section]}: needs ${NEEDS[u.section]}. An organization admin manages this.`,
      );
    }
  }
  return lines;
}
