// SPDX-License-Identifier: AGPL-3.0-or-later
import { redactWebhookUrl } from "../audit/serialize.js";
import type { Querier } from "../db/migrate.js";
import { canonicalJson, type ApprovalBinding, type ApprovalChange } from "./approvals.js";
import { labelWithId, quoted } from "./approvallabels.js";

/**
 * admin-step-up for integrations (ADR-0054 Decision 5, step 4.8): what an
 * approval binds for webhooks, Platform Connections and the GitHub App,
 * per the binding catalogue, and the summary its approver reads. Each
 * binds the query `{}` except `github_app.remove`, which reads `appId`.
 *
 * Secret-bearing input (amendment A): a webhook URL (it may carry a token
 * in its path or query), a Connection credential and a GitHub App private
 * key. The parsed value itself is part of the bound body, so the keyed HMAC
 * the intent stores (approvalHash, under the root KEK) covers the actual
 * input, and an approval given for one secret never fits another. Nothing
 * else binds it: no ciphertext (randomized per attempt), no placeholder, no
 * other hash. The intent stores only that HMAC; the summary says that a
 * secret is set or replaced, never what it is, and shows a webhook URL
 * redacted as its audit events do (redactWebhookUrl). Server-generated
 * outputs (a webhook's signing secret, a new id) are never bound.
 *
 * - webhook.create: target the Organization; body `url` (full) and
 *   `eventTypes` (a set; null when left out: every event); no version.
 * - webhook.update: target the webhook; body the resulting `url` and
 *   `eventTypes` (a set, or null for every event; absence keeps a field,
 *   null clears the filter); the version the request expects. A patch that
 *   changes neither (a reordering of the event types included) needs none.
 * - webhook.delete: target the webhook; no body; the version the server
 *   reads, checked again under the webhook's row lock.
 * - connection.create, token shape: target the Organization; body
 *   `platform` and `baseIdentity` as the server canonicalizes them, `name`
 *   and `credential`; no version.
 * - connection.create, App shape: target the Organization and the GitHub
 *   App (Varlatch's row id); body `installationId` and `name`; no version.
 *   The installation's account comes from GitHub after the precheck and is
 *   not bound.
 * - connection.replace_credential: target the Connection; body
 *   `credential`; the version the request expects.
 * - connection.delete: target the Connection; no body; the version the
 *   server reads, checked again under the Connection's row lock.
 * - github_app.register: target the registration; body the pending
 *   conversion's `githubAppId`, `slug`, `clientId` and `owner` (`login`,
 *   `id`, `type`). The private key is not in the body: the pending row is
 *   written once, so its id pins the key. No version.
 * - github_app.import: target the Organization; body `appId` and
 *   `privateKey`; no version.
 * - github_app.replace_key: target the GitHub App; body `privateKey`; the
 *   version the request expects.
 * - github_app.remove: target the GitHub App; no body; query `appId`; the
 *   version the server reads, checked again under the App's row lock.
 *
 * A summary holds no unquoted free text from the database or the request
 * (approvallabels.ts): every name, URL, event type, platform, base
 * identity, slug and client id is quoted, a list is a bracketed list of
 * quoted items, and every existing item shows its id (labelWithId), such as
 * `connection "GitHub" (pcn_a)` or a webhook's redacted URL with its id.
 * Only the fixed words and ids stay unquoted.
 */

/**
 * A list as a summary writes it: its items quoted, in brackets. A comma or
 * a bracket inside an item stays inside its quotes, so two different lists
 * never read the same. (Moves to approvallabels.ts with the shared list
 * renderer.)
 */
export function quotedList(items: readonly string[]): string {
  return `[${items.map(quoted).join(", ")}]`;
}

const set = (values: readonly string[]) => [...new Set(values)].sort();
const added = (field: string, to: string): ApprovalChange => ({ field, from: null, to, loosens: false });
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** What the approver reads instead of a secret. */
export const SECRET_SET = "a new value (not shown)";
const SECRET_KEPT = "the current value";

// ---- Webhooks

/** A webhook's event filter as bound: a set, or null for every event. */
export function boundEventTypes(eventTypes: readonly string[] | null | undefined): string[] | null {
  return eventTypes === null || eventTypes === undefined ? null : set(eventTypes);
}

const eventWords = (eventTypes: readonly string[] | null) => (eventTypes === null ? "every event" : `event types ${quotedList(eventTypes)}`);

export interface WebhookRef {
  id: string;
  url: string;
  eventTypes: string[] | null;
  version: number;
}

/** A live webhook of the Organization, read without a lock; null when there is none. */
export async function readWebhook(db: Querier, organizationId: string, webhookId: string): Promise<WebhookRef | null> {
  const row = (await db.query(
    "SELECT id, url, event_types, version FROM webhooks WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
    [webhookId, organizationId],
  )).rows[0] as { id: string; url: string; event_types: string[] | null; version: number } | undefined;
  return row ? { id: row.id, url: row.url, eventTypes: row.event_types, version: Number(row.version) } : null;
}

/** A webhook as a summary names it: its redacted URL, quoted, with its id. */
const webhookLabel = (webhook: { id: string; url: string }) => labelWithId("webhook", redactWebhookUrl(webhook.url), webhook.id);

/** Whether a webhook's resulting state means the same as its current one: the same URL, the same set of event types. */
export function sameWebhook(a: { url: string; eventTypes: readonly string[] | null }, b: { url: string; eventTypes: readonly string[] | null }): boolean {
  return a.url === b.url && canonicalJson(boundEventTypes(a.eventTypes)) === canonicalJson(boundEventTypes(b.eventTypes));
}

/** webhook.create. */
export function webhookCreateBinding(
  org: { id: string; name: string },
  input: { url: string; eventTypes?: readonly string[] | undefined },
): ApprovalBinding {
  const eventTypes = boundEventTypes(input.eventTypes);
  const redacted = redactWebhookUrl(input.url);
  return {
    operation: "webhook.create",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { url: input.url, eventTypes },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Send the audit events of ${labelWithId("organization", org.name, org.id)} to ${quoted(redacted)} (${eventWords(eventTypes)})`,
      changes: [added("url", quoted(redacted)), added("eventTypes", eventWords(eventTypes))],
    },
  };
}

/** webhook.update that changes the webhook: its resulting state, the version the request expects. */
export function webhookUpdateBinding(
  org: { id: string },
  current: WebhookRef,
  next: { url: string; eventTypes: readonly string[] | null },
  expectedVersion: number,
): ApprovalBinding {
  const label = webhookLabel(current);
  const eventTypes = boundEventTypes(next.eventTypes);
  const changes: ApprovalChange[] = [];
  if (next.url !== current.url) {
    // Decided on the bound URL, never on its redaction: a changed token
    // that redacts the same is still listed, without showing it.
    const [from, to] = [redactWebhookUrl(current.url), redactWebhookUrl(next.url)];
    changes.push(
      from === to
        ? { field: "url", from: `${quoted(from)} (current)`, to: `${quoted(to)} (another URL: the part that changed is not shown)`, loosens: false }
        : { field: "url", from: quoted(from), to: quoted(to), loosens: false },
    );
  }
  const before = boundEventTypes(current.eventTypes);
  if (canonicalJson(before) !== canonicalJson(eventTypes)) {
    changes.push({ field: "eventTypes", from: eventWords(before), to: eventWords(eventTypes), loosens: false });
  }
  return {
    operation: "webhook.update",
    organizationId: org.id,
    target: { webhookId: current.id },
    body: { url: next.url, eventTypes },
    query: {},
    expectedVersion,
    summary: { title: `Change ${label} to ${quoted(redactWebhookUrl(next.url))}`, changes },
  };
}

/** webhook.delete of a live webhook, at the version the server read. */
export function webhookDeleteBinding(org: { id: string }, webhook: WebhookRef): ApprovalBinding {
  return {
    operation: "webhook.delete",
    organizationId: org.id,
    target: { webhookId: webhook.id },
    body: null,
    query: {},
    expectedVersion: webhook.version,
    summary: { title: `Stop sending audit events to ${webhookLabel(webhook)}`, changes: [] },
  };
}

// ---- Platform Connections

export interface ConnectionRef {
  id: string;
  name: string;
  platform: string;
  baseIdentity: string;
  credentialKind: "token" | "github-app";
  version: number;
}

/** A live Connection of the Organization, read without a lock; null when there is none. */
export async function readConnection(db: Querier, organizationId: string, connectionId: string): Promise<ConnectionRef | null> {
  const row = (await db.query(
    `SELECT id, name, platform, base_identity, credential_kind, version FROM platform_connections
     WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL`,
    [connectionId, organizationId],
  )).rows[0] as { id: string; name: string; platform: string; base_identity: string; credential_kind: "token" | "github-app"; version: number } | undefined;
  return row
    ? { id: row.id, name: row.name, platform: row.platform, baseIdentity: row.base_identity, credentialKind: row.credential_kind, version: Number(row.version) }
    : null;
}

/** A Connection as a summary names it: its name, quoted, with its id. */
const connectionLabel = (connection: { id: string; name: string }) => labelWithId("connection", connection.name, connection.id);

/** The live Sync Targets of a Connection: what pushes with its credential, or stops when it is revoked. */
async function connectionTargets(db: Querier, connectionId: string): Promise<number> {
  return Number(((await db.query("SELECT count(*)::int AS n FROM sync_targets WHERE connection_id = $1 AND revoked_at IS NULL", [connectionId]))
    .rows[0] as { n: number }).n);
}

/** connection.create, token shape: the platform and base identity as the server canonicalizes them. */
export function connectionCreateBinding(
  org: { id: string },
  input: { platform: string; baseIdentity: string; name: string; credential: string },
): ApprovalBinding {
  return {
    operation: "connection.create",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { platform: input.platform, baseIdentity: input.baseIdentity, name: input.name, credential: input.credential },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Add connection ${quoted(input.name)} on platform ${quoted(input.platform)} for base identity ${quoted(input.baseIdentity)}, with a new credential`,
      changes: [
        added("platform", quoted(input.platform)),
        added("baseIdentity", quoted(input.baseIdentity)),
        added("name", quoted(input.name)),
        added("credential", SECRET_SET),
      ],
    },
  };
}

/** connection.create, App shape: on an installation of the Organization's GitHub App, from Varlatch's records. */
export function appConnectionCreateBinding(
  org: { id: string },
  app: { id: string; slug: string },
  input: { installationId: number; name: string },
): ApprovalBinding {
  return {
    operation: "connection.create",
    organizationId: org.id,
    target: { organizationId: org.id, githubAppId: app.id },
    body: { installationId: input.installationId, name: input.name },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Add connection ${quoted(input.name)} on installation ${input.installationId} of ${labelWithId("GitHub App", app.slug, app.id)}`,
      changes: [added("name", quoted(input.name)), added("installationId", String(input.installationId))],
    },
  };
}

/** connection.replace_credential of a live token Connection, at the version the request expects. */
export async function connectionReplaceCredentialBinding(
  db: Querier,
  org: { id: string },
  connection: ConnectionRef,
  credential: string,
  expectedVersion: number,
): Promise<ApprovalBinding> {
  const targets = await connectionTargets(db, connection.id);
  const label = connectionLabel(connection);
  return {
    operation: "connection.replace_credential",
    organizationId: org.id,
    target: { connectionId: connection.id },
    body: { credential },
    query: {},
    expectedVersion,
    summary: {
      title: `Replace the credential of ${label} on platform ${quoted(connection.platform)} for base identity ${quoted(connection.baseIdentity)}. ${plural(targets, "Sync Target")} will push with it`,
      changes: [{ field: "credential", from: SECRET_KEPT, to: SECRET_SET, loosens: false }],
    },
  };
}

/** connection.delete of a live Connection, at the version the server read. */
export async function connectionDeleteBinding(db: Querier, org: { id: string }, connection: ConnectionRef): Promise<ApprovalBinding> {
  const targets = await connectionTargets(db, connection.id);
  const label = connectionLabel(connection);
  return {
    operation: "connection.delete",
    organizationId: org.id,
    target: { connectionId: connection.id },
    body: null,
    query: {},
    expectedVersion: connection.version,
    summary: {
      title: `Revoke ${label}. ${plural(targets, "Sync Target")} ${targets === 1 ? "is" : "are"} disabled`,
      changes: [],
    },
  };
}

// ---- The GitHub App

export interface AppRef {
  id: string;
  githubAppId: number;
  slug: string;
  version: number;
}

/** The Organization's live GitHub App, read without a lock; null when there is none. */
export async function readApp(db: Querier, organizationId: string): Promise<AppRef | null> {
  const row = (await db.query(
    "SELECT id, github_app_id, slug, version FROM github_apps WHERE organization_id = $1 AND removed_at IS NULL",
    [organizationId],
  )).rows[0] as { id: string; github_app_id: string | number; slug: string; version: number } | undefined;
  return row ? { id: row.id, githubAppId: Number(row.github_app_id), slug: row.slug, version: Number(row.version) } : null;
}

/** What the App's live Connections, and their live Sync Targets, number. */
async function appReach(db: Querier, appRowId: string): Promise<{ connections: number; targets: number }> {
  const row = (await db.query(
    `SELECT (SELECT count(*)::int FROM platform_connections WHERE github_app_id = $1 AND revoked_at IS NULL) AS connections,
            (SELECT count(*)::int FROM sync_targets t JOIN platform_connections c ON c.id = t.connection_id
              WHERE c.github_app_id = $1 AND c.revoked_at IS NULL AND t.revoked_at IS NULL) AS targets`,
    [appRowId],
  )).rows[0] as { connections: number; targets: number };
  return { connections: Number(row.connections), targets: Number(row.targets) };
}

/** A pending conversion, as an attachment binds it. */
export interface PendingConversion {
  registrationId: string;
  githubAppId: number;
  slug: string;
  clientId: string;
  owner: { login: string; id: number; type: "organization" | "user" };
}

/** github_app.register: the attachment of a pending registration. */
export function githubAppRegisterBinding(org: { id: string; name: string }, pending: PendingConversion): ApprovalBinding {
  const app = `GitHub App ${quoted(pending.slug)} (GitHub App id ${pending.githubAppId}, client id ${quoted(pending.clientId)})`;
  const owner = `GitHub ${pending.owner.type} ${quoted(pending.owner.login)} (GitHub id ${pending.owner.id})`;
  return {
    operation: "github_app.register",
    organizationId: org.id,
    target: { registrationId: pending.registrationId },
    body: {
      githubAppId: pending.githubAppId,
      slug: pending.slug,
      clientId: pending.clientId,
      owner: { login: pending.owner.login, id: pending.owner.id, type: pending.owner.type },
    },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Attach ${app}, owned by ${owner}, to ${labelWithId("organization", org.name, org.id)}, from registration ${pending.registrationId}`,
      changes: [added("app", app), added("owner", owner)],
    },
  };
}

/** github_app.import: what is known before GitHub is asked, the App id and the key. */
export function githubAppImportBinding(org: { id: string }, input: { appId: number; privateKey: string }): ApprovalBinding {
  return {
    operation: "github_app.import",
    organizationId: org.id,
    target: { organizationId: org.id },
    body: { appId: input.appId, privateKey: input.privateKey },
    query: {},
    expectedVersion: null,
    summary: {
      title: `Import GitHub App ${input.appId} with a private key`,
      changes: [added("appId", String(input.appId)), added("privateKey", SECRET_SET)],
    },
  };
}

/** github_app.replace_key of the live App, at the version the request expects. */
export async function githubAppReplaceKeyBinding(
  db: Querier,
  org: { id: string },
  app: AppRef,
  privateKey: string,
  expectedVersion: number,
): Promise<ApprovalBinding> {
  const { targets } = await appReach(db, app.id);
  return {
    operation: "github_app.replace_key",
    organizationId: org.id,
    target: { githubAppId: app.id },
    body: { privateKey },
    query: {},
    expectedVersion,
    summary: {
      title: `Replace the private key of ${labelWithId("GitHub App", app.slug, app.id)}. ${plural(targets, "Sync Target")} will push with it`,
      changes: [{ field: "privateKey", from: SECRET_KEPT, to: SECRET_SET, loosens: false }],
    },
  };
}

/** github_app.remove of the live App the request names, at the version the server read. */
export async function githubAppRemoveBinding(db: Querier, org: { id: string }, app: AppRef): Promise<ApprovalBinding> {
  const { connections, targets } = await appReach(db, app.id);
  return {
    operation: "github_app.remove",
    organizationId: org.id,
    target: { githubAppId: app.id },
    body: null,
    query: { appId: app.id },
    expectedVersion: app.version,
    summary: {
      title:
        `Remove ${labelWithId("GitHub App", app.slug, app.id)} from Varlatch: ${plural(connections, "connection")} revoked, ` +
        `${plural(targets, "Sync Target")} disabled. It stays on GitHub`,
      changes: [],
    },
  };
}
