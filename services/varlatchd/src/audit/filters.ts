// SPDX-License-Identifier: AGPL-3.0-or-later
import { CONFIG_ITEM_NAME_PATTERN } from "@varlatch/contract";
import { DomainError } from "../domain/errors.js";

/**
 * Server-side audit filters (capability audit.filters, ADR-0016 §10:
 * authorized query with filtering). Every filter narrows the events an
 * `audit.read` caller already sees; none widens or changes authorization.
 * Filters are ANDed and only add WHERE clauses, so the listing's
 * (occurredAt, eventId) order, and with it every cursor, means the same
 * with or without them.
 */
export interface AuditFilters {
  decision?: "allow" | "deny" | "info";
  /** An exact event type, or a prefix ending in a dot ("value." for `value.*`). */
  eventType?: { exact: string } | { prefix: string };
  actorIdentityId?: string;
  /**
   * "varlatch": Varlatch's own events, recorded with no actor (sync
   * delivery, webhooks, operator commands). A failed authentication has no
   * actor either, and is not Varlatch acting, so authentication.* events
   * are left out, as the dashboard shows them as an unknown actor.
   */
  actor?: "varlatch";
  projectId?: string;
  environmentId?: string;
  item?: string;
  /** RFC 3339, inclusive; passed to PostgreSQL as written (microseconds kept). */
  since?: string;
  /** RFC 3339, exclusive. */
  until?: string;
}

export const AUDIT_FILTER_PARAMS = [
  "decision",
  "eventType",
  "actorIdentityId",
  "actor",
  "projectId",
  "environmentId",
  "item",
  "since",
  "until",
] as const;

const DECISIONS = new Set(["allow", "deny", "info"]);
const EVENT_TYPE = /^[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$/;
const IDENTIFIER = /^[A-Za-z0-9_.:-]{1,200}$/;
const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/i;

function invalid(message: string): never {
  throw new DomainError("VALIDATION_FAILED", message);
}

/** A timestamp's text for PostgreSQL, and its milliseconds for comparing since and until. */
function timestamp(name: string, raw: string): { text: string; ms: number } {
  const m = RFC3339.exec(raw);
  const [y, mo, d, h, mi, s] = (m ?? []).slice(1, 7).map(Number) as number[];
  const date = new Date(Date.UTC(2000, 0, 1));
  if (m) date.setUTCFullYear(y!, mo! - 1, d!);
  const valid =
    m !== null &&
    y! >= 1 &&
    mo! >= 1 && mo! <= 12 &&
    // setUTCFullYear rolls an impossible day (2026-02-30) into the next month.
    date.getUTCMonth() === mo! - 1 && date.getUTCDate() === d &&
    h! <= 23 && mi! <= 59 && s! <= 59 &&
    (m[9] === undefined || (Number(m[10]) <= 23 && Number(m[11]) <= 59));
  if (!valid) {
    invalid(`${name} must be an RFC 3339 timestamp with a time zone, such as 2026-10-01T00:00:00Z`);
  }
  date.setUTCHours(h!, mi!, s!, Math.floor(Number(`0${m[7] ?? ""}`) * 1000));
  const offset = m[9] === undefined ? 0 : (m[9] === "-" ? -1 : 1) * (Number(m[10]) * 60 + Number(m[11]));
  return { text: raw.toUpperCase(), ms: date.getTime() - offset * 60_000 };
}

/**
 * Read and validate the filter query parameters. `values(name)` returns
 * every value given for a parameter; a filter given twice, or given empty,
 * is refused rather than guessed at.
 */
export function parseAuditFilters(values: (name: string) => string[] | undefined): AuditFilters {
  const one = (name: (typeof AUDIT_FILTER_PARAMS)[number]): string | undefined => {
    const all = values(name);
    if (!all || all.length === 0) return undefined;
    if (all.length > 1) invalid(`${name} may be given only once`);
    if (all[0] === "") invalid(`${name} must not be empty`);
    return all[0];
  };
  const filters: AuditFilters = {};

  const decision = one("decision");
  if (decision !== undefined) {
    if (!DECISIONS.has(decision)) invalid("decision must be allow, deny, or info");
    filters.decision = decision as NonNullable<AuditFilters["decision"]>;
  }

  const eventType = one("eventType");
  if (eventType !== undefined) {
    const prefix = eventType.endsWith(".*") ? eventType.slice(0, -2) : null;
    const name = prefix ?? eventType;
    if (name.length > 200 || !EVENT_TYPE.test(name)) {
      invalid("eventType must be an event type, such as value.written, or a prefix ending in .*, such as value.*");
    }
    filters.eventType = prefix !== null ? { prefix: `${prefix}.` } : { exact: eventType };
  }

  for (const name of ["actorIdentityId", "projectId", "environmentId"] as const) {
    const value = one(name);
    if (value === undefined) continue;
    if (!IDENTIFIER.test(value)) invalid(`${name} must be an ID`);
    filters[name] = value;
  }

  const actor = one("actor");
  if (actor !== undefined) {
    if (actor !== "varlatch") invalid("actor must be varlatch, for Varlatch's own events; filter by an identity with actorIdentityId");
    // ANDed they could only ever match nothing: refused rather than answered empty.
    if (filters.actorIdentityId) invalid("actor and actorIdentityId cannot be combined: give one of them");
    filters.actor = actor;
  }

  const item = one("item");
  if (item !== undefined) {
    if (item.length > 200 || !CONFIG_ITEM_NAME_PATTERN.test(item)) {
      invalid("item must be a Config Item name, such as DATABASE_URL");
    }
    filters.item = item;
  }

  const since = one("since");
  const until = one("until");
  const from = since === undefined ? undefined : timestamp("since", since);
  const to = until === undefined ? undefined : timestamp("until", until);
  if (from && to && to.ms < from.ms) invalid("until must not be before since");
  if (from) filters.since = from.text;
  if (to) filters.until = to.text;
  return filters;
}

/**
 * The filters as SQL conditions over audit_events, ANDed; each value is a
 * bind parameter appended to `params`. An item matches an event that names
 * it in its resource (`itemName`, as value writes and rotations record it)
 * or lists it in its metadata (`items`, as disclosures and Capabilities
 * record it, `NAME` or `NAME@version`).
 */
export function auditFilterConditions(filters: AuditFilters, params: unknown[]): string[] {
  const bind = (value: unknown) => {
    params.push(value);
    return `$${params.length}`;
  };
  const conditions: string[] = [];
  if (filters.decision) conditions.push(`decision = ${bind(filters.decision)}`);
  if (filters.eventType) {
    conditions.push(
      "exact" in filters.eventType
        ? `event_type = ${bind(filters.eventType.exact)}`
        : `starts_with(event_type, ${bind(filters.eventType.prefix)})`,
    );
  }
  if (filters.actorIdentityId) conditions.push(`actor_identity_id = ${bind(filters.actorIdentityId)}`);
  if (filters.actor === "varlatch") {
    conditions.push("(actor_identity_id IS NULL AND NOT starts_with(event_type, 'authentication.'))");
  }
  if (filters.projectId) conditions.push(`resource->>'projectId' = ${bind(filters.projectId)}`);
  if (filters.environmentId) conditions.push(`resource->>'environmentId' = ${bind(filters.environmentId)}`);
  if (filters.item) {
    const item = bind(filters.item);
    conditions.push(
      `(resource->>'itemName' = ${item} OR EXISTS (
         SELECT 1 FROM unnest(string_to_array(metadata->>'items', ',')) AS listed(entry)
         WHERE split_part(listed.entry, '@', 1) = ${item}))`,
    );
  }
  if (filters.since) conditions.push(`occurred_at >= ${bind(filters.since)}::timestamptz`);
  if (filters.until) conditions.push(`occurred_at < ${bind(filters.until)}::timestamptz`);
  return conditions;
}
