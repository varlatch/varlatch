// SPDX-License-Identifier: AGPL-3.0-or-later
import { isIP } from "node:net";
import type { Querier } from "../db/migrate.js";
import { classifyAddress, defaultPort, type OutboundPolicy, type RefusalReason } from "./outbound.js";

/**
 * `varlatchd admin outbound check` (ADR-0057 Decision 10): every live
 * destination an Organization configured, with the outbound policy's
 * verdict, and the VARLATCH_OUTBOUND_ALLOW value that would allow the
 * refused ones.
 *
 * It reads only `webhooks`, `platform_connections` and `oidc_bindings`
 * (migrations 0010, 0016 and 0011) and the Organization's name, with the
 * columns those migrations created, so a new release's image can run it
 * against the previous release's database before an upgrade. It makes DNS
 * lookups only, never an HTTP request: an OIDC issuer's jwks_uri is known
 * only from its discovery document, so it is checked when it connects.
 */

export type DestinationKind = "webhook" | "coolify" | "convex" | "oidc-issuer";

export interface CheckedDestination {
  organization: string;
  organizationId: string;
  kind: DestinationKind;
  id: string;
  /** The Connection's name; null for a webhook or an issuer. */
  name: string | null;
  scheme: "https" | "http";
  host: string;
  port: number;
  /** The resolved addresses, for the operator. */
  addresses: string[];
  verdict: "public" | "allowed" | "refused" | "unresolved";
  /** The allow list entries that open it, for "allowed". */
  entries?: string[];
  reason?: RefusalReason;
  /** The resolver's error code, for "unresolved". */
  error?: string;
}

export interface OutboundCheckReport {
  /** When the scan ran. */
  checkedAt: string;
  allow: string[];
  destinations: CheckedDestination[];
  /** The allow list value that would open every refused name it can: the current entries plus the new ones. */
  suggested: string | null;
  /** Refusals no name entry fixes: literal addresses and host-only or never addresses, with why. */
  apart: { host: string; port: number; kind: DestinationKind; id: string; why: string }[];
  /** 0: everything allowed; 1: something refused; 2: nothing refused, but something did not resolve. */
  exitCode: 0 | 1 | 2;
}

interface Row {
  organization_id: string;
  organization: string;
  kind: DestinationKind;
  id: string;
  name: string | null;
  url: string;
}

async function liveDestinations(db: Querier, org: string | null): Promise<Row[]> {
  const filter = org ? " AND (o.id = $1 OR o.slug = $1)" : "";
  const params = org ? [org] : [];
  const rows: Row[] = [];
  const webhooks = await db.query(
    `SELECT w.organization_id, o.slug AS organization, w.id, w.url FROM webhooks w JOIN organizations o ON o.id = w.organization_id
     WHERE w.revoked_at IS NULL AND o.deleted_at IS NULL${filter} ORDER BY o.slug, w.created_at, w.id`,
    params,
  );
  for (const r of webhooks.rows as { organization_id: string; organization: string; id: string; url: string }[]) {
    rows.push({ ...r, kind: "webhook", name: null });
  }
  const connections = await db.query(
    `SELECT c.organization_id, o.slug AS organization, c.id, c.name, c.platform, c.base_identity FROM platform_connections c
     JOIN organizations o ON o.id = c.organization_id
     WHERE c.revoked_at IS NULL AND o.deleted_at IS NULL AND c.platform IN ('coolify', 'convex')${filter}
     ORDER BY o.slug, c.created_at, c.id`,
    params,
  );
  for (const r of connections.rows as { organization_id: string; organization: string; id: string; name: string; platform: "coolify" | "convex"; base_identity: string }[]) {
    rows.push({ organization_id: r.organization_id, organization: r.organization, kind: r.platform, id: r.id, name: r.name, url: r.base_identity });
  }
  const bindings = await db.query(
    `SELECT b.organization_id, o.slug AS organization, b.id, b.issuer FROM oidc_bindings b JOIN organizations o ON o.id = b.organization_id
     WHERE b.revoked_at IS NULL AND o.deleted_at IS NULL${filter} ORDER BY o.slug, b.created_at, b.id`,
    params,
  );
  for (const r of bindings.rows as { organization_id: string; organization: string; id: string; issuer: string }[]) {
    rows.push({ organization_id: r.organization_id, organization: r.organization, kind: "oidc-issuer", id: r.id, name: null, url: r.issuer });
  }
  return rows;
}

type Lookup = (name: string) => Promise<{ address: string; family: 4 | 6 }[]>;

async function checkRow(policy: OutboundPolicy, row: Row, lookup: Lookup): Promise<CheckedDestination | null> {
  let url: URL;
  try {
    url = new URL(row.url);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  const checked = await policy.check(url, lookup);
  const { destination } = checked;
  const base = {
    organization: row.organization,
    organizationId: row.organization_id,
    kind: row.kind,
    id: row.id,
    name: row.name,
    scheme: destination.scheme === "http:" ? ("http" as const) : ("https" as const),
    host: destination.host,
    port: destination.port,
    addresses: checked.addresses,
  };
  if (checked.outcome === "unresolved") return { ...base, verdict: "unresolved", error: checked.error ?? "ENOTFOUND" };
  if (checked.verdict?.allowed) {
    return checked.verdict.via === "public" ? { ...base, verdict: "public" } : { ...base, verdict: "allowed", entries: checked.verdict.entries };
  }
  if (checked.verdict) return { ...base, verdict: "refused", reason: checked.verdict.reason };
  return null;
}

// ---------------------------------------------------------------------------
// Bounding the DNS work (Codex review of #107). The check runs from the
// operator's terminal and doctor, and also from two dashboard pages, which
// anyone with the right authority can load as often as they like. So:
//
// - every lookup in this process takes one of LOOKUP_SLOTS, whatever scan
//   or request it is for;
// - concurrent lookups of the same name with the same policy share one;
// - within one scan, a name is resolved once however many rows use it;
// - the pages' scans (sharedOutboundCheck) are coalesced while running and
//   their result reused for SCAN_TTL_MS. The admin command and doctor run
//   their own scan each time, and get the first three.

/** Lookups in flight at once in this process, across every scan. */
export const LOOKUP_SLOTS = 8;
let lookupsActive = 0;
const lookupQueue: (() => void)[] = [];

async function acquireLookup(): Promise<void> {
  if (lookupsActive < LOOKUP_SLOTS) {
    lookupsActive++;
    return;
  }
  // The slot is handed over by the release that wakes this one.
  await new Promise<void>((resolve) => lookupQueue.push(resolve));
}

function releaseLookup(): void {
  const next = lookupQueue.shift();
  if (next) next();
  else lookupsActive--;
}

const lookupsInFlight = new WeakMap<OutboundPolicy, Map<string, ReturnType<Lookup>>>();

/** One lookup per policy and name at a time, within the process-wide slots. */
function sharedLookup(policy: OutboundPolicy, name: string): ReturnType<Lookup> {
  let inFlight = lookupsInFlight.get(policy);
  if (!inFlight) lookupsInFlight.set(policy, (inFlight = new Map()));
  const running = inFlight.get(name);
  if (running) return running;
  const lookup = (async () => {
    await acquireLookup();
    try {
      return await policy.lookupName(name);
    } finally {
      releaseLookup();
    }
  })();
  inFlight.set(name, lookup);
  const forget = () => {
    if (inFlight.get(name) === lookup) inFlight.delete(name);
  };
  void lookup.then(forget, forget);
  return lookup;
}

/** How many rows one scan checks at once; the report keeps the rows' order. */
const ROWS_AT_ONCE = 8;

/** Run the check: DNS lookups and the policy's decision, nothing else. */
export async function outboundCheck(db: Querier, policy: OutboundPolicy, opts: { org?: string | null } = {}): Promise<OutboundCheckReport> {
  const rows = await liveDestinations(db, opts.org ?? null);
  // Each name once per scan, however many rows point at it.
  const resolved = new Map<string, ReturnType<Lookup>>();
  const lookup: Lookup = (name) => {
    let answer = resolved.get(name);
    if (!answer) resolved.set(name, (answer = sharedLookup(policy, name)));
    return answer;
  };
  const checkedRows: (CheckedDestination | null)[] = new Array(rows.length).fill(null);
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < rows.length) {
      const index = next++;
      checkedRows[index] = await checkRow(policy, rows[index] as Row, lookup);
    }
  };
  await Promise.all(Array.from({ length: Math.min(ROWS_AT_ONCE, rows.length) }, worker));
  const destinations = checkedRows.filter((d): d is CheckedDestination => d !== null);

  const suggestions = new Set<string>();
  const apart: OutboundCheckReport["apart"] = [];
  for (const d of destinations) {
    if (d.verdict !== "refused") continue;
    const portSuffix = d.port === defaultPort(`${d.scheme}:`) ? "" : `:${d.port}`;
    const classes = d.addresses.map((a) => {
      try {
        return classifyAddress(a);
      } catch {
        return "never" as const;
      }
    });
    if (isIP(d.host)) {
      const cls = classes[0];
      apart.push({
        host: d.host,
        port: d.port,
        kind: d.kind,
        id: d.id,
        why:
          cls === "never"
            ? "a literal address of a class that is never allowed"
            : `a literal ${cls} address: only a CIDR entry opens it, such as ${d.host.includes(":") ? `[${d.host}/128]` : `${d.host}/32`}${portSuffix}; add one only if every Organization may reach it`,
      });
    } else if (classes.some((c) => c === "host-only" || c === "never")) {
      apart.push({
        host: d.host,
        port: d.port,
        kind: d.kind,
        id: d.id,
        why: "resolves to a loopback, link-local, metadata or reserved address, which a hostname entry never opens",
      });
    } else {
      suggestions.add(`${d.host}${portSuffix}`);
    }
  }
  const allow = policy.entries.map((e) => e.text);
  const added = [...suggestions].filter((s) => !allow.includes(s));
  const refused = destinations.some((d) => d.verdict === "refused");
  const unresolved = destinations.some((d) => d.verdict === "unresolved");
  return {
    checkedAt: new Date().toISOString(),
    allow,
    destinations,
    suggested: added.length > 0 ? [...allow, ...added].join(",") : null,
    apart,
    exitCode: refused ? 1 : unresolved ? 2 : 0,
  };
}

/** How long a page's scan is reused. The allow list changes only with a restart; DNS answers and configured destinations are at most this stale. */
export const SCAN_TTL_MS = 30_000;
/** Scans kept per policy: one per Organization asked about, and one for the installation. */
export const MAX_SCANS = 1_000;

interface Scan {
  /** When the scan finished; null while it runs. */
  at: number | null;
  report: Promise<OutboundCheckReport>;
}
const scans = new WeakMap<OutboundPolicy, Map<string, Scan>>();

/**
 * outboundCheck for the dashboard's pages (ADR-0057 Decision 8): a scan
 * already running for the same policy and Organization (or the whole
 * installation) is shared, and a finished one is reused for SCAN_TTL_MS.
 * A failed scan is never kept. At most MAX_SCANS are kept per policy.
 */
export function sharedOutboundCheck(
  db: Querier,
  policy: OutboundPolicy,
  opts: { org?: string | null } = {},
  now: () => number = Date.now,
): Promise<OutboundCheckReport> {
  let kept = scans.get(policy);
  if (!kept) scans.set(policy, (kept = new Map()));
  const key = opts.org ?? "";
  const hit = kept.get(key);
  if (hit && (hit.at === null || now() - hit.at < SCAN_TTL_MS)) return hit.report;
  for (const [k, scan] of kept) if (scan.at !== null && now() - scan.at >= SCAN_TTL_MS) kept.delete(k);
  while (kept.size >= MAX_SCANS) kept.delete(kept.keys().next().value as string);
  const scan: Scan = { at: null, report: outboundCheck(db, policy, opts) };
  kept.set(key, scan);
  scan.report.then(
    () => {
      scan.at = now();
    },
    () => {
      if (kept.get(key) === scan) kept.delete(key);
    },
  );
  return scan.report;
}

/**
 * A refused destination as the dashboard, the API and the CLI show it
 * (ADR-0057 Decision 8): who configured it, what it is and why it is
 * refused. Never the resolved addresses: those are for the operator's
 * terminal and log only.
 */
export interface RefusedDestinationView {
  organizationId: string;
  organization: string;
  kind: DestinationKind;
  id: string;
  name: string | null;
  scheme: "https" | "http";
  host: string;
  port: number;
  reason: RefusalReason;
  /** Why the suggested allow list value leaves it out; null when it covers it. */
  notSuggested: string | null;
}

/** The report's refused destinations, without resolved addresses. */
export function refusedDestinations(report: OutboundCheckReport): RefusedDestinationView[] {
  return report.destinations.flatMap((d) =>
    d.verdict === "refused" && d.reason
      ? [
          {
            organizationId: d.organizationId,
            organization: d.organization,
            kind: d.kind,
            id: d.id,
            name: d.name,
            scheme: d.scheme,
            host: d.host,
            port: d.port,
            reason: d.reason,
            notSuggested: report.apart.find((a) => a.kind === d.kind && a.id === d.id)?.why ?? null,
          },
        ]
      : [],
  );
}

const KIND_LABEL: Record<DestinationKind, string> = { webhook: "webhook", coolify: "Coolify", convex: "Convex", "oidc-issuer": "OIDC issuer" };

/** The report for a person. */
export function outboundCheckLines(report: OutboundCheckReport): string[] {
  const lines = [`VARLATCH_OUTBOUND_ALLOW: ${report.allow.length > 0 ? report.allow.join(",") : "(not set)"}`, ""];
  if (report.destinations.length === 0) lines.push("No destinations configured.");
  for (const d of report.destinations) {
    const verdict =
      d.verdict === "public"
        ? "public"
        : d.verdict === "allowed"
          ? `allowed by ${(d.entries ?? []).join(", ")}`
          : d.verdict === "refused"
            ? `REFUSED (${d.reason})`
            : `not resolved (${d.error})`;
    lines.push(
      `${d.organization}  ${KIND_LABEL[d.kind]}  ${d.id}${d.name ? ` "${d.name}"` : ""}  ${d.scheme}://${d.host}:${d.port}` +
        `  [${d.addresses.join(", ") || "-"}]  ${verdict}`,
    );
  }
  if (report.suggested) {
    lines.push("", "Suggested (then restart varlatchd):", `  VARLATCH_OUTBOUND_ALLOW=${report.suggested}`);
  }
  if (report.apart.length > 0) {
    lines.push("", "Not suggested, decide yourself:");
    for (const a of report.apart) lines.push(`  ${a.host}:${a.port} (${KIND_LABEL[a.kind]} ${a.id}): ${a.why}`);
  }
  if (report.exitCode === 0 && report.destinations.length > 0) lines.push("", "Every destination is allowed.");
  return lines;
}
