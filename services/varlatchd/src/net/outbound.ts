// SPDX-License-Identifier: AGPL-3.0-or-later
import { lookup as dnsLookup } from "node:dns/promises";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import type { Duplex } from "node:stream";
import type { ConnectionOptions } from "node:tls";
import { OUTBOUND_POLICY_DOCS, outboundRefusalMessage, type OutboundRefusalReason } from "@varlatch/protocol";
import { OUTBOUND_REFUSED_CODE } from "@varlatch/sync";
import { Agent, buildConnector, fetch as undiciFetch } from "undici";
import { recordAuditEvent, type AuditEventInput } from "../audit/events.js";
import type { Querier } from "../db/migrate.js";
import { assertOrganizationAccessChecked } from "../domain/requestaccess.js";
import { currentExternalEffect, externalEffectDeadline, noteEffectRefusal } from "../domain/externaleffect.js";
import { normalizeAddress } from "../http/client-address.js";

/**
 * The shared outbound policy (ADR-0057). Every request whose destination an
 * Organization can choose or influence (webhooks, the sync adapters, GitHub,
 * OIDC discovery and JWKS) goes through this module, and only this module:
 * test/outbound-structure.test.ts fails the build on a request made anywhere
 * else in varlatchd, apart from a short list of destinations the host chose.
 *
 * What an Organization reaches is what the internet reaches, plus what the
 * host operator allowed in VARLATCH_OUTBOUND_ALLOW:
 *
 * - every address is in one class (CLASS_TABLE): never, host-only, private
 *   or public. Public is always allowed over https. Private needs an allow
 *   list entry, host-only a CIDR entry inside its own range, and nothing
 *   opens never;
 * - plain http needs an entry, whatever the address;
 * - every DNS answer must be allowed: one refused answer refuses the name;
 * - redirects are never followed, and no environment proxy applies.
 *
 * The deciding check runs inside the connection: the dispatcher's connector
 * resolves the name, classifies every answer, and gives the socket only the
 * addresses it checked. Nothing resolves the name between the check and the
 * connect, so DNS rebinding cannot move a socket to an unchecked address.
 * SNI, certificate verification and the Host header still use the URL's
 * name. The configuration-time check (`check`) gives friendly errors only.
 */

// ---------------------------------------------------------------------------
// Addresses

export type AddressClass = "never" | "host-only" | "private" | "public";

/** The same reasons as the API's OutboundRefusalReason. */
export type RefusalReason = OutboundRefusalReason;

export type OutboundPurpose = "webhook" | "sync_check" | "sync_listing" | "sync_delivery" | "github" | "oidc" | "audit_export";

interface Ip {
  family: 4 | 6;
  value: bigint;
}

interface Range {
  family: 4 | 6;
  base: bigint;
  prefix: number;
}

const bits = (family: 4 | 6): number => (family === 4 ? 32 : 128);

function v4Value(address: string): bigint {
  return address.split(".").reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
}

function v6Value(address: string): bigint {
  let text = address.toLowerCase().replace(/%.*$/, "");
  // A trailing dotted quad (::ffff:127.0.0.1) as two groups.
  const dot = text.lastIndexOf(".");
  if (dot >= 0) {
    const colon = text.lastIndexOf(":");
    const v4 = Number(v4Value(text.slice(colon + 1)));
    text = `${text.slice(0, colon + 1)}${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const double = text.indexOf("::");
  const head = (double >= 0 ? text.slice(0, double) : text).split(":").filter((g) => g !== "");
  const tail = double >= 0 ? text.slice(double + 2).split(":").filter((g) => g !== "") : [];
  const groups = double >= 0 ? [...head, ...Array<string>(8 - head.length - tail.length).fill("0"), ...tail] : head;
  return groups.reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)), 0n);
}

/** An IP address, or null when `raw` is not one. Brackets and zones are dropped. */
export function parseIp(raw: string): Ip | null {
  const text = raw.replace(/^\[(.*)\]$/, "$1").replace(/%.*$/, "");
  const family = isIP(text);
  if (family === 4) return { family: 4, value: v4Value(text) };
  if (family === 6) return { family: 6, value: v6Value(text) };
  return null;
}

function parseRange(cidr: string): Range {
  const [address, prefix] = cidr.split("/") as [string, string];
  const ip = parseIp(address) as Ip;
  return { family: ip.family, base: ip.value, prefix: Number(prefix) };
}

function contains(range: Range, ip: Ip): boolean {
  if (range.family !== ip.family) return false;
  const shift = BigInt(bits(ip.family) - range.prefix);
  return range.base >> shift === ip.value >> shift;
}

/** `inner` lies entirely inside `outer`. */
function within(inner: Range, outer: Range): boolean {
  return inner.family === outer.family && inner.prefix >= outer.prefix && contains(outer, { family: inner.family, value: inner.base });
}

/**
 * The address classes (ADR-0057 Decision 2), from the IANA special-purpose
 * address registries. The most specific matching range decides; an address
 * no range matches is public.
 */
export const CLASS_TABLE: readonly { cidr: string; class: Exclude<AddressClass, "public">; label: string }[] = [
  // Never: no allow list entry opens these.
  { cidr: "0.0.0.0/8", class: "never", label: "unspecified" },
  { cidr: "::/128", class: "never", label: "unspecified" },
  { cidr: "224.0.0.0/4", class: "never", label: "multicast" },
  { cidr: "ff00::/8", class: "never", label: "multicast" },
  { cidr: "240.0.0.0/4", class: "never", label: "reserved and broadcast" },
  { cidr: "100::/64", class: "never", label: "discard" },
  // Host-only: opened only by a CIDR entry inside the range.
  { cidr: "127.0.0.0/8", class: "host-only", label: "loopback" },
  { cidr: "::1/128", class: "host-only", label: "loopback" },
  { cidr: "169.254.0.0/16", class: "host-only", label: "link-local (cloud metadata)" },
  { cidr: "fe80::/10", class: "host-only", label: "link-local" },
  { cidr: "100.100.100.200/32", class: "host-only", label: "metadata service" },
  { cidr: "fd00:ec2::254/128", class: "host-only", label: "metadata service" },
  { cidr: "168.63.129.16/32", class: "host-only", label: "platform services" },
  { cidr: "fec0::/10", class: "host-only", label: "deprecated site-local" },
  { cidr: "192.0.0.0/24", class: "host-only", label: "protocol assignments" },
  { cidr: "2001::/23", class: "host-only", label: "protocol assignments" },
  { cidr: "2002::/16", class: "host-only", label: "6to4" },
  { cidr: "192.88.99.0/24", class: "host-only", label: "6to4 relay" },
  { cidr: "64:ff9b:1::/48", class: "host-only", label: "NAT64 local-use" },
  { cidr: "192.0.2.0/24", class: "host-only", label: "documentation" },
  { cidr: "198.51.100.0/24", class: "host-only", label: "documentation" },
  { cidr: "203.0.113.0/24", class: "host-only", label: "documentation" },
  { cidr: "2001:db8::/32", class: "host-only", label: "documentation" },
  { cidr: "3fff::/20", class: "host-only", label: "documentation" },
  { cidr: "198.18.0.0/15", class: "host-only", label: "benchmarking" },
  { cidr: "5f00::/16", class: "host-only", label: "SRv6 segment identifiers" },
  // Private: opened by a matching hostname or CIDR entry.
  { cidr: "10.0.0.0/8", class: "private", label: "private network" },
  { cidr: "172.16.0.0/12", class: "private", label: "private network" },
  { cidr: "192.168.0.0/16", class: "private", label: "private network" },
  { cidr: "100.64.0.0/10", class: "private", label: "carrier-grade NAT (Tailscale)" },
  { cidr: "fc00::/7", class: "private", label: "unique-local (Tailscale)" },
];

const TABLE = CLASS_TABLE.map((row) => ({ ...row, range: parseRange(row.cidr) }));
const HOST_ONLY_RANGES = TABLE.filter((row) => row.class === "host-only").map((row) => row.range);

const MAPPED = parseRange("::ffff:0:0/96");
const COMPATIBLE = parseRange("::/96");
const NAT64 = parseRange("64:ff9b::/96");
const UNSPECIFIED_V6 = parseRange("::/128");
const LOOPBACK_V6 = parseRange("::1/128");

/**
 * The address a connection to `ip` really reaches, as far as classes go:
 * IPv4-mapped, IPv4-compatible and NAT64 well-known addresses carry an IPv4
 * address and are classified by it.
 */
function effective(ip: Ip): Ip {
  if (ip.family !== 6) return ip;
  const embedded =
    contains(MAPPED, ip) ||
    contains(NAT64, ip) ||
    (contains(COMPATIBLE, ip) && !contains(UNSPECIFIED_V6, ip) && !contains(LOOPBACK_V6, ip));
  return embedded ? { family: 4, value: ip.value & 0xffffffffn } : ip;
}

function classifyIp(ip: Ip): { class: AddressClass; label: string } {
  const target = effective(ip);
  let best: (typeof TABLE)[number] | null = null;
  for (const row of TABLE) {
    if (contains(row.range, target) && (!best || row.range.prefix > best.range.prefix)) best = row;
  }
  return best ? { class: best.class, label: best.label } : { class: "public", label: "public" };
}

/** The class of an IP address (ADR-0057 Decision 2). Throws for a string that is not one. */
export function classifyAddress(address: string): AddressClass {
  const ip = parseIp(address);
  if (!ip) throw new TypeError(`Not an IP address: ${address}`);
  return classifyIp(ip).class;
}

// ---------------------------------------------------------------------------
// VARLATCH_OUTBOUND_ALLOW

export type EntryPort = number | "*" | null;

export type AllowEntry =
  | { kind: "name"; text: string; name: string; wildcard: boolean; port: EntryPort }
  | { kind: "cidr"; text: string; range: Range; port: EntryPort; hostOnly: boolean };

export class OutboundAllowError extends Error {
  override name = "OutboundAllowError";
}

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HOST_NAME = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*$`);

function parsePort(raw: string | undefined, entry: string): EntryPort {
  if (raw === undefined) return null;
  if (raw === "*") return "*";
  const port = Number(raw);
  if (!/^\d{1,5}$/.test(raw) || port < 1 || port > 65535) {
    throw new OutboundAllowError(`VARLATCH_OUTBOUND_ALLOW: ${entry} has an invalid port`);
  }
  return port;
}

function cidrEntry(text: string, address: string, prefixText: string | undefined, portText: string | undefined): AllowEntry {
  const normalized = normalizeAddress(address);
  const ip = normalized && !/[[\]]/.test(address) ? parseIp(normalized) : null;
  if (!ip) throw new OutboundAllowError(`VARLATCH_OUTBOUND_ALLOW: ${text} is not a valid address or CIDR range`);
  // normalizeAddress turns ::ffff:a.b.c.d into a.b.c.d: an entry for a
  // mapped address is an entry for the IPv4 address it carries.
  const prefix = prefixText === undefined ? bits(ip.family) : Number(prefixText);
  if (!/^\d{1,3}$/.test(prefixText ?? "0") || prefix > bits(ip.family)) {
    throw new OutboundAllowError(`VARLATCH_OUTBOUND_ALLOW: ${text} is not a valid CIDR range`);
  }
  const shift = BigInt(bits(ip.family) - prefix);
  const range: Range = { family: ip.family, base: (ip.value >> shift) << shift, prefix };
  return {
    kind: "cidr",
    text,
    range,
    port: parsePort(portText, text),
    hostOnly: HOST_ONLY_RANGES.some((outer) => within(range, outer)),
  };
}

function parseEntry(text: string): AllowEntry {
  // [v6], [v6/prefix], with an optional :port after the bracket.
  const bracketed = /^\[([^\]]+)\](?::([^:]+))?$/.exec(text);
  if (bracketed) {
    const [address, prefix] = (bracketed[1] as string).split("/");
    return cidrEntry(text, address as string, prefix, bracketed[2]);
  }
  // address/prefix with an optional :port after the prefix (::1/128:*).
  const range = /^([^/]+)\/(\d+)(?::([^:/]+))?$/.exec(text);
  if (range) return cidrEntry(text, range[1] as string, range[2], range[3]);
  // A bare IPv6 address takes no port without brackets.
  if (isIP(text) === 6) return cidrEntry(text, text, undefined, undefined);
  const withPort = /^(.+?)(?::([^:]+))?$/.exec(text) as RegExpExecArray;
  const host = withPort[1] as string;
  const portText = withPort[2];
  if (isIP(host) === 4) return cidrEntry(text, host, undefined, portText);
  const lower = host.toLowerCase().replace(/\.$/, "");
  const wildcard = lower.startsWith("*.");
  const name = wildcard ? lower.slice(2) : lower;
  if (!HOST_NAME.test(name) || /^[\d.]+$/.test(name)) {
    throw new OutboundAllowError(`VARLATCH_OUTBOUND_ALLOW: ${text} is not a host name, a *.suffix, an address or a CIDR range`);
  }
  return { kind: "name", text, name, wildcard, port: parsePort(portText, text) };
}

/** Parse VARLATCH_OUTBOUND_ALLOW. Throws OutboundAllowError naming the first invalid entry. */
export function parseOutboundAllow(spec: string | undefined | null): AllowEntry[] {
  return (spec ?? "")
    .split(",")
    .map((e) => e.replace(/\s+/g, ""))
    .filter(Boolean)
    .map(parseEntry);
}

/** An entry as the operator would write it back. */
export function describeEntry(entry: AllowEntry): string {
  return entry.text;
}

/**
 * Doctor's warnings about an allow list (ADR-0057 Decision 8): entries that
 * add nothing a narrower one would not, and entries that open host-only
 * ranges.
 */
export function allowListWarnings(entries: AllowEntry[]): string[] {
  const warnings: string[] = [];
  for (const entry of entries) {
    if (entry.kind === "cidr" && entry.hostOnly) {
      warnings.push(`${entry.text} opens a host-only range (loopback, link-local or metadata) to every Organization`);
    } else if (entry.kind === "cidr" && entry.range.prefix === 0) {
      warnings.push(`${entry.text} adds only the private ranges, and opens all of them to every Organization: list the destinations instead`);
    } else if (entry.kind === "cidr" && TABLE.some((row) => row.class === "never" && within(entry.range, row.range))) {
      warnings.push(`${entry.text} adds nothing: unspecified, multicast and reserved addresses are never allowed`);
    } else if (entry.kind === "name" && entry.name === "localhost") {
      warnings.push(`${entry.text} adds nothing: a hostname entry never opens loopback; use 127.0.0.1/32 instead`);
    }
  }
  return warnings;
}

// ---------------------------------------------------------------------------
// Decisions

export interface Destination {
  scheme: "https:" | "http:";
  /** Lowercase, without brackets or a trailing dot. */
  host: string;
  port: number;
}

export type Verdict =
  | { allowed: true; via: "public" | "entry"; entries: string[] }
  | { allowed: false; reason: RefusalReason };

const SEVERITY: RefusalReason[] = ["never_address", "host_only_address", "mixed_answers", "private_address", "port", "scheme"];

export const defaultPort = (scheme: string): number => (scheme === "http:" ? 80 : 443);

function portFits(port: EntryPort, destination: Destination): boolean {
  return port === "*" || port === destination.port || (port === null && destination.port === defaultPort(destination.scheme));
}

function nameMatches(entry: Extract<AllowEntry, { kind: "name" }>, host: string): boolean {
  return entry.wildcard ? host.endsWith(`.${entry.name}`) : host === entry.name;
}

/** The URL's host as the policy compares it: lowercase, no brackets, one trailing dot removed. */
export function normalizeHost(hostname: string): string {
  return hostname.replace(/^\[(.*)\]$/, "$1").toLowerCase().replace(/\.$/, "");
}

/** A URL as a destination, or null when it is neither https nor http. */
export function destinationOf(url: URL): Destination | null {
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  return { scheme: url.protocol, host: normalizeHost(url.hostname), port: url.port ? Number(url.port) : defaultPort(url.protocol) };
}

/**
 * Decide a destination whose name resolved to `addresses` (a literal
 * address resolves to itself). Pure: the allow list and the class table
 * only.
 */
export function decide(entries: AllowEntry[], destination: Destination, addresses: string[]): Verdict {
  const literal = isIP(destination.host) !== 0;
  const names = literal ? [] : entries.filter((e): e is Extract<AllowEntry, { kind: "name" }> => e.kind === "name" && nameMatches(e, destination.host));
  const cidrs = entries.filter((e): e is Extract<AllowEntry, { kind: "cidr" }> => e.kind === "cidr");
  const nameEntry = names.find((e) => portFits(e.port, destination));
  const used = new Set<string>();
  const refusals: RefusalReason[] = [];
  let allowedCount = 0;
  if (addresses.length === 0) return { allowed: false, reason: "never_address" };
  for (const address of addresses) {
    const ip = parseIp(address);
    if (!ip) {
      refusals.push("never_address");
      continue;
    }
    const target = effective(ip);
    const { class: cls } = classifyIp(ip);
    const inRange = cidrs.filter((e) => contains(e.range, target) || contains(e.range, ip));
    const cidrEntry = inRange.find((e) => portFits(e.port, destination) && (cls !== "host-only" || e.hostOnly));
    const portOnly = (cls === "host-only" ? inRange.some((e) => e.hostOnly) : inRange.length > 0 || names.length > 0);
    let reason: RefusalReason | null = null;
    if (cls === "never") reason = "never_address";
    else if (cls === "host-only") reason = cidrEntry ? null : portOnly ? "port" : "host_only_address";
    else if (cls === "private") reason = cidrEntry || nameEntry ? null : portOnly ? "port" : "private_address";
    else if (destination.scheme === "http:") reason = cidrEntry || nameEntry ? null : portOnly ? "port" : "scheme";
    if (reason) {
      refusals.push(reason);
      continue;
    }
    allowedCount++;
    if (cls !== "public" || destination.scheme === "http:") {
      if (cidrEntry) used.add(cidrEntry.text);
      else if (nameEntry) used.add(nameEntry.text);
    }
  }
  if (refusals.length === 0) return used.size > 0 ? { allowed: true, via: "entry", entries: [...used] } : { allowed: true, via: "public", entries: [] };
  if (allowedCount > 0) return { allowed: false, reason: "mixed_answers" };
  return { allowed: false, reason: SEVERITY.find((r) => refusals.includes(r)) as RefusalReason };
}

// ---------------------------------------------------------------------------
// Refusals

export const OUTBOUND_DOCS = OUTBOUND_POLICY_DOCS;

/**
 * Fixed wording for a refusal: names the class, never the address (ADR-0057
 * Decision 6). The words live in @varlatch/protocol, so the CLI and the
 * dashboard say the same thing.
 */
export function refusalMessage(reason: RefusalReason): string {
  return outboundRefusalMessage(reason);
}

/** Shared with @varlatch/sync, which reads it to word a refused check (ADR-0057 Decision 7). */
export { OUTBOUND_REFUSED_CODE };

/**
 * A request the policy refused. `message` is the fixed wording, safe to show
 * to the Organization; `addresses` is for the operator's log only.
 */
export class OutboundRefusedError extends Error {
  override name = "OutboundRefusedError";
  readonly code = OUTBOUND_REFUSED_CODE;
  constructor(
    readonly reason: RefusalReason,
    readonly destination: Destination,
    readonly addresses: string[],
  ) {
    super(refusalMessage(reason));
  }
}

/** The policy refusal behind an error, through any number of causes; null when there is none. */
export function outboundRefusalOf(err: unknown): OutboundRefusedError | null {
  let current: unknown = err;
  for (let depth = 0; depth < 8 && current; depth++) {
    if (current instanceof OutboundRefusedError) return current;
    if (current instanceof AggregateError) {
      for (const inner of current.errors) {
        const found = outboundRefusalOf(inner);
        if (found) return found;
      }
    }
    current = (current as { cause?: unknown }).cause;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Resolution

export type Resolver = (name: string) => Promise<{ address: string; family: 4 | 6 }[]>;

const systemResolver: Resolver = async (name) =>
  (await dnsLookup(name, { all: true, order: "verbatim" })).map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));

let resolverOverride: Resolver | null = null;

/**
 * How long one name resolution of the policy may take (the configuration
 * check, a socket's lookup). A lookup that takes longer fails as
 * unresolved (ETIMEOUT), so nothing waits on DNS without a bound.
 * Adjustable in tests.
 */
export const OUTBOUND_RESOLVE = { timeoutMs: 5_000 };

/** `resolver`'s answer for `name`, or ETIMEOUT after OUTBOUND_RESOLVE.timeoutMs. */
async function resolveBounded(resolver: Resolver, name: string): Promise<{ address: string; family: 4 | 6 }[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(Object.assign(new Error(`DNS lookup of ${name} timed out`), { code: "ETIMEOUT", hostname: name })),
      OUTBOUND_RESOLVE.timeoutMs,
    );
  });
  try {
    return await Promise.race([resolver(name), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The one resolver injection point, for tests only: policies made without a
 * resolver of their own use it instead of the system resolver.
 */
export function setOutboundResolverForTests(resolver: Resolver | null): void {
  resolverOverride = resolver;
}

// ---------------------------------------------------------------------------
// The audit bound (ADR-0057 Decision 8)

const HOUR_MS = 3_600_000;

/**
 * At most one connection-phase event per key per hour, at most `processCap`
 * per hour in all; what is held back is counted, and the next recorded
 * event carries the count. Entries expire after their hour and are removed;
 * the map holds at most `maxKeys`, and a new key beyond that counts toward
 * the process cap instead of getting an entry.
 */
export class RefusalAuditLimiter {
  private readonly keys = new Map<string, number>();
  private windowStart = 0;
  private windowCount = 0;
  private suppressed = 0;

  constructor(
    private readonly now: () => number = Date.now,
    readonly limits: { perKeyMs: number; processCap: number; maxKeys: number } = { perKeyMs: HOUR_MS, processCap: 100, maxKeys: 10_000 },
  ) {}

  get size(): number {
    return this.keys.size;
  }

  private sweep(now: number): void {
    // Insertion order is expiry order: every entry lives exactly perKeyMs.
    for (const [key, expires] of this.keys) {
      if (expires > now) break;
      this.keys.delete(key);
    }
  }

  /** Whether to record an event for `key` now, and how many were held back since the last one. */
  admit(key: string): { record: boolean; suppressed: number } {
    const now = this.now();
    this.sweep(now);
    if (now - this.windowStart >= this.limits.perKeyMs) {
      this.windowStart = now;
      this.windowCount = 0;
    }
    if (this.keys.has(key) || this.windowCount >= this.limits.processCap) {
      this.suppressed++;
      return { record: false, suppressed: 0 };
    }
    if (this.keys.size < this.limits.maxKeys) this.keys.set(key, now + this.limits.perKeyMs);
    this.windowCount++;
    const suppressed = this.suppressed;
    this.suppressed = 0;
    return { record: true, suppressed };
  }

  /** Configuration-phase events are always recorded, and carry what was held back. */
  always(): { suppressed: number } {
    const suppressed = this.suppressed;
    this.suppressed = 0;
    return { suppressed };
  }
}

export interface RefusalRecord {
  organizationId: string;
  purpose: OutboundPurpose;
  phase: "configuration" | "connection";
  refusal: OutboundRefusedError;
  /** The object the request was for: { webhookId }, { connectionId }, { targetId }, { oidcBindingId }. */
  resource: Record<string, string>;
  actorIdentityId?: string | null;
  requestId?: string | null;
}

// ---------------------------------------------------------------------------
// The policy

export interface CheckOutcome {
  /** allowed, refused, or unresolved (a DNS failure: not a refusal, ADR-0057 Decision 6). */
  outcome: "allowed" | "refused" | "unresolved";
  destination: Destination;
  addresses: string[];
  verdict: Verdict | null;
  /** The resolver's error code for an unresolved name. */
  error?: string;
}

export interface OutboundPolicyOptions {
  resolve?: Resolver;
  log?: (line: string) => void;
  now?: () => number;
  /** Extra TLS options for the connector (tests: a private CA). */
  tls?: ConnectionOptions;
  /** The connect timeout, ms. */
  connectTimeoutMs?: number;
}

/** Connectors per scheme and port; more than this many distinct ports get a connector each time. */
const MAX_CONNECTORS = 256;

export class OutboundPolicy {
  readonly entries: AllowEntry[];
  readonly limiter: RefusalAuditLimiter;
  private readonly resolver: Resolver | undefined;
  private readonly log: (line: string) => void;
  private readonly tls: ConnectionOptions;
  private readonly connectTimeoutMs: number;
  private readonly connectors = new Map<string, buildConnector.connector>();
  private agent: Agent | null = null;

  constructor(entries: AllowEntry[] | string = [], opts: OutboundPolicyOptions = {}) {
    this.entries = typeof entries === "string" ? parseOutboundAllow(entries) : entries;
    this.resolver = opts.resolve;
    this.log = opts.log ?? ((line) => console.warn(line));
    this.limiter = new RefusalAuditLimiter(opts.now ?? Date.now);
    this.tls = opts.tls ?? {};
    this.connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  }

  private resolve(name: string): Promise<{ address: string; family: 4 | 6 }[]> {
    return resolveBounded(this.resolver ?? resolverOverride ?? systemResolver, name);
  }

  /**
   * Resolve a name with this policy's resolver, for the configured
   * destinations check (net/outbound-check.ts), which bounds and shares its
   * lookups. Decides nothing.
   */
  lookupName(name: string): Promise<{ address: string; family: 4 | 6 }[]> {
    return this.resolve(name);
  }

  decide(destination: Destination, addresses: string[]): Verdict {
    return decide(this.entries, destination, addresses);
  }

  /**
   * The configuration-time check (ADR-0057 Decision 6): parse, resolve and
   * classify, for a friendly error before anything is saved. Never call it
   * inside a transaction. It decides nothing at connection time. `lookup`
   * replaces the resolution (the configured destinations check shares
   * lookups between rows and requests); the decision is the same.
   */
  async check(raw: string | URL, lookup?: (name: string) => Promise<{ address: string; family: 4 | 6 }[]>): Promise<CheckOutcome> {
    const url = typeof raw === "string" ? new URL(raw) : raw;
    const destination = destinationOf(url);
    if (!destination) throw new TypeError("Only https and http destinations are checked");
    if (isIP(destination.host)) {
      const verdict = this.decide(destination, [destination.host]);
      return { outcome: verdict.allowed ? "allowed" : "refused", destination, addresses: [destination.host], verdict };
    }
    let addresses: string[];
    try {
      addresses = (await (lookup ?? ((name: string) => this.resolve(name)))(destination.host)).map((a) => a.address);
    } catch (err) {
      return { outcome: "unresolved", destination, addresses: [], verdict: null, error: (err as { code?: string }).code ?? "ENOTFOUND" };
    }
    if (addresses.length === 0) return { outcome: "unresolved", destination, addresses: [], verdict: null, error: "ENOTFOUND" };
    const verdict = this.decide(destination, addresses);
    return { outcome: verdict.allowed ? "allowed" : "refused", destination, addresses, verdict };
  }

  /** check(), as an error to throw: the refusal, or null when allowed or unresolved. */
  async refusalFor(raw: string | URL, purpose: OutboundPurpose): Promise<OutboundRefusedError | null> {
    const checked = await this.check(raw);
    if (checked.outcome !== "refused" || !checked.verdict || checked.verdict.allowed) return null;
    const refusal = new OutboundRefusedError(checked.verdict.reason, checked.destination, checked.addresses);
    this.logRefusal(purpose, "configuration", refusal);
    return refusal;
  }

  logRefusal(purpose: OutboundPurpose, phase: "configuration" | "connection", refusal: OutboundRefusedError): void {
    const { scheme, host, port } = refusal.destination;
    this.log(
      `varlatchd: outbound ${purpose} request refused at ${phase} (${refusal.reason}): ${scheme}//${host}:${port}` +
        (refusal.addresses.length > 0 ? ` resolved to ${refusal.addresses.join(", ")}` : ""),
    );
  }

  /**
   * The DNS lookup a socket uses: resolves once, checks every answer, and
   * hands over only the addresses it checked. The refusal is the socket's
   * error; the caller records it (recordRefusal), within the rate bound.
   */
  private lookupFor(scheme: "https:" | "http:", port: number): LookupFunction {
    return (hostname, options, callback) => {
      const host = normalizeHost(hostname);
      const destination: Destination = { scheme, host, port };
      this.resolve(host).then(
        (answers) => {
          if (answers.length === 0) {
            (callback as (err: Error) => void)(Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: "ENOTFOUND", hostname }));
            return;
          }
          const verdict = this.decide(destination, answers.map((a) => a.address));
          if (!verdict.allowed) {
            (callback as (err: Error) => void)(new OutboundRefusedError(verdict.reason, destination, answers.map((a) => a.address)));
            return;
          }
          const family = typeof options === "object" && options ? options.family : undefined;
          const wanted = family === 4 || family === 6 ? answers.filter((a) => a.family === family) : answers;
          if (wanted.length === 0) {
            (callback as (err: Error) => void)(Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: "ENOTFOUND", hostname }));
            return;
          }
          if (typeof options === "object" && options?.all) {
            (callback as unknown as (err: null, addresses: { address: string; family: number }[]) => void)(null, wanted);
          } else {
            const first = wanted[0] as { address: string; family: 4 | 6 };
            (callback as (err: null, address: string, family: number) => void)(null, first.address, first.family);
          }
        },
        (err: unknown) => (callback as (err: Error) => void)(err instanceof Error ? err : new Error(String(err))),
      );
    };
  }

  private connectorFor(scheme: "https:" | "http:", port: number): buildConnector.connector {
    const key = `${scheme}${port}`;
    const cached = this.connectors.get(key);
    if (cached) return cached;
    const connector = buildConnector({
      ...this.tls,
      timeout: this.connectTimeoutMs,
      autoSelectFamily: true,
      lookup: this.lookupFor(scheme, port),
    } as buildConnector.BuildOptions);
    if (this.connectors.size < MAX_CONNECTORS) this.connectors.set(key, connector);
    return connector;
  }

  /** The undici dispatcher every governed fetch uses: pools per origin, each socket checked as it opens. */
  get dispatcher(): Agent {
    this.agent ??= new Agent({
      connect: (options, callback) => {
        const scheme = options.protocol === "http:" ? "http:" : options.protocol === "https:" ? "https:" : null;
        if (!scheme) {
          callback(new Error(`Unsupported protocol ${options.protocol}`), null);
          return;
        }
        const port = options.port ? Number(options.port) : defaultPort(scheme);
        const host = normalizeHost(options.hostname);
        if (isIP(host)) {
          // A literal address is never looked up: it is checked here.
          const destination: Destination = { scheme, host, port };
          const verdict = this.decide(destination, [host]);
          if (!verdict.allowed) {
            callback(new OutboundRefusedError(verdict.reason, destination, [host]), null);
            return;
          }
        }
        this.connectorFor(scheme, port)(options, callback);
      },
    });
    return this.agent;
  }

  /**
   * A fetch bound to the policy (ADR-0057 Decision 4): the module's own
   * dispatcher, never an environment proxy, and redirects never followed.
   * A refusal rejects with the OutboundRefusedError itself; with `audit`,
   * it is first recorded for that Organization and object, within the rate
   * bound (callers that know more record it themselves).
   */
  fetch(purpose: OutboundPurpose, audit?: { db: Querier; organizationId: string; resource: Record<string, string> }): typeof fetch {
    const governed = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      if (init?.redirect !== undefined && init.redirect !== "error") {
        throw new TypeError("Outbound requests never follow redirects");
      }
      if (typeof input !== "string" && !(input instanceof URL)) throw new TypeError("Outbound requests take a URL");
      const url = new URL(input);
      const destination = destinationOf(url);
      if (!destination) throw new TypeError(`Outbound requests use https or http, not ${url.protocol}`);
      if (url.username || url.password) throw new TypeError("Outbound request URLs never carry credentials");
      // A request's outbound call for an Organization runs inside its
      // external-effect transaction, after the passkey-verification
      // checkpoint there (ADR-0054 Decision 7, liveness.ts
      // withExternalEffect); reaching here without one is a coverage gap.
      if (audit) await assertOrganizationAccessChecked(audit.db, audit.organizationId, `an outbound ${purpose} call`, { underLock: true });
      // Never after the effect's deadline (externaleffect.ts): its lock may
      // not protect a call that starts later.
      if (currentExternalEffect()?.signal.aborted) throw externalEffectDeadline();
      try {
        return (await undiciFetch(url, {
          ...(init as Record<string, unknown>),
          redirect: "error",
          dispatcher: this.dispatcher,
        } as Parameters<typeof undiciFetch>[1])) as unknown as Response;
      } catch (err) {
        const refusal = outboundRefusalOf(err);
        if (!refusal) throw err;
        if (audit) {
          await this.recordRefusal(audit.db, { organizationId: audit.organizationId, purpose, phase: "connection", refusal, resource: audit.resource }).catch(
            (e: unknown) => console.error("outbound refusal audit failed:", e),
          );
        }
        throw refusal;
      }
    };
    Object.defineProperty(governed, "outboundPurpose", { value: purpose });
    return governed as typeof fetch;
  }

  /**
   * A Node https.Agent with the same check (ADR-0057 Decision 4), for
   * clients that take an agent rather than a fetch (the S3 client of the
   * audit export). No proxy: a plain Agent never reads the environment.
   */
  httpsAgent(purpose: OutboundPurpose): https.Agent {
    const policy = this;
    void purpose;
    class PolicyAgent extends https.Agent {
      override createConnection(
        options: https.RequestOptions,
        callback?: (err: Error | null, stream: Duplex) => void,
      ): ReturnType<https.Agent["createConnection"]> {
        const host = normalizeHost(String(options.host ?? options.hostname ?? "localhost"));
        const port = Number(options.port) || 443;
        const destination: Destination = { scheme: "https:", host, port };
        if (isIP(host)) {
          const verdict = policy.decide(destination, [host]);
          if (!verdict.allowed) {
            const refusal = new OutboundRefusedError(verdict.reason, destination, [host]);
            process.nextTick(() => (callback as ((err: Error) => void) | undefined)?.(refusal));
            return undefined as unknown as ReturnType<https.Agent["createConnection"]>;
          }
        }
        const lookup = policy.lookupFor("https:", port);
        return (https.Agent.prototype.createConnection as (...args: unknown[]) => ReturnType<https.Agent["createConnection"]>).call(
          this,
          { ...options, lookup, autoSelectFamily: true, servername: options.servername ?? (isIP(host) ? undefined : host) },
          callback,
        );
      }
    }
    return new PolicyAgent({ keepAlive: true, ...policy.tls });
  }

  /**
   * Record a refusal as `outbound.refused` (ADR-0057 Decision 8), within
   * the rate bound: configuration-phase refusals always; connection-phase
   * ones once per Organization, purpose, object and reason per hour, and
   * at most 100 an hour in all. Never the resolved address, a path, a
   * query or a credential.
   */
  async recordRefusal(db: Querier, input: RefusalRecord): Promise<void> {
    const { refusal } = input;
    let suppressed = 0;
    if (input.phase === "configuration") {
      suppressed = this.limiter.always().suppressed;
    } else {
      const object = Object.values(input.resource).join(",");
      const admitted = this.limiter.admit(`${input.organizationId}|${input.purpose}|${object}|${refusal.reason}`);
      if (!admitted.record) return;
      suppressed = admitted.suppressed;
      this.logRefusal(input.purpose, "connection", refusal);
    }
    const event = {
      eventType: "outbound.refused",
      decision: "deny",
      actorIdentityId: input.actorIdentityId ?? null,
      organizationId: input.organizationId,
      requestId: input.requestId ?? null,
      resource: input.resource,
      metadata: {
        purpose: input.purpose,
        phase: input.phase,
        scheme: refusal.destination.scheme.replace(/:$/, ""),
        host: refusal.destination.host,
        port: refusal.destination.port,
        reason: refusal.reason,
        ...(suppressed > 0 ? { suppressed } : {}),
      },
    } satisfies AuditEventInput;
    await recordAuditEvent(db, event);
    // In an external effect's transaction: written again if it rolls back.
    noteEffectRefusal(event);
  }

  /** Close pooled connections (tests, and a process that is stopping). */
  async close(): Promise<void> {
    const agent = this.agent;
    this.agent = null;
    this.connectors.clear();
    await agent?.close();
  }
}

let strictDefault: OutboundPolicy | null = null;

/**
 * The policy of a context: the one varlatchd built from
 * VARLATCH_OUTBOUND_ALLOW at startup, or, where a context carries none, the
 * policy without exceptions. Never a plain fetch.
 */
export function outboundOf(ctx: { outbound?: OutboundPolicy | undefined }): OutboundPolicy {
  return ctx.outbound ?? (strictDefault ??= new OutboundPolicy([]));
}
