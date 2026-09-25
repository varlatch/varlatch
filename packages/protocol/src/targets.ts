// SPDX-License-Identifier: Apache-2.0

/**
 * Substitution targets (ADR-0039 Decisions 1 and 2): where the Broker may
 * substitute a Secret's Placeholder in an outbound request. Shared by
 * varlatchd, which validates and records them on a Capability, and the CLI,
 * which parses them from the command line and enforces them in the Broker.
 *
 * Canonical syntax: `header:<name>` (lower-cased), `query:<name>`,
 * `json:<RFC 6901 pointer>`, or `form:<name>`.
 */

export type TargetKind = "header" | "query" | "json" | "form";

export interface Target {
  kind: TargetKind;
  /** The header, query parameter, or form field name; the JSON Pointer for `json`. */
  location: string;
}

/** At most this many targets per Secret. */
export const MAX_TARGETS_PER_ITEM = 4;

/**
 * Headers that are never targets: the Broker sets or removes them itself, or
 * they decide how the request is framed, routed, or parsed.
 */
export const TRANSPORT_OWNED_HEADERS: readonly string[] = [
  "host",
  "content-length",
  "transfer-encoding",
  "expect",
  "connection",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "via",
  "forwarded",
  "content-type",
  "content-encoding",
  "accept-encoding",
  "range",
  "if-range",
];

export function isTransportOwnedHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return TRANSPORT_OWNED_HEADERS.includes(lower) || lower.startsWith("x-forwarded-");
}

/** An RFC 9110 token: the characters a header name may contain. */
const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export class TargetError extends Error {
  override name = "TargetError";
}

/** Parse and validate one target; throws TargetError naming the problem. */
export function parseTarget(raw: string): Target {
  const colon = raw.indexOf(":");
  if (colon < 0) throw new TargetError(`"${raw}" is not a target: expected header:, query:, json:, or form:`);
  const kind = raw.slice(0, colon);
  const location = raw.slice(colon + 1);
  switch (kind) {
    case "header": {
      if (!HEADER_NAME.test(location)) throw new TargetError(`"${location}" is not a valid header name`);
      if (isTransportOwnedHeader(location)) {
        throw new TargetError(`${location.toLowerCase()} is a transport-owned header and cannot be a target`);
      }
      return { kind, location: location.toLowerCase() };
    }
    case "query":
    case "form": {
      if (location.length === 0 || location.length > 256) {
        throw new TargetError(`a ${kind} target needs a name of 1 to 256 characters`);
      }
      if (/[\u0000-\u001f\u007f]/.test(location)) throw new TargetError(`a ${kind} target name cannot contain control characters`);
      return { kind, location };
    }
    case "json": {
      // RFC 6901: "" is the whole document, which is never a string target.
      if (!location.startsWith("/")) throw new TargetError(`"${location}" is not a JSON Pointer: it must start with /`);
      if (/~[^01]|~$/.test(location)) throw new TargetError(`"${location}" is not a valid JSON Pointer: ~ must be ~0 or ~1`);
      return { kind, location };
    }
    default:
      throw new TargetError(`"${kind}" is not a target kind: expected header, query, json, or form`);
  }
}

export function formatTarget(target: Target): string {
  return `${target.kind}:${target.location}`;
}

/** Decode a JSON Pointer into its reference tokens (RFC 6901). */
export function jsonPointerTokens(pointer: string): string[] {
  return pointer
    .slice(1)
    .split("/")
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * Validate a Capability's targets against its items: every item has at
 * least one target and at most MAX_TARGETS_PER_ITEM, none is repeated, and
 * no target names an item outside the Capability. Returns the canonical
 * form, items and targets sorted.
 */
export function canonicalTargets(items: string[], targets: Record<string, string[]>): Record<string, string[]> {
  const itemSet = new Set(items);
  for (const name of Object.keys(targets)) {
    if (!itemSet.has(name)) throw new TargetError(`targets name ${name}, which is not an item of this Capability`);
  }
  const result: Record<string, string[]> = {};
  for (const item of [...itemSet].sort()) {
    const raw = targets[item] ?? [];
    if (raw.length === 0) throw new TargetError(`${item} has no substitution target`);
    if (raw.length > MAX_TARGETS_PER_ITEM) {
      throw new TargetError(`${item} has ${raw.length} targets; at most ${MAX_TARGETS_PER_ITEM} are allowed`);
    }
    const canonical = raw.map((t) => formatTarget(parseTarget(t)));
    if (new Set(canonical).size !== canonical.length) throw new TargetError(`${item} repeats a target`);
    result[item] = [...canonical].sort();
  }
  return result;
}

/** The audit form: `ITEM=kind:location;…`, names and locations only. */
export function describeTargets(targets: Record<string, string[]>): string {
  return Object.keys(targets)
    .sort()
    .flatMap((item) => (targets[item] ?? []).map((t) => `${item}=${t}`))
    .join(";");
}
