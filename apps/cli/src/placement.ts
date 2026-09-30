// SPDX-License-Identifier: Apache-2.0
import { deliveredText } from "@varlatch/matcher";
import type { Target } from "@varlatch/protocol";

/**
 * Where the Broker may substitute a Placeholder (ADR-0039 Decisions 1 to 5).
 *
 * `planPlacement` decides everything that can be decided from the request as
 * the Agent sent it, before anything is exercised: which Placeholders sit at
 * one of their item's targets, which are strays, and whether the request
 * must be blocked. `apply` then builds the substituted request from the
 * exercised values; its failures happen after exercise. Nothing here opens
 * a connection: the Broker connects upstream only after `apply` succeeded.
 */

export const BODY_LIMIT = 2 * 1024 * 1024;
const TOKEN = /vlch_ph_v1_[0-9a-f]{32}/g;
const MAX_JSON_DEPTH = 256;

export interface RequestParts {
  /** Header pairs as sent, in order, without the hop-by-hop and proxy headers. */
  headers: [string, string][];
  /** The raw query string without `?`, or null. */
  query: string | null;
  body: Buffer;
}

export interface Placement {
  item: string;
  target: string;
}

export type Surface = "headers" | "query" | "body";

export interface Stray {
  item: string;
  surface: Surface;
}

/** Why a request was blocked before exercise, or failed after it. */
export type PlacementRule =
  | "outside-target"
  | "second-occurrence"
  | "repeated-header"
  | "folded-header"
  | "repeated-name"
  | "separator"
  | "encoded-placeholder"
  | "content-type"
  | "content-encoding"
  | "invalid-body"
  | "duplicate-key"
  | "unsafe-header-value"
  | "body-limit"
  | "missing-value";

export type ApplyResult =
  | { ok: true; headers: [string, string][]; query: string | null; body: Buffer }
  | { ok: false; rule: PlacementRule; message: string };

export type PlacementPlan =
  | { kind: "pass"; strays: Stray[] }
  | { kind: "block"; status: 403 | 413; rule: PlacementRule; message: string }
  | {
      kind: "substitute";
      placements: Placement[];
      strays: Stray[];
      apply: (values: Map<string, string>) => ApplyResult;
    };

class Blocked extends Error {
  constructor(
    readonly rule: PlacementRule,
    message: string,
  ) {
    // Names and pointers come from the Agent's request: never echo a
    // Placeholder (or anything shaped like one) back into diagnostics.
    super(message.replace(TOKEN, "<placeholder>"));
  }
}

function tokensIn(text: string): { token: string; index: number }[] {
  return [...text.matchAll(TOKEN)].map((m) => ({ token: m[0], index: m.index }));
}

/**
 * RFC 3986 percent-encoding: only unreserved characters stay literal. The
 * encoding is of UTF-8, which cannot carry an unpaired UTF-16 surrogate: it
 * becomes U+FFFD, as in a header or an environment variable, instead of
 * failing the request.
 */
export function percentEncode(value: string): string {
  return encodeURIComponent(deliveredText(value)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/** Every decoding a destination might apply, leniently, to find encoded Placeholders. */
function lenientDecode(text: string): string {
  return text
    .replace(/\+/g, " ")
    .replace(/%([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}

function sameTokens(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const x = [...a].sort();
  const y = [...b].sort();
  return x.every((t, i) => t === y[i]);
}

// ---------------------------------------------------------------------------
// Query strings and form bodies share one grammar.

interface Param {
  name: string;
  rawValue: string | null;
  start: number;
  valueStart: number;
  end: number;
}

function decodeForm(raw: string, where: string): string {
  try {
    return decodeURIComponent(raw.replace(/\+/g, " "));
  } catch {
    throw new Blocked("invalid-body", `malformed percent-encoding in the ${where}`);
  }
}

function parseParams(text: string, where: string): Param[] {
  const params: Param[] = [];
  let at = 0;
  for (const part of text.split("&")) {
    const eq = part.indexOf("=");
    params.push({
      name: decodeForm(eq < 0 ? part : part.slice(0, eq), where),
      rawValue: eq < 0 ? null : part.slice(eq + 1),
      start: at,
      valueStart: eq < 0 ? at + part.length : at + eq + 1,
      end: at + part.length,
    });
    at += part.length + 1;
  }
  return params;
}

// ---------------------------------------------------------------------------
// A strict JSON parser that records every string's span and pointer, and
// rejects duplicate keys anywhere.

interface JsonString {
  /** Offsets of the quotes: inclusive start, exclusive end. */
  start: number;
  end: number;
  value: string;
  pointer: string;
  isKey: boolean;
}

const escapeToken = (t: string) => t.replace(/~/g, "~0").replace(/\//g, "~1");
const LITERAL = /true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

function parseJson(text: string): JsonString[] {
  const strings: JsonString[] = [];
  let i = 0;
  const fail = (rule: PlacementRule, why: string): never => {
    throw new Blocked(rule, `the JSON body ${why}`);
  };
  const ws = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const parseString = (pointer: string, isKey: boolean): string => {
    const start = i++;
    let value = "";
    for (;;) {
      if (i >= text.length) fail("invalid-body", "has an unterminated string");
      const c = text[i]!;
      if (c === '"') break;
      if (c < " ") fail("invalid-body", "has a control character in a string");
      if (c !== "\\") {
        value += c;
        i++;
        continue;
      }
      const e = text[i + 1] ?? "";
      if (e in ESCAPES) {
        value += ESCAPES[e];
        i += 2;
      } else if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
        value += String.fromCharCode(Number.parseInt(text.slice(i + 2, i + 6), 16));
        i += 6;
      } else fail("invalid-body", "has an invalid escape");
    }
    i++;
    strings.push({ start, end: i, value, pointer, isKey });
    return value;
  };
  const parseValue = (pointer: string, depth: number): void => {
    if (depth > MAX_JSON_DEPTH) fail("invalid-body", `nests deeper than ${MAX_JSON_DEPTH} levels`);
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const keys = new Set<string>();
      ws();
      if (text[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("invalid-body", "has an object key that is not a string");
        const key = parseString(pointer, true);
        // A destination may keep the first or the last: never guess.
        if (keys.has(key)) fail("duplicate-key", `repeats the key "${key}" at "${pointer || "/"}"`);
        keys.add(key);
        ws();
        if (text[i] !== ":") fail("invalid-body", "is missing a colon");
        i++;
        parseValue(`${pointer}/${escapeToken(key)}`, depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return;
        }
        fail("invalid-body", "has an unterminated object");
      }
    }
    if (c === "[") {
      i++;
      ws();
      if (text[i] === "]") {
        i++;
        return;
      }
      for (let index = 0; ; index++) {
        parseValue(`${pointer}/${index}`, depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return;
        }
        fail("invalid-body", "has an unterminated array");
      }
    }
    if (c === '"') {
      parseString(pointer, false);
      return;
    }
    LITERAL.lastIndex = i;
    const literal = LITERAL.exec(text);
    if (!literal) fail("invalid-body", "is not valid JSON");
    i += literal![0].length;
  };
  parseValue("", 0);
  ws();
  if (i !== text.length) fail("invalid-body", "has trailing content");
  return strings;
}

// ---------------------------------------------------------------------------

interface Occurrence {
  item: string;
  surface: Surface;
  /** Where it is, for diagnostics. */
  location: string;
  /** The target it sits at, or null. */
  target: string | null;
  /** Record the substitution into `out`; called only after exercise. */
  apply: (value: string, out: Output) => void;
}

/** One application's result, built fresh on every call. */
interface Output {
  headers: [string, string][];
  query: Edit[];
  body: Edit[];
}

interface Edit {
  start: number;
  end: number;
  text: string;
}

function splice(text: string, edits: Edit[]): string {
  let out = text;
  for (const e of [...edits].sort((a, b) => b.start - a.start)) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return out;
}

/**
 * Decide, before any exercise, what to do with a request to an allowlisted
 * destination. `placeholders` maps this run's Placeholders to their items;
 * `targets` are the ones varlatchd recorded on the Capability.
 */
export function planPlacement(
  parts: RequestParts,
  placeholders: Map<string, string>,
  targets: Map<string, Target[]>,
): PlacementPlan {
  try {
    return plan(parts, placeholders, targets);
  } catch (err) {
    if (err instanceof Blocked) return { kind: "block", status: 403, rule: err.rule, message: err.message };
    throw err;
  }
}

function plan(parts: RequestParts, placeholders: Map<string, string>, targets: Map<string, Target[]>): PlacementPlan {
  // Only this run's Placeholders count; any other lookalike is ordinary text.
  const ours = (text: string) => tokensIn(text).filter((t) => placeholders.has(t.token));
  const bodyLatin1 = parts.body.toString("latin1");
  const surfaces: Record<Surface, string> = {
    headers: parts.headers.map(([, v]) => v).join("\n"),
    query: parts.query ?? "",
    body: bodyLatin1,
  };

  // Items present anywhere, as written or visible only after decoding.
  const present = new Set<string>();
  for (const text of Object.values(surfaces)) {
    for (const t of [...ours(text), ...ours(lenientDecode(text))]) present.add(placeholders.get(t.token)!);
  }
  if (present.size === 0) return { kind: "pass", strays: [] };

  const kindsOf: Record<Surface, Target["kind"][]> = { headers: ["header"], query: ["query"], body: ["json", "form"] };
  const targetsIn = (item: string, surface: Surface) =>
    (targets.get(item) ?? []).filter((t) => kindsOf[surface].includes(t.kind));
  /** The first present item that makes `surface` targeted, or undefined. */
  const targetedBy = (surface: Surface) => [...present].sort().find((item) => targetsIn(item, surface).length > 0);

  const occurrences: Occurrence[] = [];
  let bodyText: string | null = null;

  // --- headers
  if (targetedBy("headers") !== undefined) {
    for (const item of present) {
      for (const t of targetsIn(item, "headers")) {
        const same = parts.headers.filter(([n]) => n.toLowerCase() === t.location);
        if (same.length > 1) {
          throw new Blocked("repeated-header", `${item}: the target header "${t.location}" appears more than once`);
        }
        if (same.some(([, v]) => /[\r\n]/.test(v))) {
          throw new Blocked("folded-header", `${item}: the target header "${t.location}" is line-folded`);
        }
      }
    }
  }
  parts.headers.forEach(([name, value], index) => {
    for (const { token } of ours(value)) {
      const item = placeholders.get(token)!;
      const lower = name.toLowerCase();
      const at = targetsIn(item, "headers").find((t) => t.location === lower);
      occurrences.push({
        item,
        surface: "headers",
        location: `header "${lower}"`,
        target: at ? `header:${at.location}` : null,
        apply: (secret, out) => {
          if (/[\r\n\0]/.test(secret)) {
            throw new Blocked(
              "unsafe-header-value",
              `${item}: the value contains CR, LF, or NUL and cannot be carried in header "${lower}"`,
            );
          }
          out.headers[index] = [name, out.headers[index]![1].replace(token, () => secret)];
        },
      });
    }
  });

  // --- query strings and form bodies
  const params = (text: string, surface: Surface, kind: "query" | "form", by: string, edits: "query" | "body") => {
    const what = kind === "query" ? "query" : "form body";
    const label = kind === "query" ? "query parameter" : "form field";
    if (text.includes(";")) {
      throw new Blocked("separator", `${by}: a ";" in the targeted ${what}, which some servers treat as a separator`);
    }
    const list = parseParams(text, what);
    if (!sameTokens(ours(text).map((t) => t.token), ours(decodeForm(text, what)).map((t) => t.token))) {
      throw new Blocked("encoded-placeholder", `${by}: an encoded placeholder in the targeted ${what}`);
    }
    for (const item of present) {
      for (const t of targetsIn(item, surface).filter((x) => x.kind === kind)) {
        if (list.filter((p) => p.name === t.location).length > 1) {
          throw new Blocked("repeated-name", `${item}: the target ${label} "${t.location}" appears more than once`);
        }
      }
    }
    for (const { token, index } of ours(text)) {
      const item = placeholders.get(token)!;
      const param = list.find((p) => index >= p.start && index < p.end);
      const exact = param !== undefined && index >= param.valueStart && param.rawValue === token;
      const at = exact ? targetsIn(item, surface).find((t) => t.kind === kind && t.location === param.name) : undefined;
      occurrences.push({
        item,
        surface,
        location: param ? `${label} "${param.name}"` : `the ${what}`,
        target: at ? `${kind}:${at.location}` : null,
        apply: (secret, out) => out[edits].push({ start: param!.valueStart, end: param!.end, text: percentEncode(secret) }),
      });
    }
  };
  const inert = (text: string, surface: Surface, location: string) => {
    for (const { token } of ours(text)) {
      occurrences.push({ item: placeholders.get(token)!, surface, location, target: null, apply: () => {} });
    }
  };

  const queryBy = targetedBy("query");
  if (parts.query !== null && queryBy !== undefined) params(parts.query, "query", "query", queryBy, "query");
  else inert(parts.query ?? "", "query", "the query");

  // --- body
  const bodyBy = targetedBy("body");
  if (parts.body.length > 0 && bodyBy !== undefined) {
    const codings = parts.headers
      .filter(([n]) => n.toLowerCase() === "content-encoding")
      .map(([, v]) => v.trim().toLowerCase());
    if (codings.some((c) => c !== "identity")) {
      throw new Blocked("content-encoding", `${bodyBy}: the body is targeted and has a Content-Encoding`);
    }
    const types = parts.headers.filter(([n]) => n.toLowerCase() === "content-type").map(([, v]) => v);
    const [mime = "", ...mediaParams] = (types.length === 1 ? types[0]! : "").split(";").map((p) => p.trim());
    const media = mime.toLowerCase();
    const kinds = new Set([...present].flatMap((item) => targetsIn(item, "body").map((t) => t.kind)));
    const matching =
      (media === "application/json" && kinds.has("json")) ||
      (media === "application/x-www-form-urlencoded" && kinds.has("form"));
    if (types.length !== 1 || !matching) {
      const declared = types.length === 0 ? "none" : types.length > 1 ? "repeated" : types[0];
      throw new Blocked("content-type", `${bodyBy}: the body is targeted, and its Content-Type (${declared}) does not match the target`);
    }
    const charset = mediaParams.find((p) => p.toLowerCase().startsWith("charset="));
    if (charset && !/^charset="?utf-8"?$/i.test(charset)) {
      throw new Blocked("content-type", `${bodyBy}: the targeted body declares a charset other than UTF-8`);
    }
    try {
      bodyText = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(parts.body);
    } catch {
      throw new Blocked("invalid-body", `${bodyBy}: the targeted body is not valid UTF-8`);
    }
    const text = bodyText;
    if (media === "application/json") {
      const strings = parseJson(text);
      const decoded = strings.flatMap((s) => ours(s.value).map((t) => t.token));
      if (!sameTokens(ours(text).map((t) => t.token), decoded)) {
        throw new Blocked("encoded-placeholder", `${bodyBy}: an escaped placeholder in the targeted JSON body`);
      }
      for (const { token, index } of ours(text)) {
        const item = placeholders.get(token)!;
        // Outside strings a Placeholder is not valid JSON, so one contains it.
        const s = strings.find((x) => index > x.start && index < x.end)!;
        const exact = !s.isKey && s.start === index - 1 && s.end === index + token.length + 1;
        const at = exact ? targetsIn(item, "body").find((t) => t.kind === "json" && t.location === s.pointer) : undefined;
        occurrences.push({
          item,
          surface: "body",
          location: s.isKey ? `a JSON key in "${s.pointer || "/"}"` : `JSON body at "${s.pointer || "/"}"`,
          target: at ? `json:${at.location}` : null,
          apply: (secret, out) =>
            out.body.push({ start: index, end: index + token.length, text: JSON.stringify(secret).slice(1, -1) }),
        });
      }
    } else {
      params(text, "body", "form", bodyBy, "body");
    }
  } else {
    inert(bodyLatin1, "body", "the body");
  }

  // --- the placement rules (Decision 3)
  const strays: Stray[] = [];
  const used = new Set<string>();
  const placed: Occurrence[] = [];
  for (const o of occurrences) {
    if (targetsIn(o.item, o.surface).length === 0) {
      strays.push({ item: o.item, surface: o.surface });
      continue;
    }
    if (o.target === null) throw new Blocked("outside-target", `${o.item}: placeholder at ${o.location}, which is not a target`);
    const key = `${o.item}\u0000${o.target}`;
    if (used.has(key)) {
      throw new Blocked("second-occurrence", `${o.item}: a second placeholder at ${o.target}; each target is substituted at most once`);
    }
    used.add(key);
    placed.push(o);
  }
  if (placed.length === 0) return { kind: "pass", strays };

  return {
    kind: "substitute",
    strays,
    placements: placed.map((o) => ({ item: o.item, target: o.target! })),
    apply: (values) => {
      const out: Output = { headers: parts.headers.map(([n, v]) => [n, v]), query: [], body: [] };
      try {
        for (const o of placed) {
          const value = values.get(o.item);
          if (value === undefined) throw new Blocked("missing-value", `${o.item}: the exercise did not return it`);
          o.apply(value, out);
        }
        const query = parts.query !== null && out.query.length > 0 ? splice(parts.query, out.query) : parts.query;
        const body = bodyText !== null && out.body.length > 0 ? Buffer.from(splice(bodyText, out.body), "utf8") : parts.body;
        if (body.length > BODY_LIMIT) {
          throw new Blocked("body-limit", `the substituted body exceeds the ${BODY_LIMIT}-byte limit`);
        }
        return { ok: true, headers: out.headers, query, body };
      } catch (err) {
        if (err instanceof Blocked) return { ok: false, rule: err.rule, message: err.message };
        throw err;
      }
    },
  };
}
