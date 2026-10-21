// SPDX-License-Identifier: Apache-2.0
import { parse } from "yaml";
import type { NameUsage, UsageReport } from "./types.js";

/**
 * How a Coolify service's compose file uses the names a Sync Target
 * manages (ADR-0031 amendment 2026-10-21). Read from the compose file as
 * written (how each name is used) and the one Coolify generated at its
 * last parse (whether each container loads the service's `.env`), with the
 * rules of Coolify's own service parser (v4.4.6 `serviceParser`) and
 * Docker Compose's precedence (`environment:` wins over `env_file`).
 *
 * The verdicts are hints, and conservative: a form these rules do not
 * cover reads as unknown, and nothing here infers what an image does with
 * a value. The compose text never leaves this module: callers get names,
 * container names and verdicts only.
 */

/** Larger compose files are not inspected (a bound on what a token can make us parse). */
export const MAX_COMPOSE_BYTES = 512 * 1024;
/** YAML aliases are expanded at most this often (a bound against alias bombs). */
const MAX_ALIASES = 200;

/** Written into `.env` or rewritten on every start by Coolify itself. */
const OWNED_PREFIXES = ["SERVICE_FQDN_", "SERVICE_URL_", "SERVICE_NAME_", "COOLIFY_"];

/** Names Coolify sets itself on a service: a Target may not manage them. */
export function coolifyOwnsName(name: string): boolean {
  return OWNED_PREFIXES.some((p) => name.startsWith(p));
}

/** Coolify's generated-once magic names (passwords, users, keys): created once and kept. */
export function coolifyGeneratesName(name: string): boolean {
  return name.startsWith("SERVICE_") && !coolifyOwnsName(name);
}

type EnvValue = string | number | boolean | null | object;

/** One entry of a PHP array: a string key, or a list position (null). */
type PhpEntry = { key: string | null; value: unknown };

/**
 * PHP's is_numeric: what Coolify's normalisation treats as a list position.
 * A mapping with such a key is read in an order and a form JavaScript does
 * not reproduce (it lists integer-like keys first), so Varlatch claims
 * nothing about that container.
 */
const PHP_NUMERIC = /^[ \t\n\r\v\f]*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?[ \t\n\r\v\f]*$/;

/** A YAML sequence or mapping as the PHP array Coolify's YAML parser makes of it. */
function phpEntries(source: unknown): PhpEntry[] {
  if (Array.isArray(source)) return source.map((value) => ({ key: null, value }));
  if (isObject(source)) {
    // PHP turns a decimal integer key into a list position.
    return Object.entries(source).map(([key, value]) => ({ key: /^(0|-?[1-9][0-9]*)$/.test(key) ? null : key, value }));
  }
  return [];
}

/**
 * A container's `environment:` merged with its `build.args`, exactly as
 * Coolify's serviceParser reads them: Laravel's `merge` (string keys
 * replace in place, list positions append), then
 * convertToKeyValueCollection, which reads a pure list (`- NAME=value`,
 * a bare `- NAME` as an empty value) differently from a collection with
 * any string key (where a bare `- NAME` is the name without a value).
 */
function environmentOf(service: unknown): { env: Map<string, EnvValue>; opaque: boolean } {
  const env = new Map<string, EnvValue>();
  if (!isObject(service)) return { env, opaque: false };
  const merged: PhpEntry[] = [];
  const build = isObject(service.build) ? service.build.args : undefined;
  const numericKey = (source: unknown) => isObject(source) && Object.keys(source).some((k) => PHP_NUMERIC.test(k));
  if (numericKey(service.environment) || numericKey(build)) return { env, opaque: true };
  for (const entry of [...phpEntries(service.environment), ...phpEntries(build)]) {
    const at = entry.key === null ? -1 : merged.findIndex((m) => m.key === entry.key);
    if (at >= 0) merged[at] = entry;
    else merged.push(entry);
  }
  const associative = merged.some((m) => m.key !== null);
  for (const { key, value } of merged) {
    if (key !== null) {
      env.set(key, value as EnvValue);
      continue;
    }
    if (typeof value !== "string") continue;
    const eq = value.indexOf("=");
    if (!associative) {
      // `NAME=value`, or a bare `NAME` as an empty value.
      const name = eq >= 0 ? value.slice(0, eq) : value;
      if (name !== "") env.set(name, eq >= 0 ? value.slice(eq + 1) : "");
    } else if (eq >= 0) {
      env.set(value.slice(0, eq), value.slice(eq + 1));
    } else if (value !== "") {
      env.set(value, env.has(value) ? (env.get(value) as EnvValue) : null);
    }
  }
  return { env, opaque: false };
}

/** Every string a parsed YAML document holds, keys included: what its escapes decode to. */
function scalarsOf(node: unknown, out: string[] = []): string[] {
  if (typeof node === "string") out.push(node);
  else if (Array.isArray(node)) for (const item of node) scalarsOf(item, out);
  else if (isObject(node)) {
    for (const [key, value] of Object.entries(node)) {
      out.push(key);
      scalarsOf(value, out);
    }
  }
  return out;
}

/** Whether the generated compose file has the container load `.env` (Coolify ≥ v4.0.0-beta.443 adds it to every container). */
function loadsDotEnv(service: unknown): boolean {
  if (!isObject(service)) return false;
  const files = Array.isArray(service.env_file) ? service.env_file : [service.env_file];
  return files.some((f) => {
    const path = typeof f === "string" ? f : isObject(f) && typeof f.path === "string" ? f.path : undefined;
    return path === ".env" || path === "./.env";
  });
}

/** `$NAME` or `${NAME…}` anywhere in the text, `$$` escapes excluded. Over-approximates on purpose. */
function referencesName(text: string, name: string): boolean {
  return new RegExp(`(?<!\\$)\\$(?:\\{${name}(?=[}:?-])|${name}(?![A-Za-z0-9_]))`).test(text);
}

/**
 * What Coolify's replaceVariables reads out of a `$…` value: the content of
 * a leading `${…}`, or the rest after a bare `$`.
 */
function referenceContent(value: string): string {
  if (value.startsWith("${")) {
    let depth = 0;
    for (let i = 1; i < value.length; i++) {
      if (value[i] === "{") depth++;
      else if (value[i] === "}" && --depth === 0) return value.slice(2, i);
    }
    return value.slice(2);
  }
  return value.slice(1);
}

/** `${NAME}`, `$NAME`, or `${NAME` with a default or required marker: the container's NAME is the stored NAME. */
function isSelfReference(value: string, name: string): boolean {
  if (value === `$${name}`) return true;
  if (!value.startsWith("${")) return false;
  const content = referenceContent(value);
  // Something after the reference makes it an expression, not the name.
  if (value !== `\${${content}}`) return false;
  return content === name || (content.startsWith(name) && /^(:?-|:?\?)/.test(content.slice(name.length)));
}

type Verdict = "delivered" | "shadowed" | "owned" | "unknown";

/**
 * The names whose stored value Coolify copies into the generated compose
 * file for this entry, where Docker Compose expands `$` in it (Coolify's
 * serviceParser: an empty value takes the stored one; a `$…` value other
 * than the bare `NAME: ${NAME}` sets each variable it names to its stored
 * value). Over-approximates the nested defaults.
 */
function copiedNames(key: string, value: EnvValue): string[] {
  if (value === "") return [key];
  if (typeof value !== "string" || !value.startsWith("$")) return [];
  const content = referenceContent(value);
  if (content === key || content.startsWith("SERVICE_")) return [];
  const names = new Set<string>();
  const head = /^[A-Za-z_][A-Za-z0-9_]*/.exec(content);
  if (head) names.add(head[0]);
  for (const m of value.matchAll(/(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)/g)) names.add(m[1] as string);
  return [...names];
}

/** One container's reading of one name that its `environment:` (or build args) sets. */
function verdictFor(name: string, value: EnvValue): Verdict {
  // Set without a value: Coolify keeps it unset in the generated file and
  // Compose resolves it from its own environment. Not a rule we can prove.
  if (value === null) return "unknown";
  if (typeof value === "number" || typeof value === "boolean") return "shadowed";
  if (typeof value !== "string") return "unknown";
  // An empty value takes the stored one (Coolify's override for "").
  if (value === "") return "delivered";
  if (value.startsWith("$")) {
    // Coolify rewrites the name to this reference on every parse.
    if (referenceContent(value).startsWith("SERVICE_")) return "owned";
    if (isSelfReference(value, name)) return "delivered";
    // Another variable (or an expression of one) decides the container's value.
    return "shadowed";
  }
  // A literal, or a string that interpolates other names: the compose
  // file, not the stored variable, decides the container's value.
  return "shadowed";
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Parse bounded YAML; undefined when it is too large, malformed, or not a mapping. */
function parseBounded(text: string): Record<string, unknown> | undefined {
  if (Buffer.byteLength(text, "utf8") > MAX_COMPOSE_BYTES) return undefined;
  try {
    const doc = parse(text, { merge: true, maxAliasCount: MAX_ALIASES, prettyErrors: false, uniqueKeys: false }) as unknown;
    return isObject(doc) ? doc : undefined;
  } catch {
    return undefined;
  }
}

const unknown = (reason: string, names: string[]): UsageReport => ({
  checked: false,
  reason,
  names: new Map(names.map((n) => [n, {}])),
});

/**
 * Classify each name. `raw` is the compose file as written, `generated` the
 * one Coolify produced at its last parse; `parsingVersion` is the service's
 * `compose_parsing_version` (Coolify's legacy parser below 3 follows other
 * rules, so nothing is claimed for it).
 */
export function classifyComposeUsage(
  raw: string | null | undefined,
  generated: string | null | undefined,
  parsingVersion: number | null | undefined,
  names: string[],
): UsageReport {
  if (typeof parsingVersion !== "number" || parsingVersion < 3) {
    return unknown("this service uses Coolify's older compose parser, whose rules Varlatch does not check", names);
  }
  if (typeof raw !== "string" || raw === "") return unknown("Coolify did not return the service's compose file", names);
  if (typeof generated !== "string" || generated === "") {
    return unknown("Coolify has not generated this service's compose file yet (it does at the first start)", names);
  }
  const rawDoc = parseBounded(raw);
  const genDoc = parseBounded(generated);
  if (!rawDoc || !genDoc) return unknown("the service's compose file is too large or could not be read", names);
  const rawServices = isObject(rawDoc.services) ? rawDoc.services : {};
  const genServices = isObject(genDoc.services) ? genDoc.services : {};
  const containers = Object.keys(rawServices).sort();
  if (containers.length === 0) return unknown("the service's compose file defines no containers", names);

  // References as the text has them, and as YAML decodes them (an escaped
  // "\u0024NAME" is $NAME to Coolify): both only widen "referenced".
  const decoded = scalarsOf(rawDoc).join("\n");
  const copied = new Set<string>();
  for (const container of containers) {
    for (const [key, value] of environmentOf(rawServices[container]).env) {
      for (const n of copiedNames(key, value)) copied.add(n);
    }
  }

  const report: UsageReport = { checked: true, names: new Map() };
  for (const name of names) {
    const usage: NameUsage = {};
    const shadowed: string[] = [];
    const unknownIn: string[] = [];
    let reaches = false;
    for (const container of containers) {
      const { env, opaque } = environmentOf(rawServices[container]);
      if (opaque) {
        unknownIn.push(container);
        continue;
      }
      if (env.has(name)) {
        const verdict = verdictFor(name, env.get(name) as EnvValue);
        if (verdict === "owned") usage.owned = true;
        else if (verdict === "shadowed") shadowed.push(container);
        else if (verdict === "unknown") unknownIn.push(container);
        else reaches = true;
      } else if (loadsDotEnv(genServices[container])) {
        reaches = true;
      } else if (referencesName(JSON.stringify(rawServices[container] ?? null), name)) {
        // The container uses the stored value inside another of its settings.
        reaches = true;
      }
    }
    // Another name bound to a Coolify-generated value makes that name owned,
    // not this one; this one is owned when its own entry is.
    if (referencesName(raw, name) || referencesName(decoded, name)) usage.referenced = true;
    if (coolifyGeneratesName(name)) usage.generatedOnce = true;
    if (copied.has(name)) usage.copiedIntoCompose = true;
    if (shadowed.length > 0) usage.shadowedIn = shadowed;
    if (unknownIn.length > 0) usage.unknownIn = unknownIn;
    if (!reaches && !usage.owned && shadowed.length === 0 && unknownIn.length === 0) usage.notDeliveredTo = containers;
    report.names.set(name, usage);
  }
  return report;
}
