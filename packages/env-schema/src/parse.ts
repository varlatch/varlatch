// SPDX-License-Identifier: Apache-2.0
/**
 * Varlatch's .env.schema parser for the format documented in
 * docs/reference/env-schema.md, including its known limitations.
 *
 * Supported:
 *   Root decorators:  @defaultSensitive=true|false   @defaultRequired=true|false|infer
 *   Item decorators:  @required  @optional
 *                     @required=env(name, ...)   root Environments, by name
 *                     @required=tier(development|staging|production)
 *                     @sensitive  @sensitive=false  @public
 *                     @type=string|number|boolean|url|email|enum(a,b,...)
 *                     @example=... / @example="..."
 *   Items:            NAME=            (no default)
 *                     NAME=literal     (defaultValue)
 *                     NAME=fn(...)     (dynamic resolver; no defaultValue)
 *   Plain `# text` comment lines above an item become its description.
 *   After a value, whitespace followed by `#` (outside quotes) starts a
 *   comment; a `#` with no whitespace before it is part of the value.
 *
 * Anything decorator-shaped but unrecognized fails loudly (ADR-0013 §12):
 * never discarded, never approximated.
 */

import { TIERS, type Tier } from "@varlatch/contract";

export type DraftRequired =
  | { kind: "always" }
  | { kind: "never" }
  /** Root Environment names; the CLI resolves them to IDs when it pushes. */
  | { kind: "environments"; names: string[] }
  | { kind: "tier"; tier: Tier };

export interface DraftItem {
  name: string;
  required: DraftRequired | null;
  sensitive: boolean | null;
  type: "string" | "number" | "boolean" | "url" | "email" | "enum";
  enumValues?: string[];
  defaultValue?: string;
  description?: string;
  example?: string;
}

export interface ContractDraft {
  defaults: { sensitive: boolean; required: DraftRequired };
  items: DraftItem[];
  /** Every distinct Environment name referenced by env(...), sorted. */
  environmentNames: string[];
}

export class EnvSchemaParseError extends Error {
  override name = "EnvSchemaParseError";
  readonly line: number;
  constructor(line: number, message: string) {
    super(`.env.schema line ${line}: ${message}`);
    this.line = line;
  }
}

const ITEM_LINE = /^([A-Z][A-Z0-9_]*)\s*=(.*)$/;
// Matches @name, @name=value, and @name(args) — anything decorator-shaped.
const DECORATOR = /^@([A-Za-z][A-Za-z0-9]*)(?:=(.*)|(\(.*\)))?$/;
const FUNCTION_VALUE = /^[A-Za-z_][A-Za-z0-9_]*\(.*\)$/;

function stripQuotes(v: string): string {
  const t = v.trim();
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

const FOR_ENV_REMOVED =
  "forEnv(...) is not supported. Name this project's Varlatch environments instead, " +
  "for example @required=env(production, staging), or name a tier: @required=tier(production)";

/**
 * Split an item's right-hand side into its value and an optional trailing
 * comment. A comment starts at `#` preceded by whitespace, outside quotes. A
 * trailing decorator is an error: decorators go on their own line.
 */
function valueOf(rhs: string, line: number): string {
  const start = rhs.length - rhs.trimStart().length;
  const t = rhs.trimStart();
  if (t.startsWith('"') || t.startsWith("'")) {
    const quote = t[0] as string;
    let close = -1;
    for (let i = 1; i < t.length; i++) {
      if (t[i] === "\\" && quote === '"') {
        i++; // escapes are kept verbatim, but an escaped quote does not close
        continue;
      }
      if (t[i] === quote) {
        close = i;
        break;
      }
    }
    if (close < 0) throw new EnvSchemaParseError(line, "Unterminated quoted value");
    trailing(t.slice(close + 1), line);
    return t.slice(0, close + 1);
  }
  const comment = /\s#/.exec(rhs.slice(start > 0 ? start - 1 : 0));
  if (!comment) return t.trimEnd();
  const at = (start > 0 ? start - 1 : 0) + comment.index;
  trailing(rhs.slice(at), line);
  return rhs.slice(0, at).trim();
}

function trailing(rest: string, line: number): void {
  const t = rest.trim();
  if (t === "") return;
  if (!t.startsWith("#")) {
    throw new EnvSchemaParseError(line, `Unexpected text after the value: ${t.slice(0, 40)}`);
  }
  if (t.replace(/^#+\s?/, "").trim().startsWith("@")) {
    throw new EnvSchemaParseError(
      line,
      "A decorator must be on its own comment line above the item, not after its value",
    );
  }
}

function parseList(inner: string): string[] {
  return inner
    .split(",")
    .map((s) => stripQuotes(s.trim()))
    .filter((s) => s.length > 0);
}

export function parseEnvSchema(source: string): ContractDraft {
  const defaults: ContractDraft["defaults"] = {
    sensitive: true,
    required: { kind: "never" },
  };
  const items: DraftItem[] = [];
  const environmentNames = new Set<string>();

  let pendingDecorators: { name: string; value: string | undefined; line: number }[] = [];
  let pendingDescription: string[] = [];
  let sawItem = false;

  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i] ?? "";
    const line = raw.trim();
    if (line === "") {
      pendingDecorators = [];
      pendingDescription = [];
      continue;
    }
    if (line.startsWith("#")) {
      const comment = line.replace(/^#+\s?/, "").trim();
      const dec = DECORATOR.exec(comment);
      if (dec) {
        const name = dec[1] as string;
        const value = dec[2] ?? dec[3];
        // Root decorators apply immediately while no item has been seen —
        // blank lines between the header block and items must not drop them.
        if (!sawItem && (name === "defaultSensitive" || name === "defaultRequired")) {
          applyRootDecorator(defaults, { name, value, line: lineNo });
        } else {
          pendingDecorators.push({ name, value, line: lineNo });
        }
      } else if (comment.startsWith("@")) {
        throw new EnvSchemaParseError(lineNo, `Malformed decorator: ${comment.slice(0, 60)}`);
      } else if (comment !== "" && !comment.startsWith("---")) {
        pendingDescription.push(comment);
      }
      continue;
    }
    const item = ITEM_LINE.exec(line);
    if (!item) {
      throw new EnvSchemaParseError(lineNo, `Unrecognized line: ${line.slice(0, 60)}`);
    }
    sawItem = true;
    items.push(
      buildItem(
        item[1] as string,
        valueOf(item[2] ?? "", lineNo),
        pendingDecorators,
        pendingDescription,
        environmentNames,
      ),
    );
    pendingDecorators = [];
    pendingDescription = [];
  }

  return { defaults, items, environmentNames: [...environmentNames].sort() };
}

function applyRootDecorator(
  defaults: ContractDraft["defaults"],
  d: { name: string; value: string | undefined; line: number },
): void {
  if (d.name === "defaultSensitive") {
    if (d.value !== "true" && d.value !== "false") {
      throw new EnvSchemaParseError(d.line, "@defaultSensitive must be true or false");
    }
    defaults.sensitive = d.value === "true";
  } else {
    if (d.value === "true") defaults.required = { kind: "always" };
    else if (d.value === "false" || d.value === "infer" || d.value === undefined) {
      defaults.required = { kind: "never" };
    } else {
      throw new EnvSchemaParseError(d.line, "@defaultRequired must be true, false, or infer");
    }
  }
}

function buildItem(
  name: string,
  value: string,
  decorators: { name: string; value: string | undefined; line: number }[],
  description: string[],
  environmentNames: Set<string>,
): DraftItem {
  const item: DraftItem = { name, required: null, sensitive: null, type: "string" };
  if (description.length > 0) item.description = description.join(" ");

  if (value !== "" && !FUNCTION_VALUE.test(value)) {
    item.defaultValue = stripQuotes(value);
  }

  for (const d of decorators) {
    switch (d.name) {
      case "required": {
        const v = d.value?.trim();
        if (v === undefined || v === "true") item.required = { kind: "always" };
        else if (v === "false") item.required = { kind: "never" };
        else if (/^forEnv\s*\(/.test(v)) throw new EnvSchemaParseError(d.line, FOR_ENV_REMOVED);
        else if (/^env\(.*\)$/.test(v)) {
          const names = [...new Set(parseList(v.slice(4, -1)))];
          if (names.length === 0) {
            throw new EnvSchemaParseError(d.line, "env() needs at least one environment name");
          }
          for (const n of names) environmentNames.add(n);
          item.required = { kind: "environments", names };
        } else if (/^tier\(.*\)$/.test(v)) {
          const tier = v.slice(5, -1).trim();
          if (!(TIERS as readonly string[]).includes(tier)) {
            throw new EnvSchemaParseError(d.line, `tier() takes one of: ${TIERS.join(", ")}`);
          }
          item.required = { kind: "tier", tier: tier as Tier };
        } else {
          throw new EnvSchemaParseError(d.line, `Unsupported @required form: ${v}`);
        }
        break;
      }
      case "optional":
        item.required = { kind: "never" };
        break;
      case "sensitive":
        if (d.value === undefined || d.value === "true") item.sensitive = true;
        else if (d.value === "false") item.sensitive = false;
        else throw new EnvSchemaParseError(d.line, `Unsupported @sensitive form: ${d.value}`);
        break;
      case "public":
        item.sensitive = false;
        break;
      case "type": {
        const v = (d.value ?? "").trim();
        const enumMatch = /^enum\((.*)\)$/.exec(v);
        if (enumMatch) {
          item.type = "enum";
          item.enumValues = parseList(enumMatch[1] as string);
          if (item.enumValues.length === 0) {
            throw new EnvSchemaParseError(d.line, "enum() needs at least one value");
          }
        } else if (["string", "number", "boolean", "url", "email"].includes(v)) {
          item.type = v as DraftItem["type"];
        } else {
          throw new EnvSchemaParseError(d.line, `Unsupported @type: ${v}`);
        }
        break;
      }
      case "example":
        item.example = stripQuotes(d.value ?? "");
        break;
      case "docs":
      case "icon":
      case "tag":
        // Presentation-only decorators: not part of the Contract.
        break;
      default:
        throw new EnvSchemaParseError(
          d.line,
          `Unsupported decorator @${d.name}: unknown decorators fail loudly rather than being dropped`,
        );
    }
  }
  return item;
}
