// SPDX-License-Identifier: Apache-2.0
/**
 * Interim env-spec parser: a documented SUBSET of Varlock's .env.schema
 * decorator language, sufficient for Contract ingestion. This module is the
 * ADR-0002 adapter boundary — when we wire the real Varlock parser (its
 * plugin API is the flagship integration path), this file is what gets
 * replaced; nothing downstream changes.
 *
 * Supported:
 *   Root decorators:  @defaultSensitive=true|false   @defaultRequired=true|false|infer
 *   Item decorators:  @required  @optional  @required=forEnv(a,b)
 *                     @sensitive  @sensitive=false  @public
 *                     @type=string|number|boolean|url|email|enum(a,b,...)
 *                     @example=... / @example="..."
 *   Items:            NAME=            (no default)
 *                     NAME=literal     (defaultValue)
 *                     NAME=fn(...)     (dynamic resolver; no defaultValue)
 *   Plain `# text` comment lines above an item become its description.
 *
 * Anything decorator-shaped but unrecognized fails loudly (ADR-0013 §12):
 * never discarded, never approximated.
 */

export type DraftRequired =
  | { kind: "always" }
  | { kind: "never" }
  | { kind: "forEnv"; varlockNames: string[] };

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
  /** Every distinct forEnv name referenced, for mapping resolution. */
  varlockEnvNames: string[];
}

export class EnvSchemaParseError extends Error {
  override name = "EnvSchemaParseError";
  readonly line: number;
  constructor(line: number, message: string) {
    super(`.env.schema line ${line}: ${message}`);
    this.line = line;
  }
}

const ITEM_LINE = /^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$/;
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
  const envNames = new Set<string>();

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
      buildItem(item[1] as string, item[2] ?? "", pendingDecorators, pendingDescription, envNames),
    );
    pendingDecorators = [];
    pendingDescription = [];
  }

  return { defaults, items, varlockEnvNames: [...envNames].sort() };
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
  rhs: string,
  decorators: { name: string; value: string | undefined; line: number }[],
  description: string[],
  envNames: Set<string>,
): DraftItem {
  const item: DraftItem = { name, required: null, sensitive: null, type: "string" };
  if (description.length > 0) item.description = description.join(" ");

  const value = rhs.trim();
  if (value !== "" && !FUNCTION_VALUE.test(value)) {
    item.defaultValue = stripQuotes(value);
  }

  for (const d of decorators) {
    switch (d.name) {
      case "required": {
        if (d.value === undefined || d.value === "true") item.required = { kind: "always" };
        else if (d.value === "false") item.required = { kind: "never" };
        else {
          const m = /^forEnv\((.*)\)$/.exec(d.value.trim());
          if (!m) throw new EnvSchemaParseError(d.line, `Unsupported @required form: ${d.value}`);
          const names = parseList(m[1] as string);
          if (names.length === 0) throw new EnvSchemaParseError(d.line, "forEnv() needs at least one environment");
          for (const n of names) envNames.add(n);
          item.required = { kind: "forEnv", varlockNames: names };
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
        // Presentation-only Varlock decorators: not part of the Contract.
        break;
      default:
        throw new EnvSchemaParseError(
          d.line,
          `Unsupported decorator @${d.name} — the adapter fails loudly rather than dropping semantics (ADR-0013)`,
        );
    }
  }
  return item;
}
