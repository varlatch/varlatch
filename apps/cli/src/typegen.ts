// SPDX-License-Identifier: Apache-2.0
import {
  ContractValidationError,
  SEMANTICS_VERSIONS,
  contractHash,
  normalizeContract,
  semanticsVersionOf,
  type ContractItem,
} from "@varlatch/contract";
import { SCHEMA_FORMAT, implementedSemanticsVersions, type AccessorSchema } from "@varlatch/accessor";
import { ACCESSOR_RUNTIME_NAME, ACCESSOR_RUNTIME_SOURCE } from "@varlatch/accessor/embedded";

/**
 * `varlatch types`: one deterministic TypeScript module from a Contract
 * Revision. The module carries the Typed Accessor runtime inline (bundled
 * with the Contract Semantics it uses), so an application needs only this
 * file. The output depends on the revision and the generator version only:
 * never on an Environment, a value, the clock, or the machine.
 */

export class TypesError extends Error {
  override name = "TypesError";
}

export interface RevisionInput {
  id: string;
  contentHash: string;
  semanticsVersion: number;
  contract: unknown;
}

export interface GenerateOptions {
  /** The CLI release, recorded in the header. */
  generatorVersion: string;
}

const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;
const CONTENT_HASH = /^sha256:[0-9a-f]{64}$/;
export const VERSION = /^[0-9A-Za-z.+-]{1,64}$/;

const LINE_TERMINATORS = /\r\n|[\n\r\u0085\u2028\u2029]/g;
/** C0 and C1 controls (the newline is kept), DEL, and bidirectional formatting characters. */
const CONTROLS = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
/** Characters a string literal escapes: they are invisible, reorder text, or end a line. */
const LITERAL_ESCAPES = /[\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/**
 * Contract text as documentation lines: every line terminator normalized,
 * tabs made spaces, and control and bidirectional formatting characters
 * removed, so Contract text cannot hide in generated documentation. Each
 * language then neutralizes what would end its own comment or string.
 */
export function cleanLines(text: string): string[] {
  const lines = text
    .replace(LINE_TERMINATORS, "\n")
    .replace(/\t/g, " ")
    .replace(CONTROLS, "")
    .split("\n")
    .map((line) => line.trimEnd());
  while (lines[0] === "") lines.shift();
  while (lines.at(-1) === "") lines.pop();
  return lines;
}

/**
 * Comment text: cleaned, and `*\/` neutralized, so Contract text can neither
 * end the comment nor hide in it.
 */
export function commentLines(text: string): string[] {
  return cleanLines(text).map((line) => line.replace(/\*\//g, "*\\/"));
}

/** A JSON value as TypeScript source, with every invisible or line-ending character escaped. */
function literal(value: unknown, indent?: number): string {
  return JSON.stringify(value, null, indent).replace(
    LITERAL_ESCAPES,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/** A string literal that is also safe inside a comment. */
function commentLiteral(value: string): string {
  return literal(value).replace(/\*\//g, "*\\/");
}

function typeOf(item: ContractItem): string {
  switch (item.type) {
    case "number":
    case "integer":
      return "number";
    case "boolean":
      return "boolean";
    case "enum":
      return (item.enumValues ?? []).map((v) => literal(v)).join(" | ");
    default:
      return "string";
  }
}

/** Non-optional only when required in every Environment with nothing, not even a default, to satisfy it otherwise. */
export function isOptional(item: ContractItem): boolean {
  return item.required.kind !== "always" || item.defaultValue !== undefined;
}

export function requirednessLine(item: ContractItem): string {
  const satisfied = item.defaultValue !== undefined ? ", or satisfied by the Contract default" : "";
  switch (item.required.kind) {
    case "always":
      return `Required in every environment${satisfied}.`;
    case "never":
      return "Optional in every environment.";
    case "selector": {
      const selector = item.required.selector;
      const where =
        selector.kind === "tier"
          ? `in environments of tier ${selector.tier}`
          : `in the environments with root ID ${selector.environmentIds.join(", ")}`;
      return `Required only ${where}${satisfied}; checked when a run context names the environment.`;
    }
  }
}

function memberDoc(item: ContractItem): string[] {
  const body: string[] = [];
  if (item.description !== undefined) body.push(...commentLines(item.description), "");
  body.push(...commentLines(requirednessLine(item)), "");
  if (item.type === "integer") body.push("A whole number.", "");
  if (item.example !== undefined) {
    const [first = "", ...rest] = commentLines(item.example);
    body.push(`@example ${first}`.trimEnd(), ...rest);
  }
  if (item.defaultValue !== undefined) body.push(`@default ${commentLiteral(item.defaultValue)}`);
  if (item.sensitive) body.push("@sensitive");
  while (body.at(-1) === "") body.pop();
  return ["  /**", ...body.map((line) => (line === "" ? "   *" : `   * ${line}`)), "   */"];
}

/** The revision's items, after checking its ID, hash, semantics version, and content. Throws TypesError. */
export function checkRevision(
  revision: RevisionInput,
  implemented: readonly number[] = implementedSemanticsVersions(),
): ContractItem[] {
  if (typeof revision.id !== "string" || !IDENTIFIER.test(revision.id)) {
    throw new TypesError("the server returned a Contract Revision ID this CLI does not accept");
  }
  if (typeof revision.contentHash !== "string" || !CONTENT_HASH.test(revision.contentHash)) {
    throw new TypesError(`Contract Revision ${revision.id} has a content hash this CLI does not accept`);
  }
  const version = revision.semanticsVersion;
  if (!(SEMANTICS_VERSIONS as readonly unknown[]).includes(version)) {
    throw new TypesError(
      `Contract Revision ${revision.id} uses Contract Semantics version ${String(version)}, which this CLI does not implement (it generates types for version ${implemented.join(", ")}). Upgrade the CLI, or activate a revision at a version it implements`,
    );
  }
  if (!implemented.includes(version)) {
    throw new TypesError(
      `Contract Revision ${revision.id} uses Contract Semantics version ${version}, which defines no conversion, so no types can be generated from it. Activate a revision at version ${implemented.join(" or ")}: push it with varlatch contract push --semantics latest, then activate it`,
    );
  }
  let contract;
  try {
    contract = normalizeContract(revision.contract);
  } catch (err) {
    if (err instanceof ContractValidationError) {
      throw new TypesError(`Contract Revision ${revision.id} is not a valid Contract: ${err.issues.join("; ")}`);
    }
    throw err;
  }
  if (semanticsVersionOf(contract) !== version || contractHash(contract) !== revision.contentHash) {
    throw new TypesError(`Contract Revision ${revision.id} does not match its content hash`);
  }
  return contract.items;
}

/** The generated module, byte for byte. Throws TypesError when no types can be generated. */
export function generateTypesModule(revision: RevisionInput, opts: GenerateOptions): string {
  if (!VERSION.test(opts.generatorVersion)) throw new TypesError("the generator version is not printable");
  const items = checkRevision(revision);
  const version = revision.semanticsVersion;
  const generator = `varlatch ${opts.generatorVersion}`;

  const out: string[] = [
    "// @ts-nocheck",
    "/* eslint-disable */",
    "// Generated by `varlatch types` from a Varlatch Contract Revision. Do not edit",
    "// this file: regenerate it with `varlatch types`, and check that it is current",
    "// with `varlatch types --check`.",
    "//",
    `// Contract Revision:          ${revision.id}`,
    `// Content hash:               ${revision.contentHash}`,
    `// Contract Semantics version: ${version}`,
    `// Generator:                  ${generator}`,
    "//",
    "// It holds Contract metadata only: names, types, descriptions, examples,",
    "// defaults, and requiredness, never values. The Typed Accessor at the end",
    "// reads process.env, converts each value with the Contract Semantics version",
    "// above, and never writes to process.env.",
    "",
    "/**",
    " * Every Contract item, converted: numbers and integers to `number`,",
    " * booleans to `boolean`, enums to their values; URLs are validated and stay",
    " * strings. An item is optional unless the Contract requires it in every",
    " * environment without a default: a default is applied only by",
    " * `varlatch run --strict`, or by `loadConfig({ applyDefaults: true })`, and",
    " * never replaces a withheld value.",
    " */",
  ];
  if (items.length === 0) {
    out.push("export interface Config {}");
  } else {
    out.push("export interface Config {");
    items.forEach((item, i) => {
      if (i > 0) out.push("");
      out.push(...memberDoc(item), `  readonly ${item.name}${isOptional(item) ? "?" : ""}: ${typeOf(item)};`);
    });
    out.push("}");
  }
  const publicNames = items.filter((i) => !i.sensitive).map((i) => literal(i.name));
  out.push(
    "",
    "/** Only the non-sensitive Contract items. */",
    `export type PublicConfig = Pick<Config, ${publicNames.length > 0 ? publicNames.join(" | ") : "never"}>;`,
    "",
    "/** One problem with the configuration: an item name and a reason, never a value. */",
    "export interface ConfigIssue {",
    "  readonly name: string;",
    "  readonly reason: string;",
    "}",
    "",
    "/** Thrown when the configuration is invalid. It lists every problem and never contains a value. */",
    "export interface ConfigError extends Error {",
    '  readonly name: "ConfigError";',
    "  readonly issues: readonly ConfigIssue[];",
    "}",
    "",
    "export interface LoadOptions {",
    "  /** Where values are read. Default: process.env. Never written to. */",
    "  readonly env?: Readonly<Record<string, string | undefined>>;",
    "  /**",
    "   * Fill absent items with their Contract defaults, and report them in",
    "   * `defaulted`. Applies without a run context or under one from",
    "   * `varlatch run --export-context`, never to an item the server withheld,",
    "   * and has no effect after `varlatch run --strict`, which already applied",
    "   * defaults.",
    "   */",
    "  readonly applyDefaults?: boolean;",
    '  /** When the run context names a different Contract: "warn" (default) or "throw". */',
    '  readonly staleTypes?: "warn" | "throw";',
    "  /** Throw when VARLATCH_RUN_CONTEXT is not set. */",
    "  readonly requireContext?: boolean;",
    "  /** Receives warnings, such as stale types. Default: process.emitWarning. */",
    "  readonly onWarning?: (message: string) => void;",
    "}",
    "",
    "export interface LoadResult {",
    "  /** The converted configuration. Read-only: any write, delete, or definition throws. */",
    "  readonly config: Readonly<Config>;",
    "  /** Items filled with their Contract default by `applyDefaults`. */",
    "  readonly defaulted: readonly (keyof Config)[];",
    "  /** Absent items required only in some environments, unchecked without a run context. */",
    "  readonly notEvaluated: readonly (keyof Config)[];",
    '  /** The run context\'s mode, or null when the application was started without one. */',
    '  readonly context: "strict" | "exported" | null;',
    "  /** Warnings raised while loading. */",
    "  readonly warnings: readonly string[];",
    "}",
    "",
    "/** The Contract Revision this file was generated from. */",
    `export const generatedFrom = ${literal(
      { revisionId: revision.id, contentHash: revision.contentHash, semanticsVersion: version, generator },
      2,
    )} as const;`,
    "",
  );
  const schema: AccessorSchema = {
    format: SCHEMA_FORMAT,
    revisionId: revision.id,
    contentHash: revision.contentHash,
    semanticsVersion: version,
    generator,
    items: items.map((item) => ({
      name: item.name,
      type: item.type,
      required: item.required,
      ...(item.enumValues !== undefined ? { enumValues: item.enumValues } : {}),
      ...(item.defaultValue !== undefined ? { defaultValue: item.defaultValue } : {}),
    })),
  };
  out.push(
    "const varlatchSchema = {",
    ...Object.entries(schema).map(([key, value]) =>
      key === "items"
        ? [`  "items": [`, ...schema.items.map((item) => `    ${literal(item)},`), "  ],"].join("\n")
        : `  ${literal(key)}: ${literal(value)},`,
    ),
    "};",
    "",
    `const varlatchAccessor = ${ACCESSOR_RUNTIME_NAME}();`,
    "",
    "/** Thrown when the configuration is invalid. */",
    "export const ConfigError: new (issues: readonly ConfigIssue[]) => ConfigError = varlatchAccessor.ConfigError;",
    "",
    "/**",
    " * Read and convert every item now. Throws one ConfigError that lists every",
    " * problem by name and reason, never by value.",
    " */",
    "export function loadConfig(options?: LoadOptions): LoadResult {",
    "  return varlatchAccessor.loadConfig(varlatchSchema, options);",
    "}",
    "",
    "/**",
    " * The configuration from process.env, read and validated on first use with",
    " * the default options. Read-only: any write, delete, or definition throws.",
    " * If the configuration is invalid, every use throws the same ConfigError.",
    " */",
    "export const config: Readonly<Config> = varlatchAccessor.lazyConfig(varlatchSchema);",
    "",
    "/*! Varlatch Typed Accessor. Copyright 2026 Robotsson. SPDX-License-Identifier: Apache-2.0 */",
    ACCESSOR_RUNTIME_SOURCE,
    "",
  );
  return out.join("\n");
}
