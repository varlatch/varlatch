// SPDX-License-Identifier: Apache-2.0
import {
  SEMANTICS_VERSIONS,
  semanticsFor,
  type ContractSemantics,
  type ConvertedValue,
  type ParseResult,
} from "@varlatch/contract/semantics";
import { TIERS, type ContractItem, type Tier } from "@varlatch/contract/types";

/**
 * The Typed Accessor. Every module `varlatch types` generates carries this
 * runtime inline, bundled with the Contract Semantics it uses, so an
 * application needs nothing but the generated file.
 *
 * It reads the environment (process.env by default), converts each value
 * with the generated file's semantics version, and returns a read-only view.
 * It has no rules of its own: validation, conversion, and requiredness all
 * come from `@varlatch/contract`. It never writes to the environment, and no
 * error or warning it produces contains a value.
 */

/** Reserved launcher metadata that `varlatch run --strict` and `--export-context` set. */
export const RUN_CONTEXT = "VARLATCH_RUN_CONTEXT";

/** The schema format generated modules embed. A change that old runtimes cannot read bumps it. */
export const SCHEMA_FORMAT = 1;

/** What the accessor needs of a Contract item: never descriptions, examples, or values. */
export type AccessorItem = Pick<ContractItem, "name" | "type" | "required" | "enumValues" | "defaultValue">;

/** The Contract data a generated module embeds. */
export interface AccessorSchema {
  format: typeof SCHEMA_FORMAT;
  revisionId: string;
  contentHash: string;
  semanticsVersion: number;
  generator: string;
  items: AccessorItem[];
}

export interface ConfigIssue {
  readonly name: string;
  /** Never contains a value or any part of one. */
  readonly reason: string;
}

function formatIssues(issues: readonly ConfigIssue[]): string {
  const count = `${issues.length} ${issues.length === 1 ? "problem" : "problems"}`;
  return [`Varlatch configuration is invalid (${count}):`, ...issues.map((i) => `  ${i.name}: ${i.reason}`)].join("\n");
}

/** Every problem found, by item name and reason. Never a value. */
export class ConfigError extends Error {
  override name = "ConfigError";
  readonly issues: readonly ConfigIssue[];
  constructor(issues: readonly ConfigIssue[]) {
    super(formatIssues(issues));
    this.issues = Object.freeze(issues.map((i) => Object.freeze({ name: i.name, reason: i.reason })));
  }
}

export interface LoadOptions {
  /** Where values are read. Default: process.env. Never written to. */
  env?: Readonly<Record<string, string | undefined>> | undefined;
  /**
   * Fill absent items with their Contract defaults. Applies only without a
   * run context or under an exported one, never to an item the run context
   * records as withheld by the server, and never after a strict run, which
   * already applied defaults where they belong.
   */
  applyDefaults?: boolean | undefined;
  /** When the run context names a different Contract content hash: warn (default) or throw. */
  staleTypes?: "warn" | "throw" | undefined;
  /** Throw when there is no run context, instead of reporting conditional items as not evaluated. */
  requireContext?: boolean | undefined;
  /** Receives warnings. Default: process.emitWarning, else console.warn. */
  onWarning?: ((message: string) => void) | undefined;
}

export interface LoadReport {
  /** Items filled with their Contract default because of applyDefaults. */
  readonly defaulted: readonly string[];
  /** Absent items whose requiredness depends on the Environment, unknown without a run context. */
  readonly notEvaluated: readonly string[];
  /** The run context's mode, or null when there is none. */
  readonly context: "strict" | "exported" | null;
  /** Warnings raised while loading, such as stale types. */
  readonly warnings: readonly string[];
}

export interface LoadResult extends LoadReport {
  readonly config: Readonly<Record<string, ConvertedValue>>;
}

type ServerStatus = "delivered" | "withheld" | "notStored";
type Delivery = "varlatch" | "inherited" | "default" | "absent";

export interface RunContext {
  mode: "strict" | "exported";
  contractRevisionId: string;
  contractHash: string;
  semanticsVersion: number;
  environment: { rootId: string; tier: Tier };
  items: ReadonlyMap<string, { server: ServerStatus; delivery: Delivery }>;
}

const SERVER_STATUSES: readonly unknown[] = ["delivered", "withheld", "notStored"];
const DELIVERIES: readonly unknown[] = ["varlatch", "inherited", "default", "absent"];
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/;
const CONTENT_HASH = /^sha256:[0-9a-f]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function contextProblem(reason: string): ConfigError {
  return new ConfigError([{ name: RUN_CONTEXT, reason }]);
}

function typesProblem(reason: string): ConfigError {
  return new ConfigError([{ name: "generated types", reason }]);
}

/**
 * Parse `VARLATCH_RUN_CONTEXT`. Anything this accessor cannot read exactly
 * throws: an unknown version, malformed JSON, or a malformed field. Nothing
 * from the context is echoed except validated identifiers.
 */
export function parseRunContext(raw: string): RunContext {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw contextProblem("is not valid JSON");
  }
  if (!isRecord(data)) throw contextProblem("is not a JSON object");
  if (data.v !== 1) {
    throw contextProblem(
      "has a version this accessor does not read (it reads v 1); regenerate the types with the varlatch CLI that starts the application",
    );
  }
  const malformed = (field: string) => contextProblem(`is malformed: ${field}`);
  if (data.mode !== "strict" && data.mode !== "exported") throw malformed("mode");
  if (typeof data.contractRevisionId !== "string" || !IDENTIFIER.test(data.contractRevisionId)) {
    throw malformed("contractRevisionId");
  }
  if (typeof data.contractHash !== "string" || !CONTENT_HASH.test(data.contractHash)) throw malformed("contractHash");
  if (typeof data.semanticsVersion !== "number" || !Number.isInteger(data.semanticsVersion)) {
    throw malformed("semanticsVersion");
  }
  const environment = data.environment;
  if (
    !isRecord(environment) ||
    typeof environment.rootId !== "string" ||
    !(TIERS as readonly unknown[]).includes(environment.tier)
  ) {
    throw malformed("environment");
  }
  if (!isRecord(data.items)) throw malformed("items");
  const items = new Map<string, { server: ServerStatus; delivery: Delivery }>();
  for (const [name, entry] of Object.entries(data.items)) {
    if (!isRecord(entry) || !SERVER_STATUSES.includes(entry.server) || !DELIVERIES.includes(entry.delivery)) {
      throw malformed("an entry in items");
    }
    items.set(name, { server: entry.server as ServerStatus, delivery: entry.delivery as Delivery });
  }
  return {
    mode: data.mode,
    contractRevisionId: data.contractRevisionId,
    contractHash: data.contractHash,
    semanticsVersion: data.semanticsVersion,
    environment: { rootId: environment.rootId, tier: environment.tier as Tier },
    items,
  };
}

/** The semantics versions this accessor implements: those that define conversion. */
export function implementedSemanticsVersions(): number[] {
  return SEMANTICS_VERSIONS.filter((v) => semanticsFor(v).parse !== undefined);
}

interface ProcessLike {
  env?: Record<string, string | undefined>;
  emitWarning?: (message: string, type?: string) => void;
}

function currentProcess(): ProcessLike | undefined {
  return (globalThis as { process?: ProcessLike }).process;
}

function defaultWarning(message: string): void {
  const proc = currentProcess();
  if (typeof proc?.emitWarning === "function") {
    proc.emitWarning(message, "VarlatchWarning");
    return;
  }
  (globalThis as { console?: { warn(line: string): void } }).console?.warn(`VarlatchWarning: ${message}`);
}

function own(source: Readonly<Record<string, unknown>>, name: string): unknown {
  return Object.prototype.hasOwnProperty.call(source, name) ? source[name] : undefined;
}

/** Why an absent item that is required here is a problem. */
function absentReason(recorded: { server: ServerStatus; delivery: Delivery } | undefined): string {
  if (recorded?.server === "withheld") return "required in this environment, withheld by the server, and absent";
  if (recorded && recorded.delivery !== "absent") {
    return "required in this environment; the run context records it as delivered, but it is absent from the environment";
  }
  return "required in this environment and absent";
}

function evaluate(
  schema: AccessorSchema,
  options: LoadOptions,
): { values: Record<string, ConvertedValue>; report: LoadReport } {
  if (options.staleTypes !== undefined && options.staleTypes !== "warn" && options.staleTypes !== "throw") {
    throw new TypeError('staleTypes must be "warn" or "throw"');
  }
  if (!isRecord(schema) || schema.format !== SCHEMA_FORMAT || !Array.isArray(schema.items)) {
    throw typesProblem("are in a format this accessor does not read; regenerate them with varlatch types");
  }
  const version = schema.semanticsVersion;
  let semantics: ContractSemantics;
  try {
    semantics = semanticsFor(version);
  } catch {
    throw typesProblem(
      `use Contract Semantics version ${String(version)}, which this accessor does not implement (it implements ${implementedSemanticsVersions().join(", ")}); regenerate them with varlatch types`,
    );
  }
  const parse: ((item: ContractItem, value: string) => ParseResult) | undefined = semantics.parse;
  if (!parse) {
    throw typesProblem(
      `use Contract Semantics version ${version}, which defines no conversion; activate a revision at version ${implementedSemanticsVersions().join(" or ")} and regenerate them with varlatch types`,
    );
  }

  const source: Readonly<Record<string, unknown>> = options.env ?? currentProcess()?.env ?? {};
  const warnings: string[] = [];
  const warn = (message: string) => {
    warnings.push(message);
    (options.onWarning ?? defaultWarning)(message);
  };

  const rawContext = own(source, RUN_CONTEXT);
  let context: RunContext | null = null;
  if (rawContext !== undefined) {
    if (typeof rawContext !== "string") throw contextProblem("is not a string");
    context = parseRunContext(rawContext);
    if (context.semanticsVersion !== version) {
      throw contextProblem(
        `names Contract Semantics version ${context.semanticsVersion}, but these types use version ${version}; regenerate them with varlatch types`,
      );
    }
    // The content hash, not the revision ID: an identical Contract activated
    // again as a new revision is not stale.
    if (context.contractHash !== schema.contentHash) {
      const message = `the types are stale: they were generated from the Contract with content hash ${schema.contentHash}, and this run uses ${context.contractHash} (revision ${context.contractRevisionId}); regenerate them with varlatch types`;
      if (options.staleTypes === "throw") throw contextProblem(message);
      warn(message);
    }
  } else if (options.requireContext) {
    throw contextProblem(
      "is not set, and requireContext is on: start the application with varlatch run --strict or varlatch run --export-context",
    );
  }

  const issues: ConfigIssue[] = [];
  const values: Record<string, ConvertedValue> = Object.create(null) as Record<string, ConvertedValue>;
  const defaulted: string[] = [];
  const notEvaluated: string[] = [];
  for (const item of schema.items) {
    const contractItem = item as ContractItem;
    const raw = own(source, item.name);
    // Presence comes from the environment: a present item is read and
    // validated whatever the run context says about how it got there.
    if (raw !== undefined) {
      if (typeof raw !== "string") {
        issues.push({ name: item.name, reason: "is not a string in the environment" });
        continue;
      }
      const result = parse(contractItem, raw);
      if (result.ok) values[item.name] = result.value;
      else issues.push({ name: item.name, reason: result.reason });
      continue;
    }

    const recorded = context?.items.get(item.name);
    if (context?.mode === "strict") {
      // Strict startup already applied defaults where they belong.
      if (semantics.requiredApplies(contractItem, context.environment)) {
        issues.push({ name: item.name, reason: absentReason(recorded) });
      }
      continue;
    }
    const withheld = recorded?.server === "withheld";
    // A default never stands in for a value the server withheld.
    if (options.applyDefaults === true && item.defaultValue !== undefined && !withheld) {
      const result = parse(contractItem, item.defaultValue);
      if (result.ok) {
        values[item.name] = result.value;
        defaulted.push(item.name);
      } else {
        issues.push({ name: item.name, reason: `the Contract default ${result.reason}` });
      }
      continue;
    }
    if (context) {
      const missing = withheld
        ? semantics.requiredApplies(contractItem, context.environment)
        : semantics.missingWhenAbsent(contractItem, context.environment);
      if (missing) issues.push({ name: item.name, reason: absentReason(recorded) });
    } else if (item.required.kind === "selector") {
      // Requiredness depends on the Environment, which only a run context names.
      if (item.defaultValue === undefined) notEvaluated.push(item.name);
    } else if (semantics.missingWhenAbsent(contractItem, { rootId: "", tier: "production" })) {
      // "always" and "never" do not depend on the Environment.
      issues.push({ name: item.name, reason: "required in every environment and absent" });
    }
  }
  if (issues.length > 0) throw new ConfigError(issues);
  return {
    values,
    report: {
      defaulted: Object.freeze(defaulted),
      notEvaluated: Object.freeze(notEvaluated),
      context: context?.mode ?? null,
      warnings: Object.freeze(warnings),
    },
  };
}

const INSPECT = Symbol.for("nodejs.util.inspect.custom");

function readOnly(action: string, key: PropertyKey): TypeError {
  return new TypeError(`The Varlatch configuration is read-only: cannot ${action} ${String(key)}`);
}

/**
 * A read-only view whose values are computed on first use. Enumeration,
 * `in`, `JSON.stringify`, and spreading see exactly the items that have a
 * value. Every write, delete, property definition, or prototype change
 * throws, in strict and sloppy code alike (a frozen object alone fails
 * silently in sloppy code). A failed load throws again on every later use,
 * so no read ever returns undefined for an item that failed.
 */
function view(load: () => Record<string, ConvertedValue>): {
  proxy: Readonly<Record<string, ConvertedValue>>;
  ensure: () => void;
} {
  const target = Object.create(null) as Record<PropertyKey, unknown>;
  let ready = false;
  let failure: { error: unknown } | null = null;
  const ensure = () => {
    if (ready) return;
    if (failure) throw failure.error;
    let values: Record<string, ConvertedValue>;
    try {
      values = load();
    } catch (error) {
      failure = { error };
      throw error;
    }
    for (const name of Object.keys(values)) {
      Object.defineProperty(target, name, { value: values[name], enumerable: true, writable: false, configurable: false });
    }
    Object.freeze(target);
    ready = true;
  };
  // Node's inspector reads the target directly, without traps: load first.
  Object.defineProperty(target, INSPECT, {
    value: () => {
      ensure();
      return Object.assign(Object.create(null) as object, target);
    },
    enumerable: false,
    writable: false,
    configurable: false,
  });
  const proxy = new Proxy(target, {
    get(t, key) {
      ensure();
      return Reflect.get(t, key);
    },
    has(t, key) {
      ensure();
      return Reflect.has(t, key);
    },
    ownKeys(t) {
      ensure();
      return Reflect.ownKeys(t);
    },
    getOwnPropertyDescriptor(t, key) {
      ensure();
      return Reflect.getOwnPropertyDescriptor(t, key);
    },
    isExtensible(t) {
      ensure();
      return Reflect.isExtensible(t);
    },
    preventExtensions(t) {
      ensure();
      return Reflect.preventExtensions(t);
    },
    set(_t, key) {
      throw readOnly("assign", key);
    },
    deleteProperty(_t, key) {
      throw readOnly("delete", key);
    },
    defineProperty(_t, key) {
      throw readOnly("define", key);
    },
    setPrototypeOf() {
      throw readOnly("change the prototype of", "it");
    },
  });
  return { proxy: proxy as Readonly<Record<string, ConvertedValue>>, ensure };
}

/**
 * Read and convert every item now. Throws one ConfigError listing every
 * problem by name and reason, never by value.
 */
export function loadConfig(schema: AccessorSchema, options?: LoadOptions): LoadResult {
  const { values, report } = evaluate(schema, options ?? {});
  const { proxy, ensure } = view(() => values);
  ensure();
  return Object.freeze({ config: proxy, ...report });
}

/**
 * The configuration with default options, read and validated on its first
 * use rather than when the module is imported.
 */
export function lazyConfig(schema: AccessorSchema): Readonly<Record<string, ConvertedValue>> {
  return view(() => evaluate(schema, {}).values).proxy;
}
