// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import {
  CONFIG_ITEM_NAME_PATTERN,
  CONTRACT_SCHEMA_VERSION,
  LATEST_SEMANTICS_VERSION,
  semanticsFor,
  type ConfigurationContract,
  type ContractItem,
  type ItemType,
} from "@varlatch/contract";
import type { ResolvedContext } from "@varlatch/context";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";
import { DotenvParseError, parseDotenv, type DotenvEntry } from "./dotenv.js";

/**
 * `varlatch import <file>` (ADR-0043 Decision 2): the CLI reads a dotenv file
 * itself and stores its values, so the values never pass through a coding
 * agent's context. It prints names, counts, inferred types, and
 * sensitivity, never a value, including in every diagnostic.
 *
 * - `--dry-run` shows the plan and stores nothing; without a repository or a
 *   sign-in it still lists names and inferred types.
 * - `--contract` adds the file's items that are not in the active Contract
 *   to a new revision. Items already in the Contract keep their definition,
 *   sensitivity included. New items are Secrets, the default for anything
 *   uncontracted, unless named with `--plain`. A revision is never activated
 *   here, as with `varlatch contract push`.
 * - `--delete-source` removes the file only after every value was stored,
 *   and only if the file did not change meanwhile.
 */

export class ImportError extends Error {
  override name = "ImportError";
}

export interface ImportOptions {
  file: string;
  dryRun: boolean;
  contract: boolean;
  plain: string[];
  deleteSource: boolean;
}

/** The project to import into, or why there is none (a dry run still lists names). */
export type ImportTarget = { ctx: ResolvedContext; api: VarlatchClient } | { offline: string };

export interface ImportIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

interface Row {
  entry: DotenvEntry;
  type: ItemType;
  /** Null when the sensitivity is unknown (a dry run without a connection). */
  sensitive: boolean | null;
  /** Already in the active Contract. */
  contracted: boolean;
}

const TYPE_ORDER: ItemType[] = ["integer", "number", "url", "email"];

/**
 * The most specific type whose validation accepts the value, by the
 * Contract Semantics version a revision would get; `string` otherwise. A
 * hint from one Environment's value, never a guarantee for the others.
 */
export function inferType(value: string, semanticsVersion: number): ItemType {
  if (value === "") return "string";
  // `true` and `false` only: a boolean item also accepts 1 and 0, but a
  // count of 1 is far more often a number.
  if (/^(true|false)$/i.test(value)) return "boolean";
  const semantics = semanticsFor(semanticsVersion);
  for (const type of TYPE_ORDER) {
    if (type === "integer" && semanticsVersion < 3) continue;
    const item: ContractItem = { name: "X", required: { kind: "never" }, sensitive: false, type };
    if (semantics.validate(item, value) === null) return type;
  }
  return "string";
}

/** Every problem with the file's names at once, by line: names and lines only. */
export function checkEntries(entries: DotenvEntry[]): string[] {
  const problems: string[] = [];
  const lines = new Map<string, number[]>();
  for (const e of entries) {
    lines.set(e.name, [...(lines.get(e.name) ?? []), e.line]);
    if (e.name.startsWith("VARLATCH_")) {
      problems.push(`line ${e.line}: ${e.name} is reserved for the Varlatch CLI and is never stored as configuration`);
    } else if (!CONFIG_ITEM_NAME_PATTERN.test(e.name)) {
      problems.push(`line ${e.line}: ${e.name} is not a valid item name (upper-case letters, digits, and _, starting with a letter)`);
    }
    if (e.value.includes("\0")) problems.push(`line ${e.line}: ${e.name} contains a NUL byte, which an environment variable cannot hold`);
  }
  for (const [name, at] of lines) {
    if (at.length > 1) problems.push(`${name} is set more than once, on lines ${at.join(", ")}`);
  }
  return problems;
}

/**
 * The file as text, or an ImportError naming the first line that is not
 * valid UTF-8. Decoding with replacement would store U+FFFD in place of the
 * original bytes, and --delete-source would then remove the only copy.
 */
export function decodeStrict(bytes: Buffer, file: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    // A multi-byte sequence never contains a line feed, so lines can be checked one by one.
    let line = 1;
    let start = 0;
    for (;;) {
      const end = bytes.indexOf(0x0a, start);
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(start, end < 0 ? bytes.length : end));
      } catch {
        break;
      }
      if (end < 0) break;
      line++;
      start = end + 1;
    }
    throw new ImportError(`${file} line ${line}: not valid UTF-8 text. Nothing was imported.`);
  }
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function activeContract(api: VarlatchClient, ctx: ResolvedContext): Promise<ConfigurationContract | null | "forbidden"> {
  try {
    const revision = await api.getActiveContract(ctx.organization, ctx.project);
    return revision.contract as unknown as ConfigurationContract;
  } catch (err) {
    if (err instanceof VarlatchApiError && err.status === 404) return null;
    if (err instanceof VarlatchApiError && err.status === 403) return "forbidden";
    throw err;
  }
}

function formatRows(rows: Row[], plain: Set<string>): string[] {
  const width = Math.max(...rows.map((r) => r.entry.name.length));
  const typeWidth = Math.max(...rows.map((r) => r.type.length));
  return rows.map((r) => {
    const sensitivity =
      r.sensitive === null ? "" : r.sensitive ? "secret" : r.contracted || !plain.has(r.entry.name) ? "plain" : "plain (--plain)";
    const note = r.contracted ? "  in the Contract" : "";
    return `  ${r.entry.name.padEnd(width)}  ${r.type.padEnd(typeWidth)}  ${sensitivity}${note}`.trimEnd();
  });
}

export async function runImport(opts: ImportOptions, target: ImportTarget, io: ImportIo): Promise<number> {
  if (opts.plain.length > 0 && !opts.contract) {
    throw new ImportError("--plain applies only with --contract: an item's sensitivity lives in the Contract");
  }
  if (!existsSync(opts.file)) throw new ImportError(`No such file: ${opts.file}`);
  const bytes = readFileSync(opts.file);
  let entries: DotenvEntry[];
  try {
    entries = parseDotenv(decodeStrict(bytes, opts.file));
  } catch (err) {
    if (err instanceof DotenvParseError) throw new ImportError(`${opts.file} ${err.message}. Nothing was imported.`);
    throw err;
  }
  const problems = checkEntries(entries);
  const names = new Set(entries.map((e) => e.name));
  const plain = new Set(opts.plain);
  for (const name of [...plain].sort()) {
    if (!names.has(name)) problems.push(`--plain names ${name}, which ${opts.file} does not set`);
  }
  if (problems.length > 0) {
    for (const line of problems) io.err(`varlatch import: ${opts.file} ${line}`);
    throw new ImportError(`${problems.length} problem(s) in ${opts.file}. Nothing was imported.`);
  }
  if (entries.length === 0) {
    io.out(`${opts.file} sets no values; nothing to import.${opts.deleteSource ? " It was not deleted." : ""}`);
    return 0;
  }

  const online = "api" in target ? target : null;
  let contract: ConfigurationContract | null = null;
  if (online) {
    const found = await activeContract(online.api, online.ctx);
    if (found === "forbidden") {
      if (opts.contract) throw new ImportError("--contract needs contract.read on this project to merge with the active Contract. Nothing was imported.");
      io.err("varlatch import: cannot read this project's Contract (403); sensitivity is shown as the default for items outside a Contract");
    } else {
      contract = found;
    }
  }
  const semanticsVersion = contract ? (contract.semanticsVersion ?? 1) : LATEST_SEMANTICS_VERSION;
  const contracted = new Map((contract?.items ?? []).map((i) => [i.name, i]));
  for (const name of [...plain].sort()) {
    if (contracted.get(name)?.sensitive) {
      problems.push(`--plain names ${name}, which the Contract already marks sensitive; change it in the Contract instead`);
    }
  }
  if (problems.length > 0) {
    for (const line of problems) io.err(`varlatch import: ${line}`);
    throw new ImportError("Nothing was imported.");
  }

  const rows: Row[] = entries.map((entry) => {
    const existing = contracted.get(entry.name);
    const sensitive = !online ? null : existing ? existing.sensitive : opts.contract ? !plain.has(entry.name) : true;
    return { entry, type: existing?.type ?? inferType(entry.value, semanticsVersion), sensitive, contracted: existing !== undefined };
  });
  const where = online ? `${online.ctx.organization}/${online.ctx.project} (${online.ctx.environment})` : null;
  const secrets = rows.filter((r) => r.sensitive).length;
  const counts = online ? ` (${secrets} secret, ${rows.length - secrets} plain)` : "";
  io.out(
    `${opts.dryRun ? "Dry run: would import" : "Importing"} ${rows.length} value(s)${counts} from ${opts.file}` +
      (where ? ` into ${where}:` : ` (not connected: ${"offline" in target ? target.offline : ""}):`),
  );
  for (const line of formatRows(rows, plain)) io.out(line);
  const references = rows.filter((r) => r.entry.value.includes("${")).map((r) => r.entry.name);
  if (references.length > 0) {
    io.out(`Note: Varlatch reads \${NAME} in a value as a reference to another item: ${references.join(", ")}`);
  }

  const additions = opts.contract ? rows.filter((r) => !r.contracted) : [];
  if (opts.contract) {
    const kept = rows.length - additions.length;
    io.out(
      additions.length === 0
        ? "Contract: every item is already in the Contract; no revision is needed."
        : `Contract: ${additions.length} new item(s)${kept > 0 ? `; ${kept} already in the Contract keep their definition` : ""}.`,
    );
  }
  if (opts.dryRun) {
    io.out(`Dry run: nothing was stored${opts.deleteSource ? ` and ${opts.file} was not deleted` : ""}.`);
    return 0;
  }
  if (!online) throw new ImportError(`Cannot import: ${"offline" in target ? target.offline : "not connected"}`);
  const { api, ctx } = online;

  if (additions.length > 0) {
    const items: ContractItem[] = [
      ...(contract?.items ?? []),
      ...additions.map((r) => ({
        name: r.entry.name,
        required: { kind: "never" as const },
        sensitive: r.sensitive !== false,
        type: r.type,
      })),
    ];
    const next = { ...(contract ?? { schemaVersion: CONTRACT_SCHEMA_VERSION }), items };
    const revision = await api.pushContractRevision(ctx.organization, ctx.project, {
      contract: next,
      provenance: { adapter: "varlatch-import" },
    });
    io.out(`Contract revision ${revision.id} (${revision.contentHash})${revision.active ? " [active]" : ""}`);
    if (!revision.active) io.out(`Activate with: varlatch contract activate ${revision.id}`);
  }

  const stored: string[] = [];
  for (const [index, row] of rows.entries()) {
    try {
      await api.setValue(ctx.organization, ctx.project, ctx.environment, row.entry.name, { value: row.entry.value });
      stored.push(row.entry.name);
    } catch (err) {
      const reason = err instanceof VarlatchApiError ? err.code : err instanceof Error ? err.name : "an error";
      const skipped = rows.slice(index + 1).map((r) => r.entry.name);
      if (stored.length > 0) io.err(`varlatch import: stored: ${stored.join(", ")}`);
      io.err(`varlatch import: not stored: ${row.entry.name} (${reason})`);
      if (skipped.length > 0) io.err(`varlatch import: not attempted: ${skipped.join(", ")}`);
      throw new ImportError(
        `${stored.length} of ${rows.length} value(s) stored.${opts.deleteSource ? ` ${opts.file} was not deleted.` : ""} ` +
          "Fix the cause and run the import again; stored values are overwritten with the same ones.",
      );
    }
  }
  io.out(`Stored ${stored.length} value(s) in ${where}.`);

  if (opts.deleteSource) {
    let current: Buffer | null = null;
    try {
      current = readFileSync(opts.file);
    } catch {
      current = null;
    }
    if (!current || digest(current) !== digest(bytes)) {
      io.err(`varlatch import: ${opts.file} changed or disappeared while importing; it was not deleted`);
      return 1;
    }
    unlinkSync(opts.file);
    io.out(`Deleted ${opts.file}.`);
  }
  return 0;
}
