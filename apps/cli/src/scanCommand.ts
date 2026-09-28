// SPDX-License-Identifier: Apache-2.0
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { ResolvedContext } from "@varlatch/context";
import { MIN_LENGTH } from "@varlatch/matcher";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";
import {
  BASELINE_FILE,
  BaselineError,
  DEFAULT_LIMITS,
  SCAN_REPORT_VERSION,
  ScanEngine,
  baselineEntriesOf,
  formatBaseline,
  formatScanHuman,
  parseBaseline,
  parseSize,
  scanExitCode,
  scanNotices,
  type BaselineEntry,
  type ScanLimits,
  type ScanSecret,
} from "./scan.js";
import {
  ScanSourceError,
  gitTopLevel,
  listPaths,
  listStaged,
  relativePath,
  scanPaths,
  scanStaged,
  type PathListing,
  type StagedListing,
} from "./scanSources.js";

/**
 * `varlatch scan` (ADR-0038 Decision 14): check staged Git content or build
 * output for the Secrets this identity may retrieve.
 *
 * The values come from one explicit disclosure, `secret.reveal`, declared
 * with `purpose: "scan"` so the audit event says why. They are the selected
 * Environment's Secrets, current and retiring versions, and they stay in
 * this process's memory for the scan only: nothing derived from them is
 * written anywhere. Nothing is disclosed when there is nothing to read.
 */

export class ScanUsageError extends Error {
  override name = "ScanUsageError";
}

export const SCAN_USAGE =
  "Usage: varlatch scan (--staged | <path>...) [-e <env>] [--json] [--baseline <file>] [--write-baseline]\n" +
  "                     [--max-file-size <size>] [--max-total-size <size>]\n" +
  "       varlatch scan --install-hook [-e <env>]";

export interface ScanOptions {
  staged: boolean;
  paths: string[];
  json: boolean;
  installHook: boolean;
  baseline: string | undefined;
  writeBaseline: boolean;
  limits: ScanLimits;
  environment: string | undefined;
}

const VALUE_FLAGS = new Set(["-e", "--environment", "--server", "--baseline", "--max-file-size", "--max-total-size"]);
const BOOLEAN_FLAGS = new Set(["--staged", "--json", "--install-hook", "--write-baseline"]);

export function parseScanArgs(args: string[]): ScanOptions {
  const opts: ScanOptions = {
    staged: false,
    paths: [],
    json: false,
    installHook: false,
    baseline: undefined,
    writeBaseline: false,
    limits: { ...DEFAULT_LIMITS },
    environment: undefined,
  };
  let onlyPaths = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (onlyPaths || !arg.startsWith("-") || arg === "-") {
      opts.paths.push(arg);
      continue;
    }
    if (arg === "--") {
      onlyPaths = true;
      continue;
    }
    if (BOOLEAN_FLAGS.has(arg)) {
      if (arg === "--staged") opts.staged = true;
      if (arg === "--json") opts.json = true;
      if (arg === "--install-hook") opts.installHook = true;
      if (arg === "--write-baseline") opts.writeBaseline = true;
      continue;
    }
    if (!VALUE_FLAGS.has(arg)) throw new ScanUsageError(`unknown option ${arg}`);
    const value = args[++i];
    if (value === undefined || value.startsWith("-")) throw new ScanUsageError(`${arg} needs a value`);
    if (arg === "-e" || arg === "--environment") opts.environment = value;
    if (arg === "--baseline") opts.baseline = value;
    if (arg === "--max-file-size" || arg === "--max-total-size") {
      const size = parseSize(value);
      if (size === null) throw new ScanUsageError(`${arg} expects a size such as 64M, 1G, or a number of bytes; got "${value}"`);
      if (arg === "--max-file-size") opts.limits.maxFileSize = size;
      else opts.limits.maxTotalSize = size;
    }
  }
  if (opts.installHook) {
    if (opts.staged || opts.paths.length > 0 || opts.writeBaseline || opts.json || opts.baseline) {
      throw new ScanUsageError("--install-hook takes no paths and no other options than -e");
    }
    return opts;
  }
  if (opts.staged && opts.paths.length > 0) throw new ScanUsageError("give either --staged or paths, not both");
  if (!opts.staged && opts.paths.length === 0) throw new ScanUsageError("give --staged or at least one path");
  return opts;
}

export interface ScanIo {
  out: (line: string) => void;
  err: (line: string) => void;
  cwd: string;
}

export interface ScanDeps {
  /** Resolve the repository context; throws a ContextError when there is none. */
  context: () => ResolvedContext;
  /** An authenticated client; exits the process when there is no credential. */
  client: (ctx: ResolvedContext) => VarlatchClient;
}

/** Run `varlatch scan`; resolves to the exit code. */
export async function runScan(opts: ScanOptions, deps: ScanDeps, io: ScanIo): Promise<number> {
  const ctx = deps.context();
  if (opts.installHook) {
    const hook = await installHook(io.cwd, ctx.repoRoot, opts.environment);
    io.out(`Installed the pre-commit hook at ${hook}: each commit runs "varlatch scan --staged" first.`);
    io.out("Skip it once with git commit --no-verify; delete that file to remove it.");
    return 0;
  }

  // What would be read, before anything is disclosed.
  let listing: { mode: "staged"; staged: StagedListing } | { mode: "paths"; paths: PathListing };
  if (opts.staged) listing = { mode: "staged", staged: await listStaged(io.cwd, ctx.repoRoot) };
  else listing = { mode: "paths", paths: await listPaths(opts.paths, io.cwd, ctx.repoRoot) };
  const files = listing.mode === "staged" ? listing.staged.files : listing.paths.files;
  const unlisted = listing.mode === "staged" ? listing.staged.notScanned : listing.paths.notScanned;

  const baselinePath = opts.baseline ? resolve(io.cwd, opts.baseline) : join(ctx.repoRoot, BASELINE_FILE);
  const baseline = loadBaseline(baselinePath, opts.baseline !== undefined);

  // Values are disclosed only when at least one file fits the bounds and will be read.
  const readable = files.some((f) => f.size <= Math.min(opts.limits.maxFileSize, opts.limits.maxTotalSize));
  let secrets: ScanSecret[] = [];
  if (readable) {
    const api = deps.client(ctx);
    secrets = await retrieveForScan(api, ctx, io);
  }

  const engine = new ScanEngine(secrets, { limits: opts.limits, baseline });
  // Drop this reference to the values: from here on only the matcher holds them.
  secrets = [];
  for (const n of unlisted) engine.notScanned(n.path, n.reason);
  if (readable && !engine.checksAnything) {
    io.err(
      `varlatch scan: this identity may retrieve no Secret value of ${MIN_LENGTH} bytes or more in ${ctx.environment}; ` +
        "there is nothing to look for.",
    );
  } else if (listing.mode === "staged") {
    await scanStaged(engine, listing.staged);
  } else {
    await scanPaths(engine, listing.paths);
  }
  let report = engine.result();

  if (opts.writeBaseline) {
    const key = (e: BaselineEntry) => JSON.stringify([e.path, e.item, e.versionId]);
    const known = new Set(baseline.map(key));
    const added = new Set(baselineEntriesOf(report).map(key).filter((k) => !known.has(k)));
    writeFileSync(baselinePath, formatBaseline([...baseline, ...baselineEntriesOf(report)]));
    io.err(
      `varlatch scan: ${added.size === 0 ? "nothing new to add" : `added ${added.size} entr${added.size === 1 ? "y" : "ies"}`} to ${baselinePath} ` +
        "(path, item, and version only). Review it before you commit it.",
    );
    report = {
      ...report,
      findings: [],
      unlisted: [],
      allowed: [...report.allowed, ...report.findings.map((f) => ({ ...f, allowedBy: "baseline" as const }))],
    };
  }

  for (const notice of scanNotices(report)) io.err(notice);
  if (opts.json) {
    io.out(JSON.stringify(jsonReport(report, ctx, listing.mode), null, 2));
  } else if (files.length === 0 && unlisted.length === 0) {
    io.out(listing.mode === "staged" ? "varlatch scan: nothing is staged." : "varlatch scan: no files to scan.");
  } else {
    for (const line of formatScanHuman(report, { environment: ctx.environment, mode: listing.mode })) io.out(line);
  }
  return scanExitCode(report);
}

function jsonReport(report: ReturnType<ScanEngine["result"]>, ctx: ResolvedContext, mode: "staged" | "paths") {
  return { version: SCAN_REPORT_VERSION, environment: ctx.environment, mode, exitCode: scanExitCode(report), ...report };
}

/**
 * One audited disclosure of every Secret this identity may retrieve in the
 * selected Environment, current and retiring versions, with purpose `scan`.
 */
export async function retrieveForScan(api: VarlatchClient, ctx: ResolvedContext, io: Pick<ScanIo, "err">): Promise<ScanSecret[]> {
  const meta = await api.meta();
  if (!meta.capabilities.includes("secrets.disclosure-purpose")) {
    io.err(
      `varlatch scan: this server (${meta.serverVersion}) does not record a disclosure purpose; ` +
        "the disclosure is audited as an ordinary one.",
    );
  }
  let disclosed: Awaited<ReturnType<VarlatchClient["discloseSecrets"]>>;
  try {
    disclosed = await api.discloseSecrets(ctx.organization, ctx.project, ctx.environment, {
      scope: "all-authorized-secrets",
      purpose: "scan",
    });
  } catch (err) {
    if (err instanceof VarlatchApiError && (err.code === "PERMISSION_DENIED" || err.code === "RESOURCE_NOT_FOUND")) {
      throw new ScanUsageError(
        `nothing was scanned: this identity may not retrieve Secrets in ${ctx.environment} ` +
          `(${err.code}; scanning needs secret.reveal there) (request ${err.requestId})`,
      );
    }
    throw err;
  }
  const secrets: ScanSecret[] = [];
  for (const item of disclosed.items) {
    secrets.push({ item: item.name, versionId: item.versionId, retiring: false, value: item.value });
    if (item.retiring) {
      secrets.push({ item: item.name, versionId: item.retiring.versionId, retiring: true, value: item.retiring.value });
    }
  }
  return secrets;
}

function loadBaseline(path: string, explicit: boolean): BaselineEntry[] {
  if (!existsSync(path)) {
    if (explicit) throw new ScanUsageError(`no baseline file at ${path}`);
    return [];
  }
  try {
    return parseBaseline(readFileSync(path, "utf8"));
  } catch (err) {
    if (err instanceof BaselineError) throw new ScanUsageError(`invalid baseline ${path}: ${err.message}`);
    throw err;
  }
}

// ---- Pre-commit hook ---------------------------------------------------------

export const HOOK_MARKER = "# varlatch-scan-hook v1";

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The hook's text: it runs `varlatch scan --staged` from the project directory. */
export function hookScript(projectDir: string, environment: string | undefined): string {
  const lines = [
    "#!/bin/sh",
    HOOK_MARKER,
    "# Installed by `varlatch scan --install-hook`. Before each commit it checks",
    "# the staged content for Secrets and stops the commit when it finds one.",
    "# Skip it once with `git commit --no-verify`; delete this file to remove it.",
    "# Git runs hooks from the top of the working tree. Keep Git's paths valid",
    "# after changing directory.",
    'case "${GIT_INDEX_FILE:-/}" in /*) ;; *) GIT_INDEX_FILE="$PWD/$GIT_INDEX_FILE"; export GIT_INDEX_FILE ;; esac',
    'case "${GIT_DIR:-/}" in /*) ;; *) GIT_DIR="$PWD/$GIT_DIR"; export GIT_DIR ;; esac',
    'if [ -n "${GIT_DIR:-}" ] && [ -z "${GIT_WORK_TREE:-}" ]; then GIT_WORK_TREE="$PWD"; export GIT_WORK_TREE; fi',
  ];
  if (projectDir !== "" && projectDir !== ".") lines.push(`cd ${shellQuote(projectDir)} || exit 1`);
  lines.push(`exec varlatch scan --staged${environment ? ` --environment ${shellQuote(environment)}` : ""}`);
  return `${lines.join("\n")}\n`;
}

/**
 * Write the pre-commit hook (only when asked: it is never installed
 * automatically). A hook that Varlatch did not write is never replaced.
 */
export async function installHook(cwd: string, projectRoot: string, environment: string | undefined): Promise<string> {
  const top = await gitTopLevel(cwd);
  const { execFileSync } = await import("node:child_process");
  let hookPath: string;
  try {
    hookPath = execFileSync("git", ["rev-parse", "--git-path", "hooks/pre-commit"], { cwd, encoding: "utf8" }).trim();
  } catch (err) {
    throw new ScanSourceError(`could not find the hooks directory: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!isAbsolute(hookPath)) hookPath = resolve(cwd, hookPath);
  const projectDir = relativePath(top, realpathSync(projectRoot));
  if (projectDir.startsWith("..")) throw new ScanUsageError(`${projectRoot} is outside the Git working tree ${top}`);
  const script = hookScript(projectDir, environment);
  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf8");
    if (!existing.includes(HOOK_MARKER)) {
      throw new ScanUsageError(
        `${hookPath} already exists and was not written by varlatch; it was left unchanged. ` +
          `To run the scan from it, add this line:\n  ${projectDir && projectDir !== "." ? `(cd ${shellQuote(projectDir)} && varlatch scan --staged) || exit 1` : "varlatch scan --staged || exit 1"}`,
      );
    }
  }
  mkdirSync(dirname(hookPath), { recursive: true });
  writeFileSync(hookPath, script, { mode: 0o755 });
  chmodSync(hookPath, 0o755);
  return hookPath;
}

