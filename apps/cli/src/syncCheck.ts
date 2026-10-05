// SPDX-License-Identifier: Apache-2.0
import { CONFIG_ITEM_NAME_PATTERN, RESERVED_ITEM_NAMES, type ConfigurationContract } from "@varlatch/contract";
import type { ResolvedContext } from "@varlatch/context";
import type { EffectiveConfiguration } from "@varlatch/protocol";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";
import { AdapterError, getAdapter, type PlatformAdapter } from "@varlatch/sync";

/**
 * `varlatch sync check` (ADR-0044): does a platform hold the values the
 * Environment holds? The platform's current values are read through the
 * same closed adapter allowlist `sync push` uses (ADR-0031 Decision 8),
 * compared in memory with the Environment's, and only a status per key is
 * reported: never a value, a hash, a length, or anything else derived from
 * one. So the command works in assisted mode too, a Secret too short to
 * mask included: there is nothing to mask.
 *
 * The platform is read first. Only then are the Environment's Secrets
 * disclosed, and only those the comparison needs (a requested, audited
 * disclosure naming exactly the Secrets the platform also holds), so a
 * platform that cannot be read causes no disclosure at all.
 */

/** 0 every key matches; 1 drift; 2 not everything could be checked (and no drift was found). */
export const SYNC_CHECK_EXIT = { match: 0, drift: 1, unchecked: 2 } as const;

export type CheckStatus = "match" | "differs" | "missing-on-platform" | "extra-on-platform" | "unreadable" | "absent";

/** Why a key could not be compared. */
export type UnreadableReason = "platform-write-only" | "withheld" | "invalid-name";

export interface CheckedKey {
  /** The item's name in Varlatch. */
  name: string;
  /** The name on the platform (differs from `name` only with --map NAME=DEST, or a platform's own canonical form). */
  destination: string;
  status: CheckStatus;
  reason?: UnreadableReason;
}

/** One key to compare: the Varlatch item and the platform name it maps to. */
export interface KeyPair {
  name: string;
  destination: string;
  /** The platform cannot store this name, so it can hold no value under it. */
  invalid?: boolean;
}

/**
 * The comparison, values in and statuses out. `varlatch` maps each stored
 * item to its value, or to null when this identity may not read it; an item
 * not in the map is not stored. `platform` is null when the platform's
 * values cannot be read back (GitHub Actions secrets are write-only). Values
 * are compared exactly, byte for byte: a value that differs only in
 * whitespace differs (whitespace in a credential matters).
 */
export function compareKeys(pairs: KeyPair[], varlatch: ReadonlyMap<string, string | null>, platform: ReadonlyMap<string, string> | null): CheckedKey[] {
  return pairs.map(({ name, destination, invalid }) => {
    const key = (status: CheckStatus, reason?: UnreadableReason): CheckedKey => ({ name, destination, status, ...(reason ? { reason } : {}) });
    if (invalid) return key("unreadable", "invalid-name");
    if (platform === null) return key("unreadable", "platform-write-only");
    const onPlatform = platform.has(destination);
    if (!varlatch.has(name)) return key(onPlatform ? "extra-on-platform" : "absent");
    if (!onPlatform) return key("missing-on-platform");
    const value = varlatch.get(name);
    if (value === null || value === undefined) return key("unreadable", "withheld");
    return key(platform.get(destination) === value ? "match" : "differs");
  });
}

const DRIFT: ReadonlySet<CheckStatus> = new Set(["differs", "missing-on-platform", "extra-on-platform"]);

/** Drift wins over an incomplete check, as `validate` puts invalid before incomplete. */
export function checkExitCode(keys: CheckedKey[]): number {
  if (keys.some((k) => DRIFT.has(k.status))) return SYNC_CHECK_EXIT.drift;
  if (keys.some((k) => k.status === "unreadable")) return SYNC_CHECK_EXIT.unchecked;
  return SYNC_CHECK_EXIT.match;
}

export class SyncCheckUsageError extends Error {
  override name = "SyncCheckUsageError";
}

export interface SyncCheckArgs {
  platform: string;
  base: string;
  repo?: string | undefined;
  ghEnvironment?: string | undefined;
  app?: string | undefined;
  tokenEnv: string;
  maps: string[];
  /** Without --map: skip these names (exact, or trailing-* prefix). */
  excludes: string[];
}

export interface SyncCheckResult {
  platform: string;
  base: string;
  destination: Record<string, string>;
  environment: string;
  /** Whose keys were compared: the active Contract's, the stored items (no readable Contract), or the --map list. */
  keySet: "contract" | "stored" | "map";
  keys: CheckedKey[];
  /** Why the platform could not be read at all; never a value or a response body. */
  unchecked?: string;
  notices: string[];
  exitCode: number;
}

interface CheckIO {
  env: NodeJS.ProcessEnv;
  fetchImpl?: typeof fetch;
}

/** The adapter, the canonical base, and the destination, from the command line; a wrong one is a usage error. */
function resolveTarget(input: SyncCheckArgs): { adapter: PlatformAdapter; base: string; destination: Record<string, string> } {
  let adapter: PlatformAdapter;
  try {
    adapter = getAdapter(input.platform);
  } catch {
    throw new SyncCheckUsageError(`unknown platform "${input.platform}" (github-actions, coolify, convex)`);
  }
  try {
    const base = adapter.canonicalizeBaseIdentity(input.base);
    const raw: Record<string, unknown> =
      adapter.platform === "github-actions"
        ? { repo: input.repo, ...(input.ghEnvironment ? { environment: input.ghEnvironment } : {}) }
        : adapter.platform === "coolify"
          ? { applicationUuid: input.app }
          : {};
    return { adapter, base, destination: adapter.canonicalizeDestination(raw).destination };
  } catch (err) {
    throw new SyncCheckUsageError(err instanceof AdapterError ? err.message : String(err));
  }
}

/** The active Contract's item names, or null when there is none this identity can read. */
async function contractNames(api: VarlatchClient, ctx: ResolvedContext, effective: EffectiveConfiguration, notices: string[]): Promise<string[] | null> {
  // A server that reports its manifest says whether a Contract is active.
  if (effective.manifest && !effective.manifest.contract) return null;
  try {
    const revision = await api.getActiveContract(ctx.organization, ctx.project);
    const contract = revision.contract as ConfigurationContract | undefined;
    return contract ? contract.items.map((i) => i.name).filter((n) => !RESERVED_ITEM_NAMES.includes(n)) : null;
  } catch (err) {
    if (!(err instanceof VarlatchApiError) || (err.status !== 404 && err.status !== 403)) throw err;
    if (err.status === 403) notices.push("cannot read the Contract (403): comparing the stored items, and extra-on-platform is not reported");
    return null;
  }
}

/** The keys to compare, by the rules of `sync push`: --map selects (and renames); otherwise every Contract item, less --exclude. */
function selectKeys(
  adapter: PlatformAdapter,
  input: SyncCheckArgs,
  stored: ReadonlySet<string>,
  contract: string[] | null,
): { pairs: KeyPair[]; keySet: SyncCheckResult["keySet"] } {
  const pairs: KeyPair[] = [];
  const pair = (name: string, dest: string) => {
    const destination = adapter.canonicalizeName(dest);
    pairs.push({ name, destination, ...(adapter.validateName(destination) ? { invalid: true } : {}) });
  };
  let keySet: SyncCheckResult["keySet"];
  if (input.maps.length > 0) {
    if (input.excludes.length > 0) throw new SyncCheckUsageError("--exclude only applies without --map (explicit maps already select)");
    const known = new Set([...stored, ...(contract ?? [])]);
    const unknown: string[] = [];
    for (const map of input.maps) {
      const [name, rename] = map.split("=", 2) as [string, string?];
      if (!CONFIG_ITEM_NAME_PATTERN.test(name) || rename === "") throw new SyncCheckUsageError(`--map expects NAME or NAME=DEST, got "${map}"`);
      // A misspelled name must not pass as "absent": the check would then say nothing drifted.
      if (!known.has(name)) unknown.push(name);
      else pair(name, rename ?? name);
    }
    if (unknown.length > 0) throw new SyncCheckUsageError(`--map must name items stored in this environment or in its Contract; not found: ${[...new Set(unknown)].sort().join(", ")}`);
    keySet = "map";
  } else {
    const excluded = (name: string) => input.excludes.some((e) => (e.endsWith("*") ? name.startsWith(e.slice(0, -1)) : name === e));
    const names = contract ?? [...stored].filter((n) => !RESERVED_ITEM_NAMES.includes(n));
    for (const name of [...new Set(names)].sort()) if (!excluded(name)) pair(name, name);
    keySet = contract ? "contract" : "stored";
  }
  const seen = new Map<string, string>();
  for (const p of pairs) {
    const other = seen.get(p.destination);
    if (other !== undefined && other !== p.name) throw new SyncCheckUsageError(`${other} and ${p.name} both map to the platform name ${p.destination}`);
    seen.set(p.destination, p.name);
  }
  return { pairs, keySet };
}

/**
 * Run the check. Varlatch-side failures (not signed in, denied, the server
 * unreachable) propagate to the CLI's own statuses (77, 69); a platform
 * that cannot be read is a result (`unchecked`, exit 2), never a crash, and
 * its message carries a status or an error class, never a response body.
 */
export async function runSyncCheck(api: VarlatchClient, ctx: ResolvedContext, input: SyncCheckArgs, io: CheckIO): Promise<SyncCheckResult> {
  const { adapter, base, destination } = resolveTarget(input);
  const notices: string[] = [];
  const result = (keySet: SyncCheckResult["keySet"], keys: CheckedKey[], unchecked?: string): SyncCheckResult => ({
    platform: adapter.platform,
    base,
    destination,
    environment: ctx.environment,
    keySet,
    keys,
    ...(unchecked !== undefined ? { unchecked } : {}),
    notices,
    exitCode: unchecked !== undefined ? SYNC_CHECK_EXIT.unchecked : checkExitCode(keys),
  });

  // Metadata and non-sensitive values only: no Secret is disclosed yet.
  const effective = await api.effectiveConfiguration(ctx.organization, ctx.project, ctx.environment, { includeValues: true });
  const items = new Map((effective.items ?? []).map((i) => [i.name, i]));
  const contract = await contractNames(api, ctx, effective, notices);
  const { pairs, keySet } = selectKeys(adapter, input, new Set(items.keys()), contract);
  if (keySet === "stored" && !notices.some((n) => n.startsWith("cannot read the Contract"))) {
    notices.push("no active Contract: comparing the stored items, and extra-on-platform is not reported");
  }

  // The platform first: when it cannot be read, nothing is disclosed.
  let platform: Map<string, string> | null = null;
  if (!adapter.supportsReadBack || !adapter.readValues) {
    notices.push(`${adapter.platform} values cannot be read back (write-only): no key can be compared`);
  } else {
    const credential = io.env[input.tokenEnv];
    if (!credential) return result(keySet, [], `no platform credential in $${input.tokenEnv} (choose the variable with --token-env)`);
    try {
      platform = await adapter.readValues({ baseIdentity: base, destination, credential, ...(io.fetchImpl ? { fetchImpl: io.fetchImpl } : {}) });
    } catch (err) {
      // An adapter's message holds a status or an error class only. Anything
      // else (a body that is not JSON, for one) may quote the response, so it
      // is never repeated.
      return result(keySet, [], err instanceof AdapterError ? err.message : `the platform's response could not be read (${err instanceof Error ? err.name : "error"})`);
    }
  }

  // What Varlatch holds for each compared key: a value, null when withheld from this identity.
  const varlatch = new Map<string, string | null>();
  const secrets: string[] = [];
  for (const { name, destination: dest } of pairs) {
    const item = items.get(name);
    if (!item) continue;
    if (!item.sensitive) {
      varlatch.set(name, typeof item.value === "string" ? item.value : null);
      continue;
    }
    varlatch.set(name, null);
    // Only a Secret the platform also holds needs its value: presence decides the rest.
    if (platform?.has(dest)) secrets.push(name);
  }
  if (secrets.length > 0) {
    try {
      const disclosed = await api.discloseSecrets(ctx.organization, ctx.project, ctx.environment, { items: [...new Set(secrets)] });
      for (const i of disclosed.items) if (varlatch.has(i.name)) varlatch.set(i.name, i.value);
    } catch (err) {
      if (!(err instanceof VarlatchApiError) || (err.code !== "PERMISSION_DENIED" && !err.code.startsWith("TAILNET_"))) throw err;
      notices.push(`secrets not disclosed (${err.code}): Secrets the platform holds cannot be compared`);
    }
  }
  return result(keySet, compareKeys(pairs, varlatch, platform));
}

const LABEL: Record<CheckStatus, string> = {
  match: "match",
  differs: "differs",
  "missing-on-platform": "missing on the platform",
  "extra-on-platform": "extra on the platform",
  unreadable: "not compared",
  absent: "absent (neither has it)",
};

const REASON: Record<UnreadableReason, string> = {
  "platform-write-only": "the platform's values are write-only",
  withheld: "this identity may not read its value in Varlatch",
  "invalid-name": "the platform cannot store this name",
};

/** The human form: one line per key, then the verdict. Names and statuses only. */
export function formatSyncCheck(r: SyncCheckResult): { stdout: string[]; stderr: string[] } {
  const where = [r.platform, r.base, ...Object.values(r.destination)].join(" ");
  const stderr = r.notices.map((n) => `varlatch: ${n}`);
  if (r.unchecked !== undefined) {
    stderr.push(`varlatch: could not check ${where} against ${r.environment}: ${r.unchecked}`);
    return { stdout: [], stderr };
  }
  const width = Math.max(0, ...r.keys.map((k) => LABEL[k.status].length));
  const stdout = [`${where} against ${r.environment}:`];
  for (const k of r.keys) {
    const name = k.destination === k.name ? k.name : `${k.name} -> ${k.destination}`;
    stdout.push(`  ${LABEL[k.status].padEnd(width)}  ${name}${k.reason ? ` (${REASON[k.reason]})` : ""}`);
  }
  const count = (s: CheckStatus) => r.keys.filter((k) => k.status === s).length;
  const tally = `${count("match")} match, ${count("differs")} differ, ${count("missing-on-platform")} missing on the platform, ${count("extra-on-platform")} extra on the platform, ${count("unreadable")} not compared`;
  stdout.push(r.exitCode === SYNC_CHECK_EXIT.match ? `in sync: ${tally}` : r.exitCode === SYNC_CHECK_EXIT.drift ? `DRIFT: ${tally}` : `INCOMPLETE: ${tally}`);
  return { stdout, stderr };
}

/** The machine form (`--json`): names, statuses, and counts; never a value. */
export function syncCheckDocument(r: SyncCheckResult): Record<string, unknown> {
  const counts = Object.fromEntries((Object.keys(LABEL) as CheckStatus[]).map((s) => [s, r.keys.filter((k) => k.status === s).length]));
  return {
    result: r.unchecked !== undefined ? "unchecked" : r.exitCode === SYNC_CHECK_EXIT.match ? "match" : r.exitCode === SYNC_CHECK_EXIT.drift ? "drift" : "incomplete",
    platform: r.platform,
    base: r.base,
    destination: r.destination,
    environment: r.environment,
    keySet: r.keySet,
    ...(r.unchecked !== undefined ? { unchecked: r.unchecked } : {}),
    counts,
    keys: r.keys,
    notices: r.notices,
    exitCode: r.exitCode,
  };
}
