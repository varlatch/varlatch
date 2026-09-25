// SPDX-License-Identifier: Apache-2.0
import { getAdapter, AdapterError, type SyncItem } from "@varlatch/sync";
import { VarlatchApiError, type VarlatchClient } from "@varlatch/sdk";
import type { ResolvedContext } from "@varlatch/context";

/**
 * `varlatch sync push` (ADR-0031 §8): the client-side secondary mode for
 * Installations whose varlatchd has no platform egress. The server still
 * renders everything (inheritance, rotation primaries, reference
 * expansion) and audits the disclosure; this command only carries the
 * result to the platform through the same closed adapter allowlist. It is
 * write-only: it never deletes destination names — server-side Sync
 * Targets own convergence and removal semantics.
 */

export interface SyncPushArgs {
  platform: string;
  base: string;
  repo?: string | undefined;
  ghEnvironment?: string | undefined;
  app?: string | undefined;
  /** Coolify: mark managed keys available at build time ("true" | "false"). */
  buildTime?: string | undefined;
  tokenEnv: string;
  maps: string[];
  /** Without --map: skip these names (exact, or trailing-* prefix). */
  excludes: string[];
}

export async function runSyncPush(
  api: VarlatchClient,
  ctx: ResolvedContext,
  input: SyncPushArgs,
): Promise<number> {
  let adapter;
  try {
    adapter = getAdapter(input.platform);
  } catch {
    console.error(`varlatch: unknown platform "${input.platform}" (github-actions, coolify, convex)`);
    return 1;
  }

  const credential = process.env[input.tokenEnv];
  if (!credential) {
    console.error(
      `varlatch: no platform credential in $${input.tokenEnv} (choose the variable with --token-env)`,
    );
    return 1;
  }

  let baseIdentity: string;
  let destination: Record<string, string>;
  try {
    baseIdentity = adapter.canonicalizeBaseIdentity(input.base);
    let raw: Record<string, unknown>;
    switch (adapter.platform) {
      case "github-actions":
        raw = { repo: input.repo, ...(input.ghEnvironment ? { environment: input.ghEnvironment } : {}) };
        break;
      case "coolify":
        raw = { applicationUuid: input.app, ...(input.buildTime ? { buildTime: input.buildTime } : {}) };
        break;
      case "convex":
        // The deployment URL (--base) is the destination.
        raw = {};
        break;
    }
    destination = adapter.canonicalizeDestination(raw).destination;
  } catch (err) {
    console.error(`varlatch: ${err instanceof AdapterError ? err.message : String(err)}`);
    return 1;
  }

  // Server-rendered values: the server audits these disclosures (ADR-0016).
  const effective = await api.effectiveConfiguration(
    ctx.organization,
    ctx.project,
    ctx.environment,
    { includeValues: true },
  );
  try {
    const disclosed = await api.discloseSecrets(ctx.organization, ctx.project, ctx.environment, {
      scope: "all-authorized-secrets",
    });
    const byName = new Map(disclosed.items.map((i) => [i.name, i.value]));
    for (const item of effective.items ?? []) {
      const value = byName.get(item.name);
      if (item.sensitive && value !== undefined) item.value = value;
    }
  } catch (err) {
    if (
      err instanceof VarlatchApiError &&
      (err.code === "PERMISSION_DENIED" || err.code.startsWith("TAILNET_"))
    ) {
      console.error(
        `varlatch: secrets not disclosed (${err.code}); pushing non-sensitive values only`,
      );
    } else {
      throw err;
    }
  }

  const readable = new Map(
    (effective.items ?? [])
      .filter((i) => i.value !== null && i.value !== undefined)
      .map((i) => [i.name, i.value as string]),
  );

  // --map NAME[=DEST] selects (and renames); without it, push everything readable.
  const selected: SyncItem[] = [];
  const problems: string[] = [];
  const addItem = (name: string, dest: string) => {
    const value = readable.get(name);
    if (value === undefined) {
      problems.push(`${name}: not readable in this environment`);
      return;
    }
    const destName = adapter.canonicalizeName(dest);
    const invalid = adapter.validateName(destName);
    if (invalid) {
      problems.push(`${name}: ${invalid}`);
      return;
    }
    selected.push({ name: destName, value });
  };
  if (input.maps.length > 0) {
    if (input.excludes.length > 0) {
      console.error("varlatch: --exclude only applies without --map (explicit maps already select)");
      return 1;
    }
    for (const map of input.maps) {
      const [name, rename] = map.split("=", 2) as [string, string?];
      addItem(name, rename ?? name);
    }
  } else {
    const excluded = (name: string) =>
      input.excludes.some((e) => (e.endsWith("*") ? name.startsWith(e.slice(0, -1)) : name === e));
    for (const name of readable.keys()) {
      if (!excluded(name)) addItem(name, name);
    }
  }
  for (const problem of problems) console.error(`varlatch: skipped ${problem}`);
  if (selected.length === 0) {
    console.error("varlatch: nothing to push");
    return 1;
  }

  const outcomes = await adapter.writeValues(
    { baseIdentity, destination, credential },
    selected,
  );
  let failed = 0;
  for (const outcome of outcomes) {
    if (outcome.ok) console.log(`pushed ${outcome.name}`);
    else {
      failed += 1;
      console.error(`varlatch: failed ${outcome.name}: ${outcome.error ?? "error"}`);
    }
  }
  console.log(
    `${outcomes.length - failed}/${outcomes.length} value(s) pushed to ${adapter.platform} (${baseIdentity})`,
  );
  return failed > 0 ? 1 : problems.length > 0 ? 1 : 0;
}
