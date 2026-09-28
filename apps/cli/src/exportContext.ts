// SPDX-License-Identifier: Apache-2.0
import { RESERVED_ITEM_NAMES, type ConfigurationContract } from "@varlatch/contract";
import type { ContractRevision, EffectiveConfiguration, StateManifest } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";
import { RUN_CONTEXT_MAX_BYTES, encodeRunContext, type Delivery, type RunContext, type ServerStatus } from "./strictRun.js";

/**
 * `varlatch run --export-context`: a default run that also gives the command
 * `VARLATCH_RUN_CONTEXT`, with `mode: "exported"`, so the Typed Accessor can
 * enforce per-Environment requiredness and tell withheld items from absent
 * ones. The run itself is unchanged: the same values, the same precedence,
 * no defaults. Only the context is added, and it holds names and identifiers,
 * never values. Its one new failure: the run refuses to start when its two
 * requests keep describing different states (`readConsistently`).
 */

export class ExportContextError extends Error {
  override name = "ExportContextError";
}

export interface ExportContextClient {
  getContractRevision(org: string, project: string, revisionId: string): Promise<ContractRevision>;
}

type ManifestContract = NonNullable<StateManifest["contract"]>;

/** How many times an exported run reads its configuration and Secrets before it refuses. */
export const EXPORT_CONTEXT_ATTEMPTS = 3;

/** One read of a default run: the Effective Configuration, then the disclosure. */
export interface ConfigurationRead<T> {
  /** The Effective Configuration's `stateDigest`. */
  configurationDigest: string | undefined;
  /**
   * The disclosure's `stateDigest`, or `null` when nothing was disclosed
   * (the disclosure was refused), so every value delivered came from the
   * Effective Configuration.
   */
  disclosureDigest: string | null | undefined;
  result: T;
}

/**
 * A default run reads its values in two requests, the Effective
 * Configuration and then the disclosure, and each is served from its own
 * database snapshot. The exported context is built from the first and the
 * Secrets come from the second, so a write, rotation, deletion, or Contract
 * activation that commits in between could make the context misdescribe the
 * run. Both responses carry the digest of their state manifest, which is the
 * same for every caller and every endpoint looking at the same state: equal
 * digests mean both requests saw the same Environment, Contract Revision, and
 * item versions. When they differ, both requests are made again, up to
 * `attempts` reads in all. Each read discloses, and is audited, again. When
 * no read agrees, the run refuses before its command starts.
 *
 * The digest does not cover authorization, and need not: each item's server
 * status is taken from the response that delivered or withheld it. A
 * disclosure without a digest (its caller lost `config.metadata.read` after
 * the first request) is not taken as agreement.
 */
export async function readConsistently<T>(
  read: () => Promise<ConfigurationRead<T>>,
  notice: (line: string) => void,
  attempts = EXPORT_CONTEXT_ATTEMPTS,
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    const { configurationDigest, disclosureDigest, result } = await read();
    if (disclosureDigest === null) return result;
    if (disclosureDigest !== undefined && disclosureDigest === configurationDigest) return result;
    if (attempt >= attempts) {
      throw new ExportContextError(
        `the configuration changed between reading it and disclosing its Secrets, on each of ${attempts} attempts, ` +
          "so the run context could not describe the values delivered",
      );
    }
    notice(
      `varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again ` +
        `(attempt ${attempt + 1} of ${attempts}, another audited disclosure)`,
    );
  }
}

/**
 * For each Contract item, what the server did and how a default run
 * delivered it: a delivered value overrides the parent's, anything else is
 * inherited when the parent sets it, and a default run never applies a
 * Contract default.
 */
export function exportedRunContext(
  revision: ManifestContract,
  environment: StateManifest["environment"],
  contract: Pick<ConfigurationContract, "items">,
  delivered: EffectiveConfiguration,
  parent: NodeJS.ProcessEnv,
): RunContext {
  const byName = new Map((delivered.items ?? []).map((i) => [i.name, i]));
  const items: RunContext["items"] = {};
  for (const item of contract.items) {
    if (RESERVED_ITEM_NAMES.includes(item.name)) continue;
    const got = byName.get(item.name);
    const server: ServerStatus = !got ? "notStored" : got.value === null || got.value === undefined ? "withheld" : "delivered";
    const delivery: Delivery = server === "delivered" ? "varlatch" : parent[item.name] !== undefined ? "inherited" : "absent";
    items[item.name] = { server, delivery };
  }
  return {
    v: 1,
    mode: "exported",
    contractRevisionId: revision.revisionId,
    contractHash: revision.contentHash,
    semanticsVersion: revision.semanticsVersion,
    environment: { rootId: environment.rootId, tier: environment.tier },
    items,
  };
}

/**
 * Runs after the Effective Configuration and before any Secret is
 * disclosed, so a run that cannot export its context discloses nothing. The
 * Contract is fetched by the revision ID the manifest names, so the context
 * describes exactly the revision that response was served against. Returns
 * the encoder the run calls once the environment is built.
 */
export async function prepareExportedContext(
  api: ExportContextClient,
  org: string,
  project: string,
  effective: EffectiveConfiguration,
): Promise<(delivered: EffectiveConfiguration, parent: NodeJS.ProcessEnv) => string> {
  const manifest = effective.manifest;
  if (!manifest || !effective.stateDigest) {
    throw new ExportContextError(
      "--export-context needs a server that returns a state manifest with the configuration: Varlatch 0.11.0 or later",
    );
  }
  const revision = manifest.contract;
  if (!revision) throw new ExportContextError("--export-context needs an active Contract");
  let fetched: ContractRevision;
  try {
    fetched = await api.getContractRevision(org, project, revision.revisionId);
  } catch (err) {
    if (err instanceof VarlatchApiError && (err.status === 403 || err.status === 404)) {
      throw new ExportContextError("--export-context needs contract.read on the project, to list the Contract's items");
    }
    throw err;
  }
  const contract = fetched.contract as unknown as ConfigurationContract | undefined;
  if (fetched.contentHash !== revision.contentHash || !contract || !Array.isArray(contract.items)) {
    throw new ExportContextError("--export-context could not read the Contract Revision the configuration names");
  }
  // The size depends on names only: check the longest form (every item not
  // stored and inherited) now, before anything is disclosed.
  const longest = Object.fromEntries(contract.items.map((i) => [i.name, ""]));
  if (encodeRunContext(exportedRunContext(revision, manifest.environment, contract, { environmentId: "", items: [] }, longest)) === null) {
    throw new ExportContextError(`the run context would exceed ${RUN_CONTEXT_MAX_BYTES} bytes; it is never truncated`);
  }
  return (delivered, parent) => {
    const encoded = encodeRunContext(exportedRunContext(revision, manifest.environment, contract, delivered, parent));
    if (encoded === null) {
      throw new ExportContextError(`the run context would exceed ${RUN_CONTEXT_MAX_BYTES} bytes; it is never truncated`);
    }
    return encoded;
  };
}
