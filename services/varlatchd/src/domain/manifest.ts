// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { canonicalJson, semanticsVersionOf, type Tier } from "@varlatch/contract";
import { rootIdOf } from "./environments.js";
import type { CapturedState } from "./retrieval.js";

/**
 * The state manifest (ADR-0038 Decision 6): what a retrieval's snapshot
 * captured, independent of the caller. It holds identifiers and names only,
 * never plaintext and nothing derived from plaintext. It carries no
 * reference graph: references are inside the ciphertext, and the immutable
 * versions listed already determine every reference and what it resolves to.
 */
export interface StateManifest {
  manifestVersion: 1;
  projectId: string;
  environment: {
    id: string;
    rootId: string;
    parentId: string | null;
    tier: Tier;
    expiresAt: string | null;
  };
  contract: { revisionId: string; contentHash: string; semanticsVersion: number } | null;
  /** Every resolved item, by name. A retiring version appears only while its window is open at the snapshot's "now". */
  items: {
    name: string;
    source: "self" | "parent";
    valueRowId: string;
    versionId: string;
    retiringVersionId?: string;
  }[];
}

/** What this caller was not given, and which references stayed literal for it. */
export interface CallerView {
  withheld: {
    name: string;
    reason: "permission" | "requirement";
    requires: "config.value.read" | "secret.reveal";
  }[];
  /** Delivered items whose value kept a reference literal, with the names referenced. */
  unexpanded: { name: string; references: string[] }[];
}

export function stateManifest(state: CapturedState): StateManifest {
  const { project, env, revision, contract } = state;
  return {
    manifestVersion: 1,
    projectId: project.id,
    environment: {
      id: env.id,
      rootId: rootIdOf(env),
      parentId: env.parent_environment_id ?? null,
      tier: env.tier,
      expiresAt: env.expires_at ? new Date(env.expires_at).toISOString() : null,
    },
    contract:
      revision && contract
        ? { revisionId: revision.id, contentHash: revision.content_hash, semanticsVersion: semanticsVersionOf(contract) }
        : null,
    items: state.items.map((i) => ({
      name: i.name,
      source: i.source,
      valueRowId: i.valueRowId,
      versionId: i.versionId,
      ...(i.retiringVersionId ? { retiringVersionId: i.retiringVersionId } : {}),
    })),
  };
}

/** SHA-256 over the manifest's canonical encoding: a digest of identifiers, never of values. */
export function stateDigest(manifest: StateManifest): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(canonicalJson(manifest), "utf8").digest("hex")}`;
}

/** What a changed digest can be attributed to, without naming identifiers. */
export const STATE_CATEGORIES = ["environment", "contract", "items", "rotation"] as const;
export type StateCategory = (typeof STATE_CATEGORIES)[number];

const sha256 = (value: unknown): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;

/**
 * One digest per category of the manifest, so a precondition mismatch can
 * say which category changed: the Environment context, the Contract, item
 * sources and versions, or rotation windows. Identifiers only, like the
 * manifest itself.
 */
export function categoryDigests(manifest: StateManifest): Record<StateCategory, `sha256:${string}`> {
  return {
    environment: sha256({ projectId: manifest.projectId, environment: manifest.environment }),
    contract: sha256(manifest.contract),
    items: sha256(
      manifest.items.map((i) => ({ name: i.name, source: i.source, valueRowId: i.valueRowId, versionId: i.versionId })),
    ),
    rotation: sha256(
      manifest.items.flatMap((i) => (i.retiringVersionId ? [{ name: i.name, retiringVersionId: i.retiringVersionId }] : [])),
    ),
  };
}

/** The manifest and its digest, as responses carry them. */
export function manifestOf(state: CapturedState): { manifest: StateManifest; stateDigest: `sha256:${string}` } {
  const manifest = stateManifest(state);
  return { manifest, stateDigest: stateDigest(manifest) };
}
