// SPDX-License-Identifier: Apache-2.0
import { ITEM_TYPE_SINCE_SEMANTICS, type ItemType } from "@varlatch/contract";

/**
 * The semantics version a push will get (ADR-0038 Decision 3): the pinned
 * one, else the active revision's, else the server's newest for a first
 * revision. Every item type must exist at that version (ADR-0042); this
 * says why a push would be refused, before anything is sent.
 */
export interface PushVersionFacts {
  /** `--semantics`, or a `semanticsVersion` in a `--file` Contract. */
  pinned?: number | undefined;
  /** The active revision's version, or null when the project has none yet. */
  activeVersion: number | null;
  /** The versions the server evaluates (`/v1/meta`). */
  serverVersions: readonly number[];
}

interface ItemLike {
  name: string;
  type: string;
}

/** The newest version any item's type needs, and the items that need it. */
export function versionNeeded(items: readonly ItemLike[]): { version: number; items: string[] } {
  let version = 1;
  for (const item of items) version = Math.max(version, ITEM_TYPE_SINCE_SEMANTICS[item.type as ItemType] ?? 1);
  const names = items.filter((i) => (ITEM_TYPE_SINCE_SEMANTICS[i.type as ItemType] ?? 1) > 1).map((i) => `${i.name} (${i.type})`);
  return { version, items: names };
}

/** Why the push would be refused, or null when every type exists at the version it will get. */
export function pushVersionProblem(items: readonly ItemLike[], facts: PushVersionFacts): string | null {
  const needed = versionNeeded(items);
  if (needed.version === 1) return null;
  const newest = Math.max(...facts.serverVersions);
  if (newest < needed.version) {
    return `${needed.items.join(", ")} needs Contract Semantics version ${needed.version}, which this server does not evaluate (it supports ${facts.serverVersions.join(", ")}); upgrade it to Varlatch 0.13.0 or later`;
  }
  const version = facts.pinned ?? facts.activeVersion ?? newest;
  if (version >= needed.version) return null;
  const why =
    facts.pinned !== undefined ? "the version this push pins" : "the active revision's version, which a push keeps";
  return `${needed.items.join(", ")} needs Contract Semantics version ${needed.version}, but this revision would get version ${version} (${why}). Push with --semantics latest to move the Contract to the newest rules, then activate the revision; or move it on the dashboard's Contract page first`;
}
