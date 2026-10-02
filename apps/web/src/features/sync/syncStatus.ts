// SPDX-License-Identifier: AGPL-3.0-or-later
import { targetLabel as statusTargetLabel } from "./status";
import type { PlatformConnection, SyncLedgerName, SyncTarget } from "@varlatch/protocol";


/**
 * Per-item sync evidence shared by the integrations page, the values grid
 * and the item panel: which targets carry an item and what their ledger says
 * about it. The operator completes a rotation on evidence, not hope.
 */

/** The destination name an item is written under on this target. */
export function destinationName(target: SyncTarget, itemName: string): string {
  return target.mapping.kind === "explicit"
    ? (target.mapping.items.find((i) => i.name === itemName)?.rename ?? itemName)
    : itemName;
}

export function syncTargetItemStatus(
  target: SyncTarget,
  names: { name: string; state: string }[] | undefined,
  itemName: string,
): "synced" | "pending" | "failed" {
  const entry = ledgerEntry(names, destinationName(target, itemName));
  if (entry?.state.startsWith("failed")) return "failed";
  if (entry?.state === "written" && !target.needsSync) return "synced";
  return "pending";
}

export function ledgerEntry<T extends { name: string }>(names: T[] | undefined, destName: string): T | undefined {
  return names?.find((n) => n.name.toLowerCase() === destName.toLowerCase());
}

/** The ledger row for an item on a target, if the target has written or tried it. */
export function itemLedgerEntry(
  target: SyncTarget,
  names: SyncLedgerName[] | undefined,
  itemName: string,
): SyncLedgerName | undefined {
  return ledgerEntry(names, destinationName(target, itemName));
}

/** Whether the target's mapping carries this item (wildcards include future items). */
export function targetCoversItem(target: SyncTarget, itemName: string): boolean {
  if (target.mapping.kind === "explicit") return target.mapping.items.some((i) => i.name === itemName);
  const exclude = (target.mapping as { exclude?: string[] }).exclude ?? [];
  return !exclude.some((p) => (p.endsWith("*") ? itemName.startsWith(p.slice(0, -1)) : p === itemName));
}

/** One canonical label per target, the same everywhere it is named. */
export function targetLabel(t: SyncTarget, connections: PlatformConnection[] | undefined): string {
  return statusTargetLabel(t, connections?.find((c) => c.id === t.connectionId));
}

export function targetPlatform(t: SyncTarget, connections: PlatformConnection[] | undefined): string {
  return connections?.find((c) => c.id === t.connectionId)?.platform ?? "";
}
