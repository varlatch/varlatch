// SPDX-License-Identifier: AGPL-3.0-or-later
import type { TailnetConnection } from "../../lib/tailnetConnection";
import { unrecognizedReason } from "../../lib/tailnetConnection";

/**
 * "This device" and the tailnet suggestion in the requirement editor
 * (internal docs/design/tailnet-dashboard-followups.md, part 2).
 *
 * "This device" adds the node ID Varlatch verified for this browser's
 * connection, and nothing else: no tag, no user. It counts only a Connect
 * answer newer than the click, so a result from before (or from another
 * identity or endpoint, which the connection drops) is never used. A device
 * on another tailnet than the requirement's is not added: changing the
 * tailnet is a separate change, reviewed as one.
 */

const STABLE_ID = /^[A-Za-z0-9]{1,64}$/;

export type DeviceOutcome =
  /** No current answer yet: the check is running, or only an older answer is there. */
  | { kind: "waiting" }
  | { kind: "add"; nodeId: string; nodeName: string | null }
  | { kind: "other-tailnet"; nodeId: string; nodeName: string | null; deviceTailnet: string }
  | { kind: "failed"; message: string };

/** What a "This device" request asked at `requestedAt` gets from the connection as it is now. */
export function deviceOutcome(connection: TailnetConnection, requestedAt: number, tailnet: string): DeviceOutcome {
  switch (connection.status) {
    case "unavailable":
      return { kind: "failed", message: "This installation serves no tailnet browser endpoint, so this browser cannot be checked." };
    case "idle":
    case "connecting":
      return { kind: "waiting" };
    case "unreachable":
      if (connection.checkedAt < requestedAt) return { kind: "waiting" };
      return {
        kind: "failed",
        message: connection.blockedByPolicy
          ? "The dashboard's security policy stopped the request to the tailnet endpoint. Nothing was added."
          : "The tailnet endpoint did not answer from this browser. Nothing was added.",
      };
    case "unrecognized":
      if (connection.checkedAt < requestedAt) return { kind: "waiting" };
      return { kind: "failed", message: `Varlatch did not recognize this device: ${unrecognizedReason(connection.reason)}. Nothing was added.` };
    case "connected": {
      if (connection.checkedAt < requestedAt) return { kind: "waiting" };
      const { device } = connection;
      const nodeId = typeof device.nodeId === "string" && STABLE_ID.test(device.nodeId) ? device.nodeId : null;
      if (!device.recognized || !nodeId || typeof device.tailnet !== "string" || !device.tailnet) {
        return { kind: "failed", message: "Varlatch did not report a usable node ID for this device. Nothing was added." };
      }
      const nodeName = typeof device.nodeName === "string" && device.nodeName ? device.nodeName : null;
      // Exactly as the evaluator compares the tailnet.
      if (device.tailnet !== tailnet) return { kind: "other-tailnet", nodeId, nodeName, deviceTailnet: device.tailnet };
      return { kind: "add", nodeId, nodeName };
    }
  }
}

export type TailnetSuggestion = { tailnet: string; source: "device" | "endpoint" };

/**
 * A tailnet to suggest for a new requirement: the verified device's, else
 * the one in the browser endpoint's host (configured, not verified). Never
 * more than a suggestion.
 */
export function tailnetSuggestion(connection: TailnetConnection): TailnetSuggestion | null {
  if (connection.status === "unavailable") return null;
  if (connection.status === "connected" && connection.device.recognized && typeof connection.device.tailnet === "string" && connection.device.tailnet) {
    return { tailnet: connection.device.tailnet, source: "device" };
  }
  try {
    const host = new URL(connection.endpoint).hostname;
    const dot = host.indexOf(".");
    if (dot > 0 && dot < host.length - 1) return { tailnet: host.slice(dot + 1), source: "endpoint" };
  } catch {
    // not a URL: no suggestion
  }
  return null;
}
