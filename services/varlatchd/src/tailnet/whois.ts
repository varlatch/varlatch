// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";
import type { TailnetContext } from "../authz/evaluate.js";

/**
 * Tailscale LocalAPI WhoIs client (ADR-0014). WhoIs is a pure netmap lookup —
 * it does not know how a packet arrived — so this module must only ever be
 * called with the true socket peer address of a connection accepted on the
 * dedicated tailnet listener. The expected tailnet is pinned; peers resolving
 * to any other tailnet yield no Tailnet Context (fail closed upstream).
 *
 * In the userspace sidecar that peer is 127.0.0.1:<ephemeral>, which
 * tailscaled maps back to the device; WhoIs needs the port for that, and the
 * mapping ends with the connection (ADR-0046 spike S1).
 */

export interface WhoisConfig {
  /** Path to the tailscaled LocalAPI unix socket (sidecar mount). */
  socketPath: string;
  /** The pinned expected tailnet, e.g. "example.ts.net". */
  expectedTailnet: string;
}

/**
 * Why a peer has no Tailnet Context (ADR-0046 Decision 7). Every reason
 * fails closed; the reason is for audit and diagnosis, never for policy.
 */
export type WhoisRefusal =
  /** The LocalAPI could not be asked: socket missing, timeout, error, unparseable answer. */
  | "resolver-unavailable"
  /** No device known for that address and port. */
  | "unrecognized"
  /** A device of another tailnet (the tailnet pin, ADR-0014 §6). */
  | "other-tailnet"
  /** A device shared into this tailnet from elsewhere: refused whatever its name. */
  | "shared"
  /** The Varlatch node itself: no forwarding hop may inherit the server's identity. */
  | "self";

export type WhoisResult = { ok: true; context: TailnetContext } | { ok: false; reason: WhoisRefusal };

interface WhoisResponse {
  Node?: {
    ID?: number;
    StableID?: string;
    Name?: string;
    Tags?: string[];
    /** Non-zero when the node was shared into this tailnet (tailcfg.Node.Sharer). */
    Sharer?: number;
  };
  UserProfile?: {
    LoginName?: string;
  };
}

function localApiGet(socketPath: string, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path,
        method: "GET",
        // LocalAPI requires this literal host; no DNS lookup happens.
        headers: { Host: "local-tailscaled.sock" },
        timeout: 3000,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk: Buffer) => (body += chunk.toString("utf8")));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body }));
      },
    );
    req.on("timeout", () => req.destroy(new Error("LocalAPI timeout")));
    req.on("error", reject);
    req.end();
  });
}

/**
 * The Varlatch node's own StableID, from LocalAPI status. Stable for the
 * node's state, so a known answer is kept; an unknown one is asked again.
 */
export function selfNodeResolver(socketPath: string): () => Promise<string | null> {
  let known: string | null = null;
  return async () => {
    if (known) return known;
    try {
      const res = await localApiGet(socketPath, "/localapi/v0/status");
      if (res.status !== 200) return null;
      const id = (JSON.parse(res.body) as { Self?: { ID?: string } }).Self?.ID;
      if (typeof id === "string" && id) known = id;
      return known;
    } catch {
      return null;
    }
  };
}

const hostPort = (addr: string, port: number) => (addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`);

/**
 * Resolve the true socket peer to verified Tailnet Context, or say why not.
 * `selfNodeId` returns the Varlatch node's own StableID; when it cannot be
 * learned the peer is refused as resolver-unavailable, since the self check
 * could not be made.
 */
export async function resolveWhois(
  config: WhoisConfig & { selfNodeId: () => Promise<string | null> },
  remoteAddr: string,
  remotePort: number,
): Promise<WhoisResult> {
  let parsed: WhoisResponse;
  try {
    const res = await localApiGet(config.socketPath, `/localapi/v0/whois?addr=${encodeURIComponent(hostPort(remoteAddr, remotePort))}`);
    if (res.status === 404) return { ok: false, reason: "unrecognized" };
    if (res.status !== 200) return { ok: false, reason: "resolver-unavailable" };
    parsed = JSON.parse(res.body) as WhoisResponse;
  } catch {
    return { ok: false, reason: "resolver-unavailable" };
  }
  const node = parsed.Node;
  if (!node?.StableID || !node.Name) return { ok: false, reason: "unrecognized" };
  // A shared-in device is refused before its name is looked at, so the
  // tailnet pin is not the only defense against a foreign device whose
  // tags or user happen to match a selector.
  if (node.Sharer) return { ok: false, reason: "shared" };
  // Node names are MagicDNS FQDNs: <host>.<tailnet>. Pin the tailnet;
  // peers from other tailnets never qualify (ADR-0014 §6).
  const name = node.Name.replace(/\.$/, "");
  const tailnet = name.split(".").slice(1).join(".");
  if (tailnet !== config.expectedTailnet) return { ok: false, reason: "other-tailnet" };
  const self = await config.selfNodeId();
  if (!self) return { ok: false, reason: "resolver-unavailable" };
  if (node.StableID === self) return { ok: false, reason: "self" };
  const context: TailnetContext = {
    tailnet,
    nodeId: node.StableID,
    tags: node.Tags ?? [],
  };
  // Tagged nodes' identity is the tag set; the synthetic user profile is
  // not a human identity. Only surface userLogin for untagged nodes.
  if ((node.Tags ?? []).length === 0 && parsed.UserProfile?.LoginName) {
    context.userLogin = parsed.UserProfile.LoginName;
  }
  return { ok: true, context };
}

/**
 * Resolve the peer address to verified Tailnet Context, or null when there
 * is none, for any of resolveWhois's reasons. Callers treat null as "no
 * Tailnet Context": every tailnet-constrained operation then fails closed
 * (ADR-0014 §5).
 */
export async function whois(
  config: WhoisConfig & { selfNodeId: () => Promise<string | null> },
  remoteAddr: string,
  remotePort: number,
): Promise<TailnetContext | null> {
  const result = await resolveWhois(config, remoteAddr, remotePort);
  return result.ok ? result.context : null;
}
