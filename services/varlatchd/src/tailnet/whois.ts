// SPDX-License-Identifier: AGPL-3.0-or-later
import type { TailnetContext } from "../authz/evaluate.js";
import { localApiGet } from "./localapi.js";

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
  /**
   * The LocalAPI could not be asked or its answer not trusted: socket
   * missing, timeout, error, or an answer that is not the expected shape
   * (JSON null, a missing node, a field of the wrong type).
   */
  | "resolver-unavailable"
  /** No device known for that address and port (404). */
  | "unrecognized"
  /** A device of another tailnet (the tailnet pin, ADR-0014 §6). */
  | "other-tailnet"
  /** A device shared into this tailnet from elsewhere: refused whatever its name. */
  | "shared"
  /** The Varlatch node itself: no forwarding hop may inherit the server's identity. */
  | "self";

export type WhoisResult = { ok: true; context: TailnetContext } | { ok: false; reason: WhoisRefusal };

/** A WhoIs answer that passed the decoder: every field the right type. */
interface WhoisNode {
  stableId: string;
  name: string;
  tags: string[];
  /** tailcfg.Node.Sharer: non-zero when the node was shared into this tailnet. */
  sharer: number;
  loginName: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * Decode a WhoIs answer, or null when it is not the expected shape. Nothing
 * outside this guard touches the parsed body, so a malformed answer can
 * only ever become resolver-unavailable.
 */
function decodeWhois(body: string): WhoisNode | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isObject(parsed) || !isObject(parsed.Node)) return null;
  const node = parsed.Node;
  if (!nonEmptyString(node.StableID) || !nonEmptyString(node.Name)) return null;
  const tags = node.Tags ?? [];
  if (!Array.isArray(tags) || !tags.every((t) => typeof t === "string")) return null;
  const sharer = node.Sharer ?? 0;
  if (typeof sharer !== "number") return null;
  const profile = parsed.UserProfile ?? null;
  if (profile !== null && !isObject(profile)) return null;
  const loginName = profile?.LoginName ?? null;
  if (loginName !== null && typeof loginName !== "string") return null;
  return { stableId: node.StableID, name: node.Name, tags: tags as string[], sharer, loginName };
}

/**
 * The Varlatch node's own StableID, read from LocalAPI status (without the
 * peer list), so a node that re-registers under a new identity is
 * recognized at once; null when status cannot be read or is not the
 * expected shape, which callers treat as "refuse everyone". An identity
 * change is logged once.
 *
 * Every caller gets a read that started after it arrived, never an older
 * one. Concurrent callers share reads: while one is in flight, everyone who
 * arrives waits for the next, which starts when it ends. So at most one
 * status call is in flight however many requests there are (the LocalAPI
 * has a throughput ceiling, ADR-0046 spike S4).
 */
export function selfNodeResolver(socketPath: string): () => Promise<string | null> {
  let last: string | null = null;
  let current: Promise<string | null> | null = null;
  let next: Promise<string | null> | null = null;

  const read = async (): Promise<string | null> => {
    let id: string | null = null;
    try {
      const res = await localApiGet(socketPath, "/localapi/v0/status?peers=false");
      if (res.status === 200) {
        const parsed: unknown = JSON.parse(res.body);
        const self = isObject(parsed) ? parsed.Self : undefined;
        if (isObject(self) && nonEmptyString(self.ID)) id = self.ID;
      }
    } catch {
      id = null;
    }
    if (id && last && id !== last) console.warn(`varlatchd: this node's tailnet identity changed (${last} to ${id}); checking peers against the new one`);
    if (id) last = id;
    return id;
  };
  const start = (): Promise<string | null> => {
    const p = read().finally(() => {
      if (current === p) current = null;
    });
    current = p;
    return p;
  };

  return () => {
    // A queued read starts after whatever is in flight, so after this caller
    // arrived: share it. Checked first, because the read in flight clears
    // `current` just before the queued one starts; a caller in that gap would
    // otherwise start a second read alongside it.
    if (next) return next;
    if (!current) return start();
    // The read in flight may predate this caller: queue the one after it.
    next = current.then(
      () => undefined,
      () => undefined,
    ).then(() => {
      next = null;
      return start();
    });
    return next;
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
  let node: WhoisNode | null;
  try {
    const res = await localApiGet(config.socketPath, `/localapi/v0/whois?addr=${encodeURIComponent(hostPort(remoteAddr, remotePort))}`);
    if (res.status === 404) return { ok: false, reason: "unrecognized" };
    if (res.status !== 200) return { ok: false, reason: "resolver-unavailable" };
    node = decodeWhois(res.body);
  } catch {
    return { ok: false, reason: "resolver-unavailable" };
  }
  if (!node) return { ok: false, reason: "resolver-unavailable" };
  // A shared-in device is refused before its name is looked at, so the
  // tailnet pin is not the only defense against a foreign device whose
  // tags or user happen to match a selector.
  if (node.sharer !== 0) return { ok: false, reason: "shared" };
  // Node names are MagicDNS FQDNs: <host>.<tailnet>. Pin the tailnet;
  // peers from other tailnets never qualify (ADR-0014 §6).
  const name = node.name.replace(/\.$/, "");
  const tailnet = name.split(".").slice(1).join(".");
  if (tailnet !== config.expectedTailnet) return { ok: false, reason: "other-tailnet" };
  // The node's own identity, as of now: unknown means refuse.
  let self: string | null;
  try {
    self = await config.selfNodeId();
  } catch {
    self = null;
  }
  if (!self) return { ok: false, reason: "resolver-unavailable" };
  if (node.stableId === self) return { ok: false, reason: "self" };
  const context: TailnetContext = {
    tailnet,
    nodeId: node.stableId,
    nodeName: name.split(".")[0]!,
    tags: node.tags,
  };
  // Tagged nodes' identity is the tag set; the synthetic user profile is
  // not a human identity. Only surface userLogin for untagged nodes.
  if (node.tags.length === 0 && node.loginName) {
    context.userLogin = node.loginName;
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
