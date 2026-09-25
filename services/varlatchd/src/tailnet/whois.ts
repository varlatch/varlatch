// SPDX-License-Identifier: AGPL-3.0-or-later
import http from "node:http";
import type { TailnetContext } from "../authz/evaluate.js";

/**
 * Tailscale LocalAPI WhoIs client (ADR-0014). WhoIs is a pure netmap lookup —
 * it does not know how a packet arrived — so this module must only ever be
 * called with the true socket peer address of a connection accepted on the
 * dedicated tailnet listener. The expected tailnet is pinned; peers resolving
 * to any other tailnet yield no Tailnet Context (fail closed upstream).
 */

export interface WhoisConfig {
  /** Path to the tailscaled LocalAPI unix socket (sidecar mount). */
  socketPath: string;
  /** The pinned expected tailnet, e.g. "example.ts.net". */
  expectedTailnet: string;
}

interface WhoisResponse {
  Node?: {
    ID?: number;
    StableID?: string;
    Name?: string;
    Tags?: string[];
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
 * Resolve the peer address to verified Tailnet Context, or null when the
 * peer is unknown, the LocalAPI is unavailable, or the tailnet does not match
 * the pinned expectation. Callers treat null as "no Tailnet Context" — every
 * tailnet-constrained operation then fails closed (ADR-0014 §5).
 */
export async function whois(
  config: WhoisConfig,
  remoteAddr: string,
  remotePort: number,
): Promise<TailnetContext | null> {
  try {
    const addr = encodeURIComponent(`${remoteAddr}:${remotePort}`);
    const res = await localApiGet(config.socketPath, `/localapi/v0/whois?addr=${addr}`);
    if (res.status !== 200) return null;
    const parsed = JSON.parse(res.body) as WhoisResponse;
    const node = parsed.Node;
    if (!node?.StableID || !node.Name) return null;
    // Node names are MagicDNS FQDNs: <host>.<tailnet>. Pin the tailnet;
    // shared-in peers from other tailnets never qualify (ADR-0014 §6).
    const name = node.Name.replace(/\.$/, "");
    const tailnet = name.split(".").slice(1).join(".");
    if (tailnet !== config.expectedTailnet) return null;
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
    return context;
  } catch {
    return null;
  }
}
