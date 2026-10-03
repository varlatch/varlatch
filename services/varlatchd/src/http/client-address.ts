// SPDX-License-Identifier: AGPL-3.0-or-later
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import type { Context } from "hono";

/**
 * The client address behind trusted proxies. The per-peer limits (the
 * request window in app.ts, device sign-in's pending and wrong-code caps)
 * and the device sign-in confirmation need the caller's own address, but in
 * the supported deployments every request reaches varlatchd through the
 * dashboard's nginx, and often a TLS ingress in front of it (the bundled
 * Caddy, Tailscale serve, Coolify's Traefik).
 *
 * Each proxy appends the address it received the request from to
 * X-Forwarded-For (an ingress may replace the header with the client's
 * address instead). varlatchd believes the header only from the proxies
 * VARLATCH_TRUSTED_PROXIES names, and reads it from the right: the first
 * address that is not a trusted proxy is the client. Whatever a caller
 * writes into the header sits to the left of the address its first trusted
 * proxy appended, so it is never reached; a caller that is not a trusted
 * proxy has its header ignored entirely.
 */

/** Hops read from X-Forwarded-For at most. */
const MAX_HOPS = 20;

/** An address as Node reports it, without brackets, a zone, or the IPv4-mapped prefix; null when not an IP. */
export function normalizeAddress(raw: string): string | null {
  let value = raw.trim();
  // [v6]:port or [v6]
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) value = bracketed[1] as string;
  // v4:port
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) value = value.slice(0, value.lastIndexOf(":"));
  value = value.replace(/%.*$/, "").toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (mapped) value = mapped[1] as string;
  return isIP(value) ? value : null;
}

/**
 * The client of a request whose socket peer is `peer` and whose
 * X-Forwarded-For is `forwardedFor`, trusting the header only from proxies
 * `trusts` accepts: the rightmost address that is not a trusted proxy.
 */
export function clientAddressOf(peer: string, forwardedFor: string | undefined, trusts: (address: string) => boolean): string {
  let client = normalizeAddress(peer) ?? peer;
  if (!forwardedFor || !trusts(client)) return client;
  const hops = forwardedFor.split(",");
  for (let i = hops.length - 1, read = 0; i >= 0 && read < MAX_HOPS; i--, read++) {
    const hop = hops[i]?.trim();
    if (!hop) continue;
    const address = normalizeAddress(hop);
    // A malformed entry can only come from a misbehaving trusted proxy:
    // stop at the last address known good.
    if (address === null) return client;
    client = address;
    if (!trusts(address)) return address;
  }
  return client;
}

/** One VARLATCH_TRUSTED_PROXIES entry: an IP, a CIDR range, or a host name to resolve. */
type Entry = { kind: "address"; address: string } | { kind: "range"; address: string; prefix: number } | { kind: "name"; name: string };

const HOST_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export class TrustedProxyError extends Error {
  override name = "TrustedProxyError";
}

/** Parse VARLATCH_TRUSTED_PROXIES: comma-separated IPs, CIDR ranges, and host names. */
export function parseTrustedProxies(spec: string): Entry[] {
  const entries: Entry[] = [];
  for (const raw of spec.split(",").map((e) => e.trim()).filter(Boolean)) {
    const range = /^(.+)\/(\d{1,3})$/.exec(raw);
    if (range) {
      const address = normalizeAddress(range[1] as string);
      const prefix = Number(range[2]);
      if (!address || prefix > (isIP(address) === 4 ? 32 : 128)) throw new TrustedProxyError(`VARLATCH_TRUSTED_PROXIES: ${raw} is not a valid CIDR range`);
      entries.push({ kind: "range", address, prefix });
    } else if (normalizeAddress(raw)) {
      entries.push({ kind: "address", address: normalizeAddress(raw) as string });
    } else if (HOST_NAME.test(raw)) {
      entries.push({ kind: "name", name: raw.toLowerCase() });
    } else {
      throw new TrustedProxyError(`VARLATCH_TRUSTED_PROXIES: ${raw} is not an IP address, a CIDR range, or a host name`);
    }
  }
  return entries;
}

type Resolve = (name: string) => Promise<string[]>;

const resolveAll: Resolve = async (name) => (await lookup(name, { all: true })).map((a) => a.address);

/**
 * The trusted proxies, with host names (compose service names, such as
 * varlatch-web) resolved now and again every `refreshMs`, since a
 * container's address changes when it is recreated and may then belong to
 * another container. Trust from a name lasts only as long as its
 * resolution: a refresh that fails drops the name's addresses at once (a
 * proxy that no longer resolves is never trusted at an address it used to
 * have), and a resolution older than three refresh periods counts for
 * nothing even if refreshing stalls. Literal addresses and ranges are
 * trusted as configured.
 */
export class TrustedProxies {
  private readonly literal = new BlockList();
  private readonly names: string[] = [];
  private resolved = new Map<string, { addresses: string[]; at: number }>();
  private readonly failing = new Set<string>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private refreshing: Promise<void> | null = null;
  private maxAgeMs = 30_000;

  constructor(
    spec: string,
    private readonly resolve: Resolve = resolveAll,
    private readonly log: (message: string) => void = (m) => console.warn(m),
    private readonly now: () => number = Date.now,
  ) {
    for (const entry of parseTrustedProxies(spec)) {
      if (entry.kind === "name") this.names.push(entry.name);
      else if (entry.kind === "address") this.literal.addAddress(entry.address, isIP(entry.address) === 4 ? "ipv4" : "ipv6");
      else this.literal.addSubnet(entry.address, entry.prefix, isIP(entry.address) === 4 ? "ipv4" : "ipv6");
    }
  }

  /** Resolve the names once, then keep refreshing them in the background. */
  async start(refreshMs = 10_000): Promise<this> {
    this.maxAgeMs = 3 * refreshMs;
    await this.refresh();
    if (this.names.length > 0) {
      this.timer = setInterval(() => void this.refresh(), refreshMs);
      this.timer.unref();
    }
    return this;
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** Resolve every name again; one refresh at a time. */
  refresh(): Promise<void> {
    this.refreshing ??= this.refreshNames().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async refreshNames(): Promise<void> {
    for (const name of this.names) {
      const previous = this.resolved.get(name)?.addresses ?? [];
      try {
        const addresses = (await this.resolve(name)).map((a) => normalizeAddress(a)).filter((a): a is string => a !== null);
        if (JSON.stringify(addresses) !== JSON.stringify(previous) || this.failing.has(name)) {
          this.log(`varlatchd: trusted proxy ${name} is ${addresses.join(", ") || "(no address)"}`);
        }
        this.failing.delete(name);
        this.resolved.set(name, { addresses, at: this.now() });
      } catch (err) {
        this.resolved.delete(name);
        if (this.failing.has(name)) continue;
        this.failing.add(name);
        const why = (err as { code?: string }).code ?? (err instanceof Error ? err.message : String(err));
        this.log(
          previous.length > 0
            ? `varlatchd: trusted proxy ${name} no longer resolves (${why}); ${previous.join(", ")} are no longer trusted`
            : `varlatchd: trusted proxy ${name} does not resolve (${why}); its forwarded addresses are not used until it does`,
        );
      }
    }
  }

  trusts = (address: string): boolean => {
    const normalized = normalizeAddress(address);
    if (!normalized) return false;
    if (this.literal.check(normalized, isIP(normalized) === 4 ? "ipv4" : "ipv6")) return true;
    const oldest = this.now() - this.maxAgeMs;
    for (const { addresses, at } of this.resolved.values()) {
      if (at >= oldest && addresses.includes(normalized)) return true;
    }
    return false;
  };
}

/** BuildAppOptions.clientAddress over a socket peer, trusting X-Forwarded-For only from `proxies`. */
export function clientAddressResolver(
  socketPeer: (c: Context) => string,
  proxies: TrustedProxies | null,
): (c: Context) => string {
  return (c) => {
    const peer = socketPeer(c);
    return proxies ? clientAddressOf(peer, c.req.header("X-Forwarded-For"), proxies.trusts) : (normalizeAddress(peer) ?? peer);
  };
}
