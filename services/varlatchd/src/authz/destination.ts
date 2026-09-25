// SPDX-License-Identifier: AGPL-3.0-or-later
import { isIP } from "node:net";
import { domainToASCII } from "node:url";

/**
 * Destination Selectors (ADR-0022 §9): canonical host + port. Selectors and
 * exercised destinations both pass through one canonicalization so validation
 * and matching can never diverge. Wildcards match subdomains only, never the
 * apex; IP literals match exactly; a selector without a port means 443.
 */

export interface DestinationSelector {
  /** Canonical lowercase ASCII host; without the "*." prefix for wildcards. */
  host: string;
  wildcard: boolean;
  port: number;
}

export interface Destination {
  host: string;
  port: number;
}

/**
 * Canonicalize one host: lowercase, strip exactly one trailing dot, punycode
 * to ASCII. Returns null for anything malformed or ambiguous — embedded
 * credentials, paths, schemes, ports (handled separately), empty labels.
 */
export function canonicalizeHost(raw: string): string | null {
  let host = raw.trim().toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host || /[\s/@\\?#[\]]/.test(host)) return null;
  if (isIP(host)) return host;
  const ascii = domainToASCII(host);
  if (!ascii || ascii.includes("%")) return null;
  // Reject empty labels ("a..b") and lone dots that domainToASCII tolerates.
  if (ascii.split(".").some((label) => label.length === 0)) return null;
  return ascii;
}

function parsePort(raw: string): number | null {
  if (!/^\d{1,5}$/.test(raw)) return null;
  const port = Number(raw);
  return port >= 1 && port <= 65535 ? port : null;
}

/**
 * Parse a selector string: `host`, `host:port`, `*.suffix`, `*.suffix:port`,
 * an IPv4 literal, or `[ipv6]`/`[ipv6]:port`. Omitted port means 443.
 */
export function parseDestinationSelector(raw: string): DestinationSelector | null {
  let input = raw.trim();
  if (!input) return null;

  let port = 443;
  if (input.startsWith("[")) {
    const close = input.indexOf("]");
    if (close === -1) return null;
    const ip = input.slice(1, close);
    const rest = input.slice(close + 1);
    if (isIP(ip) !== 6) return null;
    if (rest) {
      if (!rest.startsWith(":")) return null;
      const parsed = parsePort(rest.slice(1));
      if (parsed === null) return null;
      port = parsed;
    }
    return { host: ip.toLowerCase(), wildcard: false, port };
  }

  const colon = input.lastIndexOf(":");
  if (colon !== -1) {
    // A bare IPv6 literal without brackets is ambiguous with host:port.
    if (input.indexOf(":") !== colon) return null;
    const parsed = parsePort(input.slice(colon + 1));
    if (parsed === null) return null;
    port = parsed;
    input = input.slice(0, colon);
  }

  let wildcard = false;
  if (input.startsWith("*.")) {
    wildcard = true;
    input = input.slice(2);
    if (isIP(input)) return null;
  } else if (input.includes("*")) {
    return null;
  }
  const host = canonicalizeHost(input);
  if (!host || host.includes("*")) return null;
  return { host, wildcard, port };
}

export function formatSelector(sel: DestinationSelector): string {
  const host = isIP(sel.host) === 6 ? `[${sel.host}]` : sel.host;
  return `${sel.wildcard ? "*." : ""}${host}:${sel.port}`;
}

export function destinationMatches(sel: DestinationSelector, dest: Destination): boolean {
  if (sel.port !== dest.port) return false;
  const host = canonicalizeHost(dest.host);
  if (!host) return false;
  if (!sel.wildcard) return host === sel.host;
  // Wildcards match subdomains at any depth, never the apex, never IPs.
  if (isIP(host)) return false;
  return host.endsWith(`.${sel.host}`);
}
