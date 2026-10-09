// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Context, Next } from "hono";
import { errorBody } from "./support.js";

/**
 * The tailnet browser endpoint's gate (ADR-0046 Decisions 3 and 4), run
 * before the device check and before authentication:
 *
 * - Only the node's own name is answered (`Host`).
 * - A request without `Origin` (the CLI, scripts) passes unchanged.
 * - A request with `Origin` passes only from an exactly allowlisted origin
 *   to one of the browser read routes; anything else is refused with 403,
 *   without CORS headers, so the page can read nothing. `null` and
 *   wildcards are never allowlisted (config.ts).
 * - Allowed requests, errors included, get CORS headers for that origin,
 *   never `Access-Control-Allow-Credentials`: cookies do not authenticate
 *   here, the bearer does.
 *
 * Nothing here contributes to Tailnet Context: the gate can only refuse.
 */
export interface TailnetBrowserOptions {
  /** The node's MagicDNS name, e.g. varlatch.example.ts.net. */
  host: string;
  port: number;
  /** Exact origins allowed to read cross-origin. */
  origins: readonly string[];
}

const ENV = String.raw`^/v1/organizations/[^/]+/projects/[^/]+/environments/[^/]+`;

/** The only routes a page may call cross-origin: protected value reads and the device check. */
const BROWSER_ROUTES: readonly { method: string; path: RegExp }[] = [
  { method: "GET", path: new RegExp(`${ENV}/effective-configuration$`) },
  { method: "POST", path: new RegExp(`${ENV}/disclosures$`) },
  { method: "POST", path: new RegExp(`${ENV}/validate$`) },
  { method: "GET", path: /^\/v1\/tailnet\/context$/ },
];

export function isBrowserRoute(method: string, path: string): boolean {
  return BROWSER_ROUTES.some((r) => r.method === method && r.path.test(path));
}

export function tailnetBrowserGate(opts: TailnetBrowserOptions) {
  const hosts = new Set([opts.host, `${opts.host}:${opts.port}`]);
  const origins = new Set(opts.origins);
  return async (c: Context, next: Next) => {
    const reqId = c.get("requestId") as string;
    if (!hosts.has((c.req.header("Host") ?? "").toLowerCase())) {
      return c.json(errorBody("PERMISSION_DENIED", `This endpoint answers only as ${opts.host}`, reqId), 403);
    }
    const origin = c.req.header("Origin");
    if (origin === undefined) return next();
    const preflight = c.req.method === "OPTIONS";
    const method = preflight ? (c.req.header("Access-Control-Request-Method") ?? "") : c.req.method;
    if (!origins.has(origin) || !isBrowserRoute(method, c.req.path)) {
      c.header("Vary", "Origin");
      return c.json(errorBody("PERMISSION_DENIED", "This origin may not make this request here", reqId), 403);
    }
    if (preflight) {
      return c.body(null, 204, {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, POST",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Max-Age": "300",
        Vary: "Origin",
      });
    }
    await next();
    c.res.headers.set("Access-Control-Allow-Origin", origin);
    c.res.headers.set("Access-Control-Expose-Headers", "Retry-After, X-Request-Id");
    c.res.headers.append("Vary", "Origin");
  };
}
