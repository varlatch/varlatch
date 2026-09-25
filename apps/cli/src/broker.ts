// SPDX-License-Identifier: Apache-2.0
import { randomBytes, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";

/**
 * The local Broker (ADR-0022): a loopback-only forward proxy that substitutes
 * per-run Placeholders with real secret material only in requests it
 * originates itself over verified TLS to allowlisted destinations. It is
 * credential mediation, not a network sandbox: non-allowlisted traffic passes
 * through unchanged (placeholders intact, useless) unless strict mode blocks
 * it. Opaque CONNECT tunnels cannot be inspected without MITM, which Varlatch
 * deliberately does not do — CONNECT to a secret-using destination is refused
 * with a precise diagnostic. No secret is cached across requests.
 */

const BODY_LIMIT = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Placeholders: opaque per-run tokens; no item name or metadata encoded.

export function generatePlaceholder(): string {
  return `vlch_ph_v1_${randomBytes(16).toString("hex")}`;
}

const PLACEHOLDER_PATTERN = /vlch_ph_v1_[0-9a-f]{32}/g;

export function containsPlaceholder(text: string): boolean {
  PLACEHOLDER_PATTERN.lastIndex = 0;
  return PLACEHOLDER_PATTERN.test(text);
}

/** Exact-token replacement only; partial tokens are never substituted. */
export function substituteExact(text: string, values: Map<string, string>): string {
  PLACEHOLDER_PATTERN.lastIndex = 0;
  return text.replace(PLACEHOLDER_PATTERN, (token) => values.get(token) ?? token);
}

// ---------------------------------------------------------------------------
// Destination matching against the Capability's canonical selectors
// (`host:port` / `*.suffix:port` / `[v6]:port`, as returned at issuance).
// varlatchd remains authoritative; this decides only local routing.

interface Selector {
  host: string;
  wildcard: boolean;
  port: number;
}

export function parseSelectors(raw: string[]): Selector[] {
  const selectors: Selector[] = [];
  for (const entry of raw) {
    const wildcard = entry.startsWith("*.");
    let rest = wildcard ? entry.slice(2) : entry;
    let host: string;
    let port: number;
    if (rest.startsWith("[")) {
      const close = rest.indexOf("]");
      host = rest.slice(1, close);
      port = Number(rest.slice(close + 2));
    } else {
      const colon = rest.lastIndexOf(":");
      host = rest.slice(0, colon);
      port = Number(rest.slice(colon + 1));
    }
    if (host && Number.isInteger(port)) selectors.push({ host: host.toLowerCase(), wildcard, port });
  }
  return selectors;
}

function canonicalHost(raw: string): string {
  let host = raw.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return host;
}

export function matchesSelectors(selectors: Selector[], host: string, port: number): boolean {
  const h = canonicalHost(host);
  return selectors.some((sel) => {
    if (sel.port !== port) return false;
    if (sel.wildcard) return !net.isIP(h) && h.endsWith(`.${sel.host}`);
    return h === sel.host;
  });
}

// ---------------------------------------------------------------------------
// Body substitution policy (ADR-0022 §14): bounded inspectable text only.

export function isTextualContentType(contentType: string | undefined): boolean {
  if (!contentType) return false;
  const mime = contentType.split(";")[0]!.trim().toLowerCase();
  return (
    mime === "application/json" ||
    mime === "application/x-www-form-urlencoded" ||
    mime.startsWith("text/")
  );
}

// ---------------------------------------------------------------------------

export interface BrokerOptions {
  /** placeholder token -> Config Item name */
  placeholders: Map<string, string>;
  /** Canonical destination selectors from the issued Capability. */
  destinations: string[];
  /** Exercise the Capability for one destination; returns item name -> value. */
  exercise: (destination: { host: string; port: number }) => Promise<Map<string, string>>;
  /** Block non-allowlisted traffic instead of passing it through. */
  strict?: boolean;
}

export interface RunningBroker {
  port: number;
  /** Per-run proxy credential; embed as http://vlt:<token>@127.0.0.1:port. */
  token: string;
  proxyUrl: string;
  close: () => Promise<void>;
}

function deny(res: http.ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "text/plain", Connection: "close", ...headers });
  res.end(`varlatch-broker: ${message}\n`);
}

/**
 * Isolating maintenance (ADR-0036 D6) is transient: tell the agent to retry
 * (503 + Retry-After) rather than reporting a broken upstream (502).
 */
function isMaintenance(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "MAINTENANCE";
}

function checkProxyAuth(headers: http.IncomingHttpHeaders, token: string): boolean {
  const header = headers["proxy-authorization"];
  if (!header || Array.isArray(header)) return false;
  const [scheme, value] = header.split(" ");
  if (scheme?.toLowerCase() !== "basic" || !value) return false;
  const expected = Buffer.from(`vlt:${token}`, "utf8").toString("base64");
  const a = Buffer.from(value, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

const CONNECT_DIAGNOSTIC = (host: string) =>
  `Varlatch blocked an HTTPS CONNECT tunnel to ${host}. ` +
  `Agent-safe secret substitution requires the broker to inspect the outbound ` +
  `request before establishing TLS. This client uses an opaque CONNECT tunnel, ` +
  `which Varlatch intentionally does not MITM. Send plain HTTP requests with ` +
  `absolute URIs through the proxy instead.`;

// Hop-by-hop headers the broker owns on the connection it originates.
const HOP_BY_HOP = new Set([
  "proxy-authorization",
  "proxy-connection",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

export function startBroker(options: BrokerOptions): Promise<RunningBroker> {
  const token = randomBytes(24).toString("base64url");
  const selectors = parseSelectors(options.destinations);

  const server = http.createServer((req, res) => {
    void handleRequest(req, res).catch((err: unknown) => {
      if (res.headersSent) res.destroy();
      else if (isMaintenance(err)) deny(res, 503, "the Varlatch installation is in maintenance (restore or upgrade); retry later", { "Retry-After": "15" });
      else deny(res, 502, err instanceof Error ? err.message : "internal error");
    });
  });

  // Opaque tunnels: never inspected, never substituted.
  server.on("connect", (req, socket) => {
    if (!checkProxyAuth(req.headers, token)) {
      socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n");
      return;
    }
    const [host = "", portRaw = "443"] = (req.url ?? "").split(":");
    const port = Number(portRaw) || 443;
    if (matchesSelectors(selectors, host, port)) {
      socket.end(
        `HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n${CONNECT_DIAGNOSTIC(host)}\n`,
      );
      return;
    }
    if (options.strict) {
      socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\nvarlatch-broker: blocked by --agent-network=strict\n");
      return;
    }
    const upstream = net.connect(port, host, () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      upstream.pipe(socket);
      socket.pipe(upstream);
    });
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
  });

  async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!checkProxyAuth(req.headers, token)) {
      res.writeHead(407, { "Proxy-Authenticate": "Basic", Connection: "close" });
      res.end();
      return;
    }
    let target: URL;
    try {
      // Proxy requests carry absolute URIs; origin-form has no destination.
      target = new URL(req.url ?? "");
    } catch {
      deny(res, 400, "expected an absolute-URI proxy request");
      return;
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      deny(res, 400, `unsupported scheme ${target.protocol}`);
      return;
    }
    const host = canonicalHost(target.hostname);
    const port = Number(target.port) || (target.protocol === "https:" ? 443 : 80);
    const allowed = matchesSelectors(selectors, host, port);
    if (!allowed && options.strict) {
      deny(res, 403, `destination ${host}:${port} blocked by --agent-network=strict`);
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let overLimit = false;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > BODY_LIMIT) {
        overLimit = true;
        break;
      }
      chunks.push(chunk as Buffer);
    }
    if (overLimit) {
      // Never forward a partially read (and potentially partially substituted)
      // request; bounded bodies are an explicit MVP limit.
      deny(res, 413, `request body exceeds the ${BODY_LIMIT}-byte broker limit`);
      req.destroy();
      return;
    }
    let body = Buffer.concat(chunks);

    const headers: Record<string, string | string[]> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(name) && value !== undefined) headers[name] = value;
    }

    const headerText = JSON.stringify(headers);
    const bodyText = body.toString("utf8");
    const bodyHasPlaceholder = containsPlaceholder(bodyText);
    const needsSubstitution = allowed && (containsPlaceholder(headerText) || bodyHasPlaceholder);

    if (needsSubstitution) {
      if (target.protocol !== "https:") {
        deny(res, 502, "secret substitution requires an HTTPS destination with verified TLS");
        return;
      }
      const contentType = req.headers["content-type"];
      if (bodyHasPlaceholder && !isTextualContentType(Array.isArray(contentType) ? contentType[0] : contentType)) {
        deny(res, 502, "placeholders found in a non-textual request body; refusing to substitute");
        return;
      }
      const items = await options.exercise({ host, port });
      const values = new Map<string, string>();
      for (const [placeholder, itemName] of options.placeholders) {
        const value = items.get(itemName);
        if (value !== undefined) values.set(placeholder, value);
      }
      for (const [name, value] of Object.entries(headers)) {
        headers[name] = Array.isArray(value)
          ? value.map((v) => substituteExact(v, values))
          : substituteExact(value, values);
      }
      if (bodyHasPlaceholder) {
        const substituted = substituteExact(bodyText, values);
        if (containsPlaceholder(substituted)) {
          deny(res, 502, "a placeholder could not be resolved for this destination");
          return;
        }
        body = Buffer.from(substituted, "utf8");
      }
    }
    // Request authority comes from the authorized URL, never the caller's
    // Host header (which could select a different virtual host).
    headers.host = target.host;
    if (needsSubstitution && containsPlaceholder(JSON.stringify(headers))) {
      deny(res, 502, "a header placeholder could not be resolved for this destination");
      return;
    }
    // The broker owns transport framing on the connection it originates.
    if (body.length > 0 || req.headers["content-length"] !== undefined) {
      headers["content-length"] = String(body.length);
    }

    // Redirects are relayed, never followed: each subsequent request re-enters
    // these checks from scratch (ADR-0022 §10). TLS verification is stock.
    const transport = target.protocol === "https:" ? https : http;
    await new Promise<void>((resolve, reject) => {
      const upstream = transport.request(
        {
          host,
          port,
          servername: net.isIP(host) ? undefined : host,
          method: req.method,
          path: `${target.pathname}${target.search}`,
          headers,
        },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
          upstreamRes.pipe(res);
          upstreamRes.on("end", resolve);
          upstreamRes.on("error", reject);
        },
      );
      upstream.on("error", reject);
      upstream.end(body);
    });
  }

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        port,
        token,
        proxyUrl: `http://vlt:${token}@127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((res2) => {
            server.closeAllConnections();
            server.close(() => res2());
          }),
      });
    });
  });
}
