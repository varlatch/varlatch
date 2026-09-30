// SPDX-License-Identifier: Apache-2.0
import { randomBytes, timingSafeEqual } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { parseTarget, type Target } from "@varlatch/protocol";
import type { SecretEntry } from "@varlatch/matcher";
import { BODY_LIMIT, planPlacement, type Placement, type PlacementRule, type Surface } from "./placement.js";
import { BeforeHeaders, Cutoff, SCRUB_LIMITS, Scrubber, Watchdog, relayScrubbed, type ScrubEvent, type ScrubLimits, BROKER_REPLY_HEADER } from "./scrub.js";

/**
 * The local Broker (ADR-0022, amended by ADR-0039): a loopback-only forward
 * proxy that substitutes per-run Placeholders with real secret material only
 * at the Substitution Targets varlatchd recorded on the Capability, in
 * requests it originates itself over verified TLS to allowlisted
 * destinations. It is
 * credential mediation, not a network sandbox: non-allowlisted traffic passes
 * through unchanged (placeholders intact, useless) unless strict mode blocks
 * it. Opaque CONNECT tunnels cannot be inspected without MITM, which Varlatch
 * deliberately does not do — CONNECT to a secret-using destination is refused
 * with a precise diagnostic. No secret is cached across requests.
 */

// ---------------------------------------------------------------------------
// Placeholders: opaque per-run tokens; no item name or metadata encoded.

export function generatePlaceholder(): string {
  return `vlch_ph_v1_${randomBytes(16).toString("hex")}`;
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

export interface Exercised {
  /** Config Item name -> value, for the placed items only. */
  values: Map<string, string>;
  /** The targets varlatchd holds for the Capability, as it returned them. */
  targets: Record<string, string[]>;
  /** Placed items the server did not return (no longer stored). */
  withheld?: string[];
  /** A rotating item's retiring value, scrubbed from responses like the current one. */
  retiring?: Map<string, string>;
}

/** What the run's diagnostics hear about; never a value. */
export type BrokerEvent =
  | { kind: "blocked"; status: number; rule: PlacementRule; message: string }
  | { kind: "failed"; rule: PlacementRule | "exercise-mismatch"; message: string }
  | { kind: "stray"; item: string; surface: Surface }
  | ScrubEvent;

export interface BrokerOptions {
  /** placeholder token -> Config Item name */
  placeholders: Map<string, string>;
  /** Canonical destination selectors from the issued Capability. */
  destinations: string[];
  /** The targets varlatchd recorded on the Capability, from the issuance response. */
  targets: Record<string, string[]>;
  /** Exercise the Capability for one destination and the placements the request needs. */
  exercise: (destination: { host: string; port: number }, placements: Placement[]) => Promise<Exercised>;
  /** Block non-allowlisted traffic instead of passing it through. */
  strict?: boolean;
  report?: (event: BrokerEvent) => void;
  /** Response scrubbing bounds; the defaults are 64 MiB decoded and 120 seconds idle. */
  limits?: Partial<ScrubLimits>;
}

export interface RunningBroker {
  port: number;
  /** Per-run proxy credential; embed as http://vlt:<token>@127.0.0.1:port. */
  token: string;
  proxyUrl: string;
  /** Exercised value sets held right now (0 between requests: nothing is cached). */
  heldValues: () => number;
  close: () => Promise<void>;
}

/** Equal target sets, whatever the order. */
export function sameTargets(a: Record<string, string[]>, b: Record<string, string[]>): boolean {
  const canonical = (t: Record<string, string[]>) =>
    JSON.stringify(
      Object.keys(t)
        .sort()
        .map((item) => [item, [...(t[item] ?? [])].sort()]),
    );
  return canonical(a) === canonical(b);
}

function deny(res: http.ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "text/plain", Connection: "close", [BROKER_REPLY_HEADER]: "refused", ...headers });
  res.end(`varlatch-broker: ${message}\n`);
}

/**
 * Isolating maintenance (ADR-0036 D6) is transient: tell the agent to retry
 * (503 + Retry-After) rather than reporting a broken upstream (502).
 */
function isMaintenance(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "MAINTENANCE";
}

/**
 * A substituted request asks for identity content and a whole
 * representation, so its response never needs decoding past what the
 * scrubber supports, and is never a partial one (ADR-0039 Decision 16).
 */
function adjustForScrubbing<T extends { headers: [string, string][] }>(request: T): T {
  const dropped = new Set(["accept-encoding", "range", "if-range"]);
  return { ...request, headers: [...request.headers.filter(([n]) => !dropped.has(n.toLowerCase())), ["Accept-Encoding", "identity"]] };
}

/** A failure after exercise: the request is dropped with its plaintext. */
class AfterExercise extends Error {
  constructor(
    readonly rule: PlacementRule | "exercise-mismatch",
    message: string,
  ) {
    super(message);
  }
}

function pairs(raw: string[]): [string, string][] {
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i]!, raw[i + 1]!]);
  return out;
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
  `which Varlatch intentionally does not MITM. Send the request with ` +
  `varlatch request (a curl-like client, for example: varlatch request -H ` +
  `"Authorization: Bearer $API_KEY" https://${host}/...), or send plain HTTP ` +
  `requests with absolute URIs through the proxy.`;

// Headers the broker owns on the connection it originates: hop-by-hop and
// proxy headers are dropped; Host and Content-Length are set from the
// authorized URL and the body actually sent.
const BROKER_OWNED = new Set([
  "proxy-authorization",
  "proxy-connection",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "host",
  "content-length",
]);

export async function startBroker(options: BrokerOptions): Promise<RunningBroker> {
  const token = randomBytes(24).toString("base64url");
  const selectors = parseSelectors(options.destinations);
  // The Broker re-checks what varlatchd recorded (transport-owned headers
  // included); a target it cannot parse stops the run before it starts.
  const targets = new Map<string, Target[]>(
    Object.entries(options.targets).map(([item, list]) => [item, list.map((t) => parseTarget(t))]),
  );
  const held = new Set<Map<string, string>>();
  const report = options.report ?? (() => {});
  const limits: ScrubLimits = { ...SCRUB_LIMITS, ...options.limits };
  const placeholderOf = new Map([...options.placeholders].map(([token, item]) => [item, Buffer.from(token)]));

  const server = http.createServer((req, res) => {
    void handleRequest(req, res).catch((err: unknown) => {
      if (err instanceof BeforeHeaders || err instanceof Cutoff) report({ kind: "aborted", reason: err.message });
      if (res.headersSent) res.destroy();
      else if (isMaintenance(err)) deny(res, 503, "the Varlatch installation is in maintenance (restore or upgrade); retry later", { "Retry-After": "15" });
      else deny(res, 502, err instanceof Error ? err.message : "internal error");
    });
  });

  // Opaque tunnels: never inspected, never substituted.
  server.on("connect", (req, socket) => {
    if (!checkProxyAuth(req.headers, token)) {
      socket.end(`HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n${BROKER_REPLY_HEADER}: refused\r\n\r\n`);
      return;
    }
    const [host = "", portRaw = "443"] = (req.url ?? "").split(":");
    const port = Number(portRaw) || 443;
    if (matchesSelectors(selectors, host, port)) {
      socket.end(
        `HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n${BROKER_REPLY_HEADER}: refused\r\n\r\n${CONNECT_DIAGNOSTIC(host)}\n`,
      );
      return;
    }
    if (options.strict) {
      socket.end(`HTTP/1.1 403 Forbidden\r\nConnection: close\r\n${BROKER_REPLY_HEADER}: refused\r\n\r\nvarlatch-broker: blocked by --agent-network=strict\n`);
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
      res.writeHead(407, { "Proxy-Authenticate": "Basic", Connection: "close", [BROKER_REPLY_HEADER]: "refused" });
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

    // A declared length over the bound is refused before any byte is read.
    const declared = Number(req.headers["content-length"] ?? 0);
    if (declared > BODY_LIMIT) {
      deny(res, 413, `request body exceeds the ${BODY_LIMIT}-byte broker limit`);
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
      // request; bounded bodies are an explicit limit.
      deny(res, 413, `request body exceeds the ${BODY_LIMIT}-byte broker limit`);
      req.destroy();
      return;
    }

    const parts = {
      headers: pairs(req.rawHeaders).filter(([name]) => !BROKER_OWNED.has(name.toLowerCase())),
      query: target.search ? target.search.slice(1) : null,
      body: Buffer.concat(chunks) as Buffer,
    };
    const hadLength = req.headers["content-length"] !== undefined;

    // Non-allowlisted traffic passes through unchanged, Placeholders inert.
    if (!allowed) return forward(parts, hadLength);

    const plan = planPlacement(parts, options.placeholders, targets);
    if (plan.kind !== "block") for (const stray of plan.strays) report({ kind: "stray", ...stray });
    if (plan.kind === "block") {
      report({ kind: "blocked", status: plan.status, rule: plan.rule, message: plan.message });
      deny(res, plan.status, plan.message);
      return;
    }
    if (plan.kind === "pass") return forward(parts, hadLength);

    if (target.protocol !== "https:") {
      deny(res, 502, "secret substitution requires an HTTPS destination with verified TLS");
      return;
    }
    const exercised = await options.exercise({ host, port }, plan.placements);
    // Exercised values live for this request and its response only.
    held.add(exercised.values);
    try {
      let built: typeof parts;
      try {
        const placed = new Set(plan.placements.map((p) => p.item));
        const returned = [...exercised.values.keys()];
        if (!sameTargets(exercised.targets, options.targets)) {
          throw new AfterExercise("exercise-mismatch", "the exercise response carries different targets than the Capability was issued with");
        }
        if (exercised.withheld && exercised.withheld.length > 0) {
          throw new AfterExercise("missing-value", `${[...exercised.withheld].sort().join(", ")}: no longer stored in this environment`);
        }
        if (returned.length !== placed.size || returned.some((item) => !placed.has(item))) {
          throw new AfterExercise("exercise-mismatch", "the exercise response carries different items than the request places");
        }
        const applied = plan.apply(exercised.values);
        if (!applied.ok) throw new AfterExercise(applied.rule, applied.message);
        built = applied;
      } catch (err) {
        if (!(err instanceof AfterExercise)) throw err;
        report({ kind: "failed", rule: err.rule, message: err.message });
        deny(res, 502, err.message);
        return;
      }
      // The response is scrubbed of exactly the values exercised for it.
      const entries: SecretEntry[] = [
        ...[...exercised.values].map(([item, value]) => ({ item, value })),
        ...[...(exercised.retiring ?? [])].map(([item, value]) => ({ item, value })),
      ];
      const scrubber = new Scrubber(entries, (item) => placeholderOf.get(item) ?? Buffer.from("vlch_ph_v1_unknown"), report);
      await forward(adjustForScrubbing(built), hadLength, scrubber);
    } finally {
      // Nothing is cached across requests.
      exercised.values.clear();
      exercised.retiring?.clear();
      held.delete(exercised.values);
    }
    return;

    // Redirects are relayed, never followed: each subsequent request re-enters
    // these checks from scratch (ADR-0022 §10). TLS verification is stock.
    // The upstream connection opens only here, once the request is complete.
    async function forward(request: typeof parts, lengthWasSent: boolean, scrubber?: Scrubber): Promise<void> {
      // Request authority comes from the authorized URL, never the caller's
      // Host header (which could select a different virtual host).
      const headers: [string, string][] = [["host", target.host], ...request.headers];
      if (request.body.length > 0 || lengthWasSent) headers.push(["content-length", String(request.body.length)]);
      const transport = target.protocol === "https:" ? https : http;
      await new Promise<void>((resolve, reject) => {
        let response: http.IncomingMessage | undefined;
        const upstream = transport.request(
          {
            host,
            port,
            servername: net.isIP(host) ? undefined : host,
            method: req.method,
            path: `${target.pathname}${request.query === null ? "" : `?${request.query}`}`,
            headers: headers.flat(),
          },
          (upstreamRes) => {
            if (!scrubber) {
              // The Broker's own marker is never relayed from a destination.
              const relayed = { ...upstreamRes.headers };
              delete relayed[BROKER_REPLY_HEADER];
              res.writeHead(upstreamRes.statusCode ?? 502, relayed);
              upstreamRes.pipe(res);
              upstreamRes.on("end", resolve);
              upstreamRes.on("error", reject);
              return;
            }
            response = upstreamRes;
            watchdog?.touch();
            relayScrubbed({ method: req.method ?? "GET", upstream: upstreamRes, res, scrubber, limits, watchdog: watchdog!, report }).then(
              resolve,
              reject,
            );
          },
        );
        // A substituted request's response is bounded by an idle timeout
        // from the moment the request is sent, headers included.
        const watchdog = scrubber
          ? new Watchdog(limits.idleMs, () =>
              (response ?? upstream).destroy(new Cutoff(`no data from the destination for ${limits.idleMs / 1000} seconds`)),
            )
          : undefined;
        if (scrubber) {
          // No protocol switch on a substituted request: the rest could not be scrubbed.
          upstream.on("upgrade", (_upgradeRes, socket) => {
            socket.destroy();
            watchdog?.stop();
            reject(new BeforeHeaders("the destination switched protocols; not relayed on a substituted request"));
          });
          // The Agent going away cancels the upstream request and discards held bytes.
          res.on("close", () => {
            if (!res.writableFinished) (response ?? upstream).destroy(new Cutoff("the Agent disconnected"));
          });
        }
        upstream.on("error", (err) => {
          watchdog?.stop();
          reject(err);
        });
        upstream.end(request.body);
      });
    }
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
        heldValues: () => held.size,
        close: () =>
          new Promise<void>((res2) => {
            server.closeAllConnections();
            server.close(() => res2());
          }),
      });
    });
  });
}
