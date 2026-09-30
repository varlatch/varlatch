// SPDX-License-Identifier: Apache-2.0
import { createWriteStream, readFileSync } from "node:fs";
import http from "node:http";
import type { Writable } from "node:stream";
import { AGENT_RUN_ENV } from "@varlatch/context";

/**
 * `varlatch request` (ADR-0043 Decision 6): a curl-like client for the
 * Agent inside an agent-safe run. It sends each request to the run's Broker
 * as a plain HTTP request with an absolute URI and the per-run proxy
 * credential, so the Broker can inspect it, substitute Secrets at their
 * targets, originate TLS itself, and scrub the response (ADR-0022, ADR-0039).
 * Clients that tunnel HTTPS with CONNECT (curl, Node's fetch, most SDKs)
 * cannot be substituted into, since the Broker never intercepts TLS.
 *
 * It needs no Varlatch credential and holds no Secret: the Agent's
 * environment carries Placeholders, and responses arrive already scrubbed.
 * Outside an agent-safe run it refuses; it is not a general HTTP client.
 */

export class RequestUsageError extends Error {
  override name = "RequestUsageError";
}

export interface RequestOptions {
  method: string;
  url: URL;
  /** Header lines as given, in order: name and value. */
  headers: [string, string][];
  body: Buffer | null;
  /** -o: write the response (and with -i its head) here instead of stdout. */
  output: string | null;
  /** -i: the status line and headers before the body. */
  include: boolean;
}

export const REQUEST_USAGE =
  "Usage: varlatch request [-X <method>] [-H '<name>: <value>']... [-d <data>|@<file>|@-] [--json <data>|@<file>|@-] " +
  "[-o <file>] [-i] <https-url>";

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const VALUED = new Set(["-X", "--request", "-H", "--header", "-d", "--data", "--json", "-o", "--output"]);

/**
 * Parse the curl-like subset. `readData` resolves `@file` and `@-` (standard
 * input): the bytes are sent as they are, like curl's --data-binary.
 */
export function parseRequestArgs(args: string[], readData: (spec: string) => Buffer): RequestOptions {
  let method: string | null = null;
  const headers: [string, string][] = [];
  let body: Buffer | null = null;
  let json = false;
  let output: string | null = null;
  let include = false;
  const positionals: string[] = [];
  const data = (flag: string, value: string) => {
    if (body !== null) throw new RequestUsageError(`give the body once: ${flag} after -d or --json`);
    return value.startsWith("@") ? readData(value.slice(1)) : Buffer.from(value, "utf8");
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === "--") {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (VALUED.has(arg)) {
      const value = args[++i];
      if (value === undefined) throw new RequestUsageError(`${arg} needs a value`);
      switch (arg) {
        case "-X":
        case "--request":
          if (!TOKEN.test(value)) throw new RequestUsageError(`${arg}: not an HTTP method: ${value}`);
          method = value;
          break;
        case "-H":
        case "--header": {
          const colon = value.indexOf(":");
          const name = colon < 0 ? "" : value.slice(0, colon).trim();
          if (!TOKEN.test(name)) throw new RequestUsageError(`${arg} expects '<name>: <value>'`);
          const headerValue = value.slice(colon + 1).trim();
          // A line break would start another header or end the head.
          if (/[\r\n\0]/.test(headerValue)) throw new RequestUsageError(`${arg} ${name}: a header value cannot contain a line break`);
          headers.push([name, headerValue]);
          break;
        }
        case "-d":
        case "--data":
          body = data(arg, value);
          break;
        case "--json":
          body = data(arg, value);
          json = true;
          break;
        case "-o":
        case "--output":
          output = value;
          break;
      }
      continue;
    }
    if (arg === "-i" || arg === "--include") {
      include = true;
      continue;
    }
    if (arg.startsWith("-")) throw new RequestUsageError(`unknown option ${arg}`);
    positionals.push(arg);
  }

  if (positionals.length !== 1) throw new RequestUsageError(positionals.length === 0 ? "give the URL" : "give one URL");
  let url: URL;
  try {
    url = new URL(positionals[0] as string);
  } catch {
    throw new RequestUsageError(`not an absolute URL: ${positionals[0]}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new RequestUsageError(`not an HTTP URL: ${url.protocol}`);
  if (url.username || url.password) throw new RequestUsageError("credentials in the URL are not sent; use a header");

  const has = (name: string) => headers.some(([n]) => n.toLowerCase() === name);
  if (body !== null && json) {
    if (!has("content-type")) headers.push(["Content-Type", "application/json"]);
    if (!has("accept")) headers.push(["Accept", "application/json"]);
  } else if (body !== null && !has("content-type")) {
    headers.push(["Content-Type", "application/x-www-form-urlencoded"]);
  }
  if (!has("accept")) headers.push(["Accept", "*/*"]);
  return { method: method ?? (body !== null ? "POST" : "GET"), url, headers, body, output, include };
}

export function readDataSpec(spec: string): Buffer {
  if (spec === "-") return readFileSync(0);
  try {
    return readFileSync(spec);
  } catch (err) {
    throw new RequestUsageError(`cannot read ${spec} (${(err as NodeJS.ErrnoException).code ?? "an error"})`);
  }
}

export interface BrokerEndpoint {
  host: string;
  port: number;
  /** The Proxy-Authorization value for the per-run credential. */
  authorization: string;
}

/**
 * The run's Broker from the Agent's environment, or why there is none. Only
 * a loopback proxy is used: that is where an agent-safe run's Broker listens.
 */
export function brokerFromEnv(env: NodeJS.ProcessEnv): BrokerEndpoint | { refusal: string } {
  const run = env[AGENT_RUN_ENV];
  if (!run) {
    return {
      refusal:
        "varlatch request sends requests through the Broker of an agent-safe run, and this is not one " +
        `(${AGENT_RUN_ENV} is not set). Outside an agent-safe run, use any HTTP client.`,
    };
  }
  const raw = env.HTTPS_PROXY ?? env.https_proxy ?? env.HTTP_PROXY ?? env.http_proxy;
  if (!raw) {
    return {
      refusal:
        `agent-safe run ${run} has no Broker: it carries no Secrets, so there is nothing to substitute. ` +
        "Use any HTTP client.",
    };
  }
  let proxy: URL;
  try {
    proxy = new URL(raw);
  } catch {
    return { refusal: "the proxy in HTTPS_PROXY is not a URL" };
  }
  const loopback = proxy.hostname === "127.0.0.1" || proxy.hostname === "localhost" || proxy.hostname === "[::1]";
  if (proxy.protocol !== "http:" || !loopback || !proxy.port || !proxy.username) {
    return { refusal: "HTTPS_PROXY does not name this run's Broker (a loopback http:// proxy with the per-run credential)" };
  }
  const credential = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
  return {
    host: proxy.hostname.replace(/^\[|\]$/g, ""),
    port: Number(proxy.port),
    authorization: `Basic ${Buffer.from(credential, "utf8").toString("base64")}`,
  };
}

export interface RequestIo {
  stdout: Writable;
  err: (line: string) => void;
}

export type RequestOutcome =
  /** The destination answered (any HTTP status, as curl reports it). */
  | { kind: "response"; status: number }
  /** The Broker refused the request itself, before or after exercising. */
  | { kind: "refused"; status: number }
  | { kind: "unreachable"; code: string };

/** The Broker's own answers are short `text/plain` bodies starting with this prefix. */
const BROKER_PREFIX = "varlatch-broker: ";
const REFUSAL_BUFFER = 64 * 1024;

function head(res: http.IncomingMessage): Buffer {
  const lines = [`HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage ?? ""}`.trimEnd()];
  for (let i = 0; i < res.rawHeaders.length; i += 2) lines.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`);
  return Buffer.from(`${lines.join("\r\n")}\r\n\r\n`, "utf8");
}

/**
 * Send one request to the Broker and relay the response: the body to stdout
 * or `-o`, streamed as it arrives, and with `-i` the status line and headers
 * first. A refusal from the Broker itself goes to stderr instead.
 */
export function sendThroughBroker(opts: RequestOptions, broker: BrokerEndpoint, io: RequestIo): Promise<RequestOutcome> {
  return new Promise((resolve) => {
    const headers: string[] = ["Host", opts.url.host];
    if (!opts.headers.some(([n]) => n.toLowerCase() === "user-agent")) headers.push("User-Agent", "varlatch-request");
    for (const [name, value] of opts.headers) headers.push(name, value);
    headers.push("Proxy-Authorization", broker.authorization);
    if (opts.body !== null) headers.push("Content-Length", String(opts.body.length));
    // A dedicated agent: the Agent's environment sets NODE_USE_ENV_PROXY, and
    // this request is addressed to the Broker itself, never proxied again.
    const agent = new http.Agent({ keepAlive: false });
    const req = http.request(
      { host: broker.host, port: broker.port, method: opts.method, path: opts.url.href, headers, agent, setHost: false },
      (res) => {
        const status = res.statusCode ?? 0;
        const type = String(res.headers["content-type"] ?? "");
        const relay = () => {
          const out: Writable = opts.output ? createWriteStream(opts.output) : io.stdout;
          if (opts.include) out.write(head(res));
          res.pipe(out, { end: opts.output !== null });
          res.on("end", () => {
            if (opts.output) out.once("finish", () => resolve({ kind: "response", status }));
            else resolve({ kind: "response", status });
          });
        };
        if (status < 400 || !type.startsWith("text/plain")) return relay();
        // Possibly the Broker's own refusal: look at the start of the body first.
        const chunks: Buffer[] = [];
        let size = 0;
        let decided = false;
        const decide = (ended: boolean) => {
          if (decided) return;
          const start = Buffer.concat(chunks).subarray(0, BROKER_PREFIX.length).toString("utf8");
          if (!ended && start.length < BROKER_PREFIX.length && size < REFUSAL_BUFFER) return;
          decided = true;
          const buffered = Buffer.concat(chunks);
          if (start === BROKER_PREFIX) {
            res.resume();
            for (const line of buffered.toString("utf8").trimEnd().split("\n")) io.err(line);
            res.on("end", () => resolve({ kind: "refused", status }));
            if (ended) resolve({ kind: "refused", status });
            return;
          }
          // An ordinary error response from the destination: relay it all.
          const out: Writable = opts.output ? createWriteStream(opts.output) : io.stdout;
          if (opts.include) out.write(head(res));
          out.write(buffered);
          if (ended) {
            if (opts.output) out.end(() => resolve({ kind: "response", status }));
            else resolve({ kind: "response", status });
            return;
          }
          res.removeAllListeners("data");
          res.pipe(out, { end: opts.output !== null });
          res.on("end", () => {
            if (opts.output) out.once("finish", () => resolve({ kind: "response", status }));
            else resolve({ kind: "response", status });
          });
        };
        res.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
          size += chunk.length;
          decide(false);
        });
        res.on("end", () => decide(true));
      },
    );
    req.on("error", (err: NodeJS.ErrnoException) => resolve({ kind: "unreachable", code: err.code ?? err.message }));
    req.end(opts.body ?? undefined);
  });
}
