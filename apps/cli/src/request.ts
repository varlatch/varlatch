// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from "node:crypto";
import { createWriteStream, readFileSync, renameSync, rmSync } from "node:fs";
import http from "node:http";
import { basename, dirname, join } from "node:path";
import type { Writable } from "node:stream";
import { AGENT_RUN_ENV } from "@varlatch/context";
import { BROKER_REPLY_HEADER } from "./scrub.js";

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
  /** The destination answered (any HTTP status, as curl reports it), and all of it was written. */
  | { kind: "response"; status: number }
  /** The Broker answered itself (it marks such replies): a refusal, or its authentication challenge. */
  | { kind: "refused"; status: number }
  | { kind: "unreachable"; code: string }
  /** The response was cut off, or could not be written: the output is incomplete. */
  | { kind: "incomplete"; reason: string };

function head(res: http.IncomingMessage): Buffer {
  const lines = [`HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage ?? ""}`.trimEnd()];
  for (let i = 0; i < res.rawHeaders.length; i += 2) lines.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`);
  return Buffer.from(`${lines.join("\r\n")}\r\n\r\n`, "utf8");
}

const errorCode = (err: unknown) => (err as NodeJS.ErrnoException).code ?? (err instanceof Error ? err.message : String(err));

/**
 * Send one request to the Broker and relay the response.
 *
 * - A reply the Broker generated itself carries its marker header, which it
 *   strips from every destination response: that reply goes to stderr, and
 *   the outcome is "refused". Every other reply is the destination's, whatever
 *   its status or body, and is relayed.
 * - The body streams to stdout, or with `-o` to a temporary file beside the
 *   named one that replaces it only once the whole response was received
 *   and written; `-i` writes the status line and headers first.
 * - Success needs the complete response and a successful write. A response
 *   the Broker or the destination cuts off (a scrubbing limit, an idle
 *   cutoff, a disconnect), or an output that cannot be written, settles as
 *   "incomplete"; a partial `-o` file is removed.
 */
export function sendThroughBroker(opts: RequestOptions, broker: BrokerEndpoint, io: RequestIo): Promise<RequestOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    const settle = (outcome: RequestOutcome) => {
      if (settled) return;
      settled = true;
      resolve(outcome);
    };
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
        if (res.headers[BROKER_REPLY_HEADER] !== undefined) return refusal(res, status);
        relay(res, status);
      },
    );
    req.on("error", (err) => settle({ kind: "unreachable", code: errorCode(err) }));
    req.end(opts.body ?? undefined);

    /** The Broker's own reply: its text to stderr, whole or not. */
    function refusal(res: http.IncomingMessage, status: number): void {
      const chunks: Buffer[] = [];
      const done = () => {
        const text = Buffer.concat(chunks).toString("utf8").trim();
        if (text) for (const line of text.split("\n")) io.err(line);
        else if (status === 407) io.err("varlatch-broker: the per-run proxy credential in HTTPS_PROXY was not accepted");
        settle({ kind: "refused", status });
      };
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", done);
      res.on("error", done);
      res.on("close", done);
    }

    function relay(res: http.IncomingMessage, status: number): void {
      const temp = opts.output ? join(dirname(opts.output), `.${basename(opts.output)}.varlatch-${randomBytes(6).toString("hex")}`) : null;
      const out: Writable = temp ? createWriteStream(temp, { flags: "wx" }) : io.stdout;
      const cleanup = () => {
        if (!temp) return;
        out.destroy();
        rmSync(temp, { force: true });
      };
      const fail = (reason: string) => {
        if (settled) return;
        res.destroy();
        cleanup();
        settle({ kind: "incomplete", reason });
      };
      out.on("error", (err) => fail(`cannot write ${opts.output ?? "standard output"} (${errorCode(err)})`));
      // A response that ends before it is complete: the Broker cut it off
      // (a scrubbing limit, an idle cutoff) or the destination went away.
      res.on("aborted", () => fail("the response was cut off before it was complete"));
      res.on("error", (err) => fail(`the response was cut off before it was complete (${errorCode(err)})`));
      res.on("close", () => {
        if (!res.complete) fail("the response was cut off before it was complete");
      });
      if (opts.include) out.write(head(res));
      res.pipe(out, { end: temp !== null });
      res.on("end", () => {
        if (!res.complete) return fail("the response was cut off before it was complete");
        if (temp) {
          out.once("finish", () => {
            if (settled) return;
            try {
              renameSync(temp, opts.output as string);
            } catch (err) {
              return fail(`cannot write ${opts.output} (${errorCode(err)})`);
            }
            settle({ kind: "response", status });
          });
          return;
        }
        // Everything relayed to stdout has been handed over before the outcome is final.
        io.stdout.write("", (err) => (err ? fail(`cannot write standard output (${errorCode(err)})`) : settle({ kind: "response", status })));
      });
    }
  });
}
