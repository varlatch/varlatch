// SPDX-License-Identifier: Apache-2.0
import type http from "node:http";
import { pipeline, type Readable } from "node:stream";
import zlib from "node:zlib";
import { StreamMatcher, type SecretEntry } from "@varlatch/matcher";

/**
 * Response scrubbing for requests the Broker substituted into (ADR-0039
 * Decisions 16 to 23). Every header value and every body byte of such a
 * response passes one matcher registered with exactly the values exercised
 * for that request; nothing else reaches the Agent.
 *
 * Framing is decided from the response headers before any header is sent:
 * a small identity body is read whole and relayed wire-exact when nothing
 * matched; anything else is decoded (gzip, deflate, br), scrubbed as a
 * stream, and re-framed. A failure before headers is a 502; after headers
 * the response is aborted without a terminating chunk, and held bytes are
 * discarded, never released.
 */

export interface ScrubLimits {
  /** Decoded content per response. */
  maxDecodedBytes: number;
  /** Without a byte from upstream, from the request being sent. */
  idleMs: number;
  /** A declared identity body at most this large is read whole. */
  bufferedBytes: number;
}

export const SCRUB_LIMITS: ScrubLimits = {
  maxDecodedBytes: 64 * 1024 * 1024,
  idleMs: 120_000,
  bufferedBytes: 2 * 1024 * 1024,
};

/** What the run's diagnostics hear about scrubbing: names and counts, never bytes. */
export type ScrubEvent =
  | { kind: "scrubbed"; item: string; count: number }
  | { kind: "unscrubbable"; item: string }
  | { kind: "incomplete-prefix"; item: string; length: number }
  | { kind: "aborted"; reason: string };

/** A failure before any header reached the Agent: the caller answers 502. */
export class BeforeHeaders extends Error {}

/** An idle or disconnect cutoff, before or after headers. */
export class Cutoff extends Error {}

// Per-connection headers, never relayed from upstream on a scrubbed response.
const HOP_BY_HOP = new Set(["connection", "keep-alive", "transfer-encoding", "proxy-connection", "trailer", "upgrade"]);
// They describe bytes the Agent may no longer receive.
const REPRESENTATION = new Set(["etag", "content-md5", "digest", "content-digest", "repr-digest"]);
const DECODERS: Record<string, () => zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress> = {
  gzip: () => zlib.createGunzip(),
  deflate: () => zlib.createInflate(),
  br: () => zlib.createBrotliDecompress(),
};

/** Restarts on every upstream byte; fires once. */
export class Watchdog {
  private timer: NodeJS.Timeout | undefined;
  constructor(
    private readonly ms: number,
    private readonly onIdle: () => void,
  ) {
    this.touch();
  }

  touch(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(this.onIdle, this.ms);
  }

  stop(): void {
    clearTimeout(this.timer);
  }
}

function pairs(raw: string[]): [string, string][] {
  const out: [string, string][] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) out.push([raw[i]!, raw[i + 1]!]);
  return out;
}

/** The single content coding of a response, "" for none, or null when unsupported. */
export function contentCoding(headers: [string, string][]): string | null {
  const codings = headers
    .filter(([n]) => n.toLowerCase() === "content-encoding")
    .flatMap(([, v]) => v.split(","))
    .map((c) => c.trim().toLowerCase())
    .filter((c) => c !== "" && c !== "identity");
  if (codings.length === 0) return "";
  if (codings.length === 1 && codings[0]! in DECODERS) return codings[0]!;
  return null;
}

export class Scrubber {
  private readonly counts = new Map<string, number>();

  constructor(
    private readonly entries: SecretEntry[],
    private readonly replacement: (item: string) => Uint8Array,
    private readonly report: (event: ScrubEvent) => void,
  ) {
    for (const item of new Set(this.matcher().skipped)) report({ kind: "unscrubbable", item });
  }

  matcher(): StreamMatcher {
    return new StreamMatcher(this.entries, this.replacement);
  }

  count(matcher: StreamMatcher): void {
    for (const [item, n] of matcher.replaced) this.counts.set(item, (this.counts.get(item) ?? 0) + n);
  }

  /** One header value, whole. */
  headerValue(value: string): string {
    const matcher = this.matcher();
    const out = Buffer.concat([matcher.push(Buffer.from(value, "latin1")), matcher.end().output]);
    this.count(matcher);
    return matcher.replaced.size > 0 ? out.toString("latin1") : value;
  }

  finish(): void {
    for (const [item, count] of [...this.counts].sort(([a], [b]) => a.localeCompare(b))) {
      this.report({ kind: "scrubbed", item, count });
    }
  }
}

/**
 * Relay one upstream response to the Agent through the scrubber. Throws
 * BeforeHeaders when nothing has been sent; after headers it aborts the
 * response itself and resolves.
 */
export async function relayScrubbed(opts: {
  method: string;
  upstream: http.IncomingMessage;
  res: http.ServerResponse;
  scrubber: Scrubber;
  limits: ScrubLimits;
  watchdog: Watchdog;
  report: (event: ScrubEvent) => void;
}): Promise<void> {
  const { upstream, res, scrubber, limits, watchdog, report } = opts;
  const status = upstream.statusCode ?? 502;
  // The status line's reason phrase and every header value are scrubbed too.
  let statusMessage: string;
  let headers: [string, string][];
  try {
    statusMessage = scrubber.headerValue(upstream.statusMessage ?? "");
    headers = pairs(upstream.rawHeaders)
      .filter(([n]) => !HOP_BY_HOP.has(n.toLowerCase()))
      .map(([n, v]) => [n, scrubber.headerValue(v)] as [string, string]);
  } catch {
    upstream.destroy();
    throw new BeforeHeaders("the response could not be scanned");
  }
  const named = (name: string) => headers.filter(([n]) => n.toLowerCase() === name).map(([, v]) => v);
  const without = (names: Set<string>) => headers.filter(([n]) => !names.has(n.toLowerCase()));

  // No body: the headers are still scrubbed.
  if (opts.method === "HEAD" || status === 204 || status === 304) {
    upstream.resume();
    res.writeHead(status, statusMessage, headers.flat());
    res.end();
    watchdog.stop();
    scrubber.finish();
    return;
  }

  const coding = contentCoding(headers);
  if (coding === null) {
    upstream.destroy();
    throw new BeforeHeaders(`the response's content coding (${named("content-encoding").join(", ")}) cannot be inspected; not relayed`);
  }
  const lengths = named("content-length");
  const declared = lengths.length === 1 && /^\d+$/.test(lengths[0]!.trim()) ? Number(lengths[0]) : undefined;

  if (coding === "" && declared !== undefined && declared <= limits.bufferedBytes) {
    // Buffered: read and scan the whole body before any header is sent.
    const chunks: Buffer[] = [];
    try {
      for await (const chunk of upstream) {
        watchdog.touch();
        chunks.push(chunk as Buffer);
      }
    } catch (err) {
      throw new BeforeHeaders(err instanceof Cutoff ? err.message : "the destination closed the response early");
    }
    watchdog.stop();
    const body = Buffer.concat(chunks);
    const matcher = scrubber.matcher();
    let out: Buffer;
    try {
      const head = matcher.push(body);
      const end = matcher.end();
      if (end.incompletePrefix) report({ kind: "incomplete-prefix", ...end.incompletePrefix });
      out = Buffer.concat([head, end.output]);
    } catch {
      throw new BeforeHeaders("the response could not be scanned");
    }
    scrubber.count(matcher);
    if (matcher.replaced.size > 0) {
      headers = [
        ...without(new Set([...REPRESENTATION, "content-length"])),
        ["Content-Length", String(out.length)],
      ];
    }
    res.writeHead(status, statusMessage, headers.flat());
    res.end(matcher.replaced.size > 0 ? out : body);
    scrubber.finish();
    return;
  }

  // Streaming: committed to chunked framing and identity content.
  headers = without(new Set([...REPRESENTATION, "content-length", "accept-ranges", "content-encoding"]));
  const matcher = scrubber.matcher();
  const source: Readable = coding ? pipeline(upstream, DECODERS[coding]!(), () => {}) : upstream;
  upstream.on("data", () => watchdog.touch());
  // Sent now, not with the first body byte: a failure before any decoded
  // byte (a corrupt gzip trailer read in one piece) must still reach the
  // Agent as a started, unterminated response, not as an empty reply.
  res.writeHead(status, statusMessage, headers.flat());
  res.flushHeaders();
  let decoded = 0;
  try {
    for await (const chunk of source) {
      decoded += (chunk as Buffer).length;
      if (decoded > limits.maxDecodedBytes) throw new Cutoff(`the response exceeds ${limits.maxDecodedBytes} bytes of decoded content`);
      const out = matcher.push(chunk as Buffer);
      if (out.length > 0 && !res.write(out)) await drained(res);
    }
    const end = matcher.end();
    if (end.incompletePrefix) report({ kind: "incomplete-prefix", ...end.incompletePrefix });
    watchdog.stop();
    scrubber.count(matcher);
    res.end(end.output);
    scrubber.finish();
  } catch (err) {
    // Never a terminating chunk, never a held byte.
    watchdog.stop();
    matcher.abort();
    upstream.destroy();
    res.destroy();
    scrubber.count(matcher);
    scrubber.finish();
    report({ kind: "aborted", reason: err instanceof Cutoff ? err.message : "the destination's response failed mid-stream" });
  }
}

function drained(res: http.ServerResponse): Promise<void> {
  return new Promise((resolve, reject) => {
    const done = () => {
      res.off("drain", done);
      res.off("close", closed);
      resolve();
    };
    const closed = () => {
      res.off("drain", done);
      reject(new Cutoff("the Agent disconnected"));
    };
    res.once("drain", done);
    res.once("close", closed);
  });
}
