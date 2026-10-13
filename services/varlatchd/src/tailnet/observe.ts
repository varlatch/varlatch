// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { durableJson } from "@varlatch/backup";
import type { NodeCertificate } from "./cert.js";
import { localApiGet } from "./localapi.js";

/**
 * What varlatchd knows about its tailnet listeners (ADR-0046, Listener
 * metadata): what is configured, and what it last observed, with the time.
 * Never reachability: only a browser or a client on the tailnet can find
 * that out, so nothing here claims it.
 *
 * The running daemon checks at start and every 60 seconds; Installation
 * Admins read the result from GET /v1/installation/listeners, and the
 * read-only `admin doctor` process from a file in the state volume.
 * Statuses are pass, fail or unknown, with fixed reason codes; raw LocalAPI
 * errors go to the log only.
 */

export type ObservedStatus = "pass" | "fail" | "unknown";

export interface ObservedCheck {
  status: ObservedStatus;
  reason?: ListenerReason;
  /** browserTls only: when the certificate in use expires. */
  certificateNotAfter?: string;
}

export type ListenerReason =
  /** Before the first check, or a check that could not be made. */
  | "NOT_CHECKED"
  /** A listener did not bind its port. */
  | "NOT_LISTENING"
  /** The browser endpoint has no valid certificate: none loaded yet, or expired. */
  | "NO_CERTIFICATE"
  /** The LocalAPI did not answer, or not with the expected shape. */
  | "LOCALAPI_UNAVAILABLE"
  /** tailscaled is not connected to the tailnet (BackendState is not Running). */
  | "NOT_RUNNING"
  /** The node is on another tailnet than the pinned one. */
  | "OTHER_TAILNET"
  /** The node's name is no longer the browser endpoint's host. */
  | "NAME_CHANGED";

/**
 * The node as varlatchd last read it from the LocalAPI status, at the
 * report's checkedAt (Installation Admins only, like the rest). Each field
 * is checked: one that is absent or malformed is omitted, never guessed.
 * Who can reach the node is not here: only a client can find that out.
 */
export interface ObservedNode {
  /** The node's actual machine name: the first label of its DNS name. */
  name?: string;
  /** Its MagicDNS name, without the trailing dot. */
  dnsName?: string;
  /** The tailnet it is on: its MagicDNS suffix. */
  tailnet?: string;
  /** Its ACL tags; absent for an untagged node. */
  tags?: string[];
  /** Its Tailscale addresses, IPv4 first. */
  addresses?: string[];
  /** Its StableID. */
  nodeId?: string;
}

export interface TailnetListenerReport {
  configured: {
    tailnet: string;
    listenerPort: number;
    /** Null when the browser endpoint is off. */
    browserEndpoint: string | null;
  };
  observed: {
    /** Null before the first check. */
    checkedAt: string | null;
    checks: {
      listener: ObservedCheck;
      /** Only when the browser endpoint is configured. */
      browserTls?: ObservedCheck;
      localApi: ObservedCheck;
      node: ObservedCheck;
    };
    /** Absent before the first successful LocalAPI read, and after a failed one. */
    node?: ObservedNode;
  };
}

export const LISTENERS_STATUS_FILE = "tailnet-listeners.json";
const CHECK_EVERY_MS = 60_000;
/** The file is rewritten when a check changes, and at least this often, so a reader can tell a stale one. */
const REFRESH_FILE_MS = 5 * 60_000;

export function readListenerReport(dir: string): TailnetListenerReport | null {
  try {
    return JSON.parse(readFileSync(join(dir, LISTENERS_STATUS_FILE), "utf8")) as TailnetListenerReport;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw e;
  }
}

const UNCHECKED: ObservedCheck = { status: "unknown", reason: "NOT_CHECKED" };

const DNS_NAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const TAG = /^tag:[A-Za-z0-9][A-Za-z0-9-]{0,127}$/;
const STABLE_ID = /^[A-Za-z0-9]{1,64}$/;

/** A list whose every entry passes, or nothing: a partial list would read as complete. */
function allOf(value: unknown, ok: (entry: string) => boolean): string[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  return value.every((v) => typeof v === "string" && ok(v)) ? [...(value as string[])] : undefined;
}

/** The node's own details from a LocalAPI status answer; undefined when none is usable. */
export function observedNode(status: Record<string, unknown>): ObservedNode | undefined {
  const self = status.Self && typeof status.Self === "object" ? (status.Self as Record<string, unknown>) : {};
  const node: ObservedNode = {};
  const dnsName = typeof self.DNSName === "string" ? self.DNSName.replace(/\.$/, "").toLowerCase() : "";
  if (DNS_NAME.test(dnsName)) {
    node.name = dnsName.split(".")[0]!;
    node.dnsName = dnsName;
  }
  const suffix = typeof status.MagicDNSSuffix === "string" ? status.MagicDNSSuffix.toLowerCase() : "";
  if (DNS_NAME.test(suffix)) node.tailnet = suffix;
  const tags = allOf(self.Tags, (t) => TAG.test(t));
  if (tags) node.tags = tags;
  const addresses = allOf(self.TailscaleIPs, (a) => isIP(a) !== 0);
  if (addresses) node.addresses = addresses.sort((a, b) => isIP(a) - isIP(b));
  if (typeof self.ID === "string" && STABLE_ID.test(self.ID)) node.nodeId = self.ID;
  return Object.keys(node).length ? node : undefined;
}

export class TailnetObserver {
  readonly #socketPath: string;
  readonly #configured: TailnetListenerReport["configured"];
  readonly #browserHost: string | null;
  readonly #certificate: NodeCertificate | null;
  readonly #stateDir: string | null;
  readonly #write: (path: string, value: unknown) => void;
  readonly #now: () => number;
  #listening = { plain: null as boolean | null, browser: null as boolean | null };
  #checks: TailnetListenerReport["observed"]["checks"];
  #node: ObservedNode | undefined;
  #checkedAt: number | null = null;
  #persisted: { json: string; at: number } | null = null;
  #timer: NodeJS.Timeout | null = null;
  #started = false;
  /**
   * Checks overlap (the minute timer, a listener binding, a certificate
   * loading), and a LocalAPI answer can take a while: each check takes a
   * ticket when it starts, and one that ends after a newer check was
   * applied is dropped, so an older snapshot never replaces a newer one.
   */
  #issued = 0;
  #applied = 0;

  constructor(opts: {
    socketPath: string;
    expectedTailnet: string;
    listenerPort: number;
    browser: { host: string; port: number } | null;
    certificate: NodeCertificate | null;
    stateDir: string | null;
    write?: (path: string, value: unknown) => void;
    now?: () => number;
  }) {
    this.#socketPath = opts.socketPath;
    this.#browserHost = opts.browser?.host ?? null;
    this.#configured = {
      tailnet: opts.expectedTailnet,
      listenerPort: opts.listenerPort,
      browserEndpoint: opts.browser ? `https://${opts.browser.host}:${opts.browser.port}` : null,
    };
    this.#certificate = opts.certificate;
    this.#stateDir = opts.stateDir;
    this.#write = opts.write ?? durableJson;
    this.#now = opts.now ?? Date.now;
    this.#checks = { listener: UNCHECKED, ...(opts.browser ? { browserTls: UNCHECKED } : {}), localApi: UNCHECKED, node: UNCHECKED };
  }

  /** A listener bound its port (or failed to): checked again at once, not at the next minute. */
  listening(which: "plain" | "browser", ok: boolean): void {
    this.#listening[which] = ok;
    if (this.#started) void this.check();
  }

  report(): TailnetListenerReport {
    return {
      configured: { ...this.#configured },
      observed: {
        checkedAt: this.#checkedAt === null ? null : new Date(this.#checkedAt).toISOString(),
        checks: structuredClone(this.#checks),
        ...(this.#node ? { node: structuredClone(this.#node) } : {}),
      },
    };
  }

  /** Check now, then every 60 seconds. */
  start(): void {
    this.#started = true;
    void this.check();
    this.#timer = setInterval(() => void this.check(), CHECK_EVERY_MS);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  async check(): Promise<TailnetListenerReport> {
    const ticket = ++this.#issued;
    const wanted = this.#configured.browserEndpoint ? [this.#listening.plain, this.#listening.browser] : [this.#listening.plain];
    const listener: ObservedCheck = wanted.every((l) => l === true)
      ? { status: "pass" }
      : wanted.some((l) => l === false)
        ? { status: "fail", reason: "NOT_LISTENING" }
        : UNCHECKED;

    let localApi: ObservedCheck;
    let node: ObservedCheck = UNCHECKED;
    // Cleared unless this read succeeds: stale details never sit next to a failing check.
    let details: ObservedNode | undefined;
    try {
      const res = await localApiGet(this.#socketPath, "/localapi/v0/status?peers=false");
      const status = res.status === 200 ? (JSON.parse(res.body) as unknown) : null;
      const s = status && typeof status === "object" ? (status as Record<string, unknown>) : null;
      const self = s?.Self && typeof s.Self === "object" ? (s.Self as Record<string, unknown>) : null;
      if (!s || typeof s.BackendState !== "string") throw new Error(`LocalAPI status answered ${res.status}`);
      localApi = { status: "pass" };
      details = observedNode(s);
      const dnsName = typeof self?.DNSName === "string" ? self.DNSName.replace(/\.$/, "").toLowerCase() : "";
      const suffix = typeof s.MagicDNSSuffix === "string" ? s.MagicDNSSuffix.toLowerCase() : "";
      node =
        s.BackendState !== "Running"
          ? { status: "fail", reason: "NOT_RUNNING" }
          : suffix !== this.#configured.tailnet.toLowerCase()
            ? { status: "fail", reason: "OTHER_TAILNET" }
            : this.#browserHost && dnsName !== this.#browserHost
              ? { status: "fail", reason: "NAME_CHANGED" }
              : { status: "pass" };
    } catch (err) {
      localApi = { status: "fail", reason: "LOCALAPI_UNAVAILABLE" };
      if (this.#checks.localApi.status !== "fail") {
        console.warn(`varlatchd: tailnet listener check: LocalAPI status failed (${err instanceof Error ? err.message : String(err)})`);
      }
    }

    let browserTls: ObservedCheck | undefined;
    if (this.#configured.browserEndpoint) {
      const notAfter = this.#certificate?.status().notAfter ?? null;
      browserTls = this.#certificate?.context()
        ? { status: "pass", certificateNotAfter: notAfter! }
        : { status: "fail", reason: "NO_CERTIFICATE", ...(notAfter ? { certificateNotAfter: notAfter } : {}) };
    }

    if (ticket < this.#applied) return this.report();
    this.#applied = ticket;
    this.#checks = { listener, ...(browserTls ? { browserTls } : {}), localApi, node };
    this.#node = details;
    this.#checkedAt = this.#now();
    this.#persist();
    return this.report();
  }

  #persist(): void {
    if (!this.#stateDir) return;
    const json = JSON.stringify({ checks: this.#checks, node: this.#node ?? null });
    const now = this.#now();
    if (this.#persisted && this.#persisted.json === json && now - this.#persisted.at < REFRESH_FILE_MS) return;
    try {
      this.#write(join(this.#stateDir, LISTENERS_STATUS_FILE), this.report());
      this.#persisted = { json, at: now };
    } catch (err) {
      console.warn(`varlatchd: could not record the tailnet listener status (${err instanceof Error ? err.message : String(err)})`);
    }
  }
}
