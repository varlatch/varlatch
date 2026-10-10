// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
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
  #checkedAt: number | null = null;
  #persisted: { json: string; at: number } | null = null;
  #timer: NodeJS.Timeout | null = null;

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

  /** A listener bound its port (or failed to). */
  listening(which: "plain" | "browser", ok: boolean): void {
    this.#listening[which] = ok;
  }

  report(): TailnetListenerReport {
    return {
      configured: { ...this.#configured },
      observed: { checkedAt: this.#checkedAt === null ? null : new Date(this.#checkedAt).toISOString(), checks: structuredClone(this.#checks) },
    };
  }

  /** Check now, then every 60 seconds. */
  start(): void {
    void this.check();
    this.#timer = setInterval(() => void this.check(), CHECK_EVERY_MS);
    this.#timer.unref();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  async check(): Promise<TailnetListenerReport> {
    const wanted = this.#configured.browserEndpoint ? [this.#listening.plain, this.#listening.browser] : [this.#listening.plain];
    const listener: ObservedCheck = wanted.every((l) => l === true)
      ? { status: "pass" }
      : wanted.some((l) => l === false)
        ? { status: "fail", reason: "NOT_LISTENING" }
        : UNCHECKED;

    let localApi: ObservedCheck;
    let node: ObservedCheck = UNCHECKED;
    try {
      const res = await localApiGet(this.#socketPath, "/localapi/v0/status?peers=false");
      const status = res.status === 200 ? (JSON.parse(res.body) as unknown) : null;
      const s = status && typeof status === "object" ? (status as Record<string, unknown>) : null;
      const self = s?.Self && typeof s.Self === "object" ? (s.Self as Record<string, unknown>) : null;
      if (!s || typeof s.BackendState !== "string") throw new Error(`LocalAPI status answered ${res.status}`);
      localApi = { status: "pass" };
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

    this.#checks = { listener, ...(browserTls ? { browserTls } : {}), localApi, node };
    this.#checkedAt = this.#now();
    this.#persist();
    return this.report();
  }

  #persist(): void {
    if (!this.#stateDir) return;
    const json = JSON.stringify(this.#checks);
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
