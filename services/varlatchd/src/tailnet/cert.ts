// SPDX-License-Identifier: AGPL-3.0-or-later
import { X509Certificate, createPrivateKey } from "node:crypto";
import { createSecureContext, type SecureContext } from "node:tls";
import { localApiGet } from "./localapi.js";

/**
 * The tailnet browser endpoint's certificate (ADR-0046 Decision 3): the
 * node's own Let's Encrypt pair, fetched from tailscaled's LocalAPI, which
 * needs cert permission for varlatchd's uid (TS_PERMIT_CERT_UID), never
 * write access. The key stays in memory; nothing is written to disk.
 *
 * Fetched at start and daily, sooner after a failure. A pair that does not
 * name the host, is not valid now, or whose key does not match is never
 * swapped in. When renewal keeps failing the last valid certificate serves
 * until it expires; after that `context()` is null and the port refuses
 * every handshake.
 */

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** An ACME order (first issuance or renewal) takes far longer than other LocalAPI calls (spike S3). */
const FETCH_TIMEOUT_MS = 180_000;
const RETRY_FIRST_MS = 30_000;

export interface NodeCertificateStatus {
  /** When the certificate in use expires; null before one loads. */
  notAfter: string | null;
  /** Why the last fetch was not used; null after a success. */
  lastError: string | null;
  /** When the last fetch finished; null before the first. */
  checkedAt: string | null;
}

interface Loaded {
  context: SecureContext;
  notBefore: number;
  notAfter: number;
}

/** Decode a LocalAPI `type=pair` answer (key, then the chain), or say why it cannot be used. */
export function decodePair(body: string, host: string, now: number): Loaded | string {
  const blocks = [...body.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----[\s\S]+?-----END \1-----/g)];
  const keys = blocks.filter((b) => b[1]!.endsWith("PRIVATE KEY")).map((b) => b[0]);
  const chain = blocks.filter((b) => b[1] === "CERTIFICATE").map((b) => b[0]);
  if (keys.length !== 1 || chain.length === 0) return "the answer is not one key with a certificate";
  let leaf: X509Certificate;
  try {
    leaf = new X509Certificate(chain[0]!);
  } catch {
    return "the certificate does not parse";
  }
  if (!leaf.checkHost(host, { subject: "never", wildcards: false })) return `the certificate does not name ${host}`;
  const notBefore = new Date(leaf.validFrom).getTime();
  const notAfter = new Date(leaf.validTo).getTime();
  if (!(now >= notBefore && now < notAfter)) return "the certificate is not valid now";
  try {
    if (!leaf.checkPrivateKey(createPrivateKey(keys[0]!))) return "the key does not match the certificate";
    return { context: createSecureContext({ key: keys[0], cert: chain.join("\n"), minVersion: "TLSv1.2" }), notBefore, notAfter };
  } catch {
    return "the key does not parse";
  }
}

export class NodeCertificate {
  readonly #socketPath: string;
  readonly #host: string;
  readonly #now: () => number;
  #loaded: Loaded | null = null;
  #lastError: string | null = null;
  #checkedAt: number | null = null;
  #inFlight: Promise<boolean> | null = null;
  #timer: NodeJS.Timeout | null = null;
  #failures = 0;
  #running = false;

  constructor(opts: { socketPath: string; host: string; now?: () => number }) {
    this.#socketPath = opts.socketPath;
    this.#host = opts.host;
    this.#now = opts.now ?? Date.now;
  }

  /** What to serve now, or null when no valid certificate is loaded: the handshake is then refused. */
  context(): SecureContext | null {
    const now = this.#now();
    const loaded = this.#loaded;
    return loaded && now >= loaded.notBefore && now < loaded.notAfter ? loaded.context : null;
  }

  status(): NodeCertificateStatus {
    return {
      notAfter: this.#loaded ? new Date(this.#loaded.notAfter).toISOString() : null,
      lastError: this.#lastError,
      checkedAt: this.#checkedAt === null ? null : new Date(this.#checkedAt).toISOString(),
    };
  }

  /** Fetch now, then keep refreshing until stop(). Resolves with the first fetch's outcome. */
  start(): Promise<boolean> {
    this.#running = true;
    return this.#cycle();
  }

  stop(): void {
    this.#running = false;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
  }

  /** Fetch once and swap in a valid pair. Concurrent callers share the fetch. */
  refresh(): Promise<boolean> {
    if (!this.#inFlight) this.#inFlight = this.#fetch().finally(() => (this.#inFlight = null));
    return this.#inFlight;
  }

  async #cycle(): Promise<boolean> {
    const ok = await this.refresh();
    if (this.#running) {
      if (this.#timer) clearTimeout(this.#timer);
      this.#timer = setTimeout(() => void this.#cycle(), this.#nextDelay(ok));
      this.#timer.unref();
    }
    return ok;
  }

  #nextDelay(ok: boolean): number {
    if (ok) {
      this.#failures = 0;
      const left = this.#loaded!.notAfter - this.#now();
      return left < 2 * DAY ? HOUR : DAY;
    }
    this.#failures++;
    return Math.min(HOUR, RETRY_FIRST_MS * 2 ** Math.min(this.#failures - 1, 7));
  }

  /**
   * Ask tailscaled to renew early: once a lifetime is known, the returned
   * pair must stay valid for a third of it (at most a week), so a daily
   * fetch renews well before expiry without asking for more than a fresh
   * certificate could give, which would renew on every fetch.
   */
  #minValidity(): string {
    if (!this.#loaded) return "";
    const lifetime = this.#loaded.notAfter - this.#loaded.notBefore;
    const hours = Math.max(1, Math.floor(Math.min(7 * DAY, lifetime / 3) / HOUR));
    return `&min_validity=${hours}h`;
  }

  async #fetch(): Promise<boolean> {
    const path = `/localapi/v0/cert/${encodeURIComponent(this.#host)}?type=pair${this.#minValidity()}`;
    let outcome: Loaded | string;
    try {
      const res = await localApiGet(this.#socketPath, path, FETCH_TIMEOUT_MS);
      outcome =
        res.status === 200
          ? decodePair(res.body, this.#host, this.#now())
          : `tailscaled answered ${res.status}: ${res.body.trim().slice(0, 200) || "(no message)"}`;
    } catch (err) {
      outcome = `tailscaled is not reachable (${err instanceof Error ? err.message : String(err)})`;
    }
    this.#checkedAt = this.#now();
    if (typeof outcome === "string") {
      // Once per distinct reason: retries must not flood the log.
      if (outcome !== this.#lastError) {
        console.warn(`varlatchd: tailnet browser endpoint certificate for ${this.#host} not loaded: ${outcome}`);
      }
      this.#lastError = outcome;
      return false;
    }
    const replaced = this.#loaded;
    this.#loaded = outcome;
    this.#lastError = null;
    if (!replaced || replaced.notAfter !== outcome.notAfter) {
      console.log(`varlatchd: tailnet browser endpoint certificate for ${this.#host} loaded, valid until ${new Date(outcome.notAfter).toISOString()}`);
    }
    return true;
  }
}
