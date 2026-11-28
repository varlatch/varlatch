// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Live updates from the Go server (realtime.sse; ADR-0059 Decision 4):
 * server-sent events at /auth/events, authenticated by the browser's
 * session cookie. The server sends, on one stream, the changeSignal of each
 * Organization the person is a member of and their own identitySignal, the
 * same signals the TypeScript server stored in Convex (realtime.ts reads
 * both the same way):
 *
 *   event: ready     {"identityId"}               the stream is open
 *   event: change    {"organizationId", "lastEventId", "occurredAt", "domains"}
 *   event: identity  {"lastEventId", "occurredAt", "domains"}
 *   event: installation {"notice": "upgrade-restarting", "version"} | {"notice": null}
 *                        to every stream: the host restarts varlatchd for an
 *                        upgrade (ADR-0065), or no longer does
 *   event: close     {"reason"}                   the server ends the stream
 *
 * Nothing is replayed: signals sent while the stream is down are lost, and
 * the dashboard refreshes its queries when it reconnects
 * (LiveUpdatesController). This store keeps the latest signal of each
 * Organization and of the person, and reconnects by itself, backing off
 * from 1 to 30 seconds with jitter.
 */

export interface Signal {
  lastEventId?: string;
  occurredAt?: string;
  domains?: string[];
}

/** The installation's notice to every dashboard (ADR-0065 Decision 8). */
export interface InstallationNotice {
  kind: "upgrade-restarting";
  version: string | null;
}

/** What a realtime.ts hook reads: undefined until the stream first opened; then [] or the latest signal. */
export type SignalDocs = { data?: Signal }[] | undefined;

/** The part of EventSource this store uses. */
export interface EventSourceLike {
  addEventListener(type: string, listener: (event: MessageEvent) => void): void;
  onerror: ((event: Event) => void) | null;
  close(): void;
}

export interface SignalStreamDeps {
  open(url: string): EventSourceLike;
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(handle: unknown): void;
  random?: () => number;
}

export const EVENTS_URL = "/auth/events";
export const RECONNECT_START_MS = 1_000;
export const RECONNECT_MAX_MS = 30_000;
/** After "replaced" (too many tabs of one session), wait this long: reconnecting at once would close another tab's stream. */
export const REPLACED_WAIT_MS = 60_000;

export function reconnectDelay(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(RECONNECT_START_MS * 2 ** attempt, RECONNECT_MAX_MS);
  return Math.round(base * (0.8 + 0.4 * random()));
}

const EMPTY: { data?: Signal }[] = [];

export class SignalStream {
  private source: EventSourceLike | null = null;
  private timer: unknown = null;
  private attempt = 0;
  private stopped = true;
  private connected = false;
  private opened = false;
  private closeReason: string | null = null;
  private orgs = new Map<string, { data: Signal }[]>();
  private me: { data: Signal }[] | null = null;
  private notice: InstallationNotice | null = null;
  private listeners = new Set<() => void>();
  private connectionListeners = new Set<(connected: boolean) => void>();

  constructor(private readonly deps: SignalStreamDeps) {}

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer !== null) this.deps.clearTimer(this.timer);
    this.timer = null;
    this.source?.close();
    this.source = null;
    this.setConnected(false);
  }

  isConnected = (): boolean => this.connected;

  /** Connection changes, for LiveUpdatesStatus. */
  onConnection = (fn: (connected: boolean) => void): (() => void) => {
    this.connectionListeners.add(fn);
    return () => this.connectionListeners.delete(fn);
  };

  /** Signal changes, for useSyncExternalStore. */
  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  /** The Organization's latest changeSignal, as a stable snapshot. */
  orgDocs(orgId: string): SignalDocs {
    if (!this.opened) return undefined;
    return this.orgs.get(orgId) ?? EMPTY;
  }

  /** The installation's notice now, as a stable snapshot: null for none. */
  installationNotice = (): InstallationNotice | null => this.notice;

  /** The person's latest identitySignal, as a stable snapshot. */
  meDocs(): SignalDocs {
    if (!this.opened) return undefined;
    return this.me ?? EMPTY;
  }

  private connect(): void {
    this.timer = null;
    if (this.stopped) return;
    this.closeReason = null;
    let source: EventSourceLike;
    try {
      source = this.deps.open(EVENTS_URL);
    } catch {
      this.retry();
      return;
    }
    this.source = source;
    source.addEventListener("ready", () => {
      if (this.source !== source) return;
      this.attempt = 0;
      this.opened = true;
      // A notice that still stands is sent again after ready.
      this.notice = null;
      this.setConnected(true);
      this.emit();
    });
    source.addEventListener("change", (e) => {
      const parsed = this.parse(e);
      if (this.source !== source || !parsed?.organizationId || parsed.lastEventId === undefined) return;
      const { organizationId, reason: _reason, ...signal } = parsed;
      this.orgs.set(organizationId, [{ data: signal }]);
      this.emit();
    });
    source.addEventListener("identity", (e) => {
      const parsed = this.parse(e);
      if (this.source !== source || parsed?.lastEventId === undefined) return;
      const { organizationId: _org, reason: _reason, ...signal } = parsed;
      this.me = [{ data: signal }];
      this.emit();
    });
    source.addEventListener("installation", (e) => {
      if (this.source !== source) return;
      let v: unknown;
      try {
        v = JSON.parse(String(e.data));
      } catch {
        return;
      }
      const data = v && typeof v === "object" ? (v as Record<string, unknown>) : null;
      if (!data || !("notice" in data)) return;
      this.notice =
        data.notice === "upgrade-restarting" ? { kind: "upgrade-restarting", version: typeof data.version === "string" ? data.version : null } : null;
      this.emit();
    });
    source.addEventListener("close", (e) => {
      if (this.source !== source) return;
      this.closeReason = this.parse(e)?.reason ?? "unknown";
    });
    // The browser would reconnect by itself after an error; this store
    // decides when instead (backoff, and none while stopped).
    source.onerror = () => {
      if (this.source !== source) return;
      source.close();
      this.source = null;
      this.setConnected(false);
      this.retry();
    };
  }

  private retry(): void {
    if (this.stopped || this.timer !== null) return;
    const ms = this.closeReason === "replaced" ? REPLACED_WAIT_MS : reconnectDelay(this.attempt, this.deps.random);
    this.attempt += 1;
    this.timer = this.deps.setTimer(() => this.connect(), ms);
  }

  /** An event's data: a signal of the expected shape, else null (ignored). */
  private parse(e: MessageEvent): (Signal & { organizationId?: string; reason?: string }) | null {
    let v: Record<string, unknown>;
    try {
      v = JSON.parse(String(e.data)) as Record<string, unknown>;
    } catch {
      return null;
    }
    if (!v || typeof v !== "object") return null;
    const out: Signal & { organizationId?: string; reason?: string } = {};
    if (typeof v.lastEventId === "string") out.lastEventId = v.lastEventId;
    if (typeof v.occurredAt === "string") out.occurredAt = v.occurredAt;
    if (Array.isArray(v.domains) && v.domains.every((d) => typeof d === "string")) out.domains = v.domains as string[];
    if (typeof v.organizationId === "string") out.organizationId = v.organizationId;
    if (typeof v.reason === "string") out.reason = v.reason;
    return out;
  }

  private setConnected(connected: boolean): void {
    if (this.connected === connected) return;
    this.connected = connected;
    for (const fn of this.connectionListeners) fn(connected);
  }

  private emit(): void {
    for (const fn of this.listeners) fn();
  }
}

/** The browser's EventSource, same-origin with the session cookie. */
export function browserDeps(): SignalStreamDeps {
  return {
    open: (url) => new EventSource(url, { withCredentials: false }) as unknown as EventSourceLike,
    setTimer: (fn, ms) => window.setTimeout(fn, ms),
    clearTimer: (handle) => window.clearTimeout(handle as number),
  };
}
