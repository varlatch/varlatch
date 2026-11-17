// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { TailnetDevice } from "@varlatch/protocol";
import { VarlatchClient } from "@varlatch/sdk";
import { useSession } from "./session";
import { useCapability } from "../features/projects/hooks";

/**
 * Reading tailnet-protected values from this browser (ADR-0046 Decision 5).
 *
 * The installation may serve a tailnet browser endpoint: varlatchd over
 * HTTPS on its tailnet name, where the device is checked on each request's
 * own connection. Nothing here goes to it until the person chooses Connect
 * in this tab; that first request (GET /v1/tailnet/context) is when a
 * browser may ask to allow access to the local network. After a successful
 * connect, protected value reads in this tab go to the endpoint; nothing
 * else does. The connected state lives in this tab's memory and is never
 * authority: varlatchd checks the device again on every request.
 *
 * Who observed what: the endpoint is *configured* (varlatchd says where it
 * is); the device is *checked by Varlatch* on the endpoint; reachability is
 * only ever known *from this browser*, by trying.
 */

/** The Connect probe gives up after this long: off the tailnet, a request can hang until the page aborts it (spike S5). */
export const PROBE_TIMEOUT_MS = 4_000;
/** The first Connect probe where the browser may ask for local network access first. */
export const PERMISSION_PROBE_TIMEOUT_MS = 30_000;
/** A protected read through the endpoint gives up after this long. */
export const READ_TIMEOUT_MS = 15_000;

export type TailnetConnection =
  /** No endpoint configured, or a server without it: protected values stay out of the dashboard. */
  | { status: "unavailable" }
  /** Configured; this tab has not connected. */
  | { status: "idle"; endpoint: string }
  /** `awaitingPermission`: the probe has waited past the usual limit, likely on the browser's local network prompt. */
  | { status: "connecting"; endpoint: string; awaitingPermission?: true }
  /** The endpoint answered from this browser and Varlatch recognized this device. */
  | { status: "connected"; endpoint: string; device: TailnetDevice; checkedAt: number }
  /** The endpoint answered, but Varlatch did not recognize this device. */
  | { status: "unrecognized"; endpoint: string; reason: string; checkedAt: number }
  /** No answer from this browser; `blockedByPolicy` when the page's own security policy stopped it. */
  | { status: "unreachable"; endpoint: string; blockedByPolicy: boolean; checkedAt: number };

/** An endpoint request that got no answer: nothing was read, and a POST is never sent again. */
export class TailnetUnreachableError extends Error {
  readonly code = "TAILNET_UNREACHABLE";
  constructor() {
    super("The tailnet endpoint stopped answering from this browser, so nothing was read. Varlatch is checking the connection again.");
    this.name = "TailnetUnreachableError";
  }
}

interface TailnetConnectionState {
  connection: TailnetConnection;
  /** The explicit Connect action, also "Try again". */
  connect: () => void;
  /** Client for protected value reads; only while connected. */
  client: VarlatchClient | null;
}

const UNAVAILABLE: TailnetConnectionState = { connection: { status: "unavailable" }, connect: () => {}, client: null };
const TailnetConnectionContext = createContext<TailnetConnectionState>(UNAVAILABLE);

/** Query-key part for values read through the endpoint, so they never share a cache entry with ordinary reads. */
export function tailnetReadKey(connection: TailnetConnection): string {
  return connection.status === "connected" ? `tailnet:${connection.device.nodeId ?? ""}` : "ordinary";
}

/**
 * Runs `run` with a signal that aborts after `ms` (or when `given` aborts),
 * and settles by then whatever `run` is waiting for, a token re-exchange
 * included: the operation as a whole has the deadline, not only its fetch.
 */
async function withTimeout<T>(ms: number, given: AbortSignal | null | undefined, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(new DOMException("The tailnet endpoint did not answer in time", "TimeoutError")), ms);
  const forward = () => ctl.abort(given!.reason);
  if (given?.aborted) forward();
  else given?.addEventListener("abort", forward, { once: true });
  const deadline = new Promise<never>((_, reject) => {
    if (ctl.signal.aborted) reject(ctl.signal.reason);
    else ctl.signal.addEventListener("abort", () => reject(ctl.signal.reason), { once: true });
  });
  try {
    return await Promise.race([run(ctl.signal), deadline]);
  } finally {
    clearTimeout(timer);
    given?.removeEventListener("abort", forward);
  }
}

/**
 * Whether this browser takes fetch's `targetAddressSpace` with Local Network
 * Access's address spaces ("loopback", "local", "public"): it reads the option
 * while building a Request, where a browser without it never looks. Older
 * Chromium read it too, but there "local" meant loopback and "loopback" did
 * not exist, so a browser must accept both values to count.
 */
export function supportsTargetAddressSpace(RequestImpl: typeof Request | undefined = globalThis.Request): boolean {
  if (typeof RequestImpl !== "function") return false;
  const accepts = (value: string) => {
    let read = false;
    const init = {
      get targetAddressSpace() {
        read = true;
        return value;
      },
    };
    try {
      new RequestImpl("https://tailnet-endpoint.invalid/", init as RequestInit);
    } catch {
      return false;
    }
    return read;
  };
  return accepts("loopback") && accepts("local");
}

/**
 * The options of every request to the tailnet endpoint: no cookies, and, where
 * the browser takes it, the endpoint declared as on the local network, so the
 * browser asks for permission up front (the endpoint is a tailnet address,
 * and the dashboard may be on a public origin).
 */
export function endpointRequestInit(init: RequestInit | undefined, localAddressSpace: boolean): RequestInit {
  return { ...init, credentials: "omit", ...(localAddressSpace ? { targetAddressSpace: "local" } : {}) } as RequestInit;
}

/**
 * How long a Connect probe waits. Where the browser may be showing its local
 * network permission prompt (it takes targetAddressSpace, and this tab has
 * not connected yet), the person gets time to answer it.
 */
export function probeTimeout(localAddressSpace: boolean, connectedBefore: boolean): number {
  return localAddressSpace && !connectedBefore ? PERMISSION_PROBE_TIMEOUT_MS : PROBE_TIMEOUT_MS;
}

/** No answer: a network error, or this side gave up waiting (not a session change, which is its own abort). */
const isNetworkFailure = (err: unknown) =>
  err instanceof TypeError ||
  (err instanceof DOMException && (err.name === "TimeoutError" || (err.name === "AbortError" && err.message !== "Session changed")));

export function TailnetConnectionProvider({ children }: { children: React.ReactNode }) {
  const { api, fetch: sessionFetch, identityId, onStepUp } = useSession();
  const qc = useQueryClient();
  const offered = useCapability("tailnet.browser-reads");
  const endpointQuery = useQuery({
    queryKey: ["tailnet-endpoint"],
    queryFn: () => api.tailnetEndpoint(),
    enabled: offered && identityId !== null,
    staleTime: 5 * 60_000,
    retry: false,
  });
  const endpoint = offered ? (endpointQuery.data?.browserEndpoint ?? null) : null;
  const [probe, setProbe] = useState<Exclude<TailnetConnection, { status: "unavailable" | "idle" }> | null>(null);
  // Bumped by every connect and every reset: an older probe's answer is dropped.
  const generation = useRef(0);
  const [localAddressSpace] = useState(() => supportsTargetAddressSpace());
  // Whether a probe has connected since the last reset: later probes need no time for a permission prompt.
  const connectedBefore = useRef(false);

  // Another identity, or another endpoint: start over, unconnected.
  useEffect(() => {
    generation.current++;
    connectedBefore.current = false;
    setProbe(null);
  }, [identityId, endpoint]);

  const runProbe = useCallback(async () => {
    if (!endpoint) return;
    const mine = ++generation.current;
    setProbe({ status: "connecting", endpoint });
    let blockedByPolicy = false;
    const onViolation = (e: SecurityPolicyViolationEvent) => {
      if (e.blockedURI.startsWith(endpoint)) blockedByPolicy = true;
    };
    globalThis.document?.addEventListener("securitypolicyviolation", onViolation);
    const timeout = probeTimeout(localAddressSpace, connectedBefore.current);
    const slow =
      timeout > PROBE_TIMEOUT_MS
        ? setTimeout(() => {
            if (generation.current === mine) setProbe({ status: "connecting", endpoint, awaitingPermission: true });
          }, PROBE_TIMEOUT_MS)
        : undefined;
    let next: TailnetConnection;
    try {
      const body = await withTimeout(timeout, null, async (signal) => {
        const res = await sessionFetch(`${endpoint}/v1/tailnet/context`, endpointRequestInit({ signal }, localAddressSpace));
        return res.ok ? ((await res.json()) as TailnetDevice) : null;
      });
      next = !body
        ? { status: "unreachable", endpoint, blockedByPolicy: false, checkedAt: Date.now() }
        : body.recognized
          ? { status: "connected", endpoint, device: body, checkedAt: Date.now() }
          : { status: "unrecognized", endpoint, reason: body.reason ?? "unrecognized", checkedAt: Date.now() };
    } catch {
      // The violation event is queued; let it land first.
      await new Promise((r) => setTimeout(r, 0));
      next = { status: "unreachable", endpoint, blockedByPolicy, checkedAt: Date.now() };
    } finally {
      clearTimeout(slow);
      globalThis.document?.removeEventListener("securitypolicyviolation", onViolation);
    }
    if (generation.current !== mine) return;
    if (next.status === "connected") connectedBefore.current = true;
    setProbe(next);
  }, [endpoint, sessionFetch, localAddressSpace]);

  const connection = useMemo<TailnetConnection>(
    () => (!endpoint ? { status: "unavailable" } : probe && probe.endpoint === endpoint ? probe : { status: "idle", endpoint }),
    [endpoint, probe],
  );

  // Values read through the endpoint leave the cache once the tab is no longer connected as that device.
  const readKey = tailnetReadKey(connection);
  useEffect(() => {
    qc.removeQueries({
      predicate: (q) => q.queryKey.some((part) => typeof part === "string" && part.startsWith("tailnet:") && part !== readKey),
    });
  }, [qc, readKey]);

  const client = useMemo(() => {
    if (connection.status !== "connected") return null;
    return new VarlatchClient({
      server: connection.endpoint,
      // An export through the endpoint may need a step-up approval
      // (ADR-0054 amendment C): the dashboard's dialog handles it, as for
      // the dashboard's own requests.
      onStepUp,
      fetch: async (input, init) => {
        try {
          // The whole response, body included, within the time limit.
          const res = await withTimeout(READ_TIMEOUT_MS, init?.signal, async (signal) => {
            const answer = await sessionFetch(input, endpointRequestInit({ ...init, signal }, localAddressSpace));
            const body = await answer.arrayBuffer();
            return new Response([101, 204, 205, 304].includes(answer.status) ? null : body, {
              status: answer.status,
              statusText: answer.statusText,
              headers: answer.headers,
            });
          });
          return res;
        } catch (err) {
          if (!isNetworkFailure(err)) throw err;
          // Never sent again; check the connection instead (ADR-0046, Failure handling).
          void runProbe();
          throw new TailnetUnreachableError();
        }
      },
    });
  }, [connection, sessionFetch, runProbe, onStepUp, localAddressSpace]);

  const value = useMemo(() => ({ connection, connect: () => void runProbe(), client }), [connection, client, runProbe]);
  return <TailnetConnectionContext.Provider value={value}>{children}</TailnetConnectionContext.Provider>;
}

export function useTailnetConnection(): TailnetConnectionState {
  return useContext(TailnetConnectionContext);
}

/** Why Varlatch did not recognize this device, in words. */
export function unrecognizedReason(reason: string): string {
  switch (reason) {
    case "shared":
      return "it is shared into the tailnet from another one, and shared devices are refused";
    case "other-tailnet":
      return "it belongs to another tailnet";
    case "self":
      return "it is the Varlatch server itself";
    case "resolver-unavailable":
      return "Varlatch could not ask Tailscale who it is; try again in a moment";
    default:
      return "Tailscale does not know this connection";
  }
}
