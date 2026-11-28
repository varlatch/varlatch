// SPDX-License-Identifier: AGPL-3.0-or-later
import React, { createContext, useContext, useEffect, useState, useSyncExternalStore } from "react";
import { browserDeps, SignalStream, type InstallationNotice, type SignalDocs, type SignalStreamDeps } from "./sse";

/**
 * The Go server's live updates for the signed-in person (lib/sse.ts),
 * provided to realtime.ts's hooks. Mounted inside the auth gate, which
 * remounts it for another person, so a stream never outlives its session's
 * page.
 */
export const SseContext = createContext<SignalStream | null>(null);

export function SseProvider({ children, enabled = true, deps }: { children: React.ReactNode; enabled?: boolean; deps?: SignalStreamDeps }) {
  const [stream] = useState(() => new SignalStream(deps ?? browserDeps()));
  useEffect(() => {
    // Only with a session: the stream needs one.
    if (!enabled) return;
    stream.start();
    return () => stream.stop();
  }, [stream, enabled]);
  return <SseContext.Provider value={stream}>{children}</SseContext.Provider>;
}

export function useSseStream(): SignalStream {
  const stream = useContext(SseContext);
  if (!stream) throw new Error("realtime.sse: no SseProvider above this component");
  return stream;
}

const NOT_LOADED = () => undefined;
const NEVER = () => () => {};

/** An Organization's changeSignal; undefined until the stream first opened. */
export function useSseOrgDocs(orgId: string | undefined): SignalDocs {
  const stream = useContext(SseContext);
  return useSyncExternalStore(
    stream?.subscribe ?? NEVER,
    stream && orgId ? () => stream.orgDocs(orgId) : NOT_LOADED,
  );
}

/** The person's own identitySignal. */
export function useSseMeDocs(): SignalDocs {
  const stream = useContext(SseContext);
  return useSyncExternalStore(stream?.subscribe ?? NEVER, stream ? () => stream.meDocs() : NOT_LOADED);
}

/** Whether the stream is open. */
export function useSseConnected(): boolean {
  const stream = useContext(SseContext);
  return useSyncExternalStore(
    stream ? (fn: () => void) => stream.onConnection(fn) : NEVER,
    stream ? stream.isConnected : () => false,
  );
}

/** The installation's notice to every dashboard (the host restarts Varlatch for an upgrade), null for none. */
export function useSseInstallationNotice(): InstallationNotice | null {
  const stream = useContext(SseContext);
  return useSyncExternalStore(stream?.subscribe ?? NEVER, stream ? stream.installationNotice : () => null);
}
