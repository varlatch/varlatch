// SPDX-License-Identifier: AGPL-3.0-or-later
import { networkInterfaces } from "node:os";

/**
 * In the Tailscale topology varlatchd shares the sidecar's network namespace
 * (`network_mode: service:tailscale`, ADR-0014). When the sidecar restarts
 * outside Compose — a crash, the container runtime's restart policy — its
 * namespace is replaced and varlatchd is left in the old one with only
 * loopback: still "healthy" to its own localhost healthcheck, unreachable to
 * everything else. Exiting lets the restart policy start varlatchd again
 * inside the sidecar's new namespace. (Restarts Compose performs itself are
 * covered by `depends_on: restart: true` in the overlay.)
 */
export function onlyLoopback(interfaces: ReturnType<typeof networkInterfaces> = networkInterfaces()): boolean {
  return Object.values(interfaces).flat().every((address) => !address || address.internal);
}

export function startNetnsWatchdog(opts: {
  intervalMs?: number;
  strikes?: number;
  check?: () => boolean;
  exit?: (code: number) => void;
  log?: (message: string) => void;
} = {}): () => void {
  const strikes = opts.strikes ?? 3;
  let seen = 0;
  const timer = setInterval(() => {
    if (!(opts.check ?? onlyLoopback)()) { seen = 0; return; }
    if (++seen < strikes) return;
    (opts.log ?? console.error)(
      "varlatchd lost its network: only loopback remains (the Tailscale sidecar was restarted). " +
        "Exiting so the container restarts inside the sidecar's new network namespace.",
    );
    clearInterval(timer);
    (opts.exit ?? process.exit)(1);
  }, opts.intervalMs ?? 5000);
  timer.unref();
  return () => clearInterval(timer);
}
