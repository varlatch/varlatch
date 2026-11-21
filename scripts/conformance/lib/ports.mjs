// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { createServer } from "node:net";

/**
 * Loopback ports for a target's servers and fixtures, chosen so nothing else
 * takes them before they are used.
 *
 * A port the kernel picks (listen on port 0) comes from its ephemeral range,
 * the range every outbound client socket draws its local port from too. A
 * target reserves its ports when it is installed and binds some of them
 * minutes later (the OIDC issuer, the webhook receiver), after hundreds of
 * local connections: one of those can hold the port by then, and the bind
 * fails. So ports are picked below the ephemeral range instead, where the
 * kernel never assigns a client socket, each checked free with a bind, and
 * never twice in one process.
 */

const picked = new Set();

/** The kernel's ephemeral range, [low, high]; Linux's default when unreadable. */
export function ephemeralRange(read = () => readFileSync("/proc/sys/net/ipv4/ip_local_port_range", "utf8")) {
  try {
    const [low, high] = read().trim().split(/\s+/).map(Number);
    if (Number.isInteger(low) && Number.isInteger(high) && low > 0 && high >= low) return [low, high];
  } catch {
    // Not Linux: macOS's range (49152-65535) starts higher than Linux's.
  }
  return [32768, 60999];
}

/** The range ports are picked from: below the ephemeral range, above the well-known services. */
export function pickRange([ephemeralLow] = ephemeralRange()) {
  const high = ephemeralLow - 1;
  const low = Math.min(20000, Math.max(1024, high - 2000));
  return [low, high];
}

function bindable(port) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => server.close(() => resolve(true)));
  });
}

/**
 * One free loopback port below the ephemeral range, not picked before by this
 * process. After `tries` taken candidates it falls back to a port the kernel
 * picks, which still works, only with the race above.
 */
export async function reservePort({ range = pickRange(), tries = 64, random = Math.random } = {}) {
  const [low, high] = range;
  for (let i = 0; i < tries; i++) {
    const port = low + Math.floor(random() * (high - low + 1));
    if (picked.has(port)) continue;
    picked.add(port);
    if (await bindable(port)) return port;
  }
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  picked.add(port);
  return port;
}

/** `count` distinct free ports (reservePort). */
export async function reservePorts(count, options) {
  const ports = [];
  for (let i = 0; i < count; i++) ports.push(await reservePort(options));
  return ports;
}
