// SPDX-License-Identifier: Apache-2.0

/**
 * The Node.js release the CLI runs on. Each maintained release line maps to
 * its oldest release with the security fixes the CLI needs. A release below
 * that, or one of an unlisted line older than the newest listed one (an
 * end-of-life line), gets one warning on stderr; stdout and the exit status
 * are unchanged. The CLI still runs: a refusal would stop pipelines whose
 * runner image lags a Node.js security release by a few days.
 *
 * Raised with each Node.js security release that fixes something the CLI
 * reaches. The October 2026 releases fixed CVE-2026-111497, an
 * out-of-bounds write in the Brotli decoder, which fetch() and the broker's
 * response scrubbing both feed with bytes from the network, and two TLS
 * hostname check bypasses.
 */
export const NODE_SECURITY_FLOOR: Readonly<Record<number, string>> = { 22: "22.23.4", 24: "24.22.1", 26: "26.12.1" };

/**
 * `off` hides the warning: for a Node.js build that carries the fixes under
 * an older version number, as a distribution's backport can.
 */
export const NODE_CHECK_ENV = "VARLATCH_NODE_CHECK";

type Version = [number, number, number];

function parseVersion(version: string): Version | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function isBelow(a: Version, b: Version): boolean {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i]! < b[i]!;
  return false;
}

function orList(items: string[]): string {
  return items.length < 2 ? items.join("") : `${items.slice(0, -1).join(", ")} or ${items[items.length - 1]}`;
}

/**
 * The warning for running on Node.js `version` (as in process.versions.node),
 * or null: the release has its line's fixes, its line is newer than every
 * listed one (its first release came after them), the version cannot be
 * read, or the check is off.
 */
export function nodeRuntimeWarning(version: string, env: NodeJS.ProcessEnv): string | null {
  if (env[NODE_CHECK_ENV] === "off") return null;
  const running = parseVersion(version);
  if (running === null) return null;
  const lines = Object.keys(NODE_SECURITY_FLOOR)
    .map(Number)
    .sort((a, b) => a - b);
  if (running[0] > lines[lines.length - 1]!) return null;
  const hide = `${NODE_CHECK_ENV}=off hides this warning.`;
  const floor = NODE_SECURITY_FLOOR[running[0]];
  if (floor !== undefined) {
    if (!isBelow(running, parseVersion(floor)!)) return null;
    return `varlatch: Node.js ${version} is missing security fixes; update it to ${floor} or later. ${hide}`;
  }
  return (
    `varlatch: Node.js ${version} no longer receives security fixes; use Node.js ${orList(lines.map(String))} ` +
    `(at least ${orList(lines.map((line) => NODE_SECURITY_FLOOR[line]!))}). ${hide}`
  );
}
