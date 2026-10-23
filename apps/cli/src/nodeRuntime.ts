// SPDX-License-Identifier: Apache-2.0

/**
 * The Node.js release the CLI runs on. Each maintained release line maps to
 * its oldest release with the security fixes the CLI needs. A release below
 * that, one of an unlisted line older than the newest listed one (an
 * end-of-life line), or a prerelease of any line (a nightly or release
 * candidate, whose fixes the version cannot show) gets one warning on
 * stderr; stdout and the exit status are unchanged. The CLI still runs: a refusal would stop pipelines whose
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

/** The release numbers, and whether anything follows them (`-rc.1`, `-nightly…`, `-pre`). */
function parseVersion(version: string): { release: Version; prerelease: boolean } | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(.*)$/.exec(version);
  return m ? { release: [Number(m[1]), Number(m[2]), Number(m[3])], prerelease: m[4] !== "" } : null;
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
 * or null: the release has its line's fixes, it is a release of a line newer
 * than every listed one (its first release came after them), the version
 * cannot be read, or the check is off. A prerelease is judged before the
 * newer-line exemption: a nightly of the next line can predate the fixes.
 */
export function nodeRuntimeWarning(version: string, env: NodeJS.ProcessEnv): string | null {
  if (env[NODE_CHECK_ENV] === "off") return null;
  const parsed = parseVersion(version);
  if (parsed === null) return null;
  const running = parsed.release;
  const lines = Object.keys(NODE_SECURITY_FLOOR)
    .map(Number)
    .sort((a, b) => a - b);
  const hide = `${NODE_CHECK_ENV}=off hides this warning.`;
  const supported = `Node.js ${orList(lines.map(String))} (at least ${orList(lines.map((line) => NODE_SECURITY_FLOOR[line]!))})`;
  if (parsed.prerelease) {
    return `varlatch: Node.js ${version} is a prerelease, so whether it has the security fixes cannot be checked; use a release of ${supported}. ${hide}`;
  }
  if (running[0] > lines[lines.length - 1]!) return null;
  const floor = NODE_SECURITY_FLOOR[running[0]];
  if (floor !== undefined) {
    if (!isBelow(running, parseVersion(floor)!.release)) return null;
    return `varlatch: Node.js ${version} is missing security fixes; update it to ${floor} or later. ${hide}`;
  }
  return `varlatch: Node.js ${version} no longer receives security fixes; use ${supported}. ${hide}`;
}
