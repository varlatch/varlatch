// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * What `varlatchd admin migration <verb>` says when it fails in a way it
 * did not refuse on purpose (go-step7 7.8b: the rehearsal on a real
 * installation found the export unable to write its bundle, behind the
 * CLI's catch-all). It names the failure's kind and place, never anything
 * it read or would write:
 *   - a system error: its code, the call and the path (EACCES open
 *     /backups/x.partial);
 *   - a PostgreSQL error: its SQLSTATE and the schema object it names
 *     (table, column, constraint), never its message, which can quote a
 *     value;
 *   - anything else: the catch-all, as before.
 */
export function migrationFailure(verb: string, err: unknown): string {
  const what = verb ? `varlatchd admin migration ${verb}` : "varlatchd admin migration";
  const e = (typeof err === "object" && err !== null ? err : {}) as Record<string, unknown>;
  const text = (k: string) => (typeof e[k] === "string" && e[k] !== "" ? (e[k] as string) : null);
  const code = text("code");
  if (code && text("syscall")) {
    const path = text("path");
    return `${what} failed: ${code} ${text("syscall")}${path ? ` ${path}` : ""}`;
  }
  if (code && /^[0-9A-Z]{5}$/.test(code) && text("severity")) {
    const names = (["table", "column", "constraint"] as const).filter((k) => text(k)).map((k) => `${k} ${text(k)}`);
    return `${what} failed: PostgreSQL error ${code}${names.length ? ` (${names.join(", ")})` : ""}`;
  }
  return `${what} failed unexpectedly; check configuration and maintenance status.`;
}

/**
 * The prefix of the summary line `admin migration export --out -` writes
 * last on standard error, its bundle having gone to standard output.
 */
export const EXPORT_SUMMARY_PREFIX = "varlatch-export-summary: ";
