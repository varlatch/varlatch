// SPDX-License-Identifier: Apache-2.0
import { listCredentials } from "@varlatch/context";
import { ERROR_CODES } from "@varlatch/protocol";
import { VarlatchApiError } from "@varlatch/sdk";

/**
 * Output that comes from a server, made safe to print (ADR-0058 Decision 2):
 * an error code only when it is one the protocol defines (a server could put
 * anything in that field, the request's own credential included), and text
 * with every control character escaped, so a name cannot add lines, move
 * the cursor or reach the terminal's clipboard.
 *
 * Fields with a known shape (a time, a version, an API major, a request id)
 * print only when they have that shape, otherwise as a fixed phrase. Free
 * text a server writes (an error's message) is shown escaped, with every
 * credential and value this CLI knows of masked (issue #119).
 */

const KNOWN = new Set<string>(ERROR_CODES);

/** The API error's code when the protocol defines it; a fixed word otherwise. */
export function safeApiCode(err: VarlatchApiError): string {
  return KNOWN.has(err.code) ? err.code : "UNRECOGNIZED_ERROR";
}

/** C0, DEL and C1 controls, and the bidirectional overrides and isolates, as visible escapes. */
export function printable(text: string): string {
  return text.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

/**
 * A template literal whose every interpolated value goes through printable():
 * safe`Project ${p.slug} (${p.name})`. Only for one line of output whose
 * interpolations are single values; text the CLI builds over several lines
 * is interpolated raw elsewhere, with printable() at each server value.
 */
export function safe(strings: TemplateStringsArray, ...values: unknown[]): string {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) out += printable(String(values[i])) + (strings[i + 1] ?? "");
  return out;
}

// ---------------------------------------------------------------------------
// Fields with a known shape.

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

/** Said in place of a time that is not an ISO 8601 timestamp. */
export const UNRECOGNIZED_TIME = "an unrecognized time";

/**
 * A server's timestamp, normalized to ISO 8601 UTC, or UNRECOGNIZED_TIME
 * when it is not one. Missing (null or undefined) stays missing, so callers
 * keep their own words for it: `${safeTime(x.lastSeenAt) ?? "never"}`.
 */
export function safeTime(value: string): string;
export function safeTime(value: unknown): string | undefined;
export function safeTime(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "string" || !ISO_TIME.test(value)) return UNRECOGNIZED_TIME;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? UNRECOGNIZED_TIME : at.toISOString();
}

// semver.org's pattern, anchored.
const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

/** Said in place of a server version that is not a version. */
export const UNRECOGNIZED_VERSION = "an unrecognized version";

/**
 * A server's version when it is a semantic version (at most 64 characters,
 * holding nothing this CLI knows as secret), UNRECOGNIZED_VERSION otherwise.
 * Missing stays missing: `${safeVersion(meta.serverVersion) ?? "an older release"}`.
 */
export function safeVersion(value: string): string;
export function safeVersion(value: unknown): string | undefined;
export function safeVersion(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 64 || !SEMVER.test(value) || maskSecrets(value) !== value) return UNRECOGNIZED_VERSION;
  return value;
}

/** The API major version when it is a small whole number (0 to 999), else undefined. */
export function safeApiMajor(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value < 1000 ? value : undefined;
}

// The request id varlatchd generates (services/varlatchd/src/http/support.ts).
const REQUEST_ID = /^req_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The request id when it has the server's format, else null: the id is then left out. */
export function safeRequestId(value: unknown): string | null {
  return typeof value === "string" && REQUEST_ID.test(value) && maskSecrets(value) === value ? value : null;
}

/** " (request <id>)" for an API error whose id has the server's format; nothing otherwise. */
export function requestNote(err: VarlatchApiError): string {
  const id = safeRequestId(err.requestId);
  return id === null ? "" : ` (request ${id})`;
}

// ---------------------------------------------------------------------------
// Secrets in a server's free text.

/** Shorter strings are not masked: they would match ordinary words. */
export const MIN_MASKED_LENGTH = 8;

/** Shown in place of a masked secret. */
export const REDACTED = "[redacted]";

/**
 * Secret material this process holds that the stored credentials do not
 * show: the bearer of each request it sends, and every value and key it
 * sends. Filled where the CLI uses or sends them (rememberSecret); never
 * printed, written or sent anywhere.
 */
const knownSecrets = new Set<string>();

/** Registers a credential or value this process uses or sends, so a server echoing it back is masked. */
export function rememberSecret(value: string | null | undefined): void {
  if (typeof value === "string" && value.length >= MIN_MASKED_LENGTH) knownSecrets.add(value);
}

/**
 * Varlatch's own token formats, `vlt_<kind>_<random>`: credentials (svc,
 * cli, web, agr, oidc), Capabilities, webhook secrets, and the setup,
 * recovery, invitation and re-enrollment links' tokens.
 */
const VARLATCH_TOKEN = /vlt_[a-z]+_[A-Za-z0-9_-]+/g;

/** The credentials the CLI holds besides those it registered: VARLATCH_TOKEN and every stored one. */
function heldCredentials(): string[] {
  const held: string[] = [];
  if (process.env.VARLATCH_TOKEN) held.push(process.env.VARLATCH_TOKEN);
  try {
    for (const { credential } of listCredentials()) if (typeof credential?.token === "string") held.push(credential.token);
  } catch {
    // An unreadable store adds nothing; the token format still masks Varlatch's own.
  }
  return held;
}

/**
 * `text` with every exact occurrence of a secret this CLI knows (registered,
 * VARLATCH_TOKEN, stored credentials) replaced by REDACTED, longest first,
 * and anything in a Varlatch token format too.
 */
export function maskSecrets(text: string): string {
  const secrets = [...new Set([...knownSecrets, ...heldCredentials()])]
    .filter((s) => s.length >= MIN_MASKED_LENGTH)
    .sort((a, b) => b.length - a.length);
  let out = text;
  for (const secret of secrets) if (out.includes(secret)) out = out.split(secret).join(REDACTED);
  return out.replace(VARLATCH_TOKEN, REDACTED);
}

/** A server's free text (an error's message) as shown: secrets masked, then controls escaped. */
export function serverMessage(text: unknown): string {
  return printable(maskSecrets(String(text)));
}

/** An API error as one line: the checked code, the masked message, and the request id when well formed. */
export function apiErrorLine(err: VarlatchApiError): string {
  return `Error ${safeApiCode(err)}: ${serverMessage(err.message)}${requestNote(err)}`;
}

/** For tests: forget every registered secret. */
export function forgetSecrets(): void {
  knownSecrets.clear();
}
