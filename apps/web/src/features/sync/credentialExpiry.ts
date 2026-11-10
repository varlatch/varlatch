// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * When a credential expires: a connection's token, as the platform last
 * said (GitHub personal access tokens), or a machine's Varlatch credential.
 * Varlatch warns ahead, so a credential is replaced before requests start
 * failing.
 */

/** Days ahead of a connection token's expiry when the warning starts. */
export const EXPIRY_WARNING_DAYS = 14;

/**
 * Days ahead of a machine credential's expiry when Access → Machines marks
 * it: the window in which varlatchd names the expiry in the
 * Varlatch-Credential-Expires header and the CLI warns about VARLATCH_TOKEN.
 */
export const MACHINE_EXPIRY_WARNING_DAYS = 7;

export type CredentialExpiry = {
  state: "expired" | "soon" | "later";
  /** Whole days left, rounded up; 0 once expired. */
  days: number;
  expiresAt: string;
};

/**
 * Null when the platform has not said: unknown, not "never expires". For a
 * Varlatch credential, null is no expiry. "soon" within `warningDays`.
 */
export function credentialExpiry(
  expiresAt: string | null | undefined,
  now: number,
  warningDays: number = EXPIRY_WARNING_DAYS,
): CredentialExpiry | null {
  if (!expiresAt) return null;
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return null;
  if (at <= now) return { state: "expired", days: 0, expiresAt };
  const days = Math.ceil((at - now) / 86_400_000);
  return { state: days <= warningDays ? "soon" : "later", days, expiresAt };
}

/** "Token expires in 5 days (Nov 8)"; the caller formats the date and may name the thing. */
export function expiryText(expiry: CredentialExpiry, date: string, noun = "Token"): string {
  if (expiry.state === "expired") return `${noun} expired ${date}`;
  if (expiry.state === "later") return `${noun} expires ${date}`;
  return expiry.days === 1 ? `${noun} expires within a day (${date})` : `${noun} expires in ${expiry.days} days (${date})`;
}

export function expiryTone(expiry: CredentialExpiry): "error" | "warn" | "muted" {
  return expiry.state === "expired" ? "error" : expiry.state === "soon" ? "warn" : "muted";
}
