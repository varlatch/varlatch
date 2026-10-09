// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * When a connection's token expires, as the platform last said (GitHub
 * personal access tokens). Varlatch warns ahead, so a credential is
 * replaced before pushes start failing.
 */

/** Days ahead of the expiry when the warning starts. */
export const EXPIRY_WARNING_DAYS = 14;

export type CredentialExpiry = {
  state: "expired" | "soon" | "later";
  /** Whole days left, rounded up; 0 once expired. */
  days: number;
  expiresAt: string;
};

/** Null when the platform has not said: unknown, not "never expires". */
export function credentialExpiry(expiresAt: string | null | undefined, now: number): CredentialExpiry | null {
  if (!expiresAt) return null;
  const at = Date.parse(expiresAt);
  if (Number.isNaN(at)) return null;
  if (at <= now) return { state: "expired", days: 0, expiresAt };
  const days = Math.ceil((at - now) / 86_400_000);
  return { state: days <= EXPIRY_WARNING_DAYS ? "soon" : "later", days, expiresAt };
}

/** "Token expires in 5 days (Nov 8)"; the caller formats the date. */
export function expiryText(expiry: CredentialExpiry, date: string): string {
  if (expiry.state === "expired") return `Token expired ${date}`;
  if (expiry.state === "later") return `Token expires ${date}`;
  return expiry.days === 1 ? `Token expires within a day (${date})` : `Token expires in ${expiry.days} days (${date})`;
}

export function expiryTone(expiry: CredentialExpiry): "error" | "warn" | "muted" {
  return expiry.state === "expired" ? "error" : expiry.state === "soon" ? "warn" : "muted";
}
