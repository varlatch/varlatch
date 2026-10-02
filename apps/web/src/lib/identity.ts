// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Passkey-only accounts carry a synthesized placeholder email
 * (`<identity>@varlatch.placeholder.invalid`); it is never shown to people.
 */
export function displayEmail(email: string | null | undefined): string | null {
  if (!email) return null;
  return /\.invalid$/i.test(email) ? null : email;
}

/** Short form of an identity id for places where no name is known. */
export function shortId(id: string): string {
  return id.length > 14 ? `${id.slice(0, 12)}…` : id;
}
