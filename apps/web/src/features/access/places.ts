// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * A Capability's destination in the words of a list (ADR-0064): a host as it
 * is written, a page by its address (without the port its scheme has anyway),
 * an application by its name and the machine's.
 */
export function placeLabel(destination: string, nameOf: (identityId: string) => string): string {
  const page = /^web:(https?):\/\/(.+?):(\d+)(\/.*)$/.exec(destination);
  if (page) {
    const [, scheme, host, port, path] = page;
    const usual = port === (scheme === "https" ? "443" : "80");
    return `${scheme}://${host}${usual ? "" : `:${port}`}${path === "/" ? "" : path}`;
  }
  const app = /^app:(.+)@(idn_[a-z2-7]+)$/.exec(destination);
  if (app) return `${app[1]} on ${nameOf(app[2]!)}`;
  return destination;
}

/** A page that is reached without TLS: allowed when it is written out, and worth a warning wherever it is shown. */
export function withoutTLS(destination: string): boolean {
  return destination.startsWith("web:http://");
}

/** What the warning says. */
export const WITHOUT_TLS = "This page is reached over http:, without encryption: whoever is on the network between the machine and the page can read what is typed there, or show another page in its place.";
