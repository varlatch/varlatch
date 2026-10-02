// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * A credential's readable client label: a short summary of the User-Agent
 * that requested a browser session credential or a CLI login credential,
 * so a person can tell their sessions apart ("Firefox on Linux", "varlatch
 * CLI 0.14.0 on Linux"). Only this summary is stored, never the User-Agent.
 *
 * Non-identifying by construction: every word of a label comes from the
 * fixed lists below, except the varlatch CLI's version, which must look
 * like a release version. No browser or OS version, device model, or other
 * free text from the header ever reaches it. Anything unrecognized is
 * null: an honest "unknown" rather than a guess.
 */

export const CLIENT_LABEL_MAX = 60;

/** What the varlatch CLI sends since 0.14.0: varlatch-cli/<version> (<platform>; <arch>). */
const CLI = /^varlatch-cli\/(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,20})?)(?=$|\s)(?:\s+\(([a-z0-9]{1,20})[;)])?/;

const CLI_PLATFORMS: Record<string, string> = {
  linux: "Linux",
  darwin: "macOS",
  win32: "Windows",
  freebsd: "FreeBSD",
  openbsd: "OpenBSD",
};

// Order matters: Edge, Opera, and others also claim Chrome and Safari.
const BROWSERS: [RegExp, string][] = [
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\bOPR\/|\bOpera\b/, "Opera"],
  [/\bSamsungBrowser\//, "Samsung Internet"],
  [/\bVivaldi\//, "Vivaldi"],
  [/\bFirefox\/|\bFxiOS\//, "Firefox"],
  [/\bChromium\//, "Chromium"],
  [/\bChrome\/|\bCriOS\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
];

// Order matters: Android and ChromeOS also claim Linux, iPadOS may claim Mac.
const SYSTEMS: [RegExp, string][] = [
  [/\bWindows\b/, "Windows"],
  [/\b(?:iPhone|iPad|iPod)\b/, "iOS"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bLinux\b|\bX11\b/, "Linux"],
];

function first(patterns: [RegExp, string][], ua: string): string | undefined {
  return patterns.find(([pattern]) => pattern.test(ua))?.[1];
}

/** The label for a User-Agent header, or null when it is missing or not recognized. */
export function clientLabel(userAgent: string | null | undefined): string | null {
  // Real User-Agents are short; a huge header is not worth matching.
  if (!userAgent || userAgent.length > 1024) return null;
  const cli = CLI.exec(userAgent);
  if (cli) {
    const platform = cli[2] ? CLI_PLATFORMS[cli[2]] : undefined;
    const label = `varlatch CLI ${cli[1]}${platform ? ` on ${platform}` : ""}`;
    return label.length <= CLIENT_LABEL_MAX ? label : null;
  }
  const browser = first(BROWSERS, userAgent);
  if (!browser) return null;
  const system = first(SYSTEMS, userAgent);
  return system ? `${browser} on ${system}` : browser;
}
