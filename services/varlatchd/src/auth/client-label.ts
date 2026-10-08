// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * A readable client label: a short summary of a User-Agent, so a person
 * can tell their sessions and clients apart ("Firefox on Linux", "varlatch
 * CLI 0.14.0 on Linux"). Credentials keep the label of the client that
 * requested them, a browser session or a CLI login, and Security Audit
 * Events the label of the request that recorded them. Only this summary is
 * stored, never the User-Agent, and it is what the client says about
 * itself: never verified, never an authorization input.
 *
 * Non-identifying by construction: every word of a label comes from the
 * fixed lists below, except a varlatch client's version, which must look
 * like a release version. No browser or OS version, device model, or other
 * free text from the header ever reaches it. Anything unrecognized is
 * null: an honest "unknown" rather than a guess.
 */

export const CLIENT_LABEL_MAX = 60;

/**
 * What varlatch's own clients send: the CLI `varlatch-cli/<version>
 * (<platform>; <arch>)` since 0.14.0, with a third token `assisted` in
 * assisted mode (ADR-0043 Decision 3), and the MCP server
 * `varlatch-mcp/<version> (<platform>; <arch>)`. Only the platform and the
 * exact token `assisted` are read from the comment.
 */
const VARLATCH = /^varlatch-(cli|mcp)\/(\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,20})?)(?=$|\s)(?:\s+\(([^()]{1,100})\))?/;

const PLATFORMS: Record<string, string> = {
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
  const own = VARLATCH.exec(userAgent);
  if (own) {
    const [os = "", ...rest] = (own[3] ?? "").split(";").map((token) => token.trim());
    const platform = Object.hasOwn(PLATFORMS, os) ? PLATFORMS[os] : undefined;
    const label =
      `varlatch ${own[1] === "mcp" ? "MCP" : "CLI"} ${own[2]}` +
      (platform ? ` on ${platform}` : "") +
      (rest.includes("assisted") ? ", assisted" : "");
    return label.length <= CLIENT_LABEL_MAX ? label : null;
  }
  const browser = first(BROWSERS, userAgent);
  if (!browser) return null;
  const system = first(SYSTEMS, userAgent);
  return system ? `${browser} on ${system}` : browser;
}
