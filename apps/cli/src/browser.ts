// SPDX-License-Identifier: Apache-2.0

/**
 * How `varlatch login` opens its sign-in page. The CLI always prints the
 * page's address first; opening it is a convenience, and a host without a
 * browser (or without the opener) just leaves the address to open by hand.
 *
 * On Windows the URL protocol handler is started directly, never through a
 * shell: `cmd /c start` would read the `&` of a query string as a command
 * separator.
 *
 * VARLATCH_NO_BROWSER is for a desktop app that drives `varlatch login`: it
 * reads the printed address and opens it itself, so the CLI must not open a
 * second tab. A CLI from before the variable ignores it, so the app can set
 * it whatever the CLI's version.
 */

export const NO_BROWSER_ENV = "VARLATCH_NO_BROWSER";

export interface BrowserCommand {
  command: string;
  args: string[];
}

/** The command that opens `url` in the default browser on `platform`, or null when nothing should be opened. */
export function browserCommand(platform: NodeJS.Platform, url: string, env: NodeJS.ProcessEnv): BrowserCommand | null {
  const noBrowser = env[NO_BROWSER_ENV];
  if (noBrowser !== undefined && noBrowser !== "" && noBrowser !== "0") return null;
  if (platform === "win32") return { command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", url] };
  if (platform === "darwin") return { command: "open", args: [url] };
  return { command: "xdg-open", args: [url] };
}
