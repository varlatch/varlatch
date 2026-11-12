// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The line that installs the CLI from this installation (ADR-0058
 * Decisions 3 and 4), shown only when /v1/meta lists cli.download. The
 * verified route links to the docs' anchor that exists before and after
 * the docs split, so a dashboard released ahead of the docs never 404s.
 */

export const CLI_DOWNLOAD_CAPABILITY = "cli.download";

export const VERIFIED_INSTALL_URL = "https://docs.varlatch.com/getting-started/#get-the-cli";

export type InstallOs = "posix" | "windows";

export function detectOs(nav: { platform?: string; userAgentData?: { platform?: string } } = navigator as never): InstallOs {
  const platform = (nav.userAgentData?.platform || nav.platform || "").toLowerCase();
  return platform.startsWith("win") ? "windows" : "posix";
}

export function installLine(origin: string, os: InstallOs): string {
  return os === "windows" ? `irm ${origin}/install.ps1 | iex` : `curl -fsSL ${origin}/install.sh | sh`;
}
