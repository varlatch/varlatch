// SPDX-License-Identifier: Apache-2.0
import { RELEASE_VERSION } from "@varlatch/backup/version";

/**
 * The CLI's User-Agent on every request to varlatchd:
 * `varlatch-cli/<version> (<platform>; <arch>)`, with a third token,
 * `assisted`, in assisted mode (ADR-0043 Decision 3). varlatchd keeps only
 * its summary ("varlatch CLI 0.16.0 on Linux, assisted"): as the label of a
 * credential issued at login, and as the client of every audit event a
 * request records, so the audit log tells a coding agent driving the CLI
 * from the human typing. It is what the CLI says about itself: the server
 * never verifies it and no authorization depends on it, and a coding agent
 * that drops `--assisted` and sets no marker is not reported as assisted.
 */
export function formatUserAgent(version: string, assisted: boolean, platform: string, arch: string): string {
  return `varlatch-cli/${version} (${platform}; ${arch}${assisted ? "; assisted" : ""})`;
}

let assistedMode = false;

/** Called once by main(), with the mode resolveAssisted() found, before any request. */
export function setAssistedUserAgent(on: boolean): void {
  assistedMode = on;
}

/** This invocation's User-Agent, for every VarlatchClient the CLI builds. */
export function cliUserAgent(): string {
  return formatUserAgent(RELEASE_VERSION, assistedMode, process.platform, process.arch);
}
