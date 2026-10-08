// SPDX-License-Identifier: Apache-2.0
import embeddedRelease from "./release.json" with { type: "json" };

/**
 * This release's version alone, for a client that only names itself (the
 * CLI's User-Agent on every request): importing it loads none of the backup
 * format, so it costs a command nothing at startup. EMBEDDED_RELEASE is the
 * validated whole.
 */
export const RELEASE_VERSION: string = embeddedRelease.version;
