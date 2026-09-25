// SPDX-License-Identifier: AGPL-3.0-or-later
import { query } from "./_generated/server";
import { FUNCTIONS_FINGERPRINT } from "./releaseStamp";

/**
 * Identifies the function bundle this backend actually serves (ADR-0035 D4):
 * reconciliation compares it with the release's fingerprint instead of
 * trusting a recorded version, and `doctor` can check it without deployment
 * authority. Public on purpose: it is a hash of public source code.
 */
export const release = query({
  args: {},
  handler: async () => ({ fingerprint: FUNCTIONS_FINGERPRINT }),
});
