// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ProtectedGate } from "../../src/domain/approvals.js";
import { noApprovalGate } from "../../src/domain/protected.js";

/**
 * The gate of a protected operation called directly by a test, as a
 * person's CLI sign-in without an approval: what an HTTP request without
 * the Varlatch-Approval header gives it.
 */
export function personGate(identityId: string): ProtectedGate {
  return noApprovalGate({ identityId, identityKind: "human", credentialId: "crd_test", credentialKind: "cli" });
}
