// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AccessCheck } from "@varlatch/protocol";

/**
 * Reading an access check for the connection and integration dialogs. A
 * check runs before anything is saved; a failed one never blocks, it asks
 * the user to fix the named field or to go ahead anyway.
 */

export function accessTone(check: AccessCheck): "success" | "warn" | "danger" {
  if (check.status === "ok") return "success";
  return check.status === "unreachable" ? "warn" : "danger";
}

export function accessTitle(check: AccessCheck): string {
  switch (check.status) {
    case "ok":
      return check.where === "destination" ? "Varlatch can reach the destination" : "Varlatch can reach the platform";
    case "credential-rejected":
      return "The credential was rejected";
    case "permission-missing":
      return "The credential is missing a permission";
    case "not-found":
      return check.where === "destination" ? "Destination not found" : "Account or instance not found";
    case "unreachable":
      return "Could not check right now";
    case "failed":
      return "The platform refused the check";
  }
}

/**
 * The Add integration step that fixes a failed check: 0 is the connection
 * (credential, account or instance), 1 the destination. A credential
 * problem is fixed at the connection wherever it showed. Null when the fix
 * is to try again (or there is nothing to fix).
 */
export function fixStep(check: AccessCheck): 0 | 1 | null {
  switch (check.status) {
    case "ok":
    case "unreachable":
      return null;
    case "credential-rejected":
    case "permission-missing":
      return 0;
    case "not-found":
    case "failed":
      return check.where === "destination" ? 1 : 0;
  }
}
