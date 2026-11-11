// SPDX-License-Identifier: AGPL-3.0-or-later

/** The caller's own organization-level permissions (GET .../me/permissions). */
export const myPermissionsKey = (org: string) => ["org-permissions", org] as const;

/** The Organization's refused outbound destinations (GET .../security/refused-destinations). */
export const refusedDestinationsKey = (org: string) => ["security-refused-destinations", org] as const;
