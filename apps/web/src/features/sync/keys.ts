// SPDX-License-Identifier: AGPL-3.0-or-later

/** Query key of the organization's platform connections, shared by every screen that lists them. */
export const connectionsKey = (org: string) => ["platform-connections", org] as const;
