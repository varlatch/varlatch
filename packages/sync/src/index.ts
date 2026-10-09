// SPDX-License-Identifier: Apache-2.0
import { convexAdapter } from "./convex.js";
import { coolifyAdapter } from "./coolify.js";
import { githubActionsAdapter } from "./github.js";
import { AdapterError, PLATFORMS, type Platform, type PlatformAdapter } from "./types.js";

export * from "./types.js";
export type {
  AccessCheck,
  AccessCheckStatus,
  AccessCheckWhere,
  DestinationListing,
  DestinationOption,
} from "./access.js";
export { MAX_DESTINATIONS } from "./access.js";
export { githubActionsAdapter } from "./github.js";
export { coolifyAdapter } from "./coolify.js";
export { convexAdapter } from "./convex.js";
export { sealedBox, sealedBoxOpen } from "./sealedbox.js";

/** The closed allowlist (ADR-0031 §8). Additions are release work, never runtime. */
const ADAPTERS: Record<Platform, PlatformAdapter> = {
  "github-actions": githubActionsAdapter,
  coolify: coolifyAdapter,
  convex: convexAdapter,
};

export function isPlatform(value: string): value is Platform {
  return (PLATFORMS as readonly string[]).includes(value);
}

export function getAdapter(platform: string): PlatformAdapter {
  if (!isPlatform(platform)) {
    throw new AdapterError(`Unknown platform adapter: ${platform}`, false);
  }
  return ADAPTERS[platform];
}
