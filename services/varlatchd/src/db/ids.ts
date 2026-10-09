// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomBytes } from "node:crypto";

/**
 * Public resource identifiers are Varlatch domain IDs (ADR-0018 §5): typed
 * prefixes + 128 bits of randomness in lowercase base32 (no padding).
 */
const PREFIXES = {
  installation: "inst",
  identity: "idn",
  organization: "org",
  project: "prj",
  environment: "env",
  value: "val",
  version: "ver",
  contractRevision: "rev",
  grant: "grt",
  requirement: "req",
  credential: "crd",
  auditEvent: "evt",
  setupGrant: "sgr",
  capability: "cap",
  webhook: "whk",
  oidcBinding: "oib",
  role: "rol",
  group: "grp",
  team: "tem",
  platformConnection: "pcn",
  syncTarget: "snt",
  deviceSignIn: "dsi",
  deviceSignInChallenge: "dsc",
  githubApp: "gha",
} as const;

export type IdKind = keyof typeof PREFIXES;

const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

function base32(bytes: Buffer): string {
  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

export function newId(kind: IdKind): string {
  return `${PREFIXES[kind]}_${base32(randomBytes(16))}`;
}
