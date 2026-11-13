// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";
import type { OutboundPolicy } from "../net/outbound.js";

/** Dependencies threaded through domain operations. */
export interface AppCtx {
  maintenance?: import("@varlatch/backup").Maintenance;
  db: Querier;
  rootKek: Buffer;
  /**
   * The daemon's small pool for Security Control access counts (ADR-0054
   * Decision 9, securityreport.ts), apart from request traffic, with its
   * own acquisition timeout. Absent: counts use `db`.
   */
  accessCountDb?: Querier;
  /**
   * The outbound policy (ADR-0057), built from VARLATCH_OUTBOUND_ALLOW at
   * startup. Absent: the policy without exceptions (outboundOf), never a
   * plain fetch.
   */
  outbound?: OutboundPolicy;
  /**
   * The audit export's installation switch (ADR-0056 Decision 6,
   * VARLATCH_AUDIT_EXPORT): false refuses creating and changing exports.
   * Absent: on, its default.
   */
  auditExport?: boolean;
}
