// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";

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
}
