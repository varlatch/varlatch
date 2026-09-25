// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Querier } from "../db/migrate.js";

/** Dependencies threaded through domain operations. */
export interface AppCtx {
  maintenance?: import("@varlatch/backup").Maintenance;
  db: Querier;
  rootKek: Buffer;
}
