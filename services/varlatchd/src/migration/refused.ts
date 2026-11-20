// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Preflight } from "./preflight.js";

/**
 * The export's refusal (export.ts): what the operator can act on, naming
 * tables, ids and columns, never a value. With the preflight when that is
 * what refused.
 */
export class ExportRefused extends Error {
  override name = "ExportRefused";
  constructor(message: string, readonly preflight?: Preflight) {
    super(message);
  }
}
