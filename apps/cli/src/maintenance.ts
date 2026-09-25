// SPDX-License-Identifier: Apache-2.0
import type { MaintenanceWait } from "@varlatch/sdk";

/**
 * ADR-0036 D6: while the SDK rides out isolating maintenance (restore,
 * schema migration), say so once, on stderr — stdout stays exactly what
 * scripts parse.
 */
let announced = false;
export function maintenanceNotice(wait: MaintenanceWait): void {
  if (announced) return;
  announced = true;
  const budget = Math.ceil((wait.retryInMs + wait.remainingMs) / 1000);
  process.stderr.write(`varlatch: the installation is in maintenance (restore or upgrade); waiting up to ${budget} s…\n`);
}
