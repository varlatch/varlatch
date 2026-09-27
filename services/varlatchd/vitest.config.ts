// SPDX-License-Identifier: AGPL-3.0-or-later
import { availableParallelism, freemem } from "node:os";
import { defineConfig } from "vitest/config";

// A worker here peaks at about 1.3 GB (a PGlite instance per test), so the
// default of one per core can exhaust a desktop's memory. Budget 2 GB of
// the memory available at start per worker; --maxWorkers overrides it.
const maxWorkers = Math.max(1, Math.min(availableParallelism() - 1, Math.floor(freemem() / 2 ** 31)));

export default defineConfig({
  test: {
    globalSetup: ["test/helpers/pglite-snapshots.ts"],
    maxWorkers,
  },
});
