// SPDX-License-Identifier: Apache-2.0
/**
 * Runs the Python tests with the standard library's unittest. Without a
 * Python 3 interpreter they are skipped with a notice, unless
 * VARLATCH_REQUIRE_PYTHON=1 (CI), which makes a missing interpreter a
 * failure. VARLATCH_PYTHON selects the interpreter.
 */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const python = process.env.VARLATCH_PYTHON ?? "python3";
const probe = spawnSync(python, ["-c", "import sys; assert sys.version_info >= (3, 10)"], { stdio: "ignore" });
if (probe.error || probe.status !== 0) {
  const message = `${python} (3.10 or later) is not available`;
  if (process.env.VARLATCH_REQUIRE_PYTHON === "1") {
    console.error(`${message}, and VARLATCH_REQUIRE_PYTHON=1`);
    process.exit(1);
  }
  console.warn(`${message}: the Python accessor tests are skipped`);
  process.exit(0);
}
const run = spawnSync(python, ["-m", "unittest", "discover", "-s", "tests"], { cwd: root, stdio: "inherit" });
process.exit(run.status ?? 1);
