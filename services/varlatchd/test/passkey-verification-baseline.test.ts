// SPDX-License-Identifier: AGPL-3.0-or-later
import { writeFileSync } from "node:fs";
import { describe, it } from "vitest";
import { generateKey } from "../src/crypto/aead.js";
import { recordOff } from "./helpers/route-sweep.js";

/**
 * Records the off-mode baseline of the passkey-verification route sweep
 * (test/helpers/route-sweep.ts): each route variant's status, error code,
 * body shape and the tables it changed, with every control off. Run only
 * on request, on the checkout whose behaviour is the baseline (main before
 * a change), with the helpers copied in:
 *
 *   PV_RECORD_OFF_BASELINE=<file> PV_BASELINE_SOURCE="main <sha>" \
 *     npx vitest run --fileParallelism=false test/passkey-verification-baseline.test.ts
 *
 * test/passkey-verification.test.ts compares the current code's off-mode
 * answers with the file it wrote (test/fixtures/).
 */
const target = process.env.PV_RECORD_OFF_BASELINE;
describe.skipIf(!target)("the off-mode baseline", () => {
  it("records every route variant", async () => {
    const variants = await recordOff(generateKey());
    writeFileSync(target!, `${JSON.stringify({ source: process.env.PV_BASELINE_SOURCE ?? "unknown", variants }, null, 1)}\n`);
  }, 300_000);
});
