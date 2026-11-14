#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * CLI serving off, the default (ADR-0058 Decision 3): the install scripts
 * and the CLI bundle answer 404 from the server (through the dashboard's
 * nginx on the TypeScript stack, never the dashboard's page), and /v1/meta
 * does not list cli.download.
 *
 *   cli-download-off.mjs <origin>      (run by scripts/conformance/run.mjs)
 */
import { reporter } from "../suite-kit.mjs";

const [origin] = process.argv.slice(2);
if (!origin) {
  console.error("Usage: cli-download-off.mjs <origin>");
  process.exit(64);
}
const { check, finish } = reporter();
const status = (path) => fetch(`${origin}${path}`).then(async (r) => (await r.arrayBuffer(), r.status), () => 0);

const paths = {
  "/install.sh": "cli-download-off.install-sh-404",
  "/install.ps1": "cli-download-off.install-ps1-404",
  "/cli/varlatch.cjs": "cli-download-off.cli-bundle-404",
};
for (const [path, id] of Object.entries(paths)) {
  const got = await status(path);
  check(id, `${path} answers 404 while serving is off (not the dashboard)`, got === 404, String(got));
}
const meta = await fetch(`${origin}/v1/meta`).then((r) => r.json(), () => null);
check(
  "cli-download-off.meta-omits-cli-download",
  "/v1/meta does not list cli.download while serving is off",
  Array.isArray(meta?.capabilities) && !meta.capabilities.includes("cli.download"),
  meta ? JSON.stringify(meta.capabilities) : "no /v1/meta",
);
finish();
