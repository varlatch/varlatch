#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import "../../redact-tokens.mjs"; // public CI logs: mask Varlatch tokens in output
/**
 * A short smoke of `packages/sdk` against the target, separate from the
 * clients built from this checkout: the runner bundles the sdk from the
 * pinned release's commit for `--cli <version>` (from this checkout for
 * `--cli source`) and names the bundle in VARLATCH_SDK. Sign-in with a
 * token, reads, and one value write, in an environment of its own that it
 * removes again.
 *
 *   sdk.mjs <origin> <api token> <seeded secret>   (run by scripts/conformance/run.mjs)
 */
import { pathToFileURL } from "node:url";
import { reporter } from "../suite-kit.mjs";

const [origin, token, seeded] = process.argv.slice(2);
if (!origin || !token || !seeded) {
  console.error("Usage: sdk.mjs <origin> <api token> <seeded secret>");
  process.exit(64);
}
const { check, error, finish } = reporter({ detailOnFailure: true });
const ORG = "acme";
const PROJECT = "api";
const ENVIRONMENT = "sdk-smoke";
const VALUE = "https://sdk-smoke.example.test/";

let client = null;
let created = false;
try {
  if (!process.env.VARLATCH_SDK) throw new Error("VARLATCH_SDK is not set: run the suite through scripts/conformance/run.mjs");
  const { VarlatchClient, VarlatchApiError } = await import(pathToFileURL(process.env.VARLATCH_SDK).href);
  client = new VarlatchClient({ server: origin, token, userAgent: "varlatch-conformance-sdk" });

  const me = await client.whoami();
  check(
    "sdk.token-sign-in",
    "with a token the sdk is signed in: whoami names an identity and its credential",
    /^idn_/.test(me?.identity?.id ?? "") && typeof me?.credential?.id === "string",
    JSON.stringify({ identity: me?.identity?.id, credential: me?.credential?.id }),
  );

  const organizations = await client.listOrganizations();
  const projects = await client.listProjects(ORG);
  const environments = await client.listEnvironments(ORG, PROJECT);
  check(
    "sdk.reads",
    "the sdk reads organizations, projects and environments",
    organizations.items.some((o) => o.slug === ORG) &&
      projects.items.some((p) => p.slug === PROJECT) &&
      ["development", "production"].every((n) => environments.items.some((e) => e.name === n)),
    JSON.stringify({ organizations: organizations.items.length, projects: projects.items.length, environments: environments.items.map((e) => e.name) }),
  );

  await client.createEnvironment(ORG, PROJECT, { name: ENVIRONMENT, tier: "development" });
  created = true;
  const written = await client.setValue(ORG, PROJECT, ENVIRONMENT, "PUBLIC_URL", { value: VALUE });
  const effective = await client.effectiveConfiguration(ORG, PROJECT, ENVIRONMENT);
  const item = effective.items.find((i) => i.name === "PUBLIC_URL");
  check(
    "sdk.value-write",
    "a value written through the sdk is stored: its version is the one the effective configuration shows",
    typeof written?.versionId === "string" && written.itemName === "PUBLIC_URL" && item?.versionId === written.versionId && item?.source === "self",
    JSON.stringify({ written, item }),
  );
  check(
    "sdk.no-value-in-metadata",
    "the write's answer and the metadata read hold no value",
    !JSON.stringify(written).includes(VALUE) && !JSON.stringify(effective).includes(VALUE) && !JSON.stringify(effective).includes(seeded),
  );

  let refused = null;
  try {
    await new VarlatchClient({ server: origin, token: "vlt_cli_not-a-credential" }).whoami();
  } catch (err) {
    refused = err;
  }
  check(
    "sdk.refused-credential-is-api-error",
    "a refused credential surfaces as the sdk's VarlatchApiError with status 401",
    refused instanceof VarlatchApiError && refused.status === 401,
    String(refused),
  );
} catch (err) {
  error(`sdk: ${err.message}`);
} finally {
  if (created) {
    await client.deleteEnvironment(ORG, PROJECT, ENVIRONMENT).catch((err) => error(`removing ${ENVIRONMENT}: ${err.message}`));
  }
}
finish("sdk check(s)");
