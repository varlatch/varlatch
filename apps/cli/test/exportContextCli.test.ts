// SPDX-License-Identifier: Apache-2.0
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { contractItem, revision } from "./fixtures.js";

/**
 * `varlatch run --export-context` in the shipped CLI bundle, against a local
 * server: the Contract Revision is fetched after the Effective Configuration
 * and before any disclosure, and the command receives the exported context.
 * The context and the Secrets come from two responses, so the run checks
 * that both describe the same state (their `stateDigest`), reads both again
 * when they do not, and refuses when they never agree.
 */

const CLI = fileURLToPath(new URL("../dist/varlatch.cjs", import.meta.url));
const REVISION = revision([
  contractItem("API_KEY", { sensitive: true, required: { kind: "always" } }),
  contractItem("PORT", { type: "number" }),
  contractItem("REGION"),
]);
/** A later Contract Revision, activated while a run reads its configuration. */
const REVISION_B = revision(
  [
    contractItem("API_KEY", { sensitive: true, required: { kind: "always" } }),
    contractItem("FEATURE_FLAG", { type: "boolean" }),
    contractItem("PORT", { type: "number" }),
    contractItem("REGION"),
  ],
  { id: "crv_types2" },
);
const ENV = "/v1/organizations/acme/projects/api/environments/development";

interface State {
  digest: string;
  revision: typeof REVISION;
  items: { name: string; sensitive: boolean; versionId: string; value: string }[];
}
const STATE_A: State = {
  digest: `sha256:${"a".repeat(64)}`,
  revision: REVISION,
  items: [
    { name: "API_KEY", sensitive: true, versionId: "ver_1", value: "sk-disclosed-1" },
    { name: "PORT", sensitive: false, versionId: "ver_2", value: "8080" },
  ],
};
/** STATE_A after a rotation of API_KEY, a new REGION value, and a Contract activation. */
const STATE_B: State = {
  digest: `sha256:${"b".repeat(64)}`,
  revision: REVISION_B,
  items: [
    { name: "API_KEY", sensitive: true, versionId: "ver_3", value: "valuebbbbbbbbbbbbb" },
    { name: "PORT", sensitive: false, versionId: "ver_2", value: "8080" },
    { name: "REGION", sensitive: false, versionId: "ver_4", value: "regionbbbbbbbbbbbb" },
  ],
};

const manifest = (state: State) => ({
  manifestVersion: 1,
  projectId: "prj_1",
  environment: { id: "env_dev", rootId: "env_dev", parentId: null, tier: "development", expiresAt: null },
  contract: { revisionId: state.revision.id, contentHash: state.revision.contentHash, semanticsVersion: 2 },
  items: state.items.map((i) => ({ name: i.name, source: "self", valueRowId: `val_${i.name}`, versionId: i.versionId })),
});

let server: Server;
let repo: string;
const requests: string[] = [];
/** The state each request is served from, in order; the last one repeats. */
let configurationStates: State[];
let disclosureStates: State[] | "denied";
const next = (states: State[]) => (states.length > 1 ? states.shift()! : states[0]!);

beforeAll(async () => {
  if (!existsSync(CLI)) throw new Error("the CLI bundle is not built: run pnpm --filter @varlatch/cli build");
  server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const json = (status: number, body: unknown) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
    if (req.method === "GET" && req.url === `${ENV}/effective-configuration?include=values`) {
      const state = next(configurationStates);
      return json(200, {
        environmentId: "env_dev",
        items: state.items.map((i) => ({ name: i.name, sensitive: i.sensitive, source: "self", versionId: i.versionId, value: i.sensitive ? null : i.value })),
        manifest: manifest(state),
        stateDigest: state.digest,
        callerView: { withheld: [], unexpanded: [] },
      });
    }
    const revision = [REVISION, REVISION_B].find((r) => req.url === `/v1/organizations/acme/projects/api/contract/revisions/${r.id}`);
    if (req.method === "GET" && revision) return json(200, revision);
    if (req.method === "POST" && req.url === `${ENV}/disclosures`) {
      if (disclosureStates === "denied") {
        return json(403, { error: { code: "PERMISSION_DENIED", message: "secret.reveal is not granted", requestId: "r" } });
      }
      const state = next(disclosureStates);
      return json(200, {
        items: state.items.filter((i) => i.sensitive).map((i) => ({ name: i.name, versionId: i.versionId, value: i.value })),
        withheld: [],
        manifest: manifest(state),
        stateDigest: state.digest,
        callerView: { withheld: [], unexpanded: [] },
      });
    }
    return json(404, { error: { code: "RESOURCE_NOT_FOUND", message: "not here", requestId: "r" } });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const origin = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
  repo = mkdtempSync(join(tmpdir(), "varlatch-export-cli-"));
  writeFileSync(join(repo, "varlatch.toml"), `organization = "acme"\nproject = "api"\nserver = "${origin}"\ndefault_environment = "development"\n`);
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
  rmSync(repo, { recursive: true, force: true });
});

beforeEach(() => {
  requests.length = 0;
  configurationStates = [STATE_A];
  disclosureStates = [STATE_A];
});

const PRINT = `process.stdout.write(JSON.stringify({ context: process.env.VARLATCH_RUN_CONTEXT ?? null, key: process.env.API_KEY ?? null, region: process.env.REGION ?? null }))`;

function cli(args: string[], extraEnv: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      {
        cwd: repo,
        env: { PATH: process.env.PATH, HOME: repo, VARLATCH_CONFIG_DIR: join(repo, ".config"), VARLATCH_TOKEN: "vlt_test_token", ...extraEnv },
      },
      (error, stdout, stderr) => resolve({ code: error ? Number(error.code ?? 1) : 0, stdout, stderr }),
    );
  });
}

describe("varlatch run --export-context, end to end", () => {
  it("gives the command the exported context, fetched before any Secret is disclosed", async () => {
    const result = await cli(["run", "--export-context", "--", process.execPath, "-e", PRINT], {
      REGION: "eu-west",
      VARLATCH_RUN_CONTEXT: '{"stale":true}',
    });
    expect(result.stderr).toBe("");
    expect(result.code).toBe(0);
    expect(requests).toEqual([
      `GET ${ENV}/effective-configuration?include=values`,
      `GET /v1/organizations/acme/projects/api/contract/revisions/${REVISION.id}`,
      `POST ${ENV}/disclosures`,
    ]);
    const seen = JSON.parse(result.stdout) as { context: string; key: string; region: string };
    expect(seen.key).toBe("sk-disclosed-1");
    expect(seen.region).toBe("eu-west");
    expect(JSON.parse(seen.context)).toEqual({
      v: 1,
      mode: "exported",
      contractRevisionId: REVISION.id,
      contractHash: REVISION.contentHash,
      semanticsVersion: 2,
      environment: { rootId: "env_dev", tier: "development" },
      items: {
        API_KEY: { server: "delivered", delivery: "varlatch" },
        PORT: { server: "delivered", delivery: "varlatch" },
        REGION: { server: "notStored", delivery: "inherited" },
      },
    });
    expect(seen.context).not.toContain("sk-disclosed-1");
  });

  it("with --redact too, the command gets a valid context and its delivered Secret is masked in its output", async () => {
    // The command sees the real value and echoes it on both streams; only
    // the relayed output is masked, and the context stays intact.
    const echo = `const key = process.env.API_KEY ?? "";
process.stdout.write(JSON.stringify({ context: process.env.VARLATCH_RUN_CONTEXT ?? null, delivered: key.length === 14 && key.startsWith("sk-"), echo: key }) + "\\n");
process.stderr.write("stderr " + key + "\\n");`;
    const result = await cli(["run", "--export-context", "--redact", "--", process.execPath, "-e", echo], { REGION: "eu-west" });
    expect(result.code).toBe(0);
    expect(requests).toEqual([
      `GET ${ENV}/effective-configuration?include=values`,
      `GET /v1/organizations/acme/projects/api/contract/revisions/${REVISION.id}`,
      `POST ${ENV}/disclosures`,
    ]);
    expect(result.stdout).not.toContain("sk-disclosed-1");
    expect(result.stderr).not.toContain("sk-disclosed-1");
    expect(result.stderr).toBe("stderr [REDACTED:API_KEY]\n");
    const seen = JSON.parse(result.stdout) as { context: string; delivered: boolean; echo: string };
    expect(seen.delivered).toBe(true);
    expect(seen.echo).toBe("[REDACTED:API_KEY]");
    expect(JSON.parse(seen.context)).toEqual({
      v: 1,
      mode: "exported",
      contractRevisionId: REVISION.id,
      contractHash: REVISION.contentHash,
      semanticsVersion: 2,
      environment: { rootId: "env_dev", tier: "development" },
      items: {
        API_KEY: { server: "delivered", delivery: "varlatch" },
        PORT: { server: "delivered", delivery: "varlatch" },
        REGION: { server: "notStored", delivery: "inherited" },
      },
    });
  });

  it("without the flag the run is unchanged, and an inherited context is removed", async () => {
    const result = await cli(["run", "--", process.execPath, "-e", PRINT], { VARLATCH_RUN_CONTEXT: '{"stale":true}' });
    expect(result.code).toBe(0);
    expect(requests).toEqual([`GET ${ENV}/effective-configuration?include=values`, `POST ${ENV}/disclosures`]);
    expect(JSON.parse(result.stdout)).toMatchObject({ context: null, key: "sk-disclosed-1" });
  });

  it("applies only to default runs", async () => {
    const result = await cli(["run", "--export-context", "--strict", "--", process.execPath, "-e", "0"]);
    expect(result.code).toBe(64);
    expect(result.stderr).toContain("--export-context applies only to default runs");
    expect(requests).toEqual([]);
  });
});

describe("varlatch run --export-context when the state changes between its two requests", () => {
  const READ_A = [
    `GET ${ENV}/effective-configuration?include=values`,
    `GET /v1/organizations/acme/projects/api/contract/revisions/${REVISION.id}`,
    `POST ${ENV}/disclosures`,
  ];
  const READ_B = [
    `GET ${ENV}/effective-configuration?include=values`,
    `GET /v1/organizations/acme/projects/api/contract/revisions/${REVISION_B.id}`,
    `POST ${ENV}/disclosures`,
  ];

  it("reads both again, and runs with the context and the values of the read whose two responses agree", async () => {
    // The first disclosure already sees STATE_B; the second read sees it throughout.
    configurationStates = [STATE_A, STATE_B];
    disclosureStates = [STATE_B];
    const result = await cli(["run", "--export-context", "--", process.execPath, "-e", PRINT], { REGION: "eu-west" });
    expect(result.code).toBe(0);
    expect(requests).toEqual([...READ_A, ...READ_B]);
    expect(result.stderr).toBe(
      "varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again " +
        "(attempt 2 of 3, another audited disclosure)\n",
    );
    const seen = JSON.parse(result.stdout) as { context: string; key: string; region: string };
    expect(seen.key).toBe("valuebbbbbbbbbbbbb");
    expect(seen.region).toBe("regionbbbbbbbbbbbb");
    expect(JSON.parse(seen.context)).toEqual({
      v: 1,
      mode: "exported",
      contractRevisionId: REVISION_B.id,
      contractHash: REVISION_B.contentHash,
      semanticsVersion: 2,
      environment: { rootId: "env_dev", tier: "development" },
      items: {
        API_KEY: { server: "delivered", delivery: "varlatch" },
        FEATURE_FLAG: { server: "notStored", delivery: "absent" },
        PORT: { server: "delivered", delivery: "varlatch" },
        REGION: { server: "delivered", delivery: "varlatch" },
      },
    });
  });

  it("refuses before starting the command when the two responses never agree, naming no value", async () => {
    configurationStates = [STATE_A];
    disclosureStates = [STATE_B];
    const marker = join(repo, "started");
    const result = await cli(["run", "--export-context", "--", process.execPath, "-e", `require("fs").writeFileSync(${JSON.stringify(marker)}, "1")`]);
    expect(result.code).toBe(1);
    expect(requests).toEqual([...READ_A, ...READ_A, ...READ_A]);
    expect(existsSync(marker)).toBe(false);
    expect(result.stdout).toBe("");
    const lines = result.stderr.trimEnd().split("\n");
    expect(lines).toEqual([
      "varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again (attempt 2 of 3, another audited disclosure)",
      "varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again (attempt 3 of 3, another audited disclosure)",
      "varlatch: the configuration changed between reading it and disclosing its Secrets, on each of 3 attempts, so the run context could not describe the values delivered. Nothing was started.",
    ]);
    for (const value of [...STATE_A.items, ...STATE_B.items].map((i) => i.value)) expect(result.stderr).not.toContain(value);
  });

  it("does not read again when the disclosure is refused: every value delivered comes from the configuration", async () => {
    configurationStates = [STATE_A];
    disclosureStates = "denied";
    const result = await cli(["run", "--export-context", "--", process.execPath, "-e", PRINT]);
    expect(result.code).toBe(0);
    expect(requests).toEqual(READ_A);
    expect(result.stderr).toBe("varlatch: secrets not disclosed (PERMISSION_DENIED); continuing with non-sensitive values\nvarlatch: 1 value(s) withheld by policy: API_KEY\n");
    const seen = JSON.parse(result.stdout) as { context: string; key: string | null };
    expect(seen.key).toBeNull();
    expect(JSON.parse(seen.context).items.API_KEY).toEqual({ server: "withheld", delivery: "absent" });
  });

  it("without the flag nothing is compared or read again, as before", async () => {
    configurationStates = [STATE_A];
    disclosureStates = [STATE_B];
    const result = await cli(["run", "--", process.execPath, "-e", PRINT]);
    expect(result.code).toBe(0);
    expect(result.stderr).toBe("");
    expect(requests).toEqual([`GET ${ENV}/effective-configuration?include=values`, `POST ${ENV}/disclosures`]);
    // The value comes from the disclosure, as it always has.
    expect(JSON.parse(result.stdout)).toMatchObject({ context: null, key: "valuebbbbbbbbbbbbb" });
  });
});
