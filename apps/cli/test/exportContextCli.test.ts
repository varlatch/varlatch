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
 */

const CLI = fileURLToPath(new URL("../dist/varlatch.cjs", import.meta.url));
const REVISION = revision([
  contractItem("API_KEY", { sensitive: true, required: { kind: "always" } }),
  contractItem("PORT", { type: "number" }),
  contractItem("REGION"),
]);
const ENV = "/v1/organizations/acme/projects/api/environments/development";

let server: Server;
let repo: string;
const requests: string[] = [];

beforeAll(async () => {
  if (!existsSync(CLI)) throw new Error("the CLI bundle is not built: run pnpm --filter @varlatch/cli build");
  server = createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const json = (status: number, body: unknown) => res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
    if (req.method === "GET" && req.url === `${ENV}/effective-configuration?include=values`) {
      return json(200, {
        environmentId: "env_dev",
        items: [
          { name: "API_KEY", sensitive: true, source: "self", versionId: "ver_1", value: null },
          { name: "PORT", sensitive: false, source: "self", versionId: "ver_2", value: "8080" },
        ],
        manifest: {
          manifestVersion: 1,
          projectId: "prj_1",
          environment: { id: "env_dev", rootId: "env_dev", parentId: null, tier: "development", expiresAt: null },
          contract: { revisionId: REVISION.id, contentHash: REVISION.contentHash, semanticsVersion: 2 },
          items: [],
        },
      });
    }
    if (req.method === "GET" && req.url === `/v1/organizations/acme/projects/api/contract/revisions/${REVISION.id}`) {
      return json(200, REVISION);
    }
    if (req.method === "POST" && req.url === `${ENV}/disclosures`) {
      return json(200, { items: [{ name: "API_KEY", versionId: "ver_1", value: "sk-disclosed-1" }], withheld: [] });
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

  it("without the flag the run is unchanged, and an inherited context is removed", async () => {
    const result = await cli(["run", "--", process.execPath, "-e", PRINT], { VARLATCH_RUN_CONTEXT: '{"stale":true}' });
    expect(result.code).toBe(0);
    expect(requests).toEqual([`GET ${ENV}/effective-configuration?include=values`, `POST ${ENV}/disclosures`]);
    expect(JSON.parse(result.stdout)).toMatchObject({ context: null, key: "sk-disclosed-1" });
  });

  it("applies only to default runs", async () => {
    const result = await cli(["run", "--export-context", "--strict", "--", process.execPath, "-e", "0"]);
    expect(result.code).toBe(1);
    expect(result.stderr).toContain("--export-context applies only to default runs");
    expect(requests).toEqual([]);
  });
});
