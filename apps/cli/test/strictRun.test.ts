// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it, vi } from "vitest";
import type { StrictRetrieval } from "@varlatch/protocol";
import {
  STRICT_EXIT,
  UsageError,
  checkAllowances,
  planStrictRun,
  runStrict,
  type StrictClient,
} from "../src/strictRun.js";
import { RUN_CONTEXT, buildEnv } from "../src/inject.js";

type Item = StrictRetrieval["items"][number];

function contractItem(name: string, fields: Record<string, unknown> = {}) {
  return { name, required: { kind: "always" }, sensitive: false, type: "string", ...fields };
}

/** A strict retrieval response, as the server shapes it. */
function retrieval(opts: {
  contract?: Record<string, unknown>[] | null;
  semanticsVersion?: number;
  items?: (Partial<Item> & { name: string })[];
  withheld?: StrictRetrieval["callerView"]["withheld"];
  unexpanded?: StrictRetrieval["callerView"]["unexpanded"];
  contractWithheld?: boolean;
  tier?: "development" | "staging" | "production";
  validation?: Partial<StrictRetrieval["validation"]>;
}): StrictRetrieval {
  const items = (opts.items ?? []).map((i) => ({
    sensitive: false,
    source: "self" as const,
    versionId: `ver_${i.name}`,
    value: null,
    ...i,
  })) as Item[];
  const semanticsVersion = opts.semanticsVersion ?? 2;
  return {
    environmentId: "env_1",
    manifest: {
      manifestVersion: 1,
      projectId: "prj_1",
      environment: { id: "env_1", rootId: "env_1", parentId: null, tier: opts.tier ?? "production", expiresAt: null },
      contract: opts.contract === null && !opts.contractWithheld ? null : { revisionId: "rev_1", contentHash: "sha256:abc", semanticsVersion },
      items: items.map((i) => ({ name: i.name, source: i.source, valueRowId: `val_${i.name}`, versionId: i.versionId })),
    },
    stateDigest: `sha256:${"0".repeat(64)}`,
    contract:
      opts.contract === null
        ? null
        : ({ schemaVersion: 1, ...(semanticsVersion !== 1 ? { semanticsVersion } : {}), items: opts.contract ?? [] } as never),
    items,
    callerView: {
      withheld: opts.withheld ?? [],
      unexpanded: opts.unexpanded ?? [],
      contractWithheld: opts.contractWithheld ?? false,
    },
    validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [], ...opts.validation } as never,
  };
}

const plan = (r: StrictRetrieval, parent: NodeJS.ProcessEnv = {}, allow: string[] = []) =>
  planStrictRun(r, parent, new Set(allow));
const kinds = (p: ReturnType<typeof plan>) => p.violations.map((v) => `${v.name}:${v.kind}`);

describe("strict startup: the delivery table", () => {
  it("a delivered value is used, overrides the parent, and is validated as received", () => {
    const p = plan(
      retrieval({ contract: [contractItem("PORT", { type: "number" })], items: [{ name: "PORT", value: "8080" }] }),
      { PORT: "1", PATH: "/bin" },
    );
    expect(p.violations).toEqual([]);
    expect(p.env.PORT).toBe("8080");
    expect(p.env.PATH).toBe("/bin");
    expect(p.context?.items.PORT).toEqual({ server: "delivered", delivery: "varlatch" });
  });

  it("an integer item at version 3 accepts whole numbers only; number keeps accepting fractions", () => {
    const contract = [contractItem("PORT", { type: "integer" }), contractItem("RATIO", { type: "number" })];
    const ok = plan(retrieval({ contract, semanticsVersion: 3, items: [{ name: "PORT", value: "3000" }, { name: "RATIO", value: "3.5" }] }));
    expect(ok.violations).toEqual([]);
    const bad = plan(retrieval({ contract, semanticsVersion: 3, items: [{ name: "PORT", value: "3.0" }, { name: "RATIO", value: "3.5" }] }));
    expect(bad.violations.map((v) => [v.name, v.kind, v.reason])).toEqual([["PORT", "invalid", "the delivered value must be a whole number"]]);
  });

  it("an invalid delivered value is a violation that names the item, never the value", () => {
    const p = plan(retrieval({ contract: [contractItem("PORT", { type: "number" })], items: [{ name: "PORT", value: "80a0" }] }));
    expect(kinds(p)).toEqual(["PORT:invalid"]);
    expect(JSON.stringify(p.violations)).not.toContain("80a0");
  });

  it("a delivered value with a reference left literal is a violation even if the text would validate", () => {
    const p = plan(
      retrieval({
        contract: [contractItem("REF")],
        items: [{ name: "REF", value: "${API_KEY}" }],
        unexpanded: [{ name: "REF", references: ["API_KEY"] }],
      }),
    );
    expect(kinds(p)).toEqual(["REF:unresolved-reference"]);
  });

  it("withheld: an allowed inherited value is used and validated; otherwise a violation", () => {
    const r = retrieval({
      contract: [contractItem("API_KEY", { sensitive: true })],
      items: [{ name: "API_KEY", sensitive: true, value: null }],
      withheld: [{ name: "API_KEY", reason: "permission", requires: "secret.reveal" }],
    });
    const allowed = plan(r, { API_KEY: "from-parent" }, ["API_KEY"]);
    expect(allowed.violations).toEqual([]);
    expect(allowed.env.API_KEY).toBe("from-parent");
    expect(allowed.context?.items.API_KEY).toEqual({ server: "withheld", delivery: "inherited" });

    const notAllowed = plan(r, { API_KEY: "from-parent" });
    expect(kinds(notAllowed)).toEqual(["API_KEY:withheld"]);
    expect(notAllowed.violations[0]?.reason).toContain("--allow-inherited API_KEY");
    expect(notAllowed.violations[0]?.reason).not.toContain("from-parent");

    expect(kinds(plan(r))).toEqual(["API_KEY:withheld"]);
  });

  it("withheld and not required here: absent, not a violation", () => {
    const p = plan(
      retrieval({
        contract: [contractItem("OPTIONAL", { sensitive: true, required: { kind: "never" } })],
        items: [{ name: "OPTIONAL", sensitive: true, value: null }],
        withheld: [{ name: "OPTIONAL", reason: "requirement", requires: "secret.reveal" }],
      }),
    );
    expect(p.violations).toEqual([]);
    expect(p.context?.items.OPTIONAL).toEqual({ server: "withheld", delivery: "absent" });
  });

  it("a Contract default never stands in for a withheld value", () => {
    const p = plan(
      retrieval({
        contract: [contractItem("FLAG", { sensitive: true, defaultValue: "off" })],
        items: [{ name: "FLAG", sensitive: true, value: null }],
        withheld: [{ name: "FLAG", reason: "permission", requires: "secret.reveal" }],
      }),
    );
    expect(kinds(p)).toEqual(["FLAG:withheld"]);
    expect(p.env.FLAG).toBeUndefined();
  });

  it("not stored: an allowed inherited value, else a violation for a parent-only value", () => {
    const r = retrieval({ contract: [contractItem("HOST")] });
    const allowed = plan(r, { HOST: "localhost" }, ["HOST"]);
    expect(allowed.violations).toEqual([]);
    expect(allowed.context?.items.HOST).toEqual({ server: "notStored", delivery: "inherited" });
    expect(kinds(plan(r, { HOST: "localhost" }))).toEqual(["HOST:inherited"]);
    // An empty string is a present value, so it is inherited too.
    expect(kinds(plan(r, { HOST: "" }))).toEqual(["HOST:inherited"]);
  });

  it("an allowed inherited value is validated exactly as received", () => {
    const p = plan(retrieval({ contract: [contractItem("PORT", { type: "number" })] }), { PORT: "eighty" }, ["PORT"]);
    expect(kinds(p)).toEqual(["PORT:invalid"]);
  });

  it("not stored and nothing inherited: the Contract default, validated; or missing if required", () => {
    const withDefault = plan(retrieval({ contract: [contractItem("PORT", { type: "number", defaultValue: "3000" })] }));
    expect(withDefault.violations).toEqual([]);
    expect(withDefault.env.PORT).toBe("3000");
    expect(withDefault.context?.items.PORT).toEqual({ server: "notStored", delivery: "default" });

    const badDefault = plan(retrieval({ contract: [contractItem("PORT", { type: "number", defaultValue: "none" })] }));
    expect(kinds(badDefault)).toEqual(["PORT:invalid"]);

    expect(kinds(plan(retrieval({ contract: [contractItem("NEEDED")] })))).toEqual(["NEEDED:missing"]);
    const optional = plan(retrieval({ contract: [contractItem("EXTRA", { required: { kind: "never" } })] }));
    expect(optional.violations).toEqual([]);
    expect(optional.context?.items.EXTRA).toEqual({ server: "notStored", delivery: "absent" });
  });

  it("requiredness follows the Environment: a production-only item is optional in development", () => {
    const item = contractItem("STRIPE", { required: { kind: "selector", selector: { kind: "tier", tier: "production" } } });
    expect(kinds(plan(retrieval({ contract: [item], tier: "production" })))).toEqual(["STRIPE:missing"]);
    expect(plan(retrieval({ contract: [item], tier: "development" })).violations).toEqual([]);
  });

  it("reports every violation at once", () => {
    const p = plan(
      retrieval({
        contract: [contractItem("A"), contractItem("B", { type: "number" }), contractItem("C")],
        items: [{ name: "B", value: "x" }],
      }),
      { C: "parent" },
    );
    expect(kinds(p)).toEqual(["A:missing", "B:invalid", "C:inherited"]);
  });

  it("items outside the Contract are delivered as usual and counted", () => {
    const p = plan(retrieval({ contract: [], items: [{ name: "LEGACY", value: "v" }] }), {});
    expect(p.env.LEGACY).toBe("v");
    expect(p.outsideContract).toBe(1);
  });
});

describe("strict startup fails closed", () => {
  it("without an active Contract", () => {
    expect(kinds(plan(retrieval({ contract: null })))).toEqual(["(contract):contract"]);
  });

  it("without contract.read", () => {
    const p = plan(retrieval({ contract: null, contractWithheld: true }));
    expect(kinds(p)).toEqual(["(contract):contract"]);
    expect(p.violations[0]?.reason).toContain("contract.read");
  });

  it("on a semantics version this CLI does not implement", () => {
    const p = plan(retrieval({ contract: [contractItem("A")], semanticsVersion: 9 }));
    expect(kinds(p)).toEqual(["(contract):semantics"]);
    expect(p.violations[0]?.reason).toContain("version 9");
  });

  it("when a stored item uses the reserved run-context name", () => {
    const p = plan(retrieval({ contract: [], items: [{ name: RUN_CONTEXT, value: "{}" }] }));
    expect(kinds(p)).toEqual([`${RUN_CONTEXT}:reserved`]);
  });

  it("on an --allow-inherited name that is not in the Contract", () => {
    expect(() => checkAllowances({ schemaVersion: 1, items: [contractItem("A") as never] }, ["A", "TYPO"])).toThrow(UsageError);
  });
});

describe("the run context", () => {
  it("records server status and delivery, names only, and replaces an inherited one", () => {
    const p = plan(
      retrieval({
        contract: [contractItem("DB", { sensitive: true }), contractItem("PORT", { defaultValue: "3000" })],
        items: [{ name: "DB", sensitive: true, value: "postgres://secret" }],
      }),
      { [RUN_CONTEXT]: '{"stale":true}' },
    );
    expect(p.violations).toEqual([]);
    const context = JSON.parse(p.env[RUN_CONTEXT] as string);
    expect(context).toEqual({
      v: 1,
      mode: "strict",
      contractRevisionId: "rev_1",
      contractHash: "sha256:abc",
      semanticsVersion: 2,
      environment: { rootId: "env_1", tier: "production" },
      items: {
        DB: { server: "delivered", delivery: "varlatch" },
        PORT: { server: "notStored", delivery: "default" },
      },
    });
    expect(p.env[RUN_CONTEXT]).not.toContain("postgres://secret");
    expect(p.env[RUN_CONTEXT]).not.toContain("3000");
  });

  it("a default run removes an inherited context and never injects a stored one", () => {
    const env = buildEnv(
      { [RUN_CONTEXT]: '{"stale":true}', PATH: "/bin" },
      { environmentId: "e", items: [{ name: RUN_CONTEXT, sensitive: false, source: "self", value: "spoof" }] },
    );
    expect(env[RUN_CONTEXT]).toBeUndefined();
    expect(env.PATH).toBe("/bin");
  });
});

describe("agent-safe strict startup", () => {
  const facts = (entries: [string, { present: boolean; authorized: boolean; reason?: "permission" | "requirement" }][] = []) => ({
    agent: new Map(entries),
  });
  const secret = (name: string, fields: Record<string, unknown> = {}) => contractItem(name, { sensitive: true, ...fields });

  it("a stored Secret with a valid verdict reaches the Agent as a Placeholder, never a value", () => {
    const p = planStrictRun(
      retrieval({
        contract: [secret("API_KEY"), contractItem("HOST")],
        items: [{ name: "API_KEY", sensitive: true, value: null }, { name: "HOST", value: "db.internal" }],
      }),
      { API_KEY: "parent-copy" },
      new Set(),
      facts([["API_KEY", { present: true, authorized: true }]]),
    );
    expect(p.violations).toEqual([]);
    expect(p.mediated).toEqual(["API_KEY"]);
    expect(p.env.HOST).toBe("db.internal");
    expect(p.context?.items.API_KEY).toEqual({ server: "delivered", delivery: "varlatch" });
  });

  it("fails closed when the operator cannot validate Secrets", () => {
    const p = planStrictRun(
      retrieval({
        contract: [secret("API_KEY")],
        items: [{ name: "API_KEY", sensitive: true, value: null }],
        validation: { notEvaluated: [{ name: "API_KEY", reason: "permission", requires: "secret.reveal" }] },
      }),
      {},
      new Set(),
      facts(),
    );
    expect(kinds(p)).toEqual(["API_KEY:not-evaluated"]);
    expect(p.violations[0]?.reason).toContain("secret.reveal");
  });

  it("reports the operator's verdicts: invalid and unresolved", () => {
    const p = planStrictRun(
      retrieval({
        contract: [secret("A", { type: "url" }), secret("B")],
        items: [
          { name: "A", sensitive: true, value: null },
          { name: "B", sensitive: true, value: null },
        ],
        validation: {
          invalid: [{ name: "A", reason: "must be a valid URL" }],
          unresolved: [{ name: "B", reason: "reference" }],
        },
      }),
      {},
      new Set(),
      facts(),
    );
    expect(kinds(p)).toEqual(["A:invalid", "B:unresolved-reference"]);
  });

  it("an Agent without secret.use at issuance is a violation", () => {
    const p = planStrictRun(
      retrieval({ contract: [secret("API_KEY")], items: [{ name: "API_KEY", sensitive: true, value: null }] }),
      {},
      new Set(),
      facts([["API_KEY", { present: true, authorized: false, reason: "requirement" }]]),
    );
    expect(kinds(p)).toEqual(["API_KEY:agent-unauthorized"]);
    expect(p.violations[0]?.reason).toContain("Requirement");
  });

  it("a Contract Secret only in the parent environment would reach the Agent: a violation", () => {
    const p = planStrictRun(retrieval({ contract: [secret("API_KEY")] }), { API_KEY: "plaintext" }, new Set(), facts());
    expect(kinds(p)).toEqual(["API_KEY:inherited"]);
    expect(p.mediated).toEqual([]);
  });

  it("--omit leaves a stored Secret out and removes the shell's copy; omitting a required one is a violation", () => {
    const r = retrieval({
      contract: [secret("API_KEY", { required: { kind: "never" } }), secret("DB_PASSWORD")],
      items: [
        { name: "API_KEY", sensitive: true, value: null },
        { name: "DB_PASSWORD", sensitive: true, value: null },
        { name: "EXTRA_TOKEN", sensitive: true, value: null },
      ],
    });
    const parent = { API_KEY: "shell", DB_PASSWORD: "shell", EXTRA_TOKEN: "shell" };
    const optional = planStrictRun(r, parent, new Set(), { ...facts(), omitted: new Set(["API_KEY", "EXTRA_TOKEN"]) });
    expect(optional.violations).toEqual([]);
    expect(optional.mediated).toEqual(["DB_PASSWORD"]);
    expect(optional.env.API_KEY).toBeUndefined();
    expect(optional.env.EXTRA_TOKEN).toBeUndefined();
    expect(optional.context?.items.API_KEY).toEqual({ server: "delivered", delivery: "absent" });
    const required = planStrictRun(r, parent, new Set(), { ...facts(), omitted: new Set(["DB_PASSWORD"]) });
    expect(kinds(required)).toEqual(["DB_PASSWORD:omitted"]);
    expect(required.env.DB_PASSWORD).toBeUndefined();
  });

  it("--allow-inherited may not name a Secret in an agent-safe run", () => {
    const contract = { schemaVersion: 1 as const, items: [secret("API_KEY") as never, contractItem("HOST") as never] };
    expect(() => checkAllowances(contract, ["API_KEY"], { agentSafe: true })).toThrow(/cannot name a Secret/);
    expect(() => checkAllowances(contract, ["HOST"], { agentSafe: true })).not.toThrow();
  });
});

describe("runStrict", () => {
  const good = retrieval({ contract: [contractItem("A")], items: [{ name: "A", value: "a" }] });
  const client = (overrides: Partial<StrictClient> = {}): StrictClient => ({
    meta: async () => ({ serverVersion: "0.11.0", capabilities: ["retrieval.strict"] }),
    strictRetrieval: async () => good,
    ...overrides,
  });
  const opts = (start = vi.fn(async () => 0)) => ({
    organization: "acme",
    project: "api",
    environment: "production",
    allowInherited: [] as string[],
    parent: {},
    start,
    log: vi.fn(),
  });

  it("starts the child with exactly the planned environment", async () => {
    const o = opts();
    expect(await runStrict(client(), o)).toBe(0);
    expect(o.start).toHaveBeenCalledTimes(1);
    expect(o.start.mock.calls[0]?.[0]).toMatchObject({ A: "a" });
  });

  it("does not start the child on a violation, and exits 78", async () => {
    const o = opts();
    const code = await runStrict(client({ strictRetrieval: async () => retrieval({ contract: [contractItem("A")] }) }), o);
    expect(code).toBe(STRICT_EXIT);
    expect(o.start).not.toHaveBeenCalled();
    expect(o.log).toHaveBeenCalledWith(expect.stringContaining("the command was not started"));
  });

  it("never falls back to a default run on a server without strict retrieval", async () => {
    const o = opts();
    const strictRetrieval = vi.fn();
    const code = await runStrict(client({ meta: async () => ({ serverVersion: "0.10.0", capabilities: [] }), strictRetrieval }), o);
    expect(code).toBe(STRICT_EXIT);
    expect(strictRetrieval).not.toHaveBeenCalled();
    expect(o.start).not.toHaveBeenCalled();
  });

  it("retries a failed retrieval once, then fails", async () => {
    const serverError = Object.assign(new Error("audit unavailable"), { status: 500 });
    const flaky = vi.fn().mockRejectedValueOnce(serverError).mockResolvedValueOnce(good);
    expect(await runStrict(client({ strictRetrieval: flaky }), opts())).toBe(0);
    expect(flaky).toHaveBeenCalledTimes(2);

    const failing = vi.fn().mockRejectedValue(serverError);
    const o = opts();
    await expect(runStrict(client({ strictRetrieval: failing }), o)).rejects.toThrow("audit unavailable");
    expect(failing).toHaveBeenCalledTimes(2);
    expect(o.start).not.toHaveBeenCalled();

    const denied = vi.fn().mockRejectedValue(Object.assign(new Error("denied"), { status: 403 }));
    await expect(runStrict(client({ strictRetrieval: denied }), opts())).rejects.toThrow("denied");
    expect(denied).toHaveBeenCalledTimes(1);
  });

  it("rejects an --allow-inherited name outside the Contract before starting anything", async () => {
    const o = { ...opts(), allowInherited: ["TYPO"] };
    await expect(runStrict(client(), o)).rejects.toThrow(UsageError);
    expect(o.start).not.toHaveBeenCalled();
  });
});
