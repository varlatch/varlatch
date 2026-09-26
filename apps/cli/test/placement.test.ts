// SPDX-License-Identifier: Apache-2.0
import { parseTarget, type Target } from "@varlatch/protocol";
import { describe, expect, it } from "vitest";
import { generatePlaceholder } from "../src/broker.js";
import { BODY_LIMIT, percentEncode, planPlacement, type PlacementPlan, type RequestParts } from "../src/placement.js";

// ADR-0039 acceptance tests 11 to 15 and the after-exercise rules of 17,
// against the pure planner; broker.test.ts covers the same through the proxy.

const A = generatePlaceholder();
const B = generatePlaceholder();
const placeholders = new Map([
  [A, "API_KEY"],
  [B, "DB_PASSWORD"],
]);

function targets(spec: Record<string, string[]>): Map<string, Target[]> {
  return new Map(Object.entries(spec).map(([item, list]) => [item, list.map((t) => parseTarget(t))]));
}

function request(init: Partial<RequestParts> & { json?: unknown; form?: string; type?: string }): RequestParts {
  const headers = [...(init.headers ?? [])];
  let body = init.body ?? Buffer.alloc(0);
  if (init.json !== undefined) {
    body = Buffer.from(typeof init.json === "string" ? init.json : JSON.stringify(init.json));
    headers.push(["Content-Type", init.type ?? "application/json"]);
  }
  if (init.form !== undefined) {
    body = Buffer.from(init.form);
    headers.push(["Content-Type", init.type ?? "application/x-www-form-urlencoded"]);
  }
  return { headers, query: init.query ?? null, body };
}

function substitute(plan: PlacementPlan, values: Record<string, string>) {
  if (plan.kind !== "substitute") throw new Error(`expected substitute, got ${JSON.stringify(plan)}`);
  const applied = plan.apply(new Map(Object.entries(values)));
  if (!applied.ok) throw new Error(applied.message);
  return applied;
}

function blocked(plan: PlacementPlan, rule: string, ...fragments: string[]) {
  expect(plan).toMatchObject({ kind: "block", status: 403, rule });
  for (const f of fragments) expect((plan as { message: string }).message).toContain(f);
  // A diagnostic names item, rule, and location, never a value.
  expect(JSON.stringify(plan)).not.toContain(A);
}

describe("substitution at each target kind (test 11)", () => {
  it("header: raw, other text in the value kept, every other header unchanged", () => {
    const plan = planPlacement(
      request({ headers: [["Authorization", `Bearer ${A}`], ["X-Other", "keep me"]] }),
      placeholders,
      targets({ API_KEY: ["header:authorization"] }),
    );
    expect(plan).toMatchObject({ placements: [{ item: "API_KEY", target: "header:authorization" }] });
    expect(substitute(plan, { API_KEY: "sk live/1" }).headers).toEqual([
      ["Authorization", "Bearer sk live/1"],
      ["X-Other", "keep me"],
    ]);
  });

  it("query: percent-encoded, every other parameter byte-exact", () => {
    const plan = planPlacement(
      request({ query: `a=%7e1&api_key=${A}&b=x+y` }),
      placeholders,
      targets({ API_KEY: ["query:api_key"] }),
    );
    expect(substitute(plan, { API_KEY: "s k/&=~é" }).query).toBe(`a=%7e1&api_key=${percentEncode("s k/&=~é")}&b=x+y`);
    expect(percentEncode("s k/&=~é!*'()")).toBe("s%20k%2F%26%3D~%C3%A9%21%2A%27%28%29");
  });

  it("json: JSON-string-escaped at the pointer; the body is never re-serialized", () => {
    const raw = `{ "a" : 1.50,\n  "auth": {"key": "${A}"}, "list": ["x"] }`;
    const plan = planPlacement(request({ json: raw }), placeholders, targets({ API_KEY: ["json:/auth/key"] }));
    const body = substitute(plan, { API_KEY: 'q"u\\o\nte</' }).body.toString();
    expect(body).toBe(`{ "a" : 1.50,\n  "auth": {"key": "q\\"u\\\\o\\nte</"}, "list": ["x"] }`);
    expect(JSON.parse(body).auth.key).toBe('q"u\\o\nte</');
  });

  it("json: pointers with escaped tokens and array indices", () => {
    const raw = JSON.stringify({ "a/b": { "c~d": [0, A] } });
    const plan = planPlacement(request({ json: raw }), placeholders, targets({ API_KEY: ["json:/a~1b/c~0d/1"] }));
    expect(JSON.parse(substitute(plan, { API_KEY: "v" }).body.toString())).toEqual({ "a/b": { "c~d": [0, "v"] } });
  });

  it("form: percent-encoded, every other field byte-exact", () => {
    const plan = planPlacement(
      request({ form: `grant_type=client_credentials&client_secret=${A}&scope=a+b` }),
      placeholders,
      targets({ API_KEY: ["form:client_secret"] }),
    );
    expect(substitute(plan, { API_KEY: "p+w d" }).body.toString()).toBe(
      "grant_type=client_credentials&client_secret=p%2Bw%20d&scope=a+b",
    );
  });

  it("several items and targets in one request", () => {
    const plan = planPlacement(
      request({ headers: [["X-Api-Key", A]], json: { password: B } }),
      placeholders,
      targets({ API_KEY: ["header:x-api-key"], DB_PASSWORD: ["json:/password", "header:x-db"] }),
    );
    expect(plan).toMatchObject({ kind: "substitute" });
    const applied = substitute(plan, { API_KEY: "k1", DB_PASSWORD: "p1" });
    expect(applied.headers).toContainEqual(["X-Api-Key", "k1"]);
    expect(JSON.parse(applied.body.toString())).toEqual({ password: "p1" });
  });

  it("a request whose targets are all absent passes unchanged", () => {
    expect(planPlacement(request({ headers: [["X-Other", "1"]] }), placeholders, targets({ API_KEY: ["header:authorization"] }))).toEqual({
      kind: "pass",
      strays: [],
    });
  });
});

describe("outside the targets (tests 12 and 13)", () => {
  const t = targets({ API_KEY: ["header:authorization", "query:key"] });

  it("a Placeholder elsewhere in a targeted surface blocks, naming item, rule, and location", () => {
    blocked(planPlacement(request({ headers: [["Authorization", `Bearer ${A}`], ["X-Debug", A]] }), placeholders, t), "outside-target", "API_KEY", 'header "x-debug"');
    blocked(planPlacement(request({ query: `q=${A}` }), placeholders, t), "outside-target", 'query parameter "q"');
    blocked(planPlacement(request({ query: `key=x${A}` }), placeholders, t), "outside-target", 'query parameter "key"');
    blocked(planPlacement(request({ query: `${A}=1` }), placeholders, t), "outside-target");
    const json = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: { key: A, log: `sent ${A}` } }), placeholders, json), "outside-target", 'JSON body at "/log"');
    blocked(planPlacement(request({ json: { key: `${A} ` } }), placeholders, json), "outside-target");
    blocked(planPlacement(request({ json: { [A]: 1 } }), placeholders, json), "outside-target", "a JSON key");
  });

  it("a stray in an untargeted surface is forwarded unchanged and reported", () => {
    const plan = planPlacement(
      request({ headers: [["Authorization", `Bearer ${A}`]], body: Buffer.from(`log: ${A}`), type: "text/plain" }),
      placeholders,
      t,
    );
    expect(plan).toMatchObject({ kind: "substitute", strays: [{ item: "API_KEY", surface: "body" }] });
    expect(substitute(plan, { API_KEY: "v" }).body.toString()).toBe(`log: ${A}`);
  });

  it("a Placeholder of an item with no target in any present surface passes inert", () => {
    const plan = planPlacement(request({ json: { note: B } }), placeholders, t);
    expect(plan).toEqual({ kind: "pass", strays: [{ item: "DB_PASSWORD", surface: "body" }] });
  });

  it("other runs' Placeholders are ordinary text", () => {
    const foreign = generatePlaceholder();
    expect(planPlacement(request({ headers: [["X-Debug", foreign]] }), placeholders, t)).toEqual({ kind: "pass", strays: [] });
  });
});

describe("each target at most once (test 14)", () => {
  it("a second occurrence at a target blocks", () => {
    blocked(
      planPlacement(request({ headers: [["Authorization", `${A} ${A}`]] }), placeholders, targets({ API_KEY: ["header:authorization"] })),
      "second-occurrence",
    );
  });

  it("the same item at two different targets is substituted at both", () => {
    const plan = planPlacement(
      request({ headers: [["Authorization", A]], query: `key=${A}` }),
      placeholders,
      targets({ API_KEY: ["header:authorization", "query:key"] }),
    );
    expect(plan).toMatchObject({ kind: "substitute", placements: [{ target: "header:authorization" }, { target: "query:key" }] });
  });
});

describe("parser differentials block (test 15)", () => {
  it("a duplicate JSON key anywhere in the body", () => {
    const t = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: `{"key":"${A}","key":"x"}` }), placeholders, t), "duplicate-key");
    blocked(planPlacement(request({ json: `{"key":"${A}","o":{"a":1,"a":2}}` }), placeholders, t), "duplicate-key");
    // Distinct only after escape decoding is still a duplicate.
    blocked(planPlacement(request({ json: `{"key":"${A}","\\u006bey":"x"}` }), placeholders, t), "duplicate-key");
  });

  it("an invalid or over-deep JSON body", () => {
    const t = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: `{"key":"${A}",}` }), placeholders, t), "invalid-body");
    blocked(planPlacement(request({ json: `{"key":"${A}"} x` }), placeholders, t), "invalid-body");
    blocked(planPlacement(request({ json: `{"key":"${A}","d":${"[".repeat(400)}${"]".repeat(400)}}` }), placeholders, t), "invalid-body");
  });

  it("a repeated target header, including in a different case, and a folded one", () => {
    const t = targets({ API_KEY: ["header:authorization"] });
    blocked(planPlacement(request({ headers: [["Authorization", A], ["authorization", "x"]] }), placeholders, t), "repeated-header");
    blocked(planPlacement(request({ headers: [["Authorization", `Bearer\r\n ${A}`]] }), placeholders, t), "folded-header");
  });

  it("a repeated query or form name, including under a percent-encoded spelling", () => {
    const q = targets({ API_KEY: ["query:api_key"] });
    blocked(planPlacement(request({ query: `api_key=${A}&api_key=x` }), placeholders, q), "repeated-name");
    blocked(planPlacement(request({ query: `api_key=${A}&api%5Fkey=x` }), placeholders, q), "repeated-name");
    const f = targets({ API_KEY: ["form:api_key"] });
    blocked(planPlacement(request({ form: `api_key=${A}&api%5fkey=x` }), placeholders, f), "repeated-name");
    blocked(planPlacement(request({ query: `api+key=${A}&api%20key=x` }), placeholders, targets({ API_KEY: ["query:api key"] })), "repeated-name");
  });

  it('";" in a targeted query or form', () => {
    blocked(planPlacement(request({ query: `api_key=${A};x=1` }), placeholders, targets({ API_KEY: ["query:api_key"] })), "separator");
    blocked(planPlacement(request({ form: `api_key=${A};x=1` }), placeholders, targets({ API_KEY: ["form:api_key"] })), "separator");
  });

  it("an encoded Placeholder in a targeted surface, even without a literal one", () => {
    const pct = A.replace("_", "%5F");
    const q = targets({ API_KEY: ["query:api_key"] });
    blocked(planPlacement(request({ query: `api_key=${pct}` }), placeholders, q), "encoded-placeholder");
    blocked(planPlacement(request({ query: `api_key=${A}&x=${pct}` }), placeholders, q), "encoded-placeholder");
    const escaped = A.replace("v", "\\u0076");
    blocked(planPlacement(request({ json: `{"key":"${A}","x":"${escaped}"}` }), placeholders, targets({ API_KEY: ["json:/key"] })), "encoded-placeholder");
    blocked(planPlacement(request({ json: `{"key":"${escaped}"}` }), placeholders, targets({ API_KEY: ["json:/key"] })), "encoded-placeholder");
    blocked(planPlacement(request({ form: `a=${pct}` }), placeholders, targets({ API_KEY: ["form:a"] })), "encoded-placeholder");
  });

  it("a Content-Type that does not match the body target, or none, or a repeated one", () => {
    const t = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: { key: A }, type: "text/plain" }), placeholders, t), "content-type");
    blocked(planPlacement(request({ form: `key=${A}` }), placeholders, t), "content-type");
    blocked(planPlacement(request({ body: Buffer.from(JSON.stringify({ key: A })) }), placeholders, t), "content-type", "none");
    blocked(
      planPlacement(request({ json: { key: A }, headers: [["Content-Type", "application/json"]] }), placeholders, t),
      "content-type",
      "repeated",
    );
  });

  it("a charset other than UTF-8, and a body that is not UTF-8", () => {
    const t = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: { key: A }, type: "application/json; charset=iso-8859-1" }), placeholders, t), "content-type");
    expect(planPlacement(request({ json: { key: A }, type: 'application/json; charset="UTF-8"' }), placeholders, t)).toMatchObject({
      kind: "substitute",
    });
    const latin1 = Buffer.concat([Buffer.from(`{"key":"${A}","n":"`), Buffer.from([0xe9]), Buffer.from('"}')]);
    blocked(planPlacement(request({ body: latin1, headers: [["Content-Type", "application/json"]] }), placeholders, t), "invalid-body");
  });

  it("a request body with a Content-Encoding", () => {
    const t = targets({ API_KEY: ["json:/key"] });
    blocked(planPlacement(request({ json: { key: A }, headers: [["Content-Encoding", "gzip"]] }), placeholders, t), "content-encoding");
    expect(planPlacement(request({ json: { key: A }, headers: [["Content-Encoding", "identity"]] }), placeholders, t)).toMatchObject({
      kind: "substitute",
    });
  });
});

describe("a body target constrains every request carrying the Placeholder", () => {
  const t = targets({ API_KEY: ["header:authorization", "json:/key"] });
  const header: [string, string][] = [["Authorization", `Bearer ${A}`]];

  it("blocks a malformed or mismatched body even when the Placeholder is only in a header", () => {
    blocked(planPlacement(request({ headers: header, json: "{not json" }), placeholders, t), "invalid-body");
    blocked(planPlacement(request({ headers: header, body: Buffer.from("plain"), type: "text/plain" }), placeholders, t), "content-type");
    blocked(planPlacement(request({ headers: [...header, ["Content-Encoding", "gzip"]], json: { other: 1 } }), placeholders, t), "content-encoding");
  });

  it("substitutes the header when the body is valid for the target, or absent", () => {
    expect(planPlacement(request({ headers: header, json: { other: 1 } }), placeholders, t)).toMatchObject({ kind: "substitute" });
    expect(planPlacement(request({ headers: header }), placeholders, t)).toMatchObject({ kind: "substitute" });
  });

  it("leaves bodies alone for a Secret without a body target", () => {
    const headerOnly = targets({ API_KEY: ["header:authorization"] });
    expect(planPlacement(request({ headers: header, body: Buffer.from("{not json"), type: "application/json" }), placeholders, headerOnly)).toMatchObject({
      kind: "substitute",
    });
  });
});

describe("after exercise (test 17)", () => {
  it("a value that cannot be carried in a header fails, as does a missing value", () => {
    const plan = planPlacement(request({ headers: [["Authorization", A]] }), placeholders, targets({ API_KEY: ["header:authorization"] }));
    if (plan.kind !== "substitute") throw new Error("expected substitute");
    for (const bad of ["a\r\nX-Injected: 1", "a\nb", "a\0b"]) {
      expect(plan.apply(new Map([["API_KEY", bad]]))).toMatchObject({ ok: false, rule: "unsafe-header-value" });
    }
    expect(plan.apply(new Map())).toMatchObject({ ok: false, rule: "missing-value" });
  });

  it("a substituted body over the limit fails", () => {
    const filler = "x".repeat(BODY_LIMIT - 200);
    const plan = planPlacement(request({ json: { key: A, filler } }), placeholders, targets({ API_KEY: ["json:/key"] }));
    if (plan.kind !== "substitute") throw new Error("expected substitute");
    expect(plan.apply(new Map([["API_KEY", "v".repeat(500)]]))).toMatchObject({ ok: false, rule: "body-limit" });
    expect(plan.apply(new Map([["API_KEY", "v"]]))).toMatchObject({ ok: true });
  });
});
