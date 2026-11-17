// SPDX-License-Identifier: Apache-2.0
/**
 * Extra cases for the Go vectors (go-vectors.test.ts imports this file
 * when it writes them): what the adapters' own tests leave out and the Go
 * port must still match. Each call is recorded as it runs; the
 * expectations here only keep the cases honest.
 *
 * A test whose name starts with "divergence:" records an input on which Go
 * is known to answer otherwise (go/lib/sync's README lists them); the Go
 * replay checks its own answer for those instead.
 */
import { describe, expect, it } from "vitest";
import { classifyComposeUsage } from "../src/coolifyCompose.js";
import { coolifyAdapter, convexAdapter, githubActionsAdapter, type AdapterRequest } from "../src/index.js";
import { parseTokenExpiration } from "../src/github.js";
import { SEAL_PUBLIC_KEYS } from "./go-vectors-seal.js";

type Answer = { status: number; body?: string; headers?: Record<string, string> } | Error;

/** A fake service: each request takes the next answer. */
function script(...answers: Answer[]): typeof fetch {
  const queue = [...answers];
  return (async () => {
    const next = queue.shift();
    if (!next) throw new TypeError("fetch failed");
    if (next instanceof Error) throw next;
    const nullBody = [204, 205, 304].includes(next.status);
    return new Response(nullBody ? null : (next.body ?? ""), {
      status: next.status,
      headers: { "content-type": "application/json", ...next.headers },
    });
  }) as typeof fetch;
}

const json = (status: number, body: unknown, headers?: Record<string, string>): Answer => ({ status, body: JSON.stringify(body), ...(headers ? { headers } : {}) });

const coolify = (fetchImpl: typeof fetch, destination: Record<string, string> = { applicationUuid: "app-uuid-1" }, extra: Partial<AdapterRequest> = {}): AdapterRequest => ({
  baseIdentity: "https://coolify.example.com",
  destination,
  credential: "tok",
  fetchImpl,
  ...extra,
});
const github = (fetchImpl: typeof fetch, destination: Record<string, string> = { repo: "api" }, extra: Partial<AdapterRequest> = {}): AdapterRequest => ({
  baseIdentity: "acme",
  destination,
  credential: "github_pat_test",
  fetchImpl,
  ...extra,
});
const convex = (fetchImpl: typeof fetch, extra: Partial<AdapterRequest> = {}): AdapterRequest => ({
  baseIdentity: "https://happy-animal-123.convex.cloud",
  destination: {},
  credential: "convex-key-material",
  fetchImpl,
  ...extra,
});

const generated = (containers: string[]) =>
  `services:\n${containers.map((c) => `  ${c}:\n    image: x\n    env_file:\n      - .env\n`).join("")}`;

describe("extra: compose YAML as the yaml package reads it", () => {
  const names = ["A", "B", "C", "D", "FOO", "null", "7", "true", "SERVICE_PASSWORD_X", "SERVICE_URL_APP"];
  const corpus: Record<string, string> = {
    plain: "services:\n  app:\n    environment:\n      A: ${A}\n      B: literal\n      C: ''\n",
    list: "services:\n  app:\n    environment:\n      - A=${A}\n      - B\n      - C=\n",
    mixedList: "services:\n  app:\n    environment:\n      A: x\n    build:\n      args:\n        - B=1\n        - C\n",
    numbers: "services:\n  app:\n    environment:\n      A: 1\n      B: 1.5\n      C: 0x1F\n      D: .inf\n",
    octalAndSeparators: "services:\n  app:\n    environment:\n      A: 017\n      B: 0o17\n      C: 1_000\n      D: +1\n",
    bools: "services:\n  app:\n    environment:\n      A: true\n      B: yes\n      C: 'true'\n      D: False\n",
    nulls: "services:\n  app:\n    environment:\n      A:\n      B: ~\n      C: null\n      D: NULL\n",
    numericKeys: "services:\n  app:\n    environment:\n      1: A\n      A: x\n",
    phpNumericKey: "services:\n  app:\n    environment:\n      ' 1.5e3 ': A\n",
    tagged: "services:\n  app:\n    environment:\n      A: !!str 123\n      B: !!int '7'\n      C: !!float 1\n      D: !custom ${D}\n",
    nonSpecificTag: "services:\n  app:\n    environment:\n      A: ! 12\n",
    quotedKeys: "services:\n  'app':\n    environment:\n      \"A\": ${A}\n      'B': $B\n",
    blockScalars: "services:\n  app:\n    environment:\n      A: |\n        ${A}\n      B: >-\n        $B\n",
    flow: "services: {app: {environment: {A: '${A}', B: $B}}, db: {image: postgres}}\n",
    anchorsAndMerge:
      "x-env: &env\n  A: ${A}\n  B: base\nservices:\n  app:\n    environment:\n      <<: *env\n      B: ${B}\n  worker:\n    environment: *env\n",
    mergeList: "x-a: &a {A: '1'}\nx-b: &b {A: '2', B: '2'}\nservices:\n  app:\n    environment:\n      <<: [*a, *b]\n      C: $C\n",
    mergeOverride: "x-a: &a {A: '1', B: '1'}\nservices:\n  app:\n    environment:\n      A: own\n      <<: *a\n      B: later\n",
    mergeQuotedKey: "x-a: &a {A: '1'}\nservices:\n  app:\n    environment:\n      '<<': *a\n",
    mergeStrTag: "x-a: &a {A: '1'}\nservices:\n  app:\n    environment:\n      !!str <<: *a\n",
    mergeScalarFails: "x-a: &a 1\nservices:\n  app:\n    environment:\n      <<: *a\n",
    duplicateKeys: "services:\n  app:\n    environment:\n      A: first\n      A: ${A}\n",
    duplicateServices: "services:\n  app:\n    environment:\n      A: x\n  app:\n    image: y\n",
    nullKey: "services:\n  app:\n    environment:\n      ~: ${A}\n      null: $B\n",
    protoKey: "services:\n  __proto__:\n    environment:\n      A: x\n  constructor:\n    environment:\n      B: ${B}\n",
    escapedDollar: "services:\n  app:\n    command: \"echo \\u0024A $$B\"\n",
    references: "services:\n  app:\n    command: run ${A:-x} $B $$C ${D}\n",
    copied: "services:\n  app:\n    environment:\n      X: ${A:-default}\n      Y: ${B}-${C}\n      D: ''\n",
    selfReferences: "services:\n  app:\n    environment:\n      A: ${A:?required}\n      B: ${B-x}\n      C: ${C}x\n      D: ${SERVICE_PASSWORD_X}\n",
    envFileForms: "services:\n  app:\n    env_file: ./.env\n  db:\n    env_file:\n      - path: .env\n        required: false\n",
    trailingDocument: "services:\n  app:\n    environment:\n      A: x\n---\n",
    multipleDocuments: "services:\n  app:\n    image: x\n---\nservices:\n  db:\n    image: y\n",
    notAMapping: "- a\n- b\n",
    empty: "",
    commentsOnly: "# nothing\n",
    malformed: "services:\n  app:\n    environment: [A, B\n",
    tabs: "services:\n  app:\n    environment:\n      A:\t${A}\n",
    aliasesAtTheLimit: `x: &v '\${A}'\nservices:\n  app:\n    environment:\n${Array.from({ length: 199 }, (_, i) => `      K${i}: *v\n`).join("")}`,
    aliasesOverTheLimit: `x: &v '\${A}'\nservices:\n  app:\n    environment:\n${Array.from({ length: 200 }, (_, i) => `      K${i}: *v\n`).join("")}`,
    nestedAliasCount: "a: &a [x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nservices:\n  app:\n    environment:\n      A: x\n    labels: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n",
    unknownAnchor: "services:\n  app:\n    environment: *nope\n",
    unicode: "services:\n  \u00e9app:\n    environment:\n      A: \"\\u00e9${A}\"\n  Zed:\n    image: x\n  apple:\n    image: x\n",
    buildArgsObject: "services:\n  app:\n    build:\n      context: .\n      args:\n        A: ${A}\n        B: ''\n",
    nonStringEnvironment: "services:\n  app:\n    environment: A=1\n  db:\n    environment: 5\n",
    servicesNotMapping: "services:\n  - app\n",
    nonSpecificKey: "services: {app: {environment: {! null: \"\", ! 7: x, ! true: y}}}\n",
    nonSpecificValues: "services:\n  app:\n    environment:\n      A: ! ${A}\n      B: &b ! null\n      C: ! &c 12\n      D: *b\n",
    nonSpecificBlock: "services:\n  app:\n    environment:\n      ! null: ''\n      ! A: $A\n",
    yaml12Directive: "%YAML 1.2\n---\nservices:\n  app:\n    environment:\n      A: ${A}\n      B: 0o17\n      C: yes\n",
    yaml12DirectiveComment: "# head\n%YAML 1.2 # the version\n---\nservices:\n  app:\n    environment:\n      A: ''\n",
    yaml12DirectiveTwice: "%YAML 1.2\n%YAML 1.2\n---\nservices:\n  app:\n    image: x\n",
    yaml12NoDocumentStart: "%YAML 1.2\nservices:\n  app:\n    image: x\n",
    mergeTaggedQuoted: "services:\n  app:\n    environment:\n      !!merge \"<<\": {FOO: \"\"}\n      A: x\n",
    mergeTaggedOtherText: "services:\n  app:\n    environment:\n      !!merge 'anything': {FOO: \"\", A: $A}\n",
    mergeTaggedValue: "services:\n  app:\n    environment:\n      A: !!merge x\n",
    bomNonSpecificKey: "\ufeffservices: {app: {environment: {! null: literal}}}\n",
    bomNonSpecificBlock: "\ufeffservices:\n  app:\n    environment:\n      ! null: ''\n      A: ! ${A}\n",
    bomYaml12: "\ufeff%YAML 1.2\n---\nservices: {app: {image: x}}\n",
    bomYaml12Tag: "\ufeff%YAML 1.2\n---\nservices: {app: {environment: {! null: x, A: $A}}}\n",
    bomMerge: "\ufeffx-a: &a {A: ''}\nservices:\n  app:\n    environment:\n      <<: *a\n      B: $B\n",
    bomMultipleDocuments: "\ufeffservices: {app: {image: x}}\n---\nservices: {db: {image: y}}\n",
    bomComment: "\ufeff# head\nservices: {app: {environment: {A: $A}}}\n",
    yaml12Garbage: "%YAML 1.2 garbage\n---\nservices: {app: {image: x}}\n",
    yaml12RepeatGarbage: "%YAML 1.2\n%YAML 1.2 garbage\n---\nservices: {app: {image: x}}\n",
    yaml12HashNoBlank: "%YAML 1.2# c\n---\nservices: {app: {image: x}}\n",
    yaml12Tabs: "%YAML\t1.2\t\n---\nservices: {app: {environment: {A: $A}}}\n",
    yaml12Crlf: "%YAML 1.2\r\n---\r\nservices:\r\n  app:\r\n    environment:\r\n      ! null: ''\r\n",
    yaml12Bare: "%YAML\n---\nservices: {app: {image: x}}\n",
    yaml12CommentsBetween: "# a\n%YAML 1.2\n\n# b\n%YAML 1.2 # again\n--- # start\nservices: {app: {image: x}}\n",
  };
  for (const [name, raw] of Object.entries(corpus)) {
    it(name, () => {
      expect(classifyComposeUsage(raw, generated(["app", "db", "worker"]), 5, names).names.size).toBeGreaterThan(0);
    });
  }
  it("generated files that do not load .env", () => {
    const raw = corpus.plain as string;
    classifyComposeUsage(raw, "services:\n  app:\n    image: x\n", 5, names);
    classifyComposeUsage(raw, "services:\n  app:\n    env_file: [other.env]\n", 3, names);
    classifyComposeUsage(raw, "services: [", 5, names);
    classifyComposeUsage(raw, generated(["app"]), 2, names);
    classifyComposeUsage(raw, generated(["app"]), null, names);
    classifyComposeUsage("", generated(["app"]), 5, names);
    classifyComposeUsage(raw, "", 5, names);
  });
  it("names repeated", () => {
    expect(classifyComposeUsage(corpus.plain as string, generated(["app"]), 5, ["A", "A", "B"]).names.size).toBe(2);
  });
  it("divergence: a %YAML 1.1 document", () => {
    classifyComposeUsage("%YAML 1.1\n---\nservices:\n  app:\n    environment:\n      A: yes\n", generated(["app"]), 5, names);
  });
  it("divergence: a YAML 1.1 type", () => {
    classifyComposeUsage("services:\n  app:\n    environment:\n      A: !!binary aGVsbG8=\n", generated(["app"]), 5, names);
  });
  it("divergence: an alias inside its own anchor", () => {
    // TypeScript builds a cyclic object and overflows the stack reading it.
    expect(() =>
      classifyComposeUsage("services: &s\n  app:\n    environment:\n      A: x\n    loop: *s\n", generated(["app"]), 5, names),
    ).toThrow(RangeError);
  });
  for (const [name, raw] of Object.entries({
    "a %TAG directive": "%TAG !e! tag:example.com,2000:\n---\nservices: {app: {image: x}}\n",
    "a reserved directive": "%FOO bar\n---\nservices: {app: {image: x}}\n",
    "%YAML 1.3": "%YAML 1.3\n---\nservices: {app: {image: x}}\n",
    "%YAML 1.20": "%YAML 1.20\n---\nservices: {app: {image: x}}\n",
    "%YAML 1.1 then 1.2": "%YAML 1.1\n%YAML 1.2\n---\nservices: {app: {image: x}}\n",
    "two byte order marks": "\ufeff\ufeffservices: {app: {image: x}}\n",
    "a byte order mark inside": "services: {app: {environment: {A: \"\ufeff$A\"}}}\n",
    "%YAML 1.2 then 1.1": "%YAML 1.2\n%YAML 1.1\n---\nservices: {app: {image: x}}\n",
  })) {
    it(`divergence: ${name}`, () => {
      classifyComposeUsage(raw, generated(["app"]), 5, names);
    });
  }
  // Bare carriage returns (#218 review, third round): unreadable on both
  // sides, so the Services are not checked.
  for (const [name, raw] of Object.entries({
    "a trailing bare carriage return": "services: {app: {}}\r",
    "a bare carriage return after a byte order mark": "\ufeffservices: {app: {}}\r",
    "CRLF and a bare carriage return": "services:\r\n  app: {}\r  db: {}\r\n",
    "a bare carriage return as the line break": "services:\r  app:\r    environment:\r      FOO: x\r",
  })) {
    it(`carriage return: ${name}`, () => {
      classifyComposeUsage(raw, "services: {app: {}}", 3, ["FOO"]);
    });
  }
  // The subset (#218 review, fourth round): what Go reads is a conservative
  // subset of YAML, everything else unreadable. Each class below, where
  // TypeScript cannot read the file either.
  for (const [name, [raw, generated]] of Object.entries({
    "a line separator": ["services: {app: {}} ", "services: {app: {}}"],
    "a paragraph separator": ["services: {app: {}} ", "services: {app: {}}"],
    "a next line (NEL)": ["services: {app: {}}\u0085", "services: {app: {}}"],
    "a line separator in the generated file": ["services: {app: {environment: {FOO: x}}}", "services: {app: {}} "],
    "a NEL in the generated file": ["services: {app: {environment: {FOO: x}}}", "services: {app: {}}\u0085"],
    "a C0 control": ["services: {app: {}}\u0001", "services: {app: {}}"],
    "a vertical tab": ["services: {app: {}}\u000b", "services: {app: {}}"],
    "a form feed": ["services:\f\n  app: {}\n", "services: {app: {}}"],
    "DEL": ["services: {app: {}}\u007f", "services: {app: {}}"],
    "a C1 control": ["services: {app: {}}\u0090", "services: {app: {}}"],
    "U+FFFE": ["services: {app: {}}￾", "services: {app: {}}"],
    "a double-quoted value over two lines": ["services: {app: {environment: {FOO: \"a\nb\"}}}", "services: {app: {}}"],
    "a double-quoted value over two CRLF lines": ["services: {app: {environment: {FOO: \"a\r\nb\"}}}", "services: {app: {}}"],
    "a single-quoted value over two lines": ["services: {app: {environment: {FOO: 'a\nb'}}}", "services: {app: {}}"],
    "a single-quoted value over two CRLF lines": ["services: {app: {environment: {FOO: 'a\r\nb'}}}", "services: {app: {}}"],
    "a flow mapping continued unindented": ["services: {app: \n{image: x}}\n", "services: {app: {}}"],
    "a flow mapping opened on its own line": ["services: {\napp: {environment: {FOO: x}}}\n", "services: {app: {}}"],
    "a flow mapping closed on the next line": ["services: {app: {environment: {FOO: x\n}}}\n", "services: {app: {}}"],
    "a tag with brackets": ["services:\n  app:\n    environment:\n      FOO: !!b[[x]]inary aGVsbG8=\n", "services: {app: {}}"],
    "a tag run into a comma": ["services:\n  app:\n    environment:\n      FOO: !!merge, x\n", "services: {app: {}}"],
    "an anchor with a comma": ["services:\n  app:\n    environment:\n      FOO: &a,b x\n", "services: {app: {}}"],
    "a tag with another !": ["services:\n  app:\n    environment:\n      !!me!ge 'anything': {FOO: \"\"}\n", "services: {app: {}}"],
    "a named tag handle with no %TAG": ["services:\n  app:\n    environment:\n      FOO: !e!x '7'\n", "services: {app: {}}"],
  })) {
    it(`subset: ${name}`, () => {
      classifyComposeUsage(raw, generated, 3, ["FOO"]);
    });
  }
  // Read by TypeScript, unreadable in Go: outside the subset.
  for (const [name, raw] of Object.entries({
    "a lone surrogate": "services: {app: {environment: {FOO: \"\ud800\"}}}\n",
    "a double-quoted value over two indented lines": "services:\n  app:\n    environment:\n      FOO: \"a\n        b\"\n",
    "a single-quoted value over two indented lines": "services:\n  app:\n    environment:\n      FOO: 'a\n        b'\n",
    "an escaped line break": "services:\n  app:\n    environment:\n      FOO: \"a\\\n        b\"\n",
    "a plain value over two lines": "services:\n  app:\n    environment:\n      FOO: a\n        b\n",
    "a flow sequence over indented lines": "services:\n  app:\n    command: [\n      \"a\",\n      \"b\"\n    ]\n    environment:\n      FOO: x\n",
    "a flow mapping over indented lines": "services:\n  app: {\n    environment: {FOO: x}\n  }\n",
    "a property alone on its line": "services:\n  app:\n    environment:\n      FOO: !!str\n        x\n",
    "a tag with a star": "services:\n  app:\n    environment:\n      !!me*age 'anything': {FOO: \"\"}\n",
  })) {
    it(`divergence: ${name}`, () => {
      classifyComposeUsage(raw, "services: {app: {}}", 3, ["FOO"]);
    });
  }
  it("a Compose file as people and Coolify write it stays readable", () => {
    const raw = [
      "# a comment",
      "x-common: &common",
      "  restart: unless-stopped",
      "  labels:",
      "    - \"traefik.http.routers.app.rule=Host(`app.example.com`)\"",
      "services:",
      "  app:",
      "    <<: *common",
      "    image: 'ghcr.io/acme/app:1.2.3' # pinned",
      "    command: [\"node\", \"server.js\", \"--port\", \"3000\"]",
      "    entrypoint: |",
      "      sh -c 'echo \"it''s up\"'",
      "    healthcheck:",
      "      test: [\"CMD-SHELL\", \"curl -f http://localhost:3000 || exit 1\"]",
      "      interval: 30s",
      "    environment:",
      "      - FOO=${FOO}",
      "      - BAR=${BAR:-default}",
      "      - 'QUOTED=a # not a comment'",
      "    env_file: [.env]",
      "  db:",
      "    image: postgres:16",
      "    environment:",
      "      POSTGRES_PASSWORD: $SERVICE_PASSWORD_POSTGRES",
      "      NOTE: >",
      "        folded",
      "        text",
      "",
    ].join("\r\n");
    expect(classifyComposeUsage(raw, "services:\n  app:\n    env_file: [.env]\n  db:\n    env_file: [.env]\n", 3, ["FOO", "BAR", "QUOTED", "OTHER"]).checked).toBe(true);
  });
  it("divergence: a bare carriage return in a quoted value", () => {
    // The `yaml` package folds it into the value; here it is unreadable too.
    classifyComposeUsage("services: {app: {environment: {FOO: \"a\rb\"}}}\n", "services: {app: {}}", 3, ["FOO"]);
  });
  it("divergence: a sequence as a key", () => {
    classifyComposeUsage("services:\n  app:\n    environment:\n      ? [A, B]\n      : x\n", generated(["app"]), 5, names);
  });
});

describe("extra: Coolify answers", () => {
  it("odd env rows", async () => {
    const rows = [
      { uuid: "u1", key: "A", value: "1", is_literal: true, is_multiline: true, is_buildtime: false, is_runtime: true },
      ["not", "a", "row"],
      null,
      7,
      { uuid: "u2", key: 5, value: "five" },
      { uuid: "u3", key: "B", value: 12, is_literal: false },
      { uuid: "u4", key: "C", value: null, is_preview: "yes" },
      { uuid: "u5", key: "C", value: null },
      { uuid: { a: 1 }, key: "D" },
      { uuid: 0, key: "E", value: "e" },
      { uuid: "u6", key: "B", value: "later", is_literal: true },
      { uuid: "u7", key: "F", is_shown_once: 1, is_runtime: "sometimes" },
    ];
    await coolifyAdapter.readRemote!(coolify(script(json(200, rows))));
    await coolifyAdapter.readValues!(coolify(script(json(200, rows)), { serviceUuid: "svc-uuid-1" }));
    await coolifyAdapter.deleteNames(coolify(script(json(200, rows), { status: 200 }, { status: 404 }, { status: 500 })), ["A", "D", "E", "Z", "B"]);
    await coolifyAdapter.writeValues(coolify(script(json(200, rows), { status: 200 }, { status: 201 }, { status: 422 })), [
      { name: "A", value: "x" },
      { name: "F", value: "y" },
      { name: "NEW", value: "z" },
    ]);
  });

  it("writes with each option", async () => {
    for (const destination of [
      { applicationUuid: "app-uuid-1", buildTime: "true" },
      { applicationUuid: "app-uuid-1", buildTime: "false", platformExpands: "B" },
      { applicationUuid: "app-uuid-1", deployAction: "restart" },
    ]) {
      const rows = [{ uuid: "u1", key: "A", value: "old", is_build_time: true, is_literal: true }];
      await coolifyAdapter.writeValues(coolify(script(json(200, rows), { status: 200 }, { status: 200 }), destination), [
        { name: "A", value: "new" },
        { name: "B", value: "{{team.X}}" },
      ]);
      await coolifyAdapter.writeValues(coolify(script(json(200, []), { status: 422 }, { status: 201 }, { status: 201 }), destination), [
        { name: "A", value: "new" },
        { name: "B", value: "$HOME" },
      ]);
      await coolifyAdapter.triggerRedeploy!(coolify(script({ status: 200 }), destination));
    }
    await expect(coolifyAdapter.triggerRedeploy!(coolify(script({ status: 500 }), { serviceUuid: "svc-uuid-1" }))).rejects.toThrow("restart failed");
  });

  it("version answers", async () => {
    for (const body of ['"4.0.0-beta.420"', "\ufeff v4.4.6\n", "4.1", '"4"', "<html>", '"4.0.0"\n"x"', "\u00a04.0.1\u2028"]) {
      await coolifyAdapter.checkAccess(coolify(script({ status: 200, body }), {}));
    }
    await coolifyAdapter.checkAccess(coolify(script({ status: 403, body: '{"message":"You are not allowed to access the API."}' }), {}));
    await coolifyAdapter.checkAccess(coolify(script({ status: 403, body: '{"message":"API IS DISABLED"}' }), {}));
    await coolifyAdapter.checkAccess(coolify(script({ status: 403, body: '{"message":"Ap\u0131 is disabled"}' }), {}));
    await coolifyAdapter.checkAccess(coolify(script({ status: 403, body: "null" }), {}));
  });

  it("service checks", async () => {
    const svc = { serviceUuid: "svc-uuid-1" };
    const service = { uuid: "svc-uuid-1", name: "  Stack  ", applications: [{ name: "web" }, { name: "web" }, { name: 5 }], databases: [{ name: "db" }, null] };
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(200, service), json(200, [{ key: "A" }, { key: "B", value: "" }])), svc));
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(200, service), json(200, [{ key: "A" }])), svc));
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(200, service), json(403, { message: "Unauthenticated." })), svc));
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(200, service), json(200, { not: "rows" })), svc));
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(200, { uuid: "other" })), svc));
    await coolifyAdapter.checkAccess(coolify(script({ status: 200, body: '"4.0.0"' }, json(418, {})), svc));
  });

  it("listing labels in collation order", async () => {
    const labels = ["beta", "Alpha", "alpha", "\u00e9clair", "eclair", "Zulu", "zulu", "10 items", "9 items", "_under", "-dash", "\u00c5ngstr\u00f6m", "a b", "ab", "\u{1f600} emoji", "\u4e2d\u6587", "\u0131stanbul", "Istanbul", ""];
    const apps = labels.map((name, i) => ({ uuid: `app-uuid-${i}`, name, fqdn: i % 3 === 0 ? `https://app${i}.example.com,http://other` : i % 3 === 1 ? 5 : "  " }));
    await coolifyAdapter.listDestinations!(coolify(script(json(200, apps), json(200, [{ uuid: "svc-uuid-1", name: "Middle" }, { uuid: "x", name: "bad uuid" }])), {}));
    await coolifyAdapter.listDestinations!(coolify(script(json(200, apps.slice(0, 3)), { status: 403, body: "" }), {}));
    await coolifyAdapter.listDestinations!(coolify(script(json(200, apps.slice(0, 3)), new TypeError("fetch failed")), {}));
  });

  it("inspection answers", async () => {
    const svc = { serviceUuid: "svc-uuid-1" };
    const compose = "services:\n  app:\n    environment:\n      A: ${A}\n";
    for (const version of [5, "5", " 3 ", "0x3", "", null, true, [4], "three", 2.9]) {
      await coolifyAdapter.inspectUsage!(coolify(script(json(200, { uuid: "svc-uuid-1", docker_compose_raw: compose, docker_compose: generated(["app"]), compose_parsing_version: version })), svc), ["A"]);
    }
    await coolifyAdapter.inspectUsage!(coolify(script(json(200, { uuid: "svc-uuid-1", docker_compose_raw: compose })), svc), ["A"]);
    await coolifyAdapter.inspectUsage!(coolify(script(json(200, { uuid: "svc-uuid-1", docker_compose_raw: 5, docker_compose: generated(["app"]), compose_parsing_version: 5 })), svc), ["A"]);
  });
});

describe("extra: values Coolify would change", () => {
  const app = { applicationUuid: "app-uuid-1" };
  const listed = { applicationUuid: "app-uuid-1", platformExpands: "X" };
  const values = [
    "plain", " lead", "trail\t", "\0x", "x\u000b", "it's", "ends\\", "ends\\\\", "{{team.X}}", "{{ project.Y }}", "{{vault.Z}}", "{{other.Z}}",
    "{{team\n.X}}", "{{a}}{{server.Q}}", '{"a":"$x"}', "[1, 2]", '{"a": "b #c"}', "{not json $}", "$HOME", "cost: 5$", "a #b", "line\nbreak",
    "tab\there", 'quote"d', "\u00e9t\u00e9", "", "{{environment.}}",
  ];
  it("for an application and a listed name", () => {
    for (const value of values) {
      coolifyAdapter.valueProblem!(app, "X", value, null);
      coolifyAdapter.valueProblem!(listed, "X", value, null);
      coolifyAdapter.heldFix!(app, "X", value);
      coolifyAdapter.heldFix!(listed, "X", value);
    }
  });
  it("for a service with usage", () => {
    const svc = { serviceUuid: "svc-uuid-1" };
    const usage = { checked: true, names: new Map([["COPIED", { copiedIntoCompose: true }], ["SAFE", {}], ["UNKNOWN", { unknownIn: ["app"] }]]) };
    for (const name of ["COPIED", "SAFE", "UNKNOWN", "ABSENT"]) {
      coolifyAdapter.valueProblem!(svc, name, "has $dollar", usage);
      coolifyAdapter.valueProblem!(svc, name, "has $dollar", { checked: false, names: new Map() });
      coolifyAdapter.valueProblem!(svc, name, "has $dollar", undefined);
    }
  });
});

describe("extra: destinations as entered", () => {
  it("Coolify", () => {
    const inputs: Record<string, unknown>[] = [
      { applicationUuid: " app-uuid-1 ", buildTime: true, deployAction: "deploy", platformExpands: " B , A,B,, " },
      { applicationUuid: "app-uuid-1", platformExpands: ["Z", "a", "_x", "A"] },
      { applicationUuid: "app-uuid-1", platformExpands: [] },
      { applicationUuid: "app-uuid-1", platformExpands: ["ok", "1bad"] },
      { applicationUuid: "app-uuid-1", platformExpands: "\u00e9t\u00e9" },
      { applicationUuid: "app-uuid-1", platformExpands: 5 },
      { applicationUuid: "app-uuid-1", platformExpands: [5] },
      { applicationUuid: "app-uuid-1", platformExpands: Array.from({ length: 101 }, (_, i) => `N${i}`) },
      { applicationUuid: "app-uuid-1", buildTime: "yes" },
      { applicationUuid: "app-uuid-1", buildTime: 0 },
      { applicationUuid: "app-uuid-1", deployAction: "redeploy" },
      { applicationUuid: 5 },
      { serviceUuid: " svc-uuid-1 " },
      { serviceUuid: "svc-uuid-1", platformExpands: [] },
      { serviceUuid: "svc-uuid-1", platformExpands: "" },
      { serviceUuid: "svc-uuid-1", platformExpands: ["A"] },
      { serviceUuid: "svc-uuid-1", buildTime: false },
      { serviceUuid: "svc-uuid-1", applicationUuid: "app-uuid-1" },
      { serviceUuid: 7 },
      { serviceUuid: "", applicationUuid: "app-uuid-1" },
      { serviceUuid: null, applicationUuid: "app-uuid-1", buildTime: null, deployAction: "" },
    ];
    for (const raw of inputs) {
      try {
        coolifyAdapter.canonicalizeDestination(raw);
      } catch {
        // recorded
      }
    }
  });
  it("Convex and GitHub", () => {
    const inputs: Record<string, unknown>[] = [{}, { a: "" }, { b: null, a: "x" }, { z: 1, 2: "two", 1: "one" }, { x: false }, { x: 0 }];
    for (const raw of inputs) {
      try {
        convexAdapter.canonicalizeDestination(raw);
      } catch {
        // recorded
      }
    }
    for (const raw of [{ repo: " API.v2 " }, { repo: "api", environment: "  prod env  " }, { repo: "api", environment: "x".repeat(256) }, { repo: "api", environment: 5 }, { repo: "a/b" }, { repo: 5 }]) {
      try {
        githubActionsAdapter.canonicalizeDestination(raw);
      } catch {
        // recorded
      }
    }
  });
  it("base identities", () => {
    for (const raw of ["https://Coolify.Example.COM", "https://coolify.example.com:443/", "https://coolify.example.com:8443", "http://coolify.example.com", "https://u:p@coolify.example.com", "https://coolify.example.com/path", "https://coolify.example.com/?", "https://coolify.example.com/#", "not a url", " https://xn--bcher-kva.example ", "https://b\u00fccher.example", "https://[::1]:8443"]) {
      for (const adapter of [coolifyAdapter, convexAdapter]) {
        try {
          adapter.canonicalizeBaseIdentity(raw);
        } catch {
          // recorded
        }
      }
    }
    for (const raw of [" @Acme ", "acme-", "-acme", "a".repeat(39), "a".repeat(40), "\u0130stanbul"]) {
      try {
        githubActionsAdapter.canonicalizeBaseIdentity(raw);
      } catch {
        // recorded
      }
    }
  });
  it("names", () => {
    for (const name of ["ok_name", "stra\u00dfe", "\ufb01le", "\u0131d", "github_x", "x".repeat(201), "_", "9x", "A-B"]) {
      githubActionsAdapter.validateName(name);
      githubActionsAdapter.canonicalizeName(name);
    }
    for (const name of ["SERVICE_URL_APP", "SERVICE_PASSWORD_DB", "COOLIFY_X", "OK"]) {
      coolifyAdapter.validateName(name);
      coolifyAdapter.validateName(name, { serviceUuid: "svc-uuid-1" });
      coolifyAdapter.validateName(name, { applicationUuid: "app-uuid-1" });
    }
    for (const name of ["CONVEX_SITE_URL", "CONVEX_OTHER", "x".repeat(257), "a.b"]) convexAdapter.validateName(name);
  });
});

describe("extra: GitHub sealed values a replay opens", () => {
  it("seals each value to the known recipients", async () => {
    const values = ["postgres://user:pw@host/db", "", "\u00e9\u20ac\ud83d\ude00", "lone \ud800 surrogate", "x".repeat(1000), "line\nbreak\u0000nul"];
    for (const [i, key] of SEAL_PUBLIC_KEYS.entries()) {
      await githubActionsAdapter.writeValues(
        github(script(json(200, { key_id: `k${i}`, key }), ...values.map(() => ({ status: 201 })))),
        values.map((value, j) => ({ name: `V${j}`, value })),
      );
    }
    await githubActionsAdapter.writeValues(
      github(script(json(200, { key_id: "env", key: SEAL_PUBLIC_KEYS[0] }), { status: 204 }), { repo: "api", environment: "prod env" }),
      [{ name: "ENV_VALUE", value: "in an environment" }],
    );
  });
});

describe("extra: GitHub answers", () => {
  it("odd public keys", async () => {
    const key = Buffer.alloc(32, 7).toString("base64");
    for (const body of ["null", "5", '"text"', "[]", JSON.stringify({ key_id: 5, key }), JSON.stringify({ key: [1, 2, 3] }), JSON.stringify({ key_id: "k", key: "short" }), JSON.stringify({ key_id: { a: 1 }, key: Array.from({ length: 32 }, (_, i) => i) }), "{bad json", `\ufeff${JSON.stringify({ key_id: "k", key })}`]) {
      try {
        await githubActionsAdapter.writeValues(github(script({ status: 200, body }, { status: 201 })), [{ name: "A", value: "v\ud800" }]);
      } catch {
        // recorded
      }
    }
    try {
      await githubActionsAdapter.writeValues(github(script(json(200, { key_id: "k", key })), { repo: "api", environment: "bad\ud800env" }), [{ name: "A", value: "v" }]);
    } catch {
      // recorded
    }
  });
  it("token expiry headers", async () => {
    for (const value of ["2026-06-03 19:52:44 UTC", "2026-06-03T19:52:44Z", "2026-06-03 19:52:44 +0130", "2026-06-03 19:52:44 -01:30", "2026-02-30 00:00:00", "2026-01-01 24:00:00", "2026-01-01 24:00:01", "2026-13-01 00:00:00", "  2026-06-03 19:52:44\u00a0UTC\u2028", "2026-06-03 19:52:44 +2400", "0000-01-01 00:00:00 +0001", "9999-12-31 23:59:59 -2359", "garbage"]) {
      parseTokenExpiration(value);
      await githubActionsAdapter.checkAccess(github(script(json(200, { login: "acme" }, { "github-authentication-token-expiration": value })), {}, { onCredentialExpiry: () => undefined }));
    }
    parseTokenExpiration(null);
  });
  it("listings with odd repositories", async () => {
    const repos = [
      { name: "ok", owner: { login: "ACME" }, private: true },
      { name: "archived", owner: { login: "acme" }, archived: true },
      { name: "other", owner: { login: "someone" } },
      { name: "num", owner: { login: 5 } },
      { name: "noowner" },
      { name: "nologin", owner: {} },
      { name: "bad name", owner: { login: "acme" } },
      { name: "dotted.repo", owner: { login: "acme" }, private: "true" },
      { name: "turkish", owner: { login: "\u0130acme" } },
      null,
    ];
    await githubActionsAdapter.listDestinations!(github(script(json(200, { login: "acme", type: "User" }), json(200, repos)), {}));
    await githubActionsAdapter.listDestinations!(github(script(json(200, { login: "5", type: "Organization" }), json(200, repos)), {}));
    await githubActionsAdapter.listDestinations!(github(script(json(200, { total_count: 3, repositories: repos })), {}, { credentialKind: "github-app" }));
    await githubActionsAdapter.checkAccess(github(script(json(200, { total_count: 1, repositories: [] })), {}, { credentialKind: "github-app" }));
    await githubActionsAdapter.checkAccess(github(script(json(200, { total_count: 1.5, repositories: [] })), {}, { credentialKind: "github-app" }));
    await githubActionsAdapter.checkAccess(github(script({ status: 403, headers: { "x-ratelimit-remaining": "0" } }), {}));
  });
});

describe("extra: Convex answers", () => {
  it("odd query answers", async () => {
    for (const body of [
      JSON.stringify({ status: "success", value: [{ name: "A", value: "1" }, { name: "A", value: "2" }, { name: 5, value: "x" }, null, "str", { name: "B" }, { name: "C", value: 3 }] }),
      JSON.stringify({ status: "success", value: {} }),
      JSON.stringify({ status: "error", errorMessage: "boom" }),
      "null",
      "[]",
      "not json",
      '{"status":"success","status":"error","value":[]}',
      '{"status":"error","status":"success","value":[]}',
    ]) {
      try {
        await convexAdapter.readValues!(convex(script({ status: 200, body })));
      } catch {
        // recorded
      }
    }
  });
  it("batches with oversized and aborted names", async () => {
    await convexAdapter.writeValues(convex(script({ status: 200 })), [
      { name: "A", value: "x".repeat(8192) },
      { name: "B", value: "\u00e9".repeat(4097) },
      { name: "C", value: "\ud800".repeat(2731) },
      { name: "A", value: "dup" },
    ]);
    await convexAdapter.writeValues(convex(script({ status: 200 }), { shouldAbort: async () => true }), [
      { name: "A", value: "x".repeat(9000) },
      { name: "B", value: "b" },
    ]);
    await convexAdapter.deleteNames(convex(script({ status: 400 })), ["A", "B"]);
    for (const body of ['{"success":true,"allowedOps":[]}', '{"success":true,"allowedOps":["Other"]}', '{"success":true,"isReadOnly":"yes"}', '{"success":"true"}', "[]"]) {
      await convexAdapter.checkAccess(convex(script({ status: 200, body })));
    }
  });
});
