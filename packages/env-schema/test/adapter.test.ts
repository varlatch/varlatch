// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { contractHash } from "@varlatch/contract";
import {
  EnvSchemaParseError,
  UnknownEnvironmentNameError,
  parseEnvSchema,
  resolveDraft,
  type EnvironmentRef,
} from "../src/index.js";

const SCHEMA = `# @defaultSensitive=false
# @defaultRequired=false

# Primary database connection string
# @required
# @sensitive
# @type=url
DATABASE_URL=

# @type=number
PORT=3000

# @type=enum(debug, info, warn, error)
LOG_LEVEL=info

# @required=env(production)
# @sensitive
# @example=sk_test_000
STRIPE_SECRET_KEY=op(op://vault/stripe)

# @required=tier(staging)
SENTRY_DSN=
`;

const ENVIRONMENTS: EnvironmentRef[] = [
  { id: "env_dev", name: "development", parentEnvironmentId: null },
  { id: "env_prod", name: "production", parentEnvironmentId: null },
  { id: "env_pr1", name: "pr-1", parentEnvironmentId: "env_dev" },
];

describe("parseEnvSchema", () => {
  it("parses items, decorators, defaults, descriptions, and conditions", () => {
    const draft = parseEnvSchema(SCHEMA);
    expect(draft.environmentNames).toEqual(["production"]);
    expect(draft.defaults).toEqual({ sensitive: false, required: { kind: "never" } });
    const byName = new Map(draft.items.map((i) => [i.name, i]));
    expect(byName.get("DATABASE_URL")).toMatchObject({
      required: { kind: "always" },
      sensitive: true,
      type: "url",
      description: "Primary database connection string",
    });
    expect(byName.get("PORT")).toMatchObject({ type: "number", defaultValue: "3000" });
    expect(byName.get("LOG_LEVEL")?.enumValues).toEqual(["debug", "info", "warn", "error"]);
    const stripe = byName.get("STRIPE_SECRET_KEY");
    expect(stripe?.required).toEqual({ kind: "environments", names: ["production"] });
    // A function value is a dynamic resolver: no default.
    expect(stripe?.defaultValue).toBeUndefined();
    expect(stripe?.example).toBe("sk_test_000");
    expect(byName.get("SENTRY_DSN")?.required).toEqual({ kind: "tier", tier: "staging" });
  });

  it("fails loudly on unsupported decorators instead of dropping them", () => {
    expect(() => parseEnvSchema("# @proxy(domain=api.stripe.com)\nKEY=\n")).toThrow(
      EnvSchemaParseError,
    );
    expect(() => parseEnvSchema("# @required=env()\nKEY=\n")).toThrow(/at least one environment name/);
    expect(() => parseEnvSchema("# @required=tier(prod)\nKEY=\n")).toThrow(
      /tier\(\) takes one of: development, staging, production/,
    );
    expect(() => parseEnvSchema("# @required=sometimes\nKEY=\n")).toThrow(/Unsupported @required form/);
    expect(() => parseEnvSchema("not a valid line\n")).toThrow(EnvSchemaParseError);
  });

  it("rejects forEnv(...) with the replacement, naming the line", () => {
    let error: unknown;
    try {
      parseEnvSchema("# @defaultSensitive=false\n\n# @required=forEnv(prod, staging)\nKEY=\n");
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(EnvSchemaParseError);
    expect((error as EnvSchemaParseError).line).toBe(3);
    expect((error as Error).message).toContain("forEnv(...) is not supported");
    expect((error as Error).message).toContain("@required=env(production, staging)");
    expect((error as Error).message).toContain("@required=tier(production)");
  });

  it("de-duplicates env(...) names and collects them across items", () => {
    const draft = parseEnvSchema(
      "# @required=env(staging, production, staging)\nA=\n\n# @required=env(development)\nB=\n",
    );
    expect(draft.items[0]?.required).toEqual({ kind: "environments", names: ["staging", "production"] });
    expect(draft.environmentNames).toEqual(["development", "production", "staging"]);
  });

  describe("values and trailing comments", () => {
    const value = (line: string) => parseEnvSchema(`${line}\n`).items[0]?.defaultValue;

    it("strips a trailing comment after whitespace, quoted or not", () => {
      expect(value('PORT="8080" # listen port')).toBe("8080");
      expect(value("PORT=8080 # listen port")).toBe("8080");
      expect(value("PORT=8080\t# tab before the comment")).toBe("8080");
      expect(value("EMPTY= # no default")).toBeUndefined();
    });

    it("keeps a # with no whitespace before it", () => {
      expect(value("PASSWORD=p@ss#w0rd")).toBe("p@ss#w0rd");
      expect(value("COLOR=#ff0000")).toBe("#ff0000");
    });

    it("keeps # inside quotes, and escaped quotes do not close a double-quoted value", () => {
      expect(value('GREETING="a # b" # comment')).toBe("a # b");
      expect(value("GREETING='a # b'")).toBe("a # b");
      expect(value('QUOTED="say \\"hi\\"" # c')).toBe('say \\"hi\\"');
    });

    it("rejects a decorator after a value: it would otherwise be silently lost", () => {
      expect(() => value("API_KEY=abc # @sensitive=false")).toThrow(/own comment line/);
      expect(() => value('API_KEY="abc" # @sensitive=false')).toThrow(/own comment line/);
    });

    it("rejects stray text after a quoted value and an unterminated quote", () => {
      expect(() => value('NAME="a" b')).toThrow(/Unexpected text after the value/);
      expect(() => value('NAME="abc')).toThrow(/Unterminated quoted value/);
    });

    it("strips a comment after a function value, which still has no default", () => {
      expect(value("TOKEN=op(op://vault/x) # from the vault")).toBeUndefined();
    });

    it("still ignores a BOM and rejects CR-only line endings", () => {
      expect(parseEnvSchema("﻿# @defaultSensitive=false\nA=1\n").defaults.sensitive).toBe(false);
      expect(() => parseEnvSchema("A=1\rB=2\r")).toThrow(EnvSchemaParseError);
    });
  });
});

describe("resolveDraft", () => {
  it("resolves env(...) to root Environment IDs and tier(...) to the tier selector", () => {
    const contract = resolveDraft(parseEnvSchema(SCHEMA), ENVIRONMENTS);
    const byName = new Map(contract.items.map((i) => [i.name, i]));
    expect(byName.get("STRIPE_SECRET_KEY")?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_prod"] },
    });
    expect(byName.get("SENTRY_DSN")?.required).toEqual({
      kind: "selector",
      selector: { kind: "tier", tier: "staging" },
    });
    expect(byName.get("STRIPE_SECRET_KEY")?.sensitive).toBe(true);
    // Defaults applied where undeclared.
    expect(byName.get("PORT")?.sensitive).toBe(false);
    expect(contractHash(contract)).toMatch(/^sha256:/);
  });

  it("fails loudly on unknown names, listing the root environments that exist", () => {
    const draft = parseEnvSchema("# @required=env(prod, qa)\nKEY=\n");
    let error: unknown;
    try {
      resolveDraft(draft, ENVIRONMENTS);
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(UnknownEnvironmentNameError);
    expect((error as UnknownEnvironmentNameError).unknown).toEqual(["prod", "qa"]);
    expect((error as Error).message).toContain("This project's root environments: development, production.");
  });

  it("rejects a derived environment: env(...) names root environments", () => {
    const draft = parseEnvSchema("# @required=env(pr-1)\nKEY=\n");
    expect(() => resolveDraft(draft, ENVIRONMENTS)).toThrow(UnknownEnvironmentNameError);
    try {
      resolveDraft(draft, ENVIRONMENTS);
    } catch (err) {
      expect((err as UnknownEnvironmentNameError).derived).toEqual(["pr-1"]);
    }
  });

  it("needs no environment list when the schema names none", () => {
    const contract = resolveDraft(parseEnvSchema("# @required=tier(production)\nKEY=\n"), []);
    expect(contract.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "tier", tier: "production" },
    });
  });

  it("resolves names at push time: a reused name selects the new Environment", () => {
    const draft = parseEnvSchema("# @required=env(staging)\nKEY=\n");
    const first = resolveDraft(draft, [{ id: "env_old", name: "staging", parentEnvironmentId: null }]);
    // The old Environment is deleted and a new one takes its name.
    const second = resolveDraft(draft, [{ id: "env_new", name: "staging", parentEnvironmentId: null }]);
    expect(first.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_old"] },
    });
    expect(second.items[0]?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_new"] },
    });
    // Different IDs are a different Contract: a new revision, never a silent reuse.
    expect(contractHash(first)).not.toBe(contractHash(second));
  });

  it("is deterministic: same schema and environments give the same hash", () => {
    const a = resolveDraft(parseEnvSchema(SCHEMA), ENVIRONMENTS);
    const b = resolveDraft(parseEnvSchema(SCHEMA), [...ENVIRONMENTS].reverse());
    expect(contractHash(a)).toBe(contractHash(b));
  });
});

describe("@type=integer (ADR-0042)", () => {
  const schema = `# @type=integer
WORKERS=4

# @type=number
RATIO=0.5
`;

  it("parses as the integer type, and number stays number", () => {
    const draft = parseEnvSchema(schema);
    expect(draft.items.map((i) => [i.name, i.type])).toEqual([
      ["WORKERS", "integer"],
      ["RATIO", "number"],
    ]);
  });

  it("resolves without a semantics version, leaving the version check to the push", () => {
    const contract = resolveDraft(parseEnvSchema(schema), []);
    expect(contract).not.toHaveProperty("semanticsVersion");
    expect(contract.items.find((i) => i.name === "WORKERS")?.type).toBe("integer");
  });

  it("rejects an unknown type as before", () => {
    expect(() => parseEnvSchema("# @type=int\nX=1\n")).toThrow(EnvSchemaParseError);
  });
});
