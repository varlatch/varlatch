// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { contractHash } from "@varlatch/contract";
import {
  EnvSchemaParseError,
  UnmappedVarlockEnvironmentError,
  parseEnvSchema,
  resolveDraft,
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

# @required=forEnv(prod)
# @sensitive
# @example=sk_test_000
STRIPE_SECRET_KEY=op(op://vault/stripe)
`;

describe("parseEnvSchema", () => {
  it("parses items, decorators, defaults, and descriptions", () => {
    const draft = parseEnvSchema(SCHEMA);
    expect(draft.defaults).toEqual({ sensitive: false, required: { kind: "never" } });
    expect(draft.varlockEnvNames).toEqual(["prod"]);

    const byName = new Map(draft.items.map((i) => [i.name, i]));
    expect(byName.get("DATABASE_URL")).toMatchObject({
      required: { kind: "always" },
      sensitive: true,
      type: "url",
      description: "Primary database connection string",
    });
    expect(byName.get("PORT")).toMatchObject({ type: "number", defaultValue: "3000" });
    expect(byName.get("LOG_LEVEL")).toMatchObject({
      type: "enum",
      enumValues: ["debug", "info", "warn", "error"],
      defaultValue: "info",
    });
    // Resolver-call RHS is dynamic, not a default.
    expect(byName.get("STRIPE_SECRET_KEY")?.defaultValue).toBeUndefined();
    expect(byName.get("STRIPE_SECRET_KEY")?.required).toEqual({
      kind: "forEnv",
      varlockNames: ["prod"],
    });
  });

  it("fails loudly on unsupported decorators instead of dropping them", () => {
    expect(() => parseEnvSchema("# @proxy(domain=api.stripe.com)\nKEY=\n")).toThrow(
      EnvSchemaParseError,
    );
    expect(() => parseEnvSchema("# @required=forEnv()\nKEY=\n")).toThrow(EnvSchemaParseError);
    expect(() => parseEnvSchema("not a valid line\n")).toThrow(EnvSchemaParseError);
  });
});

describe("resolveDraft", () => {
  it("resolves forEnv through the mapping into environment selectors", () => {
    const draft = parseEnvSchema(SCHEMA);
    const contract = resolveDraft(draft, { prod: "env_prod123" });
    const stripe = contract.items.find((i) => i.name === "STRIPE_SECRET_KEY");
    expect(stripe?.required).toEqual({
      kind: "selector",
      selector: { kind: "environments", environmentIds: ["env_prod123"] },
    });
    expect(stripe?.sensitive).toBe(true);
    // Defaults applied where undeclared.
    expect(contract.items.find((i) => i.name === "PORT")?.sensitive).toBe(false);
    // Result is canonical and hashable.
    expect(contractHash(contract)).toMatch(/^sha256:/);
  });

  it("fails loudly on unmapped names (ADR-0013 §12)", () => {
    const draft = parseEnvSchema(SCHEMA);
    expect(() => resolveDraft(draft, {})).toThrow(UnmappedVarlockEnvironmentError);
    try {
      resolveDraft(draft, {});
    } catch (err) {
      expect((err as UnmappedVarlockEnvironmentError).names).toEqual(["prod"]);
    }
  });

  it("is deterministic: same schema + mapping = same hash", () => {
    const a = resolveDraft(parseEnvSchema(SCHEMA), { prod: "env_p" });
    const b = resolveDraft(parseEnvSchema(SCHEMA), { prod: "env_p" });
    expect(contractHash(a)).toBe(contractHash(b));
  });
});
