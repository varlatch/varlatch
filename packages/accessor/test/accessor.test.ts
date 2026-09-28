// SPDX-License-Identifier: Apache-2.0
import { inspect } from "node:util";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { HASH_B, builtRuntime, configError, item, runContext, schema, type BuiltRuntime } from "./helpers.js";

let rt: BuiltRuntime;
beforeAll(async () => {
  rt = await builtRuntime();
});

const CONTRACT = schema([
  item("API_KEY", { required: { kind: "always" } }),
  item("DEBUG", { type: "boolean" }),
  item("LOG_LEVEL", { type: "enum", enumValues: ["debug", "info"], defaultValue: "info" }),
  item("PORT", { type: "number", required: { kind: "always" } }),
  item("PUBLIC_URL", { type: "url" }),
  item("SENTRY_DSN", { required: { kind: "selector", selector: { kind: "tier", tier: "production" } } }),
]);

const VALID = { API_KEY: "valueaaaaaaaaaaaaa", DEBUG: "TRUE", PORT: "8080", PUBLIC_URL: "https://app.example.com/" };

describe("conversion", () => {
  it("converts numbers, booleans, and enums, and returns URLs as validated strings", () => {
    const { config } = rt.loadConfig(CONTRACT, { env: { ...VALID, LOG_LEVEL: "debug" } });
    expect(config.PORT).toBe(8080);
    expect(config.DEBUG).toBe(true);
    expect(config.LOG_LEVEL).toBe("debug");
    expect(config.PUBLIC_URL).toBe("https://app.example.com/");
    expect(config.API_KEY).toBe("valueaaaaaaaaaaaaa");
  });

  it("an empty string is a present value, validated like any other", () => {
    expect(rt.loadConfig(CONTRACT, { env: { ...VALID, API_KEY: "" } }).config.API_KEY).toBe("");
    expect(configError(() => rt.loadConfig(CONTRACT, { env: { ...VALID, PORT: "" } })).issues).toEqual([
      { name: "PORT", reason: "must be a number" },
    ]);
  });
});

describe("the read-only view (C-C2)", () => {
  it("is enumerable and inspectable: Object.keys, in, JSON.stringify, spread, and inspect see the items", () => {
    const { config } = rt.loadConfig(CONTRACT, { env: VALID });
    expect(Object.keys(config)).toEqual(["API_KEY", "DEBUG", "PORT", "PUBLIC_URL"]);
    expect("PORT" in config).toBe(true);
    expect("LOG_LEVEL" in config).toBe(false);
    expect(JSON.parse(JSON.stringify(config))).toEqual({ API_KEY: "valueaaaaaaaaaaaaa", DEBUG: true, PORT: 8080, PUBLIC_URL: "https://app.example.com/" });
    expect({ ...config }).toEqual({ API_KEY: "valueaaaaaaaaaaaaa", DEBUG: true, PORT: 8080, PUBLIC_URL: "https://app.example.com/" });
    expect(inspect(config)).toContain("PORT: 8080");
    expect(Object.isFrozen(config)).toBe(true);
  });

  it("throws on every write, delete, and definition, in strict code", () => {
    const { config } = rt.loadConfig(CONTRACT, { env: VALID });
    const writable = config as Record<string, unknown>;
    expect(() => {
      writable.PORT = 1;
    }).toThrow(TypeError);
    expect(() => {
      writable.NEW_ITEM = "x";
    }).toThrow(/read-only/);
    expect(() => delete writable.PORT).toThrow(/read-only/);
    expect(() => Object.defineProperty(config, "PORT", { value: 1 })).toThrow(/read-only/);
    expect(() => Reflect.defineProperty(config, "OTHER", { value: 1 })).toThrow(/read-only/);
    expect(() => Object.assign(config, { PORT: 2 })).toThrow(/read-only/);
    expect(() => Object.setPrototypeOf(config, {})).toThrow(/read-only/);
    expect(config.PORT).toBe(8080);
    expect(Object.keys(config)).not.toContain("NEW_ITEM");
  });

  it("throws on every write, delete, and definition in sloppy code too", () => {
    const { config } = rt.loadConfig(CONTRACT, { env: VALID });
    // Function bodies are sloppy unless they opt in.
    const sloppy = (body: string) => new Function("config", body) as (c: unknown) => unknown;
    expect(sloppy("return this === undefined")(config)).toBe(false);
    expect(() => sloppy("config.PORT = 1")(config)).toThrow(/read-only/);
    expect(() => sloppy("config.NEW_ITEM = 1")(config)).toThrow(/read-only/);
    expect(() => sloppy("delete config.PORT")(config)).toThrow(/read-only/);
    expect(() => sloppy("Object.defineProperty(config, 'X', { value: 1 })")(config)).toThrow(/read-only/);
    expect(config.PORT).toBe(8080);
  });

  it("the module-level config validates on first use, not when created", () => {
    const lazy = rt.lazyConfig(schema([item("LAZY_ITEM_FOR_TEST", { type: "number", required: { kind: "always" } })]));
    process.env.LAZY_ITEM_FOR_TEST = "41";
    try {
      expect(lazy.LAZY_ITEM_FOR_TEST).toBe(41);
      expect(inspect(lazy)).toContain("LAZY_ITEM_FOR_TEST: 41");
      expect(() => {
        (lazy as Record<string, unknown>).LAZY_ITEM_FOR_TEST = 1;
      }).toThrow(/read-only/);
    } finally {
      delete process.env.LAZY_ITEM_FOR_TEST;
    }
  });
});

describe("invalid configuration (C-C3)", () => {
  it("throws one aggregated error naming every item and reason, never a value", () => {
    const env = { API_KEY: "valueaaaaaaaaaaaaa", DEBUG: "yes-please", PORT: "80abc", PUBLIC_URL: "not a url 9d2e", LOG_LEVEL: "verbose" };
    const err = configError(() => rt.loadConfig(CONTRACT, { env }));
    expect(err).toBeInstanceOf(rt.ConfigError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("ConfigError");
    expect(err.issues).toEqual([
      { name: "DEBUG", reason: "must be a boolean" },
      { name: "LOG_LEVEL", reason: "must be one of: debug, info" },
      { name: "PORT", reason: "must be a number" },
      { name: "PUBLIC_URL", reason: "must be a valid URL" },
    ]);
    expect(err.message).toContain("Varlatch configuration is invalid (4 problems):");
    for (const value of Object.values(env)) {
      if (value === "valueaaaaaaaaaaaaa") continue;
      expect(err.message).not.toContain(value);
      expect(JSON.stringify(err.issues)).not.toContain(value);
    }
    expect(err.message).not.toContain("valueaaaaaaaaaaaaa");
  });

  it("a lazily loaded config never returns undefined for an item that failed: every use throws", () => {
    const lazy = rt.lazyConfig(schema([item("LAZY_BAD_FOR_TEST", { type: "number", required: { kind: "always" } })]));
    process.env.LAZY_BAD_FOR_TEST = "12px";
    try {
      const first = configError(() => lazy.LAZY_BAD_FOR_TEST);
      expect(first.issues).toEqual([{ name: "LAZY_BAD_FOR_TEST", reason: "must be a number" }]);
      // Even after the environment is fixed, the failed load stands.
      process.env.LAZY_BAD_FOR_TEST = "12";
      expect(configError(() => lazy.LAZY_BAD_FOR_TEST)).toBe(first);
      expect(configError(() => Object.keys(lazy))).toBe(first);
      expect(configError(() => JSON.stringify(lazy))).toBe(first);
      expect(configError(() => "LAZY_BAD_FOR_TEST" in lazy)).toBe(first);
    } finally {
      delete process.env.LAZY_BAD_FOR_TEST;
    }
  });
});

describe("the environment is only read (C-C4, C-C5)", () => {
  it("never writes to the environment it reads, and leaves every string as delivered", () => {
    const writes: string[] = [];
    const delivered = { ...VALID, LOG_LEVEL: "debug", VARLATCH_RUN_CONTEXT: runContext({}, { mode: "exported" }) };
    const env = new Proxy({ ...delivered }, {
      set: (t, k, v) => {
        writes.push(`set ${String(k)}`);
        return Reflect.set(t, k, v);
      },
      defineProperty: (t, k, d) => {
        writes.push(`define ${String(k)}`);
        return Reflect.defineProperty(t, k, d);
      },
      deleteProperty: (t, k) => {
        writes.push(`delete ${String(k)}`);
        return Reflect.deleteProperty(t, k);
      },
    });
    const { config } = rt.loadConfig(CONTRACT, { env, applyDefaults: true });
    expect(config.PORT).toBe(8080);
    expect(writes).toEqual([]);
    expect({ ...env }).toEqual(delivered);
  });

  it("reads process.env by default and changes nothing in it", () => {
    const before = JSON.stringify(process.env);
    process.env.ACCESSOR_TEST_PORT = "3000";
    try {
      const { config } = rt.loadConfig(schema([item("ACCESSOR_TEST_PORT", { type: "number", required: { kind: "always" } })]), {
        applyDefaults: true,
      });
      expect(config.ACCESSOR_TEST_PORT).toBe(3000);
      expect(process.env.ACCESSOR_TEST_PORT).toBe("3000");
    } finally {
      delete process.env.ACCESSOR_TEST_PORT;
    }
    expect(JSON.stringify(process.env)).toBe(before);
  });
});

describe("presence comes from the environment", () => {
  const strict = (items: Parameters<typeof runContext>[0]) => runContext(items, { mode: "strict" });

  it("a withheld value supplied by an allowed inherited value is returned (the API_KEY regression)", () => {
    const ctx = strict({
      API_KEY: { server: "withheld", delivery: "inherited" },
      PORT: { server: "delivered", delivery: "varlatch" },
    });
    const { config, context } = rt.loadConfig(CONTRACT, { env: { API_KEY: "valueaaaaaaaaaaaaa", PORT: "8080", VARLATCH_RUN_CONTEXT: ctx } });
    expect(context).toBe("strict");
    expect(config.API_KEY).toBe("valueaaaaaaaaaaaaa");
  });

  it("an item present in the environment is validated whatever its provenance", () => {
    const ctx = strict({ API_KEY: { server: "withheld", delivery: "inherited" }, PORT: { server: "delivered", delivery: "varlatch" } });
    const err = configError(() => rt.loadConfig(CONTRACT, { env: { API_KEY: "k", PORT: "eighty", VARLATCH_RUN_CONTEXT: ctx } }));
    expect(err.issues).toEqual([{ name: "PORT", reason: "must be a number" }]);
  });

  it("an item recorded as delivered but removed from the environment is absent", () => {
    const optional = strict({
      API_KEY: { server: "delivered", delivery: "varlatch" },
      PORT: { server: "delivered", delivery: "varlatch" },
      DEBUG: { server: "delivered", delivery: "varlatch" },
    });
    const { config } = rt.loadConfig(CONTRACT, { env: { API_KEY: "k", PORT: "1", VARLATCH_RUN_CONTEXT: optional } });
    expect("DEBUG" in config).toBe(false);
    expect(config.DEBUG).toBeUndefined();

    const err = configError(() => rt.loadConfig(CONTRACT, { env: { PORT: "1", VARLATCH_RUN_CONTEXT: optional } }));
    expect(err.issues).toEqual([
      {
        name: "API_KEY",
        reason: "required in this environment; the run context records it as delivered, but it is absent from the environment",
      },
    ]);
  });
});

describe("defaults", () => {
  it("under a strict context none are applied, even with applyDefaults: a withheld optional item with a default stays absent", () => {
    const ctx = runContext(
      {
        API_KEY: { server: "delivered", delivery: "varlatch" },
        PORT: { server: "delivered", delivery: "varlatch" },
        LOG_LEVEL: { server: "withheld", delivery: "absent" },
      },
      { mode: "strict" },
    );
    for (const applyDefaults of [false, true]) {
      const result = rt.loadConfig(CONTRACT, { env: { API_KEY: "k", PORT: "1", VARLATCH_RUN_CONTEXT: ctx }, applyDefaults });
      expect("LOG_LEVEL" in result.config).toBe(false);
      expect(result.defaulted).toEqual([]);
    }
  });

  it("under a strict context a required item recorded as withheld and absent is an error", () => {
    const ctx = runContext({ API_KEY: { server: "withheld", delivery: "absent" } }, { mode: "strict" });
    const err = configError(() => rt.loadConfig(CONTRACT, { env: { PORT: "1", VARLATCH_RUN_CONTEXT: ctx } }));
    expect(err.issues).toEqual([{ name: "API_KEY", reason: "required in this environment, withheld by the server, and absent" }]);
  });

  it("without a context none are applied unless applyDefaults is set; then they are reported", () => {
    const plain = rt.loadConfig(CONTRACT, { env: VALID });
    expect("LOG_LEVEL" in plain.config).toBe(false);
    expect(plain.defaulted).toEqual([]);
    expect(plain.context).toBeNull();

    const filled = rt.loadConfig(CONTRACT, { env: VALID, applyDefaults: true });
    expect(filled.config.LOG_LEVEL).toBe("info");
    expect(filled.defaulted).toEqual(["LOG_LEVEL"]);
  });

  it("under an exported context applyDefaults fills items not stored, and never one the server withheld", () => {
    const exported = (server: "notStored" | "withheld") =>
      runContext(
        {
          API_KEY: { server: "delivered", delivery: "varlatch" },
          PORT: { server: "delivered", delivery: "varlatch" },
          LOG_LEVEL: { server, delivery: "absent" },
        },
        { mode: "exported" },
      );
    const notStored = rt.loadConfig(CONTRACT, { env: { ...VALID, VARLATCH_RUN_CONTEXT: exported("notStored") }, applyDefaults: true });
    expect(notStored.context).toBe("exported");
    expect(notStored.config.LOG_LEVEL).toBe("info");
    expect(notStored.defaulted).toEqual(["LOG_LEVEL"]);

    const withheld = rt.loadConfig(CONTRACT, { env: { ...VALID, VARLATCH_RUN_CONTEXT: exported("withheld") }, applyDefaults: true });
    expect("LOG_LEVEL" in withheld.config).toBe(false);
    expect(withheld.defaulted).toEqual([]);
  });

  it("a withheld item that is required stays an error under an exported context, default or not", () => {
    const s = schema([item("TOKEN", { required: { kind: "always" }, defaultValue: "placeholder" })]);
    const ctx = runContext({ TOKEN: { server: "withheld", delivery: "absent" } }, { mode: "exported" });
    const err = configError(() => rt.loadConfig(s, { env: { VARLATCH_RUN_CONTEXT: ctx }, applyDefaults: true }));
    expect(err.issues).toEqual([{ name: "TOKEN", reason: "required in this environment, withheld by the server, and absent" }]);
  });

  it("an invalid Contract default is reported by name, never by value", () => {
    const s = schema([item("RETRIES", { type: "number", defaultValue: "three-ish" })]);
    const err = configError(() => rt.loadConfig(s, { env: {}, applyDefaults: true }));
    expect(err.issues).toEqual([{ name: "RETRIES", reason: "the Contract default must be a number" }]);
    expect(err.message).not.toContain("three-ish");
  });
});

describe("the run context", () => {
  const env = (context: string) => ({ ...VALID, VARLATCH_RUN_CONTEXT: context });

  it("throws on malformed JSON and on an unknown version", () => {
    expect(configError(() => rt.loadConfig(CONTRACT, { env: env("{not json") })).issues).toEqual([
      { name: "VARLATCH_RUN_CONTEXT", reason: "is not valid JSON" },
    ]);
    const unknown = JSON.stringify({ ...JSON.parse(runContext({})), v: 2 });
    expect(configError(() => rt.loadConfig(CONTRACT, { env: env(unknown) })).issues[0]?.reason).toContain(
      "has a version this accessor does not read",
    );
    expect(configError(() => rt.loadConfig(CONTRACT, { env: env("[]") })).issues[0]?.reason).toBe("is not a JSON object");
  });

  it("throws on a malformed field, without echoing the context", () => {
    const base = JSON.parse(runContext({ API_KEY: { server: "delivered", delivery: "varlatch" } }));
    const cases: [Record<string, unknown>, string][] = [
      [{ mode: "loose" }, "mode"],
      [{ contractHash: "md5:abc" }, "contractHash"],
      [{ contractRevisionId: "rev one\n" }, "contractRevisionId"],
      [{ semanticsVersion: "2" }, "semanticsVersion"],
      [{ environment: { rootId: "env_prod", tier: "prod" } }, "environment"],
      [{ items: [] }, "items"],
      [{ items: { API_KEY: { server: "leaked-secret-value", delivery: "varlatch" } } }, "an entry in items"],
    ];
    for (const [patch, field] of cases) {
      const err = configError(() => rt.loadConfig(CONTRACT, { env: env(JSON.stringify({ ...base, ...patch })) }));
      expect(err.issues).toEqual([{ name: "VARLATCH_RUN_CONTEXT", reason: `is malformed: ${field}` }]);
      expect(err.message).not.toContain("leaked-secret-value");
    }
  });

  it("throws when its semantics version differs from the generated file's", () => {
    const err = configError(() => rt.loadConfig(CONTRACT, { env: env(runContext({}, { semanticsVersion: 1 })) }));
    expect(err.issues).toEqual([
      {
        name: "VARLATCH_RUN_CONTEXT",
        reason: "names Contract Semantics version 1, but these types use version 2; regenerate them with varlatch types",
      },
    ]);
  });

  it("warns on a content-hash mismatch by default, and throws with staleTypes: throw", () => {
    const stale = env(runContext({}, { contractHash: HASH_B, contractRevisionId: "crv_two", mode: "exported" }));
    const onWarning = vi.fn();
    const result = rt.loadConfig(CONTRACT, { env: stale, onWarning });
    expect(result.config.PORT).toBe(8080);
    expect(onWarning).toHaveBeenCalledTimes(1);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("the types are stale");
    expect(result.warnings[0]).toContain(HASH_B);
    expect(result.warnings[0]).toContain("crv_two");

    const err = configError(() => rt.loadConfig(CONTRACT, { env: stale, staleTypes: "throw" }));
    expect(err.issues[0]?.reason).toContain("the types are stale");
  });

  it("the default warning goes through process.emitWarning", () => {
    const emit = vi.spyOn(process, "emitWarning").mockImplementation(() => undefined);
    try {
      rt.loadConfig(CONTRACT, { env: env(runContext({}, { contractHash: HASH_B, mode: "exported" })) });
      expect(emit).toHaveBeenCalledWith(expect.stringContaining("the types are stale"), "VarlatchWarning");
    } finally {
      emit.mockRestore();
    }
  });

  it("an identical Contract activated again as a new revision is not stale: the hash is compared, not the ID", () => {
    const onWarning = vi.fn();
    const result = rt.loadConfig(CONTRACT, {
      env: env(runContext({}, { contractRevisionId: "crv_reactivated", mode: "exported" })),
      onWarning,
      staleTypes: "throw",
    });
    expect(result.warnings).toEqual([]);
    expect(onWarning).not.toHaveBeenCalled();
  });

  it("enforces per-environment requiredness with a context", () => {
    const production = runContext({}, { mode: "exported", environment: { rootId: "env_prod", tier: "production" } });
    expect(configError(() => rt.loadConfig(CONTRACT, { env: env(production) })).issues).toEqual([
      { name: "SENTRY_DSN", reason: "required in this environment and absent" },
    ]);
    const development = runContext({}, { mode: "exported", environment: { rootId: "env_dev", tier: "development" } });
    expect(rt.loadConfig(CONTRACT, { env: env(development) }).notEvaluated).toEqual([]);
  });

  it("without a context enforces types and always-required items, and reports conditional items as not evaluated", () => {
    const result = rt.loadConfig(CONTRACT, { env: VALID });
    expect(result.context).toBeNull();
    expect(result.notEvaluated).toEqual(["SENTRY_DSN"]);
    expect(configError(() => rt.loadConfig(CONTRACT, { env: { PORT: "1" } })).issues).toEqual([
      { name: "API_KEY", reason: "required in every environment and absent" },
    ]);
  });

  it("requireContext makes a missing context an error", () => {
    const err = configError(() => rt.loadConfig(CONTRACT, { env: VALID, requireContext: true }));
    expect(err.issues).toEqual([
      {
        name: "VARLATCH_RUN_CONTEXT",
        reason:
          "is not set, and requireContext is on: start the application with varlatch run --strict or varlatch run --export-context",
      },
    ]);
  });

  it("rejects an unknown staleTypes option instead of guessing", () => {
    expect(() => rt.loadConfig(CONTRACT, { env: VALID, staleTypes: "error" as never })).toThrow(/staleTypes/);
  });
});
