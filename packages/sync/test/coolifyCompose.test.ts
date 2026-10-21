// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { MAX_COMPOSE_BYTES, classifyComposeUsage, coolifyGeneratesName, coolifyOwnsName } from "../src/coolifyCompose.js";

/** Coolify (≥ v4.0.0-beta.443) gives every container of the generated file `env_file: .env`. */
const generatedWithEnvFile = (containers: string[]) =>
  `services:\n${containers.map((c) => `  ${c}:\n    image: x\n    env_file:\n      - .env\n`).join("")}`;
const generatedWithout = (containers: string[]) =>
  `services:\n${containers.map((c) => `  ${c}:\n    image: x\n`).join("")}`;

const classify = (raw: string, names: string[], generated = generatedWithEnvFile(["app", "db"]), version: number | null = 5) =>
  classifyComposeUsage(raw, generated, version, names);

describe("Coolify service names", () => {
  it("owns the names it rewrites or writes into .env itself, and generates the rest of SERVICE_*", () => {
    for (const name of ["SERVICE_FQDN_APP", "SERVICE_URL_APP_3000", "SERVICE_NAME_DB", "COOLIFY_RESOURCE_UUID"]) {
      expect(coolifyOwnsName(name)).toBe(true);
      expect(coolifyGeneratesName(name)).toBe(false);
    }
    for (const name of ["SERVICE_PASSWORD_POSTGRES", "SERVICE_USER_ADMIN", "SERVICE_BASE64_64_KEY"]) {
      expect(coolifyOwnsName(name)).toBe(false);
      expect(coolifyGeneratesName(name)).toBe(true);
    }
    expect(coolifyOwnsName("DATABASE_URL")).toBe(false);
    expect(coolifyGeneratesName("DATABASE_URL")).toBe(false);
  });
});

describe("compose usage", () => {
  it("reads a reference to the name itself as delivered; with a default or required marker, Coolify copies the value in", () => {
    const raw = `services:
  app:
    environment:
      A: \${A}
      B: $B
      C: \${C:-fallback}
      D: \${D:?D is required}
      E: \${E-other}
  db:
    image: postgres
`;
    const report = classify(raw, ["A", "B", "C", "D", "E"]);
    expect(report.checked).toBe(true);
    // The bare reference keeps ${NAME} for Compose to read from .env.
    for (const name of ["A", "B"]) expect(report.names.get(name)).toEqual({ referenced: true });
    // With a marker, Coolify writes the stored value into the compose file itself.
    for (const name of ["C", "D", "E"]) expect(report.names.get(name)).toEqual({ referenced: true, copiedIntoCompose: true });
  });

  it("names the containers where a literal or another variable wins over .env", () => {
    const raw = `services:
  app:
    environment:
      FOO: bar
      PORT: 3000
      DEBUG: true
      ALIAS: \${OTHER}
      URL: "https://\${HOST}/x"
      LISTED_ELSEWHERE: \${LISTED_ELSEWHERE}
  db:
    environment:
      - LISTED_ELSEWHERE=fixed
`;
    const report = classify(raw, ["FOO", "PORT", "DEBUG", "ALIAS", "URL", "LISTED_ELSEWHERE", "OTHER", "HOST"]);
    expect(report.names.get("FOO")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("PORT")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("DEBUG")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("ALIAS")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("URL")).toEqual({ shadowedIn: ["app"] });
    // Delivered to app by its reference, overridden in db by a literal.
    expect(report.names.get("LISTED_ELSEWHERE")).toEqual({ referenced: true, shadowedIn: ["db"] });
    // Used through other names. Coolify copies OTHER's value in for ALIAS;
    // HOST is interpolated by Compose from .env inside a literal string.
    expect(report.names.get("OTHER")).toEqual({ referenced: true, copiedIntoCompose: true });
    expect(report.names.get("HOST")).toEqual({ referenced: true });
  });

  it("treats a name bound to a Coolify-generated value as Coolify's, and the generated one as managed with a note", () => {
    const raw = `services:
  app:
    environment:
      DB_PASSWORD: \${SERVICE_PASSWORD_POSTGRES}
      DB_URL: $SERVICE_URL_DB/path
`;
    const report = classify(raw, ["DB_PASSWORD", "DB_URL", "SERVICE_PASSWORD_POSTGRES"]);
    expect(report.names.get("DB_PASSWORD")).toEqual({ owned: true });
    expect(report.names.get("DB_URL")).toEqual({ owned: true });
    expect(report.names.get("SERVICE_PASSWORD_POSTGRES")).toEqual({ referenced: true, generatedOnce: true });
  });

  it("reads a pure list like Coolify does: a bare name is an empty value, which takes the stored one, copied in", () => {
    const raw = `services:
  app:
    build:
      context: .
      args:
        - BUILD_FLAG=on
        - BUILD_REF
    environment:
      - LITERAL=value
      - BARE
      - EMPTY=
`;
    const report = classify(raw, ["BUILD_FLAG", "BUILD_REF", "LITERAL", "BARE", "EMPTY"]);
    expect(report.names.get("BUILD_FLAG")).toEqual({ shadowedIn: ["app"] });
    // Environment and build arguments both lists: Coolify's merge is a list,
    // where a bare name reads as an empty value (convertToKeyValueCollection).
    expect(report.names.get("BUILD_REF")).toEqual({ copiedIntoCompose: true });
    expect(report.names.get("LITERAL")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("BARE")).toEqual({ copiedIntoCompose: true });
    // An empty value takes the stored one, copied into the compose file.
    expect(report.names.get("EMPTY")).toEqual({ copiedIntoCompose: true });
  });

  it("reads a bare list name next to a mapping as a name without a value, which Varlatch does not claim to know", () => {
    // A mapping environment with list build arguments: the merge has string
    // keys, so Coolify keeps a bare name unset (null), as `NAME:` is.
    const raw = `services:
  app:
    build:
      args:
        - BARE_ARG
        - SET_ARG=x
    environment:
      MAPPED: value
      UNSET:
`;
    const report = classify(raw, ["BARE_ARG", "SET_ARG", "MAPPED", "UNSET"]);
    expect(report.names.get("BARE_ARG")).toEqual({ unknownIn: ["app"] });
    expect(report.names.get("SET_ARG")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("MAPPED")).toEqual({ shadowedIn: ["app"] });
    expect(report.names.get("UNSET")).toEqual({ unknownIn: ["app"] });
  });

  it("lets a build argument replace an environment entry of the same name, as Laravel's merge does", () => {
    const raw = `services:
  app:
    build:
      args:
        SAME: \${SAME}
    environment:
      SAME: literal
`;
    expect(classify(raw, ["SAME"]).names.get("SAME")).toEqual({ referenced: true });
  });

  it("finds a reference YAML escapes, as Coolify reads it", () => {
    const raw = 'services:\n  app:\n    environment:\n      ESCAPED: "\\u0024ESCAPED"\n      ALIASED: "\\u0024{OTHER_ESCAPED:-x}"\n';
    const report = classify(raw, ["ESCAPED", "OTHER_ESCAPED"]);
    // The raw text has no $: only the decoded scalar shows the reference.
    expect(raw).not.toContain("$");
    expect(report.names.get("ESCAPED")).toEqual({ referenced: true });
    expect(report.names.get("OTHER_ESCAPED")).toEqual({ referenced: true, copiedIntoCompose: true });
  });

  it("says when a name reaches no container: no reference, and no container loads .env", () => {
    const raw = `services:
  app:
    command: echo \${USED_IN_COMMAND}
    environment:
      KNOWN: \${KNOWN}
  db:
    image: postgres
`;
    const report = classify(raw, ["UNUSED", "USED_IN_COMMAND", "KNOWN"], generatedWithout(["app", "db"]));
    expect(report.names.get("UNUSED")).toEqual({ notDeliveredTo: ["app", "db"] });
    expect(report.names.get("USED_IN_COMMAND")).toEqual({ referenced: true });
    expect(report.names.get("KNOWN")).toEqual({ referenced: true });
    // With .env loaded (newer Coolify), an unmentioned name reaches every container.
    expect(classify(raw, ["UNUSED"]).names.get("UNUSED")).toEqual({});
  });

  it("does not count an escaped $$ as a reference", () => {
    const raw = `services:
  app:
    command: echo $$NOT_A_REF and $\${ALSO_NOT}
`;
    const report = classify(raw, ["NOT_A_REF", "ALSO_NOT"], generatedWithout(["app"]));
    expect(report.names.get("NOT_A_REF")).toEqual({ notDeliveredTo: ["app"] });
    expect(report.names.get("ALSO_NOT")).toEqual({ notDeliveredTo: ["app"] });
  });

  it("follows YAML merge keys, as Coolify's parser does", () => {
    const raw = `x-common: &common
  environment:
    SHARED: fixed
services:
  app:
    <<: *common
    image: x
`;
    expect(classify(raw, ["SHARED"]).names.get("SHARED")).toEqual({ shadowedIn: ["app"] });
  });

  it("claims nothing for the legacy parser, a missing file, or input beyond its bounds", () => {
    const raw = "services:\n  app:\n    image: x\n";
    for (const report of [
      classify(raw, ["A"], undefined, 2),
      classify(raw, ["A"], undefined, null),
      classifyComposeUsage(null, generatedWithEnvFile(["app"]), 5, ["A"]),
      classifyComposeUsage(raw, "", 5, ["A"]),
      classifyComposeUsage(`services:\n  app:\n    image: "${"x".repeat(MAX_COMPOSE_BYTES)}"\n`, generatedWithEnvFile(["app"]), 5, ["A"]),
      classifyComposeUsage("services: [unclosed", generatedWithEnvFile(["app"]), 5, ["A"]),
      classifyComposeUsage("services: {}\n", generatedWithEnvFile(["app"]), 5, ["A"]),
    ]) {
      expect(report.checked).toBe(false);
      expect(report.reason).toBeTruthy();
      expect(report.names.get("A")).toEqual({});
    }
  });

  it("refuses an alias bomb instead of expanding it", () => {
    const levels = ['a: &a ["x","x","x","x","x","x","x","x","x","x"]'];
    for (let i = 1; i < 9; i++) {
      const prev = String.fromCharCode(96 + i);
      const next = String.fromCharCode(97 + i);
      levels.push(`${next}: &${next} [${Array(10).fill(`*${prev}`).join(",")}]`);
    }
    const bomb = `${levels.join("\n")}\nservices:\n  app:\n    environment:\n      A: \${A}\n`;
    const report = classifyComposeUsage(bomb, generatedWithEnvFile(["app"]), 5, ["A"]);
    expect(report.checked).toBe(false);
  });

  it("never puts compose text into its report", () => {
    const raw = `services:
  app:
    environment:
      API_KEY: sk_live_hardcoded_secret
`;
    const report = classify(raw, ["API_KEY"]);
    expect(JSON.stringify([...report.names])).not.toContain("sk_live");
    expect(report.reason ?? "").not.toContain("sk_live");
  });
});
