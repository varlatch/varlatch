// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalJson, contractHash, normalizeContract, type ConfigurationContract } from "@varlatch/contract";
import { EnvSchemaParseError, parseEnvSchema, resolveDraft, UnknownEnvironmentNameError, type EnvironmentRef } from "@varlatch/env-schema";
import { describe, expect, it } from "vitest";
import { writeOrCompare } from "./goKit.js";

/**
 * Vectors for the Go CLI's `contract push` (internal docs/design/go-cli.md,
 * slice 5.3b and decision 8), from the TypeScript code itself:
 *
 * - envSchema: what packages/env-schema's parseEnvSchema makes of each
 *   .env.schema text (the draft, or the error's line and message), and what
 *   resolveDraft makes of the draft against a fixed set of Environments (the
 *   Contract with its canonical bytes and hash, or the error's message);
 * - push: for every valid Contract of lib/contract's normalization vectors,
 *   the canonical bytes and hash of the revision `contract push --file`
 *   gives the server (the file as JSON.parse reads it, normalized as the
 *   server normalizes it), so Go's push is held to the same revision.
 *
 * Regenerate and commit:
 *
 *   VARLATCH_WRITE_GO_VECTORS=1 pnpm --filter @varlatch/cli exec vitest run test/go-vectors-envschema.test.ts
 */

const VECTORS = fileURLToPath(new URL("../../../go/cmd/varlatch/testdata/vectors/envschema.json", import.meta.url));
const NORMALIZE = fileURLToPath(new URL("../../../go/lib/contract/testdata/ts-vectors.json", import.meta.url));

const ENVIRONMENTS: EnvironmentRef[] = [
  { id: "env_dev", name: "development", parentEnvironmentId: null },
  { id: "env_staging", name: "staging", parentEnvironmentId: null },
  { id: "env_prod", name: "production", parentEnvironmentId: null },
  { id: "env_pr1", name: "pr-1", parentEnvironmentId: "env_dev" },
  { id: "env_other", name: "other", parentEnvironmentId: null },
  { id: "env_other2", name: "other", parentEnvironmentId: null },
];

const FULL = `# @defaultSensitive=false
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

const SCHEMAS: string[] = [
  FULL,
  "",
  "\n\n",
  "A=\n",
  "A=1\nB=2\n",
  "A=1\r\nB=2\r\n",
  "A=1\rB=2\r",
  "\ufeff# @defaultSensitive=false\nA=1\n",
  "\ufeff\ufeffA=1\n",
  "# @defaultSensitive=true\nA=\n",
  "# @defaultSensitive=maybe\nA=\n",
  "# @defaultSensitive\nA=\n",
  "# @defaultRequired=true\nA=\n",
  "# @defaultRequired=infer\nA=\n",
  "# @defaultRequired\nA=\n",
  "# @defaultRequired=always\nA=\n",
  "A=\n# @defaultSensitive=false\nB=\n",
  "# @defaultSensitive=false\n\n\n# @defaultRequired=true\n\nA=\n",
  "# @proxy(domain=api.stripe.com)\nKEY=\n",
  "# @required=env()\nKEY=\n",
  "# @required=env(, ,)\nKEY=\n",
  "# @required=tier(prod)\nKEY=\n",
  "# @required=tier( production )\nKEY=\n",
  "# @required=sometimes\nKEY=\n",
  "# @required=false\nKEY=\n",
  "# @required=true\nKEY=\n",
  "# @required= true \nKEY=\n",
  "# @required(env)\nKEY=\n",
  "# @optional\nKEY=\n",
  "not a valid line\n",
  "lower=1\n",
  "# @defaultSensitive=false\n\n# @required=forEnv(prod, staging)\nKEY=\n",
  "# @required=forEnv (prod)\nKEY=\n",
  "# @required=env(staging, production, staging)\nA=\n\n# @required=env(development)\nB=\n",
  "# @required=env('staging', \"production\")\nA=\n",
  "# @required=env(pr-1)\nA=\n",
  "# @required=env(nosuch, pr-1, production)\nA=\n",
  "# @required=env(other)\nA=\n",
  'PORT="8080" # listen port\n',
  "PORT=8080 # listen port\n",
  "PORT=8080\t# tab before the comment\n",
  "EMPTY= # no default\n",
  "PASSWORD=p@ss#w0rd\n",
  "COLOR=#ff0000\n",
  "COLOR= #ff0000\n",
  "COLOR=\u00a0#ff0000\n",
  'GREETING="a # b" # comment\n',
  "GREETING='a # b'\n",
  'QUOTED="say \\"hi\\"" # c\n',
  "QUOTED='it\\'s'\n",
  "API_KEY=abc # @sensitive=false\n",
  'API_KEY="abc" # @sensitive=false\n',
  "API_KEY=abc ## @sensitive=false\n",
  'NAME="a" b\n',
  'NAME="abc\n',
  "NAME='abc\n",
  "NAME=\"\n",
  "NAME='\n",
  "TOKEN=op(op://vault/x) # from the vault\n",
  "TOKEN=op(\n",
  "TOKEN=_x()\n",
  "TOKEN=x(y\n",
  "A = 1\n",
  "A\t=\t1\t\n",
  "A=  spaced value  \n",
  "  A=1\n",
  "A=\u00e9 \u00fcn\u00efc\u00f6d\u00e9 \u{1F600}\n",
  "A=x\u2028y\n",
  "A=1\u00a0\n",
  "# @sensitive\n# @sensitive=false\nA=\n",
  "# @sensitive=yes\nA=\n",
  "# @public\nA=\n",
  "# @sensitive=true\nA=\n",
  "# @type=integer\nA=1\n# @type=number\nB=1\n",
  "# @type=enum()\nA=\n",
  "# @type=enum( a , 'b' ,\"c\",, )\nA=\n",
  "# @type=enum(a\nA=\n",
  "# @type= url \nA=\n",
  "# @type=uuid\nA=\n",
  "# @type\nA=\n",
  "# @example=\"quoted\"\nA=\n",
  "# @example=\nA=\n",
  "# @example\nA=\n",
  "# @rotationGrace=3600\n# @rotationHint=Issue a new key, then revoke the old one.\n# then more description\nA=\n",
  "# @rotationGrace=3600\n# @rotationGrace=60\nA=\n",
  "# @rotationHint=a\n# @rotationHint=b\nA=\n",
  "# @rotationGrace=0\nA=\n",
  "# @rotationGrace=2592001\nA=\n",
  "# @rotationGrace=2592000\nA=\n",
  "# @rotationGrace=1e3\nA=\n",
  "# @rotationGrace=\"60\"\nA=\n",
  "# @rotationGrace=99999999999999999999\nA=\n",
  "# @rotationHint=\nA=\n",
  "# @rotationHint\nA=\n",
  "# @rotationHint=has\ta tab\nA=\n",
  "# @rotationHint=   spaced   \nA=\n",
  "# @rotationHint=\"quoted hint\"\nA=\n",
  "# @rotationHint='one'\nA=\n",
  "# @rotationHint=\u202ebidi\nA=\n",
  "##   @rotationHint=double hash\nA=\n",
  "# @docs=https://x\n# @icon=key\n# @tag=a\nA=\n",
  "# @Unknown\nA=\n",
  "# @9bad\nA=\n",
  "# @\nA=\n",
  "# @a b\nA=\n",
  "# --- section\n# description\n\nA=\n",
  "# first\n# second\nA=\n# third\nB=\n",
  "# described\n\nA=\n",
  "#\n#   \nA=\n",
  "# @required\nA=\nA=\n",
  "# @type=enum(x)\nA=y\n",
  "# @type=number\nA=abc\n",
  "# @type=url\nA=not a url\n",
  "# @type=integer\nA=1.5\n",
  "A=" + "x".repeat(70) + "\nlowercase=" + "y".repeat(70) + "\n",
];

/** An error as a vector holds it. */
function failure(err: unknown): { error: string; line?: number; kind: string } {
  if (err instanceof EnvSchemaParseError) return { error: err.message, line: err.line, kind: "parse" };
  if (err instanceof UnknownEnvironmentNameError) return { error: err.message, kind: "environments" };
  if (err instanceof Error && err.name === "ContractValidationError") return { error: err.message, kind: "contract" };
  throw err;
}

function schemaVector(source: string) {
  let draft;
  try {
    draft = parseEnvSchema(source);
  } catch (err) {
    return { source, ...failure(err) };
  }
  try {
    const contract = resolveDraft(draft, ENVIRONMENTS);
    return { source, draft, contract, canonical: canonicalJson(contract), hash: contractHash(contract) };
  } catch (err) {
    return { source, draft, resolveError: failure(err) };
  }
}

describe("Go CLI vectors: contract push", () => {
  it("envschema.json is the TypeScript code's answers", () => {
    const normalize = (JSON.parse(readFileSync(NORMALIZE, "utf8")) as { normalize: { name: string; input: string; versionUndecided: boolean; canonical?: string }[] }).normalize;
    const push = normalize
      .filter((v) => v.canonical !== undefined)
      .map((v) => {
        // What `contract push --file` sends: the file as JSON.parse reads it.
        const sent = JSON.parse(v.input) as unknown;
        const revision = normalizeContract(sent, { versionUndecided: v.versionUndecided }) as ConfigurationContract;
        return { name: v.name, input: v.input, versionUndecided: v.versionUndecided, canonical: canonicalJson(revision), hash: contractHash(revision) };
      });
    expect(push.length).toBeGreaterThan(20);
    const vectors = {
      comment: "Generated by apps/cli/test/go-vectors-envschema.test.ts from the TypeScript CLI's packages; do not edit. Regenerate with VARLATCH_WRITE_GO_VECTORS=1.",
      environments: ENVIRONMENTS,
      envSchema: SCHEMAS.map(schemaVector),
      push,
    };
    const result = writeOrCompare(VECTORS, `${JSON.stringify(vectors, null, 2)}\n`);
    expect(result.current, "envschema.json is stale: regenerate it (see this file's comment)").toBe(true);
  });
});
