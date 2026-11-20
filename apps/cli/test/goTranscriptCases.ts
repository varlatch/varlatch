// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { EMBEDDED_RELEASE } from "@varlatch/backup";
import { agentsBlock } from "../src/agents/install.js";
import { skillFiles } from "../src/agents/skill.js";
import { generateTypesModule } from "../src/typegen.js";
import { generatePythonModule } from "../src/typegenPython.js";
import { ITEMS, contractItem, revision } from "./fixtures.js";
import type { Exchange, TranscriptCase } from "./goKit.js";

/**
 * The transcript cases, by area (one file each under
 * go/cmd/varlatch/testdata/transcripts/). An area is named after the slice of
 * internal docs/design/go-cli.md that builds what it covers; each later slice
 * adds its own area here.
 */

/** Every command with a usage entry: `varlatch <command> --help` prints it. */
const HELP_TOPICS = [
  "admin", "adopt", "agents", "audit", "audit-export", "context", "contract", "credential", "doctor", "env", "env-create",
  "env-delete", "identity", "import", "init", "invite", "login", "logout", "mcp", "member", "move", "org", "project",
  "request", "run", "scan", "security", "self-update", "server", "setup", "status", "sync", "tailnet", "types", "upgrade",
  "validate", "values", "whoami",
];

/**
 * `admin`'s help is a Go installation's in the Go CLI (go/README.md, the
 * accepted difference `admin-usage`); this recording is the TypeScript
 * CLI's Compose usage.
 */
const helpDifferences = (topic: string): { differences?: string[] } =>
  topic === "admin" ? { differences: ["admin-usage"] } : {};

const framework: TranscriptCase[] = [
  { id: "usage.no-command", title: "no command prints the usage on stdout, status 0", args: [] },
  { id: "usage.help", title: "--help prints the usage", args: ["--help"] },
  { id: "usage.h", title: "-h prints the usage", args: ["-h"] },
  { id: "usage.help-command", title: "help prints the usage", args: ["help"] },
  { id: "usage.unknown-command", title: "an unknown command is a usage error (64) with the usage on stderr", args: ["nosuch"] },
  { id: "usage.unknown-option-as-command", title: "an option where the command goes is an unknown command", args: ["--nosuch"] },
  { id: "usage.separator-as-command", title: "-- where the command goes is an unknown command", args: ["--", "--help"] },
  { id: "usage.help-unknown-topic", title: "help for a word that is not a command is a usage error", args: ["help", "nosuch"] },
  { id: "usage.help-extra-words", title: "help reads only its first word", args: ["help", "run", "values"] },
  { id: "usage.help-topic-version", title: "help --version prints that entry", args: ["help", "--version"] },
  { id: "usage.help-topic-approval", title: "help --approval: the global option is taken first, so the topic is missing", args: ["help", "--approval"] },
  { id: "usage.help-topic-assisted", title: "help --assisted: --assisted is taken first, so the whole usage prints", args: ["help", "--assisted"] },
  { id: "usage.version-help", title: "--version --help prints --version's entry", args: ["--version", "--help"] },
  { id: "version.long", title: "--version", args: ["--version"], differences: ["version"] },
  { id: "version.word", title: "version", args: ["version"], differences: ["version"] },
  { id: "version.ignores-arguments", title: "version ignores what follows it", args: ["version", "--json"], differences: ["version"] },
  { id: "assisted.option-then-help", title: "--assisted before help changes nothing about help", args: ["--assisted", "--help"] },
  { id: "assisted.option-alone", title: "--assisted alone prints the usage", args: ["--assisted"] },
  { id: "assisted.option-twice", title: "--assisted twice is still one option", args: ["--assisted", "--assisted"] },
  { id: "assisted.marker-help", title: "a coding agent's marker changes nothing about help", args: ["--help"], env: { CLAUDECODE: "1" } },
  { id: "assisted.option-after-command-help", title: "--assisted after the command is still the global option", args: ["status", "--assisted", "--help"] },
  { id: "approval.missing-id", title: "--approval without an id is a usage error", args: ["--approval"] },
  { id: "approval.option-as-id", title: "--approval followed by an option is a usage error", args: ["--approval", "--help"] },
  { id: "approval.twice", title: "--approval given twice is a usage error", args: ["--approval", "apr_1", "--approval", "apr_2", "status"] },
  { id: "approval.malformed-id", title: "--approval with an id the server never gives is a usage error", args: ["--approval", "apr.1", "status"] },
  { id: "approval.long-id", title: "--approval with an id over 100 characters is a usage error", args: ["--approval", "a".repeat(101), "status"] },
  { id: "approval.control-in-id", title: "a control character in a refused id is printed as it was given", args: ["--approval", "a\u001bb", "status"] },
  { id: "approval.no-command", title: "--approval with an id and no command prints the usage", args: ["--approval", "apr_1"] },
  { id: "approval.then-help", title: "--approval with an id, then --help", args: ["--approval", "apr_1", "--help"] },
  { id: "approval.after-separator", title: "--approval after -- belongs to the command, not the CLI", args: ["nosuch", "--", "--approval"] },
  ...HELP_TOPICS.flatMap((topic): TranscriptCase[] => [
    { id: `help.${topic}`, title: `help ${topic}`, args: ["help", topic], ...helpDifferences(topic) },
    { id: `help.${topic}.option`, title: `${topic} --help`, args: [topic, "--help"], ...helpDifferences(topic) },
    { id: `help.${topic}.short`, title: `${topic} -h`, args: [topic, "-h"], ...helpDifferences(topic) },
  ]),
  { id: "help.after-separator", title: "--help after -- belongs to the command run starts", args: ["nosuch", "--", "--help"] },
  { id: "help.after-arguments", title: "--help anywhere before -- asks for the command's help", args: ["values", "set", "API_KEY", "--help"] },
];

// ---- 5.1b: context and the credential store ---------------------------------
//
// Offline commands only: no case talks to a server. Times are fixed and far
// from the clock: an "ok" credential lives from 1900 to 2100, an expiring one
// from 1000 to 2100 (less than a fifth of its lifetime left), an expired one
// ended in 2020. Tokens are fakes.

const OK = { issuedAt: "1900-01-01T00:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z" };
const EXPIRING = { issuedAt: "1000-01-01T00:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z" };
const EXPIRED = { issuedAt: "2020-01-01T00:00:00.000Z", expiresAt: "2020-01-02T00:00:00.000Z" };

const credentials = (servers: Record<string, unknown>): string => `${JSON.stringify({ servers }, null, 2)}\n`;
const STORE_ONE = credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", ...OK, credentialId: "cred_a", name: "laptop" } });
const STORE_SEVERAL = credentials({
  "https://a.example": { token: "vlt_cli_fakeAAAA", ...OK, credentialId: "cred_a", name: "laptop" },
  "https://b.example/team": { token: "vlt_cli_fakeBBBB", ...EXPIRED, credentialId: "cred_b", name: "old" },
  "https://c.example": { token: "vlt_cli_fakeCCCC" },
  "http://127.0.0.1:8080": { token: "vlt_cli_fakeDDDD", ...EXPIRING, credentialId: "cred_d" },
});

/** A repository at repo/: its varlatch.toml and, optionally, its .varlatch/local.json. */
function repoFiles(toml: string, local?: unknown): Record<string, string> {
  const files: Record<string, string> = { "repo/varlatch.toml": toml };
  if (local !== undefined) files["repo/.varlatch/local.json"] = typeof local === "string" ? local : `${JSON.stringify(local, null, 2)}\n`;
  return files;
}
const TOML_FULL = 'server = "https://repo.example"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n';
const TOML_NO_SERVER = 'organization = "acme"\nproject = "web"\ndefault_environment = "dev"\n';
const TOML_NO_ENV = 'server = "https://repo.example"\norganization = "acme"\nproject = "web"\n';
const IN_REPO = { cwd: "repo" };

/** The TOML documents `context` reads, each a case: what a hand-written varlatch.toml can hold. */
const TOML_CASES: Array<[string, string, string]> = [
  ["unterminated-string", "unterminated string", 'organization = "acme\nproject = "web"\n'],
  ["missing-project", "no project", 'organization = "acme"\n'],
  ["empty-organization", "an empty organization", 'organization = ""\nproject = "web"\n'],
  ["number-organization", "an organization that is not a string", "organization = 42\nproject = \"web\"\n"],
  ["duplicate-key", "a key given twice", 'organization = "acme"\norganization = "beta"\nproject = "web"\n'],
  ["bad-escape", "an escape TOML does not have", 'organization = "ac\\qme"\nproject = "web"\n'],
  ["no-newline-between", "two keys on one line", 'organization = "acme" project = "web"\n'],
  ["bad-date", "a date that is not one", 'organization = "acme"\nproject = "web"\nwhen = 2026-13-45\n'],
  ["table-redefined", "a table defined twice", 'organization = "acme"\nproject = "web"\n[a]\nx = 1\n[a]\ny = 2\n'],
  ["in-a-table", "organization inside a table, not at the top", '[varlatch]\norganization = "acme"\nproject = "web"\n'],
  ["crlf-multiline", "CRLF line ends, a literal and a multi-line string", "organization = 'acme'\r\nproject = \"\"\"\r\nweb\"\"\"\r\ndefault_environment = \"dev\"\r\nserver = \"https://repo.example\"\r\n"],
  ["unicode-escapes", "escapes in the values", 'organization = "\\u0061cme"\nproject = "w\\U0001F600b"\ndefault_environment = "d\\tev"\nserver = "https://repo.example"\n'],
  ["bom-and-comments", "a byte order mark and comments", '\uFEFF# context\norganization = "acme" # the org\nproject = "web"\nserver = "https://repo.example"\ndefault_environment = "dev"\n'],
  ["control-in-comment", "a control character in a comment", 'organization = "acme" # a\u0001b\nproject = "web"\n'],
  ["bad-key", "a character a key cannot have", 'organ!zation = "acme"\nproject = "web"\n'],
  ["unfinished-array", "an array never closed", 'organization = "acme"\nproject = "web"\nlist = [1, 2\n'],
  ["inline-table", "inline tables and arrays of tables", 'organization = "acme"\nproject = "web"\nserver = "https://repo.example"\ndefault_environment = "dev"\npoint = { x = 1, y.z = 2 }\n[[items]]\nname = "a"\n[[items]]\nname = "b"\n'],
  ["big-integer", "an integer JavaScript cannot hold", 'organization = "acme"\nproject = "web"\nn = 9007199254740993\n'],
  ["long-line-number", "an error on line 10, past a two-digit line number", `${"# x\n".repeat(9)}organization = = "acme"\n`],
  ["non-ascii", "values beyond ASCII, a key needing quotes", 'organization = "acm\u00e9"\nproject = "w\u00ebb \u{1F600}"\n"server" = "https://repo.example"\ndefault_environment = "d\u00e9v"\n'],
];

const context51b: TranscriptCase[] = [
  // status: the store, offline (ADR-0032)
  { id: "status.none", title: "status with no stored credentials, outside a repository", args: ["status"] },
  { id: "status.none.json", title: "status --json with no servers", args: ["status", "--json"] },
  { id: "status.one", title: "status with one credential", args: ["status"], files: { "config/credentials.json": STORE_ONE } },
  { id: "status.one.json", title: "status --json with one credential", args: ["status", "--json"], files: { "config/credentials.json": STORE_ONE } },
  { id: "status.several", title: "status with several: ok, expired, unknown (token only) and expiring", args: ["status"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "status.several.json", title: "status --json with several credentials", args: ["status", "--json"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "status.expired.json", title: "status --json with an expired credential", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", ...EXPIRED } }) } },
  { id: "status.unknown.json", title: "status --json with an unknown expiry: token only, garbage timestamps, expiry before issue, expiry only", args: ["status", "--json"], files: { "config/credentials.json": credentials({
    "https://a.example": { token: "vlt_cli_fakeAAAA" },
    "https://b.example": { token: "vlt_cli_fakeBBBB", issuedAt: "yesterday", expiresAt: "tomorrow" },
    "https://c.example": { token: "vlt_cli_fakeCCCC", issuedAt: "2100-01-02T00:00:00Z", expiresAt: "2100-01-01T00:00:00Z" },
    "https://d.example": { token: "vlt_cli_fakeDDDD", expiresAt: "2020-01-01T00:00:00+02:00" },
    "https://e.example": { token: "vlt_cli_fakeEEEE", issuedAt: "", expiresAt: "2100-01-01" },
  }) } },
  { id: "status.unknown", title: "status with unknown expiries, human", args: ["status"], files: { "config/credentials.json": credentials({
    "https://a.example": { token: "vlt_cli_fakeAAAA" },
    "https://b.example": { token: "vlt_cli_fakeBBBB", issuedAt: "yesterday", expiresAt: "tomorrow" },
    "https://d.example": { token: "vlt_cli_fakeDDDD", expiresAt: "2020-01-01T00:00:00+02:00" },
  }) } },
  { id: "status.expiring.json", title: "status --json with a credential in the last fifth of its lifetime", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", ...EXPIRING } }) } },
  { id: "status.unsafe-name", title: "a credential name with control and bidirectional characters is escaped", args: ["status"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", ...OK, name: "lap\u001b[31mtop\u202e" } }) } },
  { id: "status.unsafe-name.json", title: "the same name in the JSON document", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", ...OK, name: "lap\u001b[31mtop\u202e" } }) } },
  { id: "status.odd-fields.json", title: "metadata that is not text is passed through as it is", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", name: 7, issuedAt: ["2020"], expiresAt: { at: 1 }, credentialId: false, extra: "kept" } }) } },
  { id: "status.odd-fields", title: "the same, human", args: ["status"], files: { "config/credentials.json": credentials({ "https://a.example": { token: "vlt_cli_fakeAAAA", name: 7, expiresAt: { at: 1 } }, "https://b.example": { token: "t", name: ["x", "y"], expiresAt: 5 } }) } },
  { id: "status.corrupt-store", title: "a store that is not JSON reads as empty", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": {"https://a.example": {"token": "vlt_cli_fake' } },
  { id: "status.bom-store", title: "a store with a byte order mark reads as empty (JSON.parse refuses it)", args: ["status", "--json"], files: { "config/credentials.json": `\uFEFF${STORE_ONE}` } },
  { id: "status.null-store", title: "a store holding null reads as empty", args: ["status", "--json"], files: { "config/credentials.json": "null\n" } },
  { id: "status.array-servers", title: "servers as an array: its elements are listed by index", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": [{"token": "vlt_cli_fakeAAAA", "name": "first"}]}\n' }, differences: ["server-display"] },
  { id: "status.string-servers", title: "servers as a string: one entry per character", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": "ab"}\n' }, differences: ["server-display"] },
  { id: "status.array-store", title: "a store that is an array holds no servers", args: ["status", "--json"], files: { "config/credentials.json": "[1, 2]\n" } },
  { id: "status.null-entry", title: "an entry that is null stops status (TypeScript throws a TypeError)", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": {"https://a.example": null}}\n' }, differences: ["uncaught"] },
  { id: "status.c1-name", title: "C1 control characters in a name are escaped", args: ["status"], files: { "config/credentials.json": '{"servers": {"https://a.example": {"token": "t", "name": "a\u0082b\u009fc"}}}\n' } },
  { id: "status.lone-surrogate", title: "a lone surrogate in a server: escaped in JSON, U+FFFD in text", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": {"https://a.example/\\ud800": {"token": "t"}}}\n' }, differences: ["server-display"] },
  { id: "status.lone-surrogate.text", title: "the same, human", args: ["status"], files: { "config/credentials.json": '{"servers": {"https://a.example/\\ud800": {"token": "t"}}}\n' }, differences: ["server-display"] },
  { id: "status.lenient-options", title: "status reads its options leniently: an unknown one is ignored", args: ["status", "--nosuch", "--json", "extra"] },
  // status: the repository
  { id: "status.repo", title: "status inside a repository: the committed default", args: ["status"], files: { ...repoFiles(TOML_FULL), "config/credentials.json": STORE_ONE }, ...IN_REPO },
  { id: "status.repo.json", title: "status --json inside a repository", args: ["status", "--json"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "status.repo.tier", title: "the cached tier of the local selection", args: ["status"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy", selectedTier: "production", tierCachedAt: "2026-11-17T10:00:00.000Z" }), ...IN_REPO },
  { id: "status.repo.tier.json", title: "the cached tier in the JSON document", args: ["status", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy", selectedTier: "production", tierCachedAt: "2026-11-17T10:00:00.000Z" }), ...IN_REPO },
  { id: "status.repo.flag-env", title: "-e selects another Environment, whose tier is unknown", args: ["status", "--json", "-e", "prod"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy", selectedTier: "production" }), ...IN_REPO },
  { id: "status.repo.environment-server", title: "--environment and --server reach the repository's context", args: ["status", "--json", "--environment", "staging", "--server", "https://flag.example"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "status.repo.env-var", title: "VARLATCH_ENV and VARLATCH_SERVER", args: ["status", "--json"], env: { VARLATCH_ENV: "qa", VARLATCH_SERVER: "https://env.example" }, files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "status.repo.null-tier", title: "a selected tier of null still brings its cached time", args: ["status", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev", selectedTier: null, tierCachedAt: "then" }), ...IN_REPO },
  { id: "status.repo.tier-control", title: "a tier holding control characters, human", args: ["status"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev", selectedTier: "pro\u0007d" }), ...IN_REPO },
  { id: "status.repo.incomplete", title: "a repository without an Environment: the repository part is left out", args: ["status", "--json"], files: repoFiles(TOML_NO_ENV), ...IN_REPO },
  { id: "status.repo.bad-toml", title: "a varlatch.toml that is not TOML: the repository part is left out", args: ["status"], files: repoFiles('organization = "acme\n'), ...IN_REPO },
  { id: "status.repo.null-local", title: "a local.json holding null: the repository part is left out", args: ["status", "--json", "-e", "dev"], files: repoFiles(TOML_FULL, "null\n"), ...IN_REPO },
  { id: "status.repo.nested", title: "from a directory inside the repository", args: ["status", "--json"], files: repoFiles(TOML_FULL), cwd: "repo/src/app" },
  // where the store is
  { id: "store.xdg", title: "without VARLATCH_CONFIG_DIR, the store is under XDG_CONFIG_HOME", args: ["status", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { XDG_CONFIG_HOME: "{{dir}}/xdg" }, files: { "xdg/varlatch/credentials.json": STORE_ONE } },
  { id: "store.home", title: "without either, under the home directory's .config", args: ["status", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { HOME: "{{dir}}/home2", USERPROFILE: "{{dir}}/home2" }, files: { "home2/.config/varlatch/credentials.json": STORE_ONE } },
  { id: "store.empty-xdg", title: "an empty XDG_CONFIG_HOME counts as unset", args: ["status", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { XDG_CONFIG_HOME: "" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE } },
  { id: "store.config-dir-wins", title: "VARLATCH_CONFIG_DIR wins over XDG_CONFIG_HOME", args: ["status", "--json"], env: { VARLATCH_CONFIG_DIR: "{{dir}}/mine", XDG_CONFIG_HOME: "{{dir}}/xdg" }, files: { "mine/credentials.json": STORE_ONE, "xdg/varlatch/credentials.json": STORE_SEVERAL } },
  { id: "store.agent-run-default", title: "inside an agent-safe run the operator's default store is never read", args: ["status", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { VARLATCH_AGENT_RUN: "run_1", USERPROFILE: "{{dir}}/home" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE } },
  { id: "store.agent-run-default-named", title: "naming the default directory in VARLATCH_CONFIG_DIR changes nothing", args: ["status", "--json"], env: { VARLATCH_AGENT_RUN: "run_1", VARLATCH_CONFIG_DIR: "{{dir}}/home/.config/varlatch/", USERPROFILE: "{{dir}}/home" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE } },
  { id: "store.agent-run-own", title: "the run's own directory is read", args: ["status", "--json"], env: { VARLATCH_AGENT_RUN: "run_1" }, files: { "config/credentials.json": STORE_ONE } },
  { id: "store.agent-run-empty", title: "an empty VARLATCH_AGENT_RUN is no run", args: ["status", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { VARLATCH_AGENT_RUN: "", USERPROFILE: "{{dir}}/home" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE } },
  // server: the default server (ADR-0058 Decision 1)
  { id: "server.none", title: "server with nothing stored", args: ["server"] },
  { id: "server.none.json", title: "server --json with nothing stored", args: ["server", "--json"] },
  { id: "server.default", title: "outside a repository: the default server", args: ["server"], files: { "config/credentials.json": STORE_SEVERAL, "config/settings.json": '{"defaultServer": "https://c.example"}\n' } },
  { id: "server.default.json", title: "the same, --json", args: ["server", "--json"], files: { "config/credentials.json": STORE_SEVERAL, "config/settings.json": '{"defaultServer": "https://c.example"}\n' } },
  { id: "server.only-credential", title: "outside a repository with no default: the only stored credential", args: ["server"], files: { "config/credentials.json": STORE_ONE } },
  { id: "server.only-credential.json", title: "the same, --json", args: ["server", "--json"], files: { "config/credentials.json": STORE_ONE } },
  { id: "server.several-no-default", title: "several stored and no default: none", args: ["server"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.env-var", title: "VARLATCH_SERVER wins over the default", args: ["server"], env: { VARLATCH_SERVER: "https://env.example" }, files: { "config/settings.json": '{"defaultServer": "https://c.example"}\n' } },
  { id: "server.env-var.json", title: "the same, --json", args: ["server", "--json"], env: { VARLATCH_SERVER: "https://env.example" } },
  { id: "server.repo", title: "inside a repository: varlatch.toml, whatever the default", args: ["server"], files: { ...repoFiles(TOML_FULL), "config/settings.json": '{"defaultServer": "https://c.example"}\n' }, ...IN_REPO },
  { id: "server.repo.json", title: "the same, --json", args: ["server", "--json"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "server.repo.local-override", title: "the local override wins over varlatch.toml", args: ["server"], files: repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...IN_REPO },
  { id: "server.repo.no-server", title: "a repository without a server: none, never the default", args: ["server"], files: { ...repoFiles(TOML_NO_SERVER), "config/credentials.json": STORE_ONE, "config/settings.json": '{"defaultServer": "https://a.example"}\n' }, ...IN_REPO },
  { id: "server.repo.bad-toml", title: "a varlatch.toml that is not TOML: none, with the problem", args: ["server"], files: repoFiles('organization = "acme"\nproject = web\n'), ...IN_REPO },
  { id: "server.repo.bad-toml.json", title: "the same, --json", args: ["server", "--json"], files: repoFiles('organization = "acme"\nproject = web\n'), ...IN_REPO },
  { id: "server.repo.bad-toml-env-var", title: "VARLATCH_SERVER is read before a malformed varlatch.toml", args: ["server"], env: { VARLATCH_SERVER: "https://env.example" }, files: repoFiles("organization = \n"), ...IN_REPO },
  { id: "server.repo.odd-override.json", title: "a local override that is not a string is passed through", args: ["server", "--json"], files: repoFiles(TOML_FULL, { serverOverride: { url: "x" } }), ...IN_REPO, differences: ["server-display"] },
  { id: "server.repo.odd-override", title: "the same, human", args: ["server"], files: repoFiles(TOML_FULL, { serverOverride: 42 }), ...IN_REPO },
  { id: "server.repo.null-local", title: "a local.json holding null stops server (TypeScript throws a TypeError)", args: ["server"], files: repoFiles(TOML_FULL, "null\n"), ...IN_REPO, differences: ["uncaught"] },
  { id: "server.odd-settings", title: "a default that is not a non-empty string is no default", args: ["server", "--json"], files: { "config/credentials.json": STORE_SEVERAL, "config/settings.json": '{"defaultServer": ""}\n' } },
  // A special scheme's backslash starts the path, and an at-sign follows it: Go shows the server as
  // unrecognised. TypeScript (0.22.2 on) masks through the backslash: the server-display difference.
  { id: "server.backslash-path.json", title: "a server whose path follows a backslash is no user name and password", args: ["server", "--json"], files: { "config/credentials.json": credentials({ "https://example.com\\path@segment": { token: "vlt_cli_fakeAAAA" } }), "config/settings.json": '{"defaultServer": "https://example.com\\\\path@segment"}\n' }, differences: ["server-display"] },
  { id: "status.backslash-path.json", title: "the same server in status --json", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://example.com\\path@segment": { token: "vlt_cli_fakeAAAA" } }) }, differences: ["server-display"] },
  { id: "server.agent-run", title: "inside an agent-safe run: no default, no stored servers", args: ["server", "--json"], unset: ["VARLATCH_CONFIG_DIR"], env: { VARLATCH_AGENT_RUN: "run_1", USERPROFILE: "{{dir}}/home" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE, "home/.config/varlatch/settings.json": '{"defaultServer": "https://a.example"}\n' } },
  { id: "server.extra-argument", title: "server takes no argument", args: ["server", "list"] },
  { id: "server.unknown-option", title: "server's options are strict", args: ["server", "--chek"] },
  { id: "server.json-twice", title: "--json twice is allowed", args: ["server", "--json", "--json"] },
  { id: "server.use", title: "server use makes a signed-in server the default", args: ["server", "use", "https://b.example/team/"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.use.json", title: "server use --json", args: ["server", "use", "--json", "https://a.example"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.use.keeps-settings", title: "server use keeps settings it does not know, and replaces the default", args: ["server", "use", "https://c.example"], files: { "config/credentials.json": STORE_SEVERAL, "config/settings.json": '{"theme": "dark", "defaultServer": "https://a.example", "2": true}\n' } },
  { id: "server.use.corrupt-settings", title: "server use over a settings file that is not JSON replaces it", args: ["server", "use", "https://a.example"], files: { "config/credentials.json": STORE_ONE, "config/settings.json": "{not json" } },
  { id: "server.use.array-settings", title: "server use over settings that are an array starts afresh", args: ["server", "use", "https://a.example"], files: { "config/credentials.json": STORE_ONE, "config/settings.json": "[1]\n" } },
  { id: "server.use.not-signed-in", title: "server use refuses a server with no stored credential, naming those there are", args: ["server", "use", "https://z.example"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.use.nothing-stored", title: "server use with nothing stored", args: ["server", "use", "https://z.example"] },
  { id: "server.use.other-path", title: "the same origin with another path is another server", args: ["server", "use", "https://b.example"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.use.not-a-url", title: "server use refuses what is not a URL", args: ["server", "use", "b.example"], differences: ["server-display"] },
  { id: "server.use.missing", title: "server use without a URL", args: ["server", "use"] },
  { id: "server.use.json-only", title: "server use --json without a URL", args: ["server", "use", "--json"] },
  { id: "server.use.extra", title: "server use takes one URL", args: ["server", "use", "https://a.example", "https://b.example"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "server.use.unknown-option", title: "server use's options are strict", args: ["server", "use", "--yes", "https://a.example"] },
  { id: "server.use.agent-run", title: "inside an agent-safe run the operator's store holds nothing to choose", args: ["server", "use", "https://a.example"], unset: ["VARLATCH_CONFIG_DIR"], env: { VARLATCH_AGENT_RUN: "run_1", USERPROFILE: "{{dir}}/home" }, files: { "home/.config/varlatch/credentials.json": STORE_ONE } },
  { id: "server.use.agent-run-own", title: "an agent-safe run's own directory is written", args: ["server", "use", "https://a.example"], env: { VARLATCH_AGENT_RUN: "run_1" }, files: { "config/credentials.json": STORE_ONE } },
  { id: "server.use.new-directory", title: "server use creates the settings in a store directory of its own", args: ["server", "use", "--json", "https://a.example"], unset: ["VARLATCH_CONFIG_DIR"], env: { XDG_CONFIG_HOME: "{{dir}}/xdg" }, files: { "xdg/varlatch/credentials.json": STORE_ONE } },
  // context: ADR-0017 §7's order
  { id: "context.outside", title: "context outside a repository", args: ["context"] },
  { id: "context.committed-default", title: "context: the committed default", args: ["context"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.committed-default.json", title: "the same, --json", args: ["context", "--json"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.local-selection", title: "the local selection beats the committed default", args: ["context", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy" }), ...IN_REPO },
  { id: "context.env-var", title: "VARLATCH_ENV beats the local selection", args: ["context", "--json"], env: { VARLATCH_ENV: "qa" }, files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy" }), ...IN_REPO },
  { id: "context.flag", title: "--environment beats VARLATCH_ENV", args: ["context", "--json", "--environment", "prod"], env: { VARLATCH_ENV: "qa" }, files: repoFiles(TOML_FULL, { selectedEnvironment: "dev/jeremy" }), ...IN_REPO },
  { id: "context.short-flag", title: "-e beats VARLATCH_ENV", args: ["context", "-e", "prod"], env: { VARLATCH_ENV: "qa" }, files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.both-flags", title: "--environment is read before -e", args: ["context", "--json", "-e", "short", "--environment", "long"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.empty-flag", title: "--environment \"\" is given but empty: -e is not read, and the next source decides", args: ["context", "--json", "--environment", "", "-e", "short"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.flag-last", title: "--environment last has no value: -e is read", args: ["context", "--json", "-e", "short", "--environment"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.no-environment", title: "no Environment from any source", args: ["context"], files: repoFiles(TOML_NO_ENV), ...IN_REPO },
  { id: "context.server-flag", title: "--server beats VARLATCH_SERVER", args: ["context", "--json", "--server", "https://flag.example"], env: { VARLATCH_SERVER: "https://env.example" }, files: repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...IN_REPO },
  { id: "context.server-env-var", title: "VARLATCH_SERVER beats the local override", args: ["context", "--json"], env: { VARLATCH_SERVER: "https://env.example" }, files: repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...IN_REPO },
  { id: "context.server-local-override", title: "the local override beats varlatch.toml", args: ["context", "--json"], files: repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...IN_REPO },
  { id: "context.server-repository", title: "varlatch.toml's server", args: ["context", "--json"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.no-server", title: "no server: never the default, and no example without one", args: ["context"], files: { ...repoFiles(TOML_NO_SERVER), "config/credentials.json": STORE_ONE }, ...IN_REPO },
  { id: "context.no-server-default", title: "no server, with the default as an example", args: ["context"], files: { ...repoFiles(TOML_NO_SERVER), "config/settings.json": '{"defaultServer": "https://c.example"}\n' }, ...IN_REPO },
  { id: "context.tier", title: "the cached tier, escaped", args: ["context"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev", selectedTier: "pro\u001bd", tierCachedAt: "2026-11-17T10:00:00.000Z" }), ...IN_REPO },
  { id: "context.tier-no-time", title: "a cached tier without a time", args: ["context"], files: repoFiles(TOML_FULL, { selectedEnvironment: "dev", selectedTier: "production" }), ...IN_REPO },
  { id: "context.odd-local.json", title: "a local selection and override that are not strings are passed through", args: ["context", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: 5, serverOverride: ["a", "b"], selectedTier: "x" }), ...IN_REPO, differences: ["server-display"] },
  { id: "context.odd-local", title: "the same, human", args: ["context"], files: repoFiles(TOML_FULL, { selectedEnvironment: 5, serverOverride: ["a", "b"] }), ...IN_REPO, differences: ["server-display"] },
  { id: "context.object-selection.json", title: "a selected Environment that is an object never matches itself: no tier", args: ["context", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: { a: 1 }, selectedTier: "x" }), ...IN_REPO },
  { id: "context.corrupt-local", title: "a local.json that is not JSON reads as empty", args: ["context", "--json"], files: repoFiles(TOML_FULL, "{"), ...IN_REPO },
  { id: "context.null-local", title: "a local.json holding null stops context (TypeScript throws a TypeError)", args: ["context", "-e", "dev", "--server", "https://flag.example"], files: repoFiles(TOML_FULL, "null\n"), ...IN_REPO, differences: ["uncaught"] },
  { id: "context.null-local-resolving", title: "the same, when resolving the Environment reads it", args: ["context"], files: repoFiles(TOML_FULL, "null\n"), ...IN_REPO, differences: ["uncaught"] },
  { id: "context.nested", title: "from a directory inside the repository", args: ["context"], files: repoFiles(TOML_FULL), cwd: "repo/src/app" },
  { id: "context.lenient-options", title: "context reads its options leniently", args: ["context", "--nosuch", "x"], files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.agent-run", title: "inside an agent-safe run: the variables holding Placeholders, names only", args: ["context"], env: { VARLATCH_AGENT_RUN: "run_7", API_KEY: "vlch_ph_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", B_TOKEN: "vlch_ph_v1_ffffffffffffffffffffffffffffffff", NOT_ONE: "vlch_ph_v1_short" }, files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.agent-run.json", title: "the same, --json", args: ["context", "--json"], env: { VARLATCH_AGENT_RUN: "run_7", API_KEY: "vlch_ph_v1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.agent-run-none", title: "an agent-safe run with no Placeholders", args: ["context"], env: { VARLATCH_AGENT_RUN: "run_7" }, files: repoFiles(TOML_FULL), ...IN_REPO },
  { id: "context.toml-directory", title: "a varlatch.toml that is a directory stops context (TypeScript lets the read error escape)", args: ["context"], files: { "repo/varlatch.toml/.keep": "" }, ...IN_REPO, differences: ["uncaught"] },
  ...TOML_CASES.map(([id, title, toml]): TranscriptCase => ({ id: `context.toml.${id}`, title: `varlatch.toml: ${title}`, args: ["context", "--json"], files: repoFiles(toml), ...IN_REPO })),
];

// ---- 5.1c: the API client and status --probe ------------------------------

/** Every request the Go CLI sends carries its own User-Agent (the version and the platform it runs on). */
const ONLINE = ["user-agent"];

const CURRENT = { id: "cred_a", current: true, kind: "cli", name: "laptop", createdAt: "2026-11-01T10:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z" };
const OTHER = { id: "cred_b", current: false, kind: "cli", name: "desktop", createdAt: "2026-10-01T10:00:00.000Z", expiresAt: null };
const META = { serverVersion: "0.22.0", apiVersion: 1, capabilities: [] as string[] };
const META_WHOAMI = { ...META, capabilities: ["retrieval.strict", "identity.whoami"] };
const ME = {
  identity: { id: "idn_1", name: "Ada", kind: "human", extra: "not shown" },
  organization: { id: "org_1", slug: "acme", name: "Acme", plan: "x" },
  credential: { id: "cred_a" },
};
const PROBED = { token: "vlt_cli_probeAAAA", issuedAt: "2026-11-01T10:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z", credentialId: "cred_a", name: "laptop" };
const storeAt = (entries: Record<string, unknown>): Record<string, string> => ({ "config/credentials.json": credentials(entries) });
const ok = (path: string, answer: unknown, headers?: Record<string, string>): Exchange => ({ method: "GET", path, status: 200, answer, ...(headers ? { headers: { "content-type": "application/json", ...headers } } : {}) });
const apiError = (status: number, code: unknown, message = "refused", requestId: unknown = "req_00000000-0000-4000-8000-000000000000"): Exchange["answer"] => ({ error: { code, message, requestId } });
const MAINTENANCE: Exchange = { method: "GET", path: "/v1/meta", status: 503, headers: { "content-type": "application/json", "retry-after": "0" }, answer: { error: { code: "MAINTENANCE", message: "restore in progress", requestId: "req_00000000-0000-4000-8000-000000000001" } } };
const VALID: Exchange[] = [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [OTHER, CURRENT], nextCursor: null })];
const VALID_WHOAMI: Exchange[] = [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [CURRENT], nextCursor: null }), ok("/v1/me", ME)];
const probe = (c: Omit<TranscriptCase, "differences" | "args"> & { args?: string[] }): TranscriptCase => ({ args: ["status", "--probe", "--json"], ...c, differences: ONLINE });

/**
 * A stored token or server that fetch refuses to send (a character not
 * allowed in a header, a URL with credentials) is not recorded here: the Go
 * CLI's diagnostics never print credential values, so its message differs
 * on purpose, and go/cmd/varlatch's TestDiagnosticsNeverPrintCredentials
 * pins it.
 */
const apiClient51c: TranscriptCase[] = [
  probe({ id: "probe.none", title: "--probe with nothing stored sends no request", args: ["status", "--probe"] }),
  probe({ id: "probe.valid", title: "a valid credential whose metadata is complete: nothing is written", files: storeAt({ "{{server}}": PROBED }), server: VALID }),
  probe({ id: "probe.valid.human", title: "the human format adds the probe's state", args: ["status", "--probe"], files: storeAt({ "{{server}}": PROBED }), server: VALID }),
  probe({ id: "probe.whoami", title: "a server with identity.whoami: the identity and organization, in the JSON only", files: storeAt({ "{{server}}": PROBED }), server: VALID_WHOAMI }),
  probe({ id: "probe.whoami.human", title: "the human format does not show the identity", args: ["status", "--probe"], files: storeAt({ "{{server}}": PROBED }), server: VALID_WHOAMI }),
  probe({ id: "probe.whoami.no-organization", title: "an identity without an Organization, and fields left out", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [CURRENT] }), ok("/v1/me", { identity: { id: "idn_2", kind: "service", name: null }, organization: null })] }),
  // The Go CLI leaves out an object or array where the API defines a scalar (json-scalars).
  { ...probe({ id: "probe.whoami.odd-shapes", title: "identity fields of any JSON type are shown as they are; an organization that is a string", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [CURRENT] }), ok("/v1/me", { identity: { id: 7, name: ["a", { b: 1 }], kind: "a\u0007b " }, organization: "acme" })] }), differences: [...ONLINE, "json-scalars"] },
  probe({ id: "probe.whoami.capability-string", title: "capabilities given as a string: includes() finds a substring", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", { capabilities: "x identity.whoami y" }), ok("/v1/me/credentials", { items: [CURRENT] }), ok("/v1/me", ME)] }),
  probe({ id: "probe.backfill", title: "a token stored without metadata: the probe backfills it from the credential's own record", files: storeAt({ "{{server}}": { token: "vlt_cli_probeAAAA" } }), server: VALID }),
  probe({ id: "probe.backfill.human", title: "the backfilled expiry shows in the human format", args: ["status", "--probe"], files: storeAt({ "{{server}}": { token: "vlt_cli_probeAAAA" } }), server: VALID }),
  probe({ id: "probe.backfill.keeps", title: "unknown keys and an existing issuedAt are kept; a different id and name replace the stored ones", files: storeAt({ "{{server}}": { future: { a: 1 }, token: "vlt_cli_probeAAAA", issuedAt: "2020-01-01T00:00:00.000Z", credentialId: "cred_old", name: "old", "7": "index" } }), server: VALID }),
  probe({ id: "probe.backfill.no-expiry", title: "a credential without expiry or name: only the id and issue time are added", files: storeAt({ "{{server}}": { token: "vlt_cli_probeAAAA", expiresAt: "2099-01-01T00:00:00.000Z" } }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [{ id: "cred_c", current: true, createdAt: "2026-11-02T00:00:00.000Z", expiresAt: null, name: null }] })] }),
  probe({ id: "probe.backfill.no-id", title: "a current credential without an id removes the stored id; issuedAt null takes the record's", files: storeAt({ "{{server}}": { token: "vlt_cli_probeAAAA", credentialId: "cred_a", issuedAt: null } }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [{ current: 1, createdAt: "2026-11-03T00:00:00.000Z" }] })] }),
  probe({ id: "probe.backfill.no-current", title: "no credential marked current: nothing is written", files: storeAt({ "{{server}}": { token: "vlt_cli_probeAAAA" } }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [OTHER, "x", 0, { current: "" }] })] }),
  probe({ id: "probe.backfill.no-token", title: "an entry without a token: no Authorization header, and the store still backfills", files: storeAt({ "{{server}}": { name: "tokenless" } }), server: VALID }),
  probe({ id: "probe.trailing-slash", title: "a server stored with a trailing slash: the request drops it, and the entry is read under the other key", files: storeAt({ "{{server}}/": { token: "vlt_cli_probeAAAA" } }), server: VALID }),
  probe({ id: "probe.path", title: "a server with a path: the API is under it", files: storeAt({ "{{server}}/base": PROBED }), server: [ok("/base/v1/meta", META), ok("/base/v1/me/credentials", { items: [CURRENT] })] }),
  probe({ id: "probe.several", title: "several servers, probed in order: valid, refused, unreachable", args: ["status", "--probe"], files: storeAt({ "{{server}}": PROBED, "{{server}}/two": { token: "vlt_cli_probeBBBB" }, "http://127.0.0.1:2": { token: "vlt_cli_probeCCCC" } }), server: [...VALID, { method: "GET", path: "/two/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  probe({ id: "probe.invalid", title: "a refused credential: invalid, with the error's code", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  probe({ id: "probe.invalid.human", title: "invalid in the human format", args: ["status", "--probe"], files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  probe({ id: "probe.invalid.credentials", title: "refused at the credential listing", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), { method: "GET", path: "/v1/me/credentials", status: 403, answer: apiError(403, "PERMISSION_DENIED") }] }),
  probe({ id: "probe.invalid.whoami", title: "refused at /v1/me", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [CURRENT] }), { method: "GET", path: "/v1/me", status: 403, answer: apiError(403, "ORGANIZATION_FROZEN") }] }),
  probe({ id: "probe.invalid.unknown-code", title: "a code the protocol does not define", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 400, answer: apiError(400, "MADE_UP\u001b[31m") }] }),
  probe({ id: "probe.invalid.code-not-string", title: "a code that is not a string", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 400, answer: apiError(400, 5) }] }),
  probe({ id: "probe.invalid.error-not-object", title: "an error that is a string: no code", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 400, answer: { error: "boom" } }] }),
  probe({ id: "probe.invalid.error-null", title: "an error that is null: HTTP <status>, INTERNAL", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 418, answer: { error: null } }] }),
  probe({ id: "probe.invalid.html", title: "a proxy's HTML page", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 502, headers: { "content-type": "text/html; charset=utf-8" }, answer: "<html>bad gateway</html>" }] }),
  probe({ id: "probe.invalid.ok-not-json", title: "an OK answer that is not JSON", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 200, headers: {}, answer: "hello" }] }),
  probe({ id: "probe.invalid.503", title: "a 503 that is not maintenance is not retried", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 503, headers: { "content-type": "application/json", "retry-after": "0" }, answer: apiError(503, "INTERNAL") }] }),
  probe({ id: "probe.maintenance", title: "maintenance is ridden out, said once on stderr", files: storeAt({ "{{server}}": PROBED }), server: [MAINTENANCE, MAINTENANCE, ...VALID] }),
  probe({ id: "probe.maintenance.no-retry-after", title: "maintenance without Retry-After: retried at once (Number(null) is 0)", files: storeAt({ "{{server}}": PROBED }), server: [{ ...MAINTENANCE, headers: { "content-type": "application/json" } }, ...VALID] }),
  probe({ id: "probe.maintenance.later-call", title: "maintenance met at a later call of the same command", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), { ...MAINTENANCE, path: "/v1/me/credentials" }, ok("/v1/me/credentials", { items: [CURRENT] })] }),
  probe({ id: "probe.maintenance.two-servers", title: "two servers in maintenance: the notice still comes once per process", files: storeAt({ "{{server}}/a": PROBED, "{{server}}/b": PROBED }), server: [{ ...MAINTENANCE, path: "/a/v1/meta" }, ok("/a/v1/meta", META), ok("/a/v1/me/credentials", { items: [] }), { ...MAINTENANCE, path: "/b/v1/meta" }, ok("/b/v1/meta", META), ok("/b/v1/me/credentials", { items: [] })] }),
  probe({ id: "probe.maintenance.then-refused", title: "maintenance, then a refusal", files: storeAt({ "{{server}}": PROBED }), server: [MAINTENANCE, { method: "GET", path: "/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  probe({ id: "probe.expiry-header", title: "the server's Varlatch-Credential-Expires is no warning for a probe", env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META, { "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" }), ok("/v1/me/credentials", { items: [CURRENT] }, { "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" })] }),
  probe({ id: "probe.redirect", title: "a redirect on the same server is followed with the credential", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 302, headers: { location: "/moved/v1/meta" } }, ok("/moved/v1/meta", META), { method: "GET", path: "/v1/me/credentials", status: 307, headers: { location: "credentials-moved?x=1" } }, ok("/v1/me/credentials-moved?x=1", { items: [] })] }),
  probe({ id: "probe.bom", title: "an answer with a byte order mark is still JSON", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 200, answer: "﻿{\"capabilities\":[]}" }, { method: "GET", path: "/v1/me/credentials", status: 200, answer: "﻿ {\"items\":[]} " }] }),
  probe({ id: "probe.shape.meta-empty", title: "an empty meta answer: the TypeError's text is the detail", files: storeAt({ "{{server}}": PROBED }), server: [{ method: "GET", path: "/v1/meta", status: 204 }, ok("/v1/me/credentials", { items: [] })] }),
  probe({ id: "probe.shape.meta-null", title: "a meta answer of null", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", null), ok("/v1/me/credentials", { items: [] })] }),
  probe({ id: "probe.shape.capabilities-missing", title: "meta without capabilities", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", {}), ok("/v1/me/credentials", { items: [] })] }),
  probe({ id: "probe.shape.capabilities-number", title: "capabilities that are a number", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", { capabilities: 3 }), ok("/v1/me/credentials", { items: [] })] }),
  probe({ id: "probe.shape.credentials-empty", title: "an empty credential listing", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), { method: "GET", path: "/v1/me/credentials", status: 200, headers: {} }] }),
  probe({ id: "probe.shape.items-missing", title: "a listing without items", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", {})] }),
  probe({ id: "probe.shape.items-string", title: "items that are a string", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: "abc" })] }),
  probe({ id: "probe.shape.item-null", title: "a null item", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [OTHER, null, CURRENT] })] }),
  probe({ id: "probe.shape.whoami-null", title: "/v1/me answers null", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [] }), ok("/v1/me", null)] }),
  probe({ id: "probe.shape.whoami-empty", title: "/v1/me answers nothing", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [] }), { method: "GET", path: "/v1/me", status: 204 }] }),
  probe({ id: "probe.shape.identity-missing", title: "/v1/me without an identity", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [] }), ok("/v1/me", { organization: null })] }),
  probe({ id: "probe.shape.stored-string", title: "a stored entry that is a string: spread into the backfilled entry", files: storeAt({ "{{server}}": "ab" }), server: [ok("/v1/meta", META), ok("/v1/me/credentials", { items: [CURRENT] })] }),
  probe({ id: "probe.unreachable", title: "a server that refuses the connection: fetch failed", files: storeAt({ "http://127.0.0.1:2": PROBED }) }),
  probe({ id: "probe.unreachable.human", title: "unreachable in the human format", args: ["status", "--probe"], files: storeAt({ "http://127.0.0.1:2": PROBED }) }),
  probe({ id: "probe.unreachable.bad-port", title: "a port fetch never connects to", files: storeAt({ "http://127.0.0.1:1": PROBED }) }),
  probe({ id: "probe.unreachable.scheme", title: "a scheme fetch cannot fetch", files: storeAt({ "ftp://127.0.0.1:2": PROBED }) }),
  { ...probe({ id: "probe.unreachable.not-a-url", title: "a stored server that is not a URL: fetch's own message", files: storeAt({ "not a url": PROBED }) }), differences: [...ONLINE, "server-display"] },
  probe({ id: "probe.token-latin1", title: "a stored token with Latin-1 characters and surrounding spaces is sent", files: storeAt({ "{{server}}": { ...PROBED, token: " vlt_cli_é " } }), server: VALID }),
  probe({ id: "probe.token-number", title: "a stored token that is a number is sent as text", files: storeAt({ "{{server}}": { ...PROBED, token: 12345 } }), server: VALID }),
  probe({ id: "probe.in-repo", title: "inside a repository, the repository's context follows", files: { ...storeAt({ "{{server}}": PROBED }), "repo/varlatch.toml": 'server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n' }, cwd: "repo", server: VALID }),
  probe({ id: "probe.assisted", title: "assisted mode marks the User-Agent", args: ["--assisted", "status", "--probe", "--json"], files: storeAt({ "{{server}}": PROBED }), server: VALID }),
  { id: "probe.null-entry", title: "a null stored entry: TypeScript throws before probing", args: ["status", "--probe"], files: storeAt({ "{{server}}": null }), differences: ["uncaught"] },
];

// ---- 5.1d: agent files and init with flags --------------------------------
//
// The skill files name the CLI's version: a case that starts from installed
// files, or writes them, lists the "skill-version" difference, and the Go
// replay puts its own version in both (go/README.md).

const SKILL = ["skill-version"];
const AGENT_NAMES = ["claude-code", "codex", "cursor", "copilot", "gemini", "opencode", "devin", "amp", "goose", "zed", "cline", "roo", "aider", "jules"];

/** The skill as this TypeScript CLI installs it, under root (a prefix ending in "/", or ""). */
function installedSkill(root = ""): Record<string, string> {
  const files: Record<string, string> = {};
  for (const [path, content] of skillFiles(EMBEDDED_RELEASE.version)) {
    files[`${root}.agents/skills/varlatch/${path}`] = content;
    files[`${root}.claude/skills/varlatch/${path}`] = content;
  }
  return files;
}

const BLOCK_FILE = `# Rules\n\n${agentsBlock()}\n`;
const MARKED_CLAUDE = "# Claude\n\n<!-- varlatch: the Varlatch instructions are in AGENTS.md -->\n@AGENTS.md\n";
const REGION = "# varlatch:begin: added by varlatch agents install; varlatch agents install --remove takes it out";
const pretty = (v: unknown): string => `${JSON.stringify(v, null, 2)}\n`;
/** A project's settings, each formatted as the CLI writes it, with the CLI's entries in them. */
const GUARDED = {
  "AGENTS.md": BLOCK_FILE,
  "CLAUDE.md": MARKED_CLAUDE,
  ".claude/settings.json": pretty({
    env: { VARLATCH_ASSISTED: "1", OTHER: "x" },
    permissions: { deny: ["Read(./.env)", "Read(./.env.local)", "Read(./.env.*.local)", "Read(~/.config/varlatch/**)"] },
    hooks: { PreToolUse: [{ matcher: "Bash|Read|Grep|Edit|MultiEdit|Write|NotebookEdit|mcp__.*", hooks: [{ type: "command", command: "varlatch agents hook --format claude", timeout: 30 }] }] },
  }),
  ".codex/hooks.json": pretty({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "varlatch agents hook --format codex", timeout: 30 }] }] } }),
  ".codex/config.toml": `model = "o3"\n\n${REGION}\n[shell_environment_policy.set]\nVARLATCH_ASSISTED = "1"\n\n[mcp_servers.varlatch]\ncommand = "varlatch"\nargs = ["mcp"]\n# varlatch:end\n`,
  ".mcp.json": pretty({ mcpServers: { varlatch: { command: "varlatch", args: ["mcp"] }, other: { command: "o" } } }),
  ".vscode/mcp.json": pretty({ servers: { varlatch: { type: "stdio", command: "varlatch", args: ["mcp"] } } }),
  ".gemini/settings.json": pretty({ context: { fileName: ["GEMINI.md", "AGENTS.md"] }, mcpServers: { varlatch: { command: "varlatch", args: ["mcp", "-e", "dev"] } } }),
  ".aider.conf.yml": "model: x\nread: AGENTS.md # added by varlatch agents install\n",
};
/** Existing files of every kind an adapter reads, as a person left them. */
const EXISTING_PROJECT = {
  "AGENTS.md": "# Rules\r\n\r\nUse pnpm.\r\n",
  "CLAUDE.md": "# Claude\n",
  ".gemini/settings.json": pretty({ theme: "dark" }),
  ".aider.conf.yml": "model: gpt-4\n",
  ".codex/config.toml": 'model = "o3"\n',
  ".claude/settings.json": '{"permissions":{"allow":["Bash(ls)"]}}\n',
  "opencode.json": pretty({ $schema: "https://opencode.ai/config.json" }),
};
const TOML_SERVER = 'server = "https://repo.example"\norganization = "acme"\nproject = "web"\n';
const INIT = ["init", "--org", "acme", "--project", "web"];
const INIT_SERVER = [...INIT, "--server", "https://varlatch.example.com"];
const install = (...rest: string[]) => ["agents", "install", ...rest];

const agentFiles51d: TranscriptCase[] = [
  // agents guide: the skill, or one reference, on stdout
  { id: "guide.skill", title: "agents guide prints the skill's body and its topics", args: ["agents", "guide"] },
  { id: "guide.assisted", title: "the same in assisted mode", args: ["--assisted", "agents", "guide"] },
  ...["setup", "run", "agent-run", "self-hosting", "contract"].map((topic): TranscriptCase => ({ id: `guide.${topic}`, title: `agents guide ${topic}`, args: ["agents", "guide", topic] })),
  { id: "guide.unknown", title: "an unknown topic is a usage error naming the topics", args: ["agents", "guide", "nosuch"] },
  { id: "guide.case", title: "topics are case-sensitive", args: ["agents", "guide", "SETUP"] },
  { id: "guide.empty", title: "an empty topic is a topic", args: ["agents", "guide", ""] },
  { id: "guide.extra", title: "one topic only", args: ["agents", "guide", "run", "extra"] },
  { id: "guide.option", title: "guide has no options", args: ["agents", "guide", "--topic", "run"] },
  { id: "guide.json", title: "not even --json", args: ["agents", "guide", "--json"] },
  // the command line
  { id: "agents.none", title: "agents without a subcommand is a usage error", args: ["agents"] },
  { id: "agents.unknown", title: "an unknown subcommand is a usage error", args: ["agents", "nosuch"] },
  { id: "agents.option-first", title: "an option where the subcommand goes", args: ["agents", "--check"] },
  ...[
    ["check-remove", "--check and --remove do not combine", ["--check", "--remove"]],
    ["scope-unknown", "--scope must be project or user", ["--scope", "system"]],
    ["scope-missing", "--scope needs a value", ["--scope"]],
    ["scope-twice", "--scope given twice", ["--scope", "user", "--scope", "project"]],
    ["agent-unknown", "an unknown coding agent", ["--agent", "nosuch"]],
    ["agent-unknown-later", "an unknown coding agent after known ones", ["--agent", "codex", "--agent", "Codex"]],
    ["agent-missing", "--agent needs a value", ["--agent"]],
    ["agent-option", "--agent followed by an option", ["--agent", "--check"]],
    ["user-agent", "--agent applies to a project", ["--scope", "user", "--agent", "codex"]],
    ["user-guardrails", "--guardrails applies to a project", ["--scope", "user", "--guardrails"]],
    ["user-mcp", "--mcp applies to a project", ["--scope", "user", "--mcp"]],
    ["typo", "a mistyped option is refused before anything is written", ["--chek"]],
    ["equals", "--check=true is not --check", ["--check=true"]],
    ["extra", "install takes no argument", ["extra"]],
    ["separator", "-- is not an end of options here", ["--", "--check"]],
    ["short", "no short options", ["-c"]],
  ].map(([id, title, rest]): TranscriptCase => ({
    id: `install.usage.${id}`,
    title: title as string,
    args: install(...(rest as string[])),
    // The Go CLI never echoes an attached option value (go/README.md).
    ...(id === "equals" ? { differences: ["option-value"] } : {}),
  })),
  // install, check, remove: the project scope
  { id: "install.empty", title: "a project with nothing: the skill twice and AGENTS.md", args: install(), differences: SKILL },
  { id: "install.empty.json", title: "--json: the result after the schema version", args: install("--json"), differences: SKILL },
  { id: "install.empty.assisted", title: "assisted mode changes nothing", args: ["--assisted", ...install()], differences: SKILL },
  { id: "install.check.missing", title: "--check on a project without the files: missing, exit 1, nothing written", args: install("--check") },
  { id: "install.check.missing.json", title: "--check --json: drift true, exit 1", args: install("--check", "--json") },
  { id: "install.check.clean", title: "--check on an installed project: up to date, exit 0", args: install("--check"), files: { ...installedSkill(), "AGENTS.md": BLOCK_FILE }, differences: SKILL },
  { id: "install.check.differs", title: "--check names an edited skill file and an extra one", args: install("--check"), files: { ...installedSkill(), "AGENTS.md": BLOCK_FILE, ".agents/skills/varlatch/SKILL.md": "edited\n", ".claude/skills/varlatch/old.md": "old\n" }, differences: SKILL },
  { id: "install.again", title: "install again: an edited file is updated, an old one removed", args: install(), files: { ...installedSkill(), "AGENTS.md": BLOCK_FILE, ".agents/skills/varlatch/references/run.md": "edited\n", ".claude/skills/varlatch/old.md": "old\n" }, differences: SKILL },
  { id: "install.up-to-date", title: "install on an installed project: up to date", args: install(), files: { ...installedSkill(), "AGENTS.md": BLOCK_FILE }, differences: SKILL },
  { id: "install.existing", title: "existing files of every adapter, without options", args: install(), files: EXISTING_PROJECT, differences: SKILL },
  { id: "install.subdirectory", title: "from a subdirectory: the files go to the varlatch.toml root", args: install(), files: { "repo/varlatch.toml": TOML_SERVER, "repo/src/app/index.ts": "" }, cwd: "repo/src/app", differences: SKILL },
  { id: "install.subdirectory.check", title: "--check from a subdirectory", args: install("--check", "--json"), files: { "repo/varlatch.toml": TOML_SERVER }, cwd: "repo/src" },
  { id: "install.damaged", title: "AGENTS.md with only a begin marker: exit 78, nothing written", args: install(), files: { "AGENTS.md": "<!-- varlatch:begin -->\nhalf\n" } },
  { id: "install.damaged.end", title: "AGENTS.md with only an end marker: exit 78", args: install("--remove"), files: { "AGENTS.md": "half\n<!-- varlatch:end -->\n" } },
  { id: "install.claude-local", title: "CLAUDE.local.md: the import is the human's to add", args: install(), files: { "CLAUDE.local.md": "# Local\n" }, differences: SKILL },
  { id: "install.not-canonical", title: "settings the CLI would reformat: the edits are the human's", args: install("--guardrails", "--mcp", "--agent", "gemini"), files: { ".gemini/settings.json": '{"theme":"dark"}\n', ".claude/settings.json": "{}", ".mcp.json": "{ nope" }, differences: SKILL },
  // every coding agent
  { id: "install.agents.all", title: "every coding agent at once", args: install(...AGENT_NAMES.flatMap((a) => ["--agent", a])), differences: SKILL },
  ...AGENT_NAMES.map((agent): TranscriptCase => ({ id: `install.agent.${agent}.check`, title: `--agent ${agent} --check: what it would write, and how it reads the files`, args: install("--agent", agent, "--check") })),
  ...["claude-code", "gemini", "aider", "jules"].map((agent): TranscriptCase => ({ id: `install.agent.${agent}`, title: `--agent ${agent}`, args: install("--agent", agent), differences: SKILL })),
  { id: "install.agent.repeated", title: "an agent named twice", args: install("--agent", "aider", "--agent", "aider", "--check") },
  // --guardrails and --mcp
  { id: "install.guardrails", title: "--guardrails without agents: Claude Code, and Codex only where .codex exists", args: install("--guardrails"), differences: SKILL },
  { id: "install.guardrails.codex-dir", title: "--guardrails with a .codex directory", args: install("--guardrails"), files: { ".codex/.keep": "" }, differences: SKILL },
  { id: "install.guardrails.agents", title: "--guardrails for named agents, one without guardrails", args: install("--guardrails", "--agent", "codex", "--agent", "cursor"), differences: SKILL },
  { id: "install.mcp", title: "--mcp without agents: .mcp.json", args: install("--mcp"), differences: SKILL },
  ...["codex", "copilot", "cursor", "gemini", "opencode", "devin"].map((agent): TranscriptCase => ({ id: `install.mcp.${agent}`, title: `--mcp --agent ${agent}`, args: install("--mcp", "--agent", agent), differences: SKILL })),
  { id: "install.everything", title: "--guardrails --mcp over existing files", args: install("--guardrails", "--mcp"), files: EXISTING_PROJECT, differences: SKILL },
  { id: "install.everything.json", title: "--guardrails --mcp --json for every agent with an adapter", args: install("--guardrails", "--mcp", "--json", "--agent", "claude-code", "--agent", "codex", "--agent", "gemini", "--agent", "aider"), differences: SKILL },
  { id: "install.guarded.check", title: "--check --guardrails --mcp on a guarded project: only the skill is missing", args: install("--check", "--guardrails", "--mcp"), files: GUARDED },
  { id: "install.remove", title: "--remove: the CLI's entries come out, differing ones and settings stay, empty directories go", args: install("--remove"), files: { ...installedSkill(), ...GUARDED }, differences: SKILL },
  { id: "install.remove.json", title: "--remove --json", args: install("--remove", "--json"), files: GUARDED },
  { id: "install.remove.nothing", title: "--remove with nothing installed", args: install("--remove") },
  { id: "install.remove.keeps-own", title: "--remove keeps the human's AGENTS.md and CLAUDE.md content", args: install("--remove"), files: { "AGENTS.md": BLOCK_FILE, "CLAUDE.md": MARKED_CLAUDE, ".claude/skills/other/SKILL.md": "x\n" } },
  // the user scope: HOME
  { id: "install.user", title: "--scope user writes the skill under HOME", args: install("--scope", "user"), differences: SKILL },
  { id: "install.user.check", title: "--scope user --check", args: install("--scope", "user", "--check"), files: installedSkill("home/"), differences: SKILL },
  { id: "install.user.remove", title: "--scope user --remove", args: install("--scope", "user", "--remove", "--json"), files: { ...installedSkill("home/"), "home/.agents/other": "x\n" }, differences: SKILL },
  { id: "install.user.ignores-project", title: "--scope user ignores the project's files", args: install("--scope", "user"), files: { "AGENTS.md": "# Rules\n" }, differences: SKILL },
  // init with flags, off a terminal
  { id: "init.server", title: "init with --server writes varlatch.toml and the agent files", args: INIT_SERVER, differences: SKILL },
  { id: "init.no-agent-files", title: "--no-agent-files writes varlatch.toml only", args: [...INIT_SERVER, "--no-agent-files"] },
  { id: "init.default-environment", title: "--default-environment", args: [...INIT_SERVER, "--default-environment", "staging", "--no-agent-files"] },
  { id: "init.existing-agents", title: "an existing AGENTS.md and CLAUDE.md: the summary names what changed", args: INIT_SERVER, files: { "AGENTS.md": "# Mine\n", "CLAUDE.md": "# Claude\n" }, differences: SKILL },
  { id: "init.up-to-date", title: "agent files already in place: no summary line", args: INIT_SERVER, files: { ...installedSkill(), "AGENTS.md": BLOCK_FILE }, differences: SKILL },
  { id: "init.to-do", title: "a CLAUDE.local.md: init says what to do by hand", args: INIT_SERVER, files: { "CLAUDE.local.md": "# Local\n" }, differences: SKILL },
  { id: "init.agent-files-fail", title: "agent files that cannot be written: init still succeeds and says how to retry", args: INIT_SERVER, files: { "AGENTS.md": "<!-- varlatch:end -->\n" } },
  { id: "init.env-var", title: "the server from VARLATCH_SERVER", args: [...INIT, "--no-agent-files"], env: { VARLATCH_SERVER: "https://var.example" } },
  { id: "init.flag-over-env", title: "--server wins over VARLATCH_SERVER", args: [...INIT_SERVER, "--no-agent-files"], env: { VARLATCH_SERVER: "https://var.example" } },
  { id: "init.default-server", title: "the server from the default server", args: [...INIT, "--no-agent-files"], files: { "config/settings.json": pretty({ defaultServer: "https://default.example" }) } },
  { id: "init.only-credential", title: "the server from the only stored credential", args: [...INIT, "--no-agent-files"], files: { "config/credentials.json": pretty({ servers: { "https://only.example": { token: "vlt_cli_fakeAAAA" } } }) } },
  { id: "init.several-credentials", title: "several credentials and no default: no server", args: INIT, files: { "config/credentials.json": pretty({ servers: { "https://a.example": { token: "vlt_cli_fakeAAAA" }, "https://b.example": { token: "vlt_cli_fakeBBBB" } } }) } },
  { id: "init.empty-server", title: "an empty --server counts as none", args: [...INIT, "--server", ""] },
  { id: "init.no-server", title: "no server anywhere: a usage error, nothing written", args: INIT },
  { id: "init.raw-values", title: "the values go into varlatch.toml as given", args: ["init", "--org", 'a"b', "--project", "w\\b", "--server", "https://x.example/p q", "--default-environment", "d e", "--no-agent-files"], differences: ["toml-escaped", "server-display"] },
  { id: "init.bad-settings", title: "an unreadable settings.json", args: INIT, files: { "config/settings.json": "nope" } },
  { id: "init.in-repository", title: "inside a configured repository: nothing to initialize, exit 1", args: INIT_SERVER, files: { "repo/varlatch.toml": TOML_SERVER }, cwd: "repo/sub" },
  { id: "init.in-repository.assisted", title: "the same in assisted mode names --assisted in its commands", args: ["--assisted", ...INIT_SERVER], files: { "repo/varlatch.toml": TOML_SERVER }, cwd: "repo" },
  { id: "init.in-repository.marker", title: "a coding agent's marker turns on assisted mode too", args: INIT_SERVER, env: { CLAUDECODE: "1" }, files: { "repo/varlatch.toml": TOML_SERVER }, cwd: "repo" },
  { id: "init.assisted", title: "assisted mode off a terminal: the flags path", args: ["--assisted", ...INIT_SERVER, "--no-agent-files"] },
  ...[
    ["none", "no flags off a terminal: the usage", []],
    ["org-only", "--org without --project", ["--org", "acme"]],
    ["project-only", "--project without --org: the usage", ["--project", "web"]],
    ["typo", "a mistyped --no-agent-files is refused", ["--org", "acme", "--project", "web", "--no-agent-file"]],
    ["extra", "init takes no argument", ["--org", "acme", "--project", "web", "extra"]],
    ["project-missing-value", "--project needs a value", ["--org", "acme", "--project"]],
    ["org-twice", "--org given twice", ["--org", "acme", "--org", "other", "--project", "web"]],
    ["value-option", "a value that looks like an option", ["--org", "-acme", "--project", "web"]],
    ["no-agent-files-twice", "--no-agent-files twice is still one", ["--org", "acme", "--project", "web", "--no-agent-files", "--no-agent-files", "--server", "https://s.example"]],
  ].map(([id, title, rest]): TranscriptCase => ({ id: `init.usage.${id}`, title: title as string, args: ["init", ...(rest as string[])] })),
];

// ---- 5.1e: session commands ------------------------------------------------
//
// login with a token, logout, whoami, env list and env use, against the
// fake server. login and env use write the time of the run: those cases
// list the "now" pattern (goKit.ts). Every request names the CLI in its
// User-Agent ("user-agent"). Tokens are fakes.

const LOGIN_META = { serverVersion: "0.22.0", apiMajor: 1, capabilities: ["identity.whoami"] };
const ORGS = ok("/v1/organizations", { items: [{ id: "org_1", slug: "acme", name: "Acme" }], nextCursor: null });
const LOGIN_OK: Exchange[] = [ok("/v1/meta", LOGIN_META), ORGS];
const del = (path: string, status = 204, answer?: unknown): Exchange => ({ method: "DELETE", path, status, ...(answer === undefined ? { headers: {} } : { answer }) });
const NOW = ["now"];
const session = (c: TranscriptCase): TranscriptCase => ({ ...c, differences: [...(c.differences ?? []), ...ONLINE] });
const TOKEN = "vlt_cli_fakeNEWW";
const loginArgs = (...rest: string[]) => ["login", "--server", "{{server}}", ...rest];
const STORED_LIVE = { token: "vlt_cli_fakeOLDD", issuedAt: "2026-11-01T10:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z", credentialId: "cred_old", name: "laptop" };
const SETTINGS_DEFAULT = (server: string) => `${JSON.stringify({ defaultServer: server }, null, 2)}\n`;
const TOML_HERE = 'server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n';
const ENVS_PATH = "/v1/organizations/acme/projects/web/environments";

/** Every tier, kind and selection: the frozen human format of env list (robotsson parses it). */
const TIERS = ["development", "staging", "production"];
const KINDS = ["shared", "personal", "preview"];
const ALL_ENVS = TIERS.flatMap((tier) => KINDS.map((kind) => ({ id: `env_${tier}_${kind}`, name: `${tier}-${kind}`, tier, kind, createdAt: "2026-11-01T10:00:00.000Z" })));
const envList = (items: unknown, extra: Partial<Exchange> = {}): Exchange => ({ ...ok(ENVS_PATH, { items, nextCursor: null }), ...extra });
const ME_FULL = {
  identity: { id: "idn_1", name: "Ada", kind: "human", email: "ada@example.com" },
  organization: null,
  credential: { id: "cred_a", name: "laptop", kind: "cli", expiresAt: "2100-01-01T00:00:00.000Z" },
  listener: "ordinary",
};
const ME_SERVICE = {
  identity: { id: "idn_2", name: "deployer", kind: "service" },
  organization: { id: "org_1", slug: "acme", name: "Acme" },
  credential: { id: "cred_s", name: null, kind: "service", expiresAt: null },
  listener: "tailnet",
  tailnet: { recognized: true, tailnet: "example.ts.net", nodeId: "nABC", nodeName: "ci-runner", tags: ["tag:ci", "tag:deploy"] },
};
const WHOAMI_OK = (me: unknown): Exchange[] => [ok("/v1/meta", LOGIN_META), ok("/v1/me", me)];
const STORE_HERE = storeAt({ "{{server}}": STORED_LIVE });
const inRepo = (extra: Record<string, string> = {}, local?: unknown): Record<string, string> => ({ ...repoFiles(TOML_HERE, local), ...extra });

const session51e: TranscriptCase[] = [
  // login --token
  session({ id: "login.token", title: "login --token: verified, stored with the time, and the server becomes the default", args: loginArgs("--token", TOKEN), server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.trailing-slash", title: "a server given with a trailing slash: stored and remembered without it, said as given", args: ["login", "--server", "{{server}}/", "--token", TOKEN], server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.path", title: "a server with a path: the API is under it", args: ["login", "--server", "{{server}}/base", "--token", TOKEN], server: [ok("/base/v1/meta", LOGIN_META), { ...ORGS, path: "/base/v1/organizations" }], patterns: NOW }),
  session({ id: "login.token.default-kept", title: "a default server already set is kept, and nothing is said about it", args: loginArgs("--token", TOKEN), files: { "config/settings.json": SETTINGS_DEFAULT("https://other.example") }, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.settings-kept", title: "other settings are kept when the default is set", args: loginArgs("--token", TOKEN), files: { "config/settings.json": '{"future": [1, 2]}\n' }, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.other-entries", title: "other stored servers and unknown keys are kept", args: loginArgs("--token", TOKEN), files: { "config/credentials.json": `${JSON.stringify({ version: 9, servers: { "https://a.example": { token: "vlt_cli_fakeAAAA", future: true } }, extra: "kept" }, null, 2)}\n` }, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.repo-server", title: "without --server, inside a repository: its server", args: ["login", "--token", TOKEN], files: inRepo(), ...IN_REPO, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.local-override", title: "without --server: the repository's local override comes before varlatch.toml", args: ["login", "--token", TOKEN], files: { ...repoFiles('server = "https://repo.example"\norganization = "acme"\nproject = "web"\n', { serverOverride: "{{server}}" }) }, ...IN_REPO, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.env-server", title: "without --server: VARLATCH_SERVER", args: ["login", "--token", TOKEN], env: { VARLATCH_SERVER: "{{server}}" }, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.default-server", title: "without --server, outside a repository: the default server", args: ["login", "--token", TOKEN], files: { "config/settings.json": SETTINGS_DEFAULT("{{server}}") }, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.only-credential", title: "without --server: the only stored credential's server; the same token replaces nothing", args: ["login", "--token", "vlt_cli_fakeOLDD"], files: STORE_HERE, server: LOGIN_OK, patterns: NOW }),
  { id: "login.no-server", title: "no server anywhere: a usage error", args: ["login", "--token", TOKEN] },
  { id: "login.no-server.repo", title: "inside a repository without a server: a usage error, never the default", args: ["login", "--token", TOKEN], files: { ...repoFiles(TOML_NO_SERVER), "config/settings.json": SETTINGS_DEFAULT("https://a.example") }, ...IN_REPO },
  { id: "login.no-server.several", title: "several stored credentials and no default: a usage error", args: ["login", "--token", TOKEN], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "login.bad-toml", title: "an unreadable varlatch.toml without --server: the context error", args: ["login", "--token", TOKEN], files: repoFiles('organization = "acme\n'), ...IN_REPO },
  session({ id: "login.bad-toml.flag", title: "an unreadable varlatch.toml does not block --server", args: loginArgs("--token", TOKEN), files: repoFiles('organization = "acme\n'), ...IN_REPO, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.ignores-oidc-options", title: "--ttl, --org, --audience and --oidc-token belong to other sign-ins; with --token they change nothing", args: loginArgs("--token", TOKEN, "--ttl", "600", "--org", "acme", "--audience", "x", "--oidc-token", "y"), server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.assisted", title: "in assisted mode, --token signs in; the User-Agent says assisted", args: ["--assisted", ...loginArgs("--token", TOKEN)], server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.token.marker", title: "a coding agent's marker: --token still signs in", args: loginArgs("--token", TOKEN), env: { CLAUDECODE: "1" }, server: LOGIN_OK, patterns: NOW }),
  // replacing a stored credential (ADR-0032)
  session({ id: "login.replaces", title: "a live stored credential is revoked after the new one is stored", args: loginArgs("--token", TOKEN), files: STORE_HERE, server: [...LOGIN_OK, del("/v1/me/credentials/cred_old")], patterns: NOW }),
  session({ id: "login.replaces.refused", title: "the revocation refused: said on stderr with the old expiry, the sign-in stands", args: loginArgs("--token", TOKEN), files: STORE_HERE, server: [...LOGIN_OK, del("/v1/me/credentials/cred_old", 401, apiError(401, "INVALID_CREDENTIAL"))], patterns: NOW }),
  session({ id: "login.replaces.unknown-code", title: "a refusal with a code the protocol does not define", args: loginArgs("--token", TOKEN), files: STORE_HERE, server: [...LOGIN_OK, del("/v1/me/credentials/cred_old", 400, apiError(400, "MADE_UP"))], patterns: NOW }),
  session({ id: "login.replaces.no-id", title: "a stored credential without an id cannot be revoked: said, without an expiry", args: loginArgs("--token", TOKEN), files: storeAt({ "{{server}}": { token: "vlt_cli_fakeOLDD" } }), server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.replaces.expired", title: "an expired stored credential is replaced without revoking it", args: loginArgs("--token", TOKEN), files: storeAt({ "{{server}}": { ...STORED_LIVE, expiresAt: "2020-01-01T00:00:00.000Z" } }), server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.replaces.odd-entry", title: "a stored entry with odd fields: a numeric id, an expiry that does not parse", args: loginArgs("--token", TOKEN), files: storeAt({ "{{server}}": { token: 5, credentialId: 7, expiresAt: "soon" } }), server: [...LOGIN_OK, { ...del("/v1/me/credentials/7"), status: 204 }], patterns: NOW }),
  session({ id: "login.replaces.maintenance", title: "the revocation waits out maintenance, said once", args: loginArgs("--token", TOKEN), files: STORE_HERE, server: [...LOGIN_OK, { ...MAINTENANCE, method: "DELETE", path: "/v1/me/credentials/cred_old" }, del("/v1/me/credentials/cred_old")], patterns: NOW }),
  // --token-stdin (ADR-0043 Decision 2)
  session({ id: "login.stdin", title: "--token-stdin: one line break at the end is dropped", args: loginArgs("--token-stdin"), stdin: `${TOKEN}\n`, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.stdin.crlf", title: "--token-stdin: a CRLF at the end is dropped", args: loginArgs("--token-stdin"), stdin: `${TOKEN}\r\n`, server: LOGIN_OK, patterns: NOW }),
  session({ id: "login.stdin.no-newline", title: "--token-stdin without a line break", args: loginArgs("--token-stdin"), stdin: TOKEN, server: LOGIN_OK, patterns: NOW }),
  { id: "login.stdin.empty", title: "--token-stdin with nothing piped", args: loginArgs("--token-stdin"), stdin: "" },
  { id: "login.stdin.only-newline", title: "--token-stdin with only a line break", args: loginArgs("--token-stdin"), stdin: "\n" },
  { id: "login.stdin.two-lines", title: "--token-stdin with two lines: whitespace, and the credential is not shown", args: loginArgs("--token-stdin"), stdin: `${TOKEN}\nvlt_cli_fakeSECOND\n` },
  { id: "login.stdin.two-newlines", title: "--token-stdin ending in two line breaks: only one is dropped", args: loginArgs("--token-stdin"), stdin: `${TOKEN}\n\n` },
  { id: "login.stdin.space", title: "--token-stdin with a space inside", args: loginArgs("--token-stdin"), stdin: "vlt_cli_fake NEWW\n" },
  { id: "login.stdin.tab", title: "--token-stdin with a leading tab", args: loginArgs("--token-stdin"), stdin: `\t${TOKEN}\n` },
  { id: "login.stdin.nbsp", title: "--token-stdin with a no-break space: JavaScript's \\s", args: loginArgs("--token-stdin"), stdin: `${TOKEN} \n` },
  { id: "login.stdin.bom", title: "--token-stdin with a byte order mark: JavaScript's \\s", args: loginArgs("--token-stdin"), stdin: `﻿${TOKEN}\n` },
  { id: "login.stdin.line-separator", title: "--token-stdin with U+2028", args: loginArgs("--token-stdin"), stdin: `${TOKEN} x\n` },
  { id: "login.stdin.cr-only", title: "--token-stdin ending in a lone CR: not dropped, whitespace", args: loginArgs("--token-stdin"), stdin: `${TOKEN}\r` },
  // usage errors
  { id: "login.usage.two-methods", title: "--token and --token-stdin together", args: loginArgs("--token", TOKEN, "--token-stdin") },
  { id: "login.usage.token-oidc", title: "--token and --oidc together", args: loginArgs("--token", TOKEN, "--oidc") },
  { id: "login.usage.start-wait", title: "--start and --wait together", args: loginArgs("--start", "--wait") },
  { id: "login.usage.three-methods", title: "three methods, listed in their order", args: loginArgs("--wait", "--oidc", "--token-stdin") },
  { id: "login.usage.empty-token-oidc", title: "--token with an empty value still counts as a method", args: loginArgs("--token", "", "--oidc") },
  { id: "login.usage.json", title: "--json applies to --start and --wait", args: loginArgs("--token", TOKEN, "--json") },
  { id: "login.usage.timeout", title: "--timeout applies to --wait", args: loginArgs("--token", TOKEN, "--timeout", "5") },
  { id: "login.usage.unknown-option", title: "login is parsed strictly: an unknown option", args: loginArgs("--token", TOKEN, "--tokn", "x") },
  { id: "login.usage.argument", title: "login takes no argument", args: loginArgs("--token", TOKEN, "extra") },
  { id: "login.usage.token-missing", title: "--token without a value", args: loginArgs("--token") },
  { id: "login.usage.token-twice", title: "--token given twice", args: loginArgs("--token", TOKEN, "--token", TOKEN) },
  { id: "login.usage.server-twice", title: "--server given twice", args: ["login", "--server", "https://a.example", "--server", "https://b.example", "--token", TOKEN] },
  { id: "login.usage.before-server", title: "a usage error comes before the server is looked for", args: ["login", "--tokn"] },
  { id: "login.agent-run", title: "inside an agent-safe run: refused before anything else", args: loginArgs("--token", TOKEN), env: { VARLATCH_AGENT_RUN: "run_0123" } },
  { id: "login.agent-run.bad-options", title: "inside an agent-safe run even a malformed command line gets the refusal", args: ["login", "--nosuch"], env: { VARLATCH_AGENT_RUN: "run_0123" } },
  // the server refuses or cannot be reached
  session({ id: "login.refused.meta", title: "the credential refused at /v1/meta: nothing stored", args: loginArgs("--token", TOKEN), server: [{ method: "GET", path: "/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  session({ id: "login.refused.organizations", title: "refused at /v1/organizations: nothing stored, and the server's echo of the token is masked", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", LOGIN_META), { method: "GET", path: "/v1/organizations", status: 403, answer: apiError(403, "PERMISSION_DENIED", `token ${TOKEN} is not allowed`) }] }),
  session({ id: "login.refused.frozen", title: "an Organization frozen", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", LOGIN_META), { method: "GET", path: "/v1/organizations", status: 403, answer: apiError(403, "ORGANIZATION_FROZEN") }] }),
  session({ id: "login.refused.html", title: "a proxy's HTML page", args: loginArgs("--token", TOKEN), server: [{ method: "GET", path: "/v1/meta", status: 502, headers: { "content-type": "text/html" }, answer: "<html>bad gateway</html>" }] }),
  { id: "login.unreachable", title: "a server that refuses the connection: 69", args: ["login", "--server", "http://127.0.0.1:2", "--token", TOKEN] },
  session({ id: "login.maintenance", title: "maintenance is waited out, said once on stderr", args: loginArgs("--token", TOKEN), server: [MAINTENANCE, MAINTENANCE, ...LOGIN_OK], patterns: NOW }),
  session({ id: "login.maintenance.later", title: "maintenance at the verification request", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", LOGIN_META), { ...MAINTENANCE, path: "/v1/organizations" }, ORGS], patterns: NOW }),
  session({ id: "login.meta.version-odd", title: "a version that is not one and no API version: said as unrecognized", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", { serverVersion: "x\u001b[31m", apiMajor: "1" }), ORGS], patterns: NOW }),
  session({ id: "login.meta.version-missing", title: "no version at all", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", { apiMajor: 1000 }), ORGS], patterns: NOW }),
  session({ id: "login.meta.version-prerelease", title: "a prerelease version and API 0", args: loginArgs("--token", TOKEN), server: [ok("/v1/meta", { serverVersion: "1.2.3-rc.1+build.5", apiMajor: 0 }), ORGS], patterns: NOW }),
  session({ id: "login.meta.empty", title: "an empty meta answer: the credential is stored, then TypeScript throws", args: loginArgs("--token", TOKEN), server: [{ method: "GET", path: "/v1/meta", status: 204 }, ORGS], patterns: NOW, differences: ["uncaught"] }),
  session({ id: "login.expiry-header", title: "Varlatch-Credential-Expires is no warning at sign-in", args: loginArgs("--token", TOKEN), env: { VARLATCH_TOKEN: TOKEN }, server: [ok("/v1/meta", LOGIN_META, { "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" }), ORGS], patterns: NOW }),

  // logout (ADR-0032)
  { id: "logout.none", title: "nothing stored", args: ["logout"] },
  { id: "logout.none.all", title: "nothing stored, --all", args: ["logout", "--all"] },
  session({ id: "logout.only", title: "the only stored credential: revoked and removed, and the default forgotten", args: ["logout"], files: { ...STORE_HERE, "config/settings.json": SETTINGS_DEFAULT("{{server}}") }, server: [del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.default", title: "several stored: the default server's", args: ["logout"], files: { ...storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }), "config/settings.json": SETTINGS_DEFAULT("{{server}}") }, server: [del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.default-other", title: "another server's logout keeps the default", args: ["logout", "--server", "{{server}}"], files: { ...storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }), "config/settings.json": SETTINGS_DEFAULT("https://a.example") }, server: [del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.server", title: "--server names it; a trailing slash finds it", args: ["logout", "--server", "{{server}}/"], files: storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }), server: [del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.repo", title: "inside a repository: its server", args: ["logout"], files: { ...inRepo(), ...storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }) }, ...IN_REPO, server: [del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.env-server", title: "VARLATCH_SERVER names it", args: ["logout"], env: { VARLATCH_SERVER: "{{server}}" }, files: storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }), server: [del("/v1/me/credentials/cred_old")] }),
  { id: "logout.multiple", title: "several stored and no default: a usage error naming them", args: ["logout"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "logout.no-server-here", title: "inside a repository without a server: a usage error naming what is stored", args: ["logout"], files: { ...repoFiles(TOML_NO_SERVER), ...STORE_HERE }, ...IN_REPO },
  { id: "logout.bad-toml", title: "an unreadable varlatch.toml names no server", args: ["logout"], files: { ...repoFiles('organization = "acme\n'), ...STORE_HERE }, ...IN_REPO },
  { id: "logout.not-stored", title: "--server with nothing stored for it", args: ["logout", "--server", "https://nosuch.example"], files: STORE_HERE },
  session({ id: "logout.all", title: "--all: each in order, one without an id, one refused", args: ["logout", "--all"], files: { ...storeAt({ "{{server}}": STORED_LIVE, "{{server}}/two": { token: "vlt_cli_fakeTWOO", expiresAt: "2100-01-01T00:00:00.000Z" }, "{{server}}/three": { token: "vlt_cli_fakeTHRE", credentialId: "cred_3", expiresAt: "2100-01-01T00:00:00.000Z" } }), "config/settings.json": SETTINGS_DEFAULT("{{server}}/three") }, server: [del("/v1/me/credentials/cred_old"), del("/three/v1/me/credentials/cred_3", 403, apiError(403, "PERMISSION_DENIED"))] }),
  session({ id: "logout.refused", title: "the revocation refused: removed locally, said with the expiry", args: ["logout"], files: STORE_HERE, server: [del("/v1/me/credentials/cred_old", 401, apiError(401, "INVALID_CREDENTIAL"))] }),
  { id: "logout.unreachable", title: "a server that cannot be reached: removed locally, fetch failed", args: ["logout"], files: storeAt({ "http://127.0.0.1:2": STORED_LIVE }) },
  session({ id: "logout.maintenance", title: "maintenance at the revocation is waited out", args: ["logout"], files: STORE_HERE, server: [{ ...MAINTENANCE, method: "DELETE", path: "/v1/me/credentials/cred_old" }, del("/v1/me/credentials/cred_old")] }),
  session({ id: "logout.odd-entry", title: "an entry without a token: no Authorization header", args: ["logout"], files: storeAt({ "{{server}}": { credentialId: "cred_x" } }), server: [del("/v1/me/credentials/cred_x")] }),
  { id: "logout.null-entry", title: "a null stored entry: TypeScript throws, nothing removed", args: ["logout"], files: storeAt({ "{{server}}": null }), differences: ["uncaught"] },
  session({ id: "logout.agent-run", title: "inside an agent-safe run the operator's store is not read: nothing stored", args: ["logout"], env: { VARLATCH_AGENT_RUN: "run_0123" }, unset: ["VARLATCH_CONFIG_DIR"], files: { "home/.config/varlatch/credentials.json": credentials({ "{{server}}": STORED_LIVE }) } }),

  // whoami (identity.whoami)
  session({ id: "whoami.human", title: "a person: email, no Organization, a credential with a name and expiry", args: ["whoami", "--server", "{{server}}"], files: STORE_HERE, server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.json", title: "--json: the server and /v1/me's answer as it is", args: ["whoami", "--server", "{{server}}", "--json"], files: STORE_HERE, server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.service", title: "a service in an Organization, from a tailnet device with tags", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK(ME_SERVICE) }),
  session({ id: "whoami.service.json", title: "the same in JSON", args: ["whoami", "--json"], files: STORE_HERE, server: WHOAMI_OK(ME_SERVICE) }),
  session({ id: "whoami.devices", title: "a device by user login, without a name", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_SERVICE, tailnet: { recognized: true, tailnet: "t.ts.net", nodeId: "n1", tags: [], userLogin: "ada@github" } }) }),
  session({ id: "whoami.device-untagged", title: "a device without tags or user", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_SERVICE, tailnet: { recognized: true, tailnet: "t.ts.net", nodeId: "n1", nodeName: "box" } }) }),
  session({ id: "whoami.device-unrecognized", title: "a device not recognized, with and without a reason", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_SERVICE, tailnet: { recognized: false, reason: "other-tailnet" } }) }),
  session({ id: "whoami.device-no-reason", title: "a device not recognized without a reason", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_SERVICE, tailnet: { recognized: false } }) }),
  session({ id: "whoami.machine-no-org", title: "a machine identity without an Organization", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_SERVICE, organization: null, tailnet: undefined }) }),
  session({ id: "whoami.escaped", title: "names with control and bidirectional characters are escaped", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ ...ME_FULL, identity: { id: "idn_1", name: "A\u001b[31mda‮", kind: "human" }, credential: { id: "c", name: "lap\u0007top", kind: "cli", expiresAt: "garbage" } }) }),
  session({ id: "whoami.odd-shapes", title: "fields missing or of other types are shown as JavaScript writes them", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ identity: { id: 7, name: ["a", null, "b"] }, organization: { slug: "acme" }, credential: { kind: { x: 1 } } }) }),
  // A server key or any other field outside the WhoAmI document is not recorded here: `whoami --json` in Go shows only the documented fields, and go/cmd/varlatch's TestWhoamiJSONShowsOnlyTheDocumentedFields pins it.
  session({ id: "whoami.json.empty", title: "--json with an empty answer: the server only", args: ["whoami", "--json"], files: STORE_HERE, server: [ok("/v1/meta", LOGIN_META), { method: "GET", path: "/v1/me", status: 204 }] }),
  session({ id: "whoami.null", title: "an answer of null: TypeScript throws", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK(null), differences: ["uncaught"] }),
  session({ id: "whoami.no-identity", title: "an answer without an identity: TypeScript throws", args: ["whoami"], files: STORE_HERE, server: WHOAMI_OK({ credential: {} }), differences: ["uncaught"] }),
  session({ id: "whoami.unsupported", title: "a server without identity.whoami: said, 1", args: ["whoami"], files: STORE_HERE, server: [ok("/v1/meta", { serverVersion: "0.16.0", capabilities: ["x"] })] }),
  session({ id: "whoami.unsupported.no-version", title: "an older server without a version", args: ["whoami"], files: STORE_HERE, server: [ok("/v1/meta", { capabilities: [] })] }),
  session({ id: "whoami.unsupported.odd-version", title: "a version that is not one", args: ["whoami"], files: STORE_HERE, server: [ok("/v1/meta", { serverVersion: 7, capabilities: "" })] }),
  session({ id: "whoami.trailing-slash", title: "--server with a trailing slash: shown without it", args: ["whoami", "--server", "{{server}}/"], files: STORE_HERE, server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.env-token", title: "VARLATCH_TOKEN comes before the stored credential, and its expiry header warns", args: ["whoami"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: STORE_HERE, server: [ok("/v1/meta", LOGIN_META, { "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" }), ok("/v1/me", ME_SERVICE, { "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" })] }),
  session({ id: "whoami.expiring", title: "a stored credential in the last fifth of its lifetime warns once", args: ["whoami"], files: storeAt({ "{{server}}": { token: "vlt_cli_fakeOLDD", ...EXPIRING } }), server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.expired", title: "an expired stored credential warns, and is still sent", args: ["whoami"], files: storeAt({ "{{server}}": { token: "vlt_cli_fakeOLDD", ...EXPIRED } }), server: [{ method: "GET", path: "/v1/meta", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  session({ id: "whoami.repo", title: "inside a repository: its server", args: ["whoami"], files: { ...inRepo(), ...storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }) }, ...IN_REPO, server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.env-server", title: "VARLATCH_SERVER", args: ["whoami"], env: { VARLATCH_SERVER: "{{server}}" }, files: STORE_HERE, server: WHOAMI_OK(ME_FULL) }),
  session({ id: "whoami.default", title: "outside a repository: the default server", args: ["whoami"], files: { ...storeAt({ "{{server}}": STORED_LIVE, "https://a.example": { token: "vlt_cli_fakeAAAA" } }), "config/settings.json": SETTINGS_DEFAULT("{{server}}") }, server: WHOAMI_OK(ME_FULL) }),
  { id: "whoami.no-server", title: "no server: a usage error", args: ["whoami"] },
  { id: "whoami.several", title: "several stored and no default: a usage error naming them", args: ["whoami"], files: { "config/credentials.json": STORE_SEVERAL } },
  { id: "whoami.bad-toml", title: "an unreadable varlatch.toml names no server", args: ["whoami"], files: { ...repoFiles('organization = "acme\n'), ...STORE_HERE }, ...IN_REPO },
  { id: "whoami.not-signed-in", title: "no credential for the server: 77", args: ["whoami", "--server", "https://a.example"] },
  { id: "whoami.agent-run", title: "inside an agent-safe run without a credential: 77, never the operator's", args: ["whoami", "--server", "{{server}}"], env: { VARLATCH_AGENT_RUN: "run_0123" }, unset: ["VARLATCH_CONFIG_DIR"], files: { "home/.config/varlatch/credentials.json": credentials({ "{{server}}": STORED_LIVE }) } },
  { id: "whoami.usage.option", title: "whoami is parsed strictly", args: ["whoami", "--nosuch"] },
  { id: "whoami.usage.argument", title: "whoami takes no argument", args: ["whoami", "me"] },
  { id: "whoami.usage.server-missing", title: "--server without a value", args: ["whoami", "--server"] },
  session({ id: "whoami.refused", title: "refused at /v1/me: the error line, 77", args: ["whoami"], files: STORE_HERE, server: [ok("/v1/meta", LOGIN_META), { method: "GET", path: "/v1/me", status: 401, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  { id: "whoami.unreachable", title: "a server that cannot be reached: 69", args: ["whoami", "--server", "http://127.0.0.1:2"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" } },
  session({ id: "whoami.maintenance", title: "maintenance is waited out", args: ["whoami"], files: STORE_HERE, server: [MAINTENANCE, ...WHOAMI_OK(ME_FULL)] }),

  // env list: the frozen human format, every tier, kind and selection
  ...[
    ["flag", "--environment selects", ["env", "list", "--environment", "staging-personal"], {}, undefined],
    ["short-flag", "-e selects", ["env", "list", "-e", "production-preview"], {}, undefined],
    ["env-var", "VARLATCH_ENV selects", ["env", "list"], { VARLATCH_ENV: "development-shared" }, undefined],
    ["local", "the local selection", ["env", "list"], {}, { selectedEnvironment: "staging-shared" }],
    ["default", "the committed default", ["env", "list"], {}, undefined],
    ["flag-over-env", "--environment comes before VARLATCH_ENV", ["env", "list", "-e", "production-shared"], { VARLATCH_ENV: "development-shared" }, { selectedEnvironment: "staging-shared" }],
    ["env-over-local", "VARLATCH_ENV comes before the local selection", ["env", "list"], { VARLATCH_ENV: "development-preview" }, { selectedEnvironment: "staging-shared" }],
    ["none-selected", "an Environment the server does not list: none selected", ["env", "list", "-e", "nosuch"], {}, undefined],
  ].flatMap(([id, title, args, env, local]): TranscriptCase[] => [
    session({ id: `env.list.${id}`, title: `env list: ${title as string}`, args: args as string[], env: env as Record<string, string>, files: { ...inRepo({}, local), ...STORE_HERE }, ...IN_REPO, server: [envList(ALL_ENVS)] }),
    session({ id: `env.list.${id}.json`, title: `env list --json: ${title as string}`, args: [...(args as string[]), "--json"], env: env as Record<string, string>, files: { ...inRepo({}, local), ...STORE_HERE }, ...IN_REPO, server: [envList(ALL_ENVS)] }),
  ]),
  session({ id: "env.list.dev-default", title: "env list with the committed default dev", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev", tier: "development", kind: "shared" }, { name: "prod", tier: "production", kind: "shared" }])] }),
  session({ id: "env.list.odd-marks", title: "missing, empty and odd tiers and kinds: only truthy marks, as JavaScript writes them", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }, { name: "a", tier: "", kind: null }, { name: "b", tier: 0, kind: ["x", null, 2] }, { name: "c", tier: { t: 1 }, kind: true }, { name: 5, tier: "staging" }, { tier: "production", kind: "shared" }, {}])] }),
  // The Go CLI leaves out an object or array where the API defines a string (json-scalars).
  session({ differences: ["json-scalars"], id: "env.list.odd-marks.json", title: "the same in JSON: missing fields left out", args: ["env", "list", "--json"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }, { name: "a", tier: "", kind: null }, { name: "b", tier: 0, kind: ["x", null, 2] }, { name: 5, tier: "staging" }, {}])] }),
  session({ id: "env.list.selected-number", title: "a local selection that is a number never equals a name", args: ["env", "list"], files: { ...inRepo({}, { selectedEnvironment: 5 }), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: 5, tier: "staging" }, { name: "5" }])] }),
  session({ id: "env.list.escaped", title: "names and marks with control characters are escaped", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "d\u001b[31mev", tier: "development‮", kind: "shared\u0007" }])] }),
  session({ id: "env.list.empty", title: "no Environments: nothing printed", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([])] }),
  session({ id: "env.list.empty.json", title: "no Environments in JSON", args: ["env", "list", "--json"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([])] }),
  session({ id: "env.list.items-string", title: "items that are a string: each character an Environment without a name", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [ok(ENVS_PATH, { items: "ab" })] }),
  session({ id: "env.list.items-missing", title: "no items: TypeScript throws", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [ok(ENVS_PATH, {})], differences: ["uncaught"] }),
  session({ id: "env.list.items-missing.json", title: "no items, --json: TypeScript throws", args: ["env", "list", "--json"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [ok(ENVS_PATH, {})], differences: ["uncaught"] }),
  session({ id: "env.list.item-null", title: "a null item: the lines before it are printed, then TypeScript throws", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev", tier: "development", kind: "shared" }, null, { name: "prod" }])], differences: ["uncaught"] }),
  session({ id: "env.list.answer-empty", title: "an empty answer: TypeScript throws", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ method: "GET", path: ENVS_PATH, status: 204 }], differences: ["uncaught"] }),
  session({ id: "env.list.encoded", title: "an Organization and Project that need encoding in the path", args: ["env", "list"], files: { ...repoFiles('server = "{{server}}"\norganization = "a c/m"\nproject = "wéb?"\ndefault_environment = "dev"\n'), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }], { path: "/v1/organizations/a%20c%2Fm/projects/w%C3%A9b%3F/environments" })] }),
  // the server and the credential: precedence (inventory)
  session({ id: "env.list.server-flag", title: "--server comes before VARLATCH_SERVER, the local override and varlatch.toml", args: ["env", "list", "--server", "{{server}}"], env: { VARLATCH_SERVER: "https://env.example" }, files: { ...repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.server-env", title: "VARLATCH_SERVER comes before the local override and varlatch.toml", args: ["env", "list"], env: { VARLATCH_SERVER: "{{server}}" }, files: { ...repoFiles(TOML_FULL, { serverOverride: "https://local.example" }), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.server-local", title: "the local override comes before varlatch.toml", args: ["env", "list"], files: { ...repoFiles(TOML_FULL, { serverOverride: "{{server}}" }), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  { id: "env.list.server-none", title: "a repository without a server never falls back to the default", args: ["env", "list"], files: { ...repoFiles(TOML_NO_SERVER), ...STORE_HERE, "config/settings.json": SETTINGS_DEFAULT("{{server}}") }, ...IN_REPO },
  session({ id: "env.list.token-env", title: "VARLATCH_TOKEN comes before the stored credential", args: ["env", "list"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.token-stored", title: "without VARLATCH_TOKEN, the stored credential", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.token-expiring", title: "an expiring stored credential warns once on stderr", args: ["env", "list"], files: { ...inRepo(), ...storeAt({ "{{server}}": { token: "vlt_cli_fakeOLDD", ...EXPIRING } }) }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.token-env-expiry", title: "VARLATCH_TOKEN near its expiry: the server's header warns once", args: ["env", "list"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: inRepo(), ...IN_REPO, server: [envList([{ name: "dev" }], { headers: { "content-type": "application/json", "varlatch-credential-expires": "2999-01-01T00:00:00.000Z" } })] }),
  session({ id: "env.list.token-env-expired", title: "VARLATCH_TOKEN already expired and refused: the warning, then the error", args: ["env", "list"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: inRepo(), ...IN_REPO, server: [{ method: "GET", path: ENVS_PATH, status: 401, headers: { "content-type": "application/json", "varlatch-credential-expires": "2020-01-01T00:00:00.000Z" }, answer: apiError(401, "INVALID_CREDENTIAL") }] }),
  { id: "env.list.not-signed-in", title: "no credential: 77", args: ["env", "list"], files: inRepo(), ...IN_REPO },
  { id: "env.list.agent-run", title: "inside an agent-safe run the operator's store (the default directory) is never read: 77", args: ["env", "list"], env: { VARLATCH_AGENT_RUN: "run_0123" }, unset: ["VARLATCH_CONFIG_DIR"], files: { ...inRepo(), "home/.config/varlatch/credentials.json": credentials({ "{{server}}": STORED_LIVE }) }, ...IN_REPO },
  session({ id: "env.list.agent-run.own-store", title: "inside an agent-safe run with a configuration directory of its own, its store is used", args: ["env", "list"], env: { VARLATCH_AGENT_RUN: "run_0123" }, files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev" }])] }),
  session({ id: "env.list.agent-run.token", title: "inside an agent-safe run, its own VARLATCH_TOKEN: no expiry warning", args: ["env", "list"], env: { VARLATCH_AGENT_RUN: "run_0123", VARLATCH_TOKEN: "vlt_agt_runAAAAAA" }, files: inRepo(), ...IN_REPO, server: [envList([{ name: "dev" }], { headers: { "content-type": "application/json", "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" } })] }),
  { id: "env.list.outside", title: "outside a repository: the context error", args: ["env", "list"], files: STORE_HERE },
  { id: "env.list.no-environment", title: "no Environment selected anywhere: the context error", args: ["env", "list"], files: { ...repoFiles(TOML_NO_ENV.replace("https://repo.example", "{{server}}")), ...STORE_HERE }, ...IN_REPO },
  session({ id: "env.list.refused", title: "refused: the error line with its request id, 77", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ method: "GET", path: ENVS_PATH, status: 403, answer: apiError(403, "PERMISSION_DENIED", "no access to vlt_cli_fakeOLDD") }] }),
  session({ id: "env.list.not-found", title: "a Project the server does not have", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ method: "GET", path: ENVS_PATH, status: 404, answer: apiError(404, "NOT_FOUND", "no such project") }] }),
  session({ id: "env.list.maintenance", title: "maintenance is waited out, said once, stdout untouched", args: ["env", "list"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ ...MAINTENANCE, path: ENVS_PATH }, { ...MAINTENANCE, path: ENVS_PATH }, envList([{ name: "dev", tier: "development", kind: "shared" }])] }),
  session({ id: "env.list.maintenance.json", title: "maintenance with --json: the document unchanged", args: ["env", "list", "--json"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ ...MAINTENANCE, path: ENVS_PATH }, envList([{ name: "dev", tier: "development", kind: "shared" }])] }),
  { id: "env.list.unreachable", title: "a server that cannot be reached: 69", args: ["env", "list", "--server", "http://127.0.0.1:2"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: inRepo(), ...IN_REPO },
  // env, and its usage
  { id: "env.usage.none", title: "env with no subcommand, in a repository: the usage", args: ["env"], files: inRepo(), ...IN_REPO },
  { id: "env.usage.unknown", title: "an unknown subcommand: the usage", args: ["env", "show"], files: inRepo(), ...IN_REPO },
  { id: "env.usage.outside", title: "outside a repository the context error comes first", args: ["env", "show"] },
  // env use (the tier cache, ADR-0032)
  session({ id: "env.use", title: "env use: selected, its tier cached with the time, .varlatch ignores itself", args: ["env", "use", "staging-shared"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList(ALL_ENVS)], patterns: NOW }),
  session({ id: "env.use.keeps", title: "other keys of local.json are kept; an old tier is replaced at the end", args: ["env", "use", "production-preview"], files: { ...inRepo({}, { selectedTier: "development", serverOverride: "{{server}}", tierCachedAt: "2020-01-01T00:00:00.000Z", selectedEnvironment: "old", "1": "index" }), ...STORE_HERE, "repo/.varlatch/.gitignore": "custom\n" }, ...IN_REPO, server: [envList(ALL_ENVS)], patterns: NOW }),
  session({ id: "env.use.not-listed", title: "an Environment the server does not list: selected, no tier, an old one removed", args: ["env", "use", "nosuch"], files: { ...inRepo({}, { selectedTier: "development", tierCachedAt: "2020-01-01T00:00:00.000Z" }), ...STORE_HERE }, ...IN_REPO, server: [envList(ALL_ENVS)] }),
  { id: "env.use.offline", title: "no credential: selected without asking anyone", args: ["env", "use", "dev"], files: inRepo(), ...IN_REPO },
  { id: "env.use.unreachable", title: "a server that cannot be reached: selected without a tier", args: ["env", "use", "dev"], env: { VARLATCH_SERVER: "http://127.0.0.1:2", VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: inRepo(), ...IN_REPO },
  session({ id: "env.use.refused", title: "refused by the server: selected without a tier, nothing said", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ method: "GET", path: ENVS_PATH, status: 403, answer: apiError(403, "PERMISSION_DENIED") }] }),
  session({ id: "env.use.env-token", title: "VARLATCH_TOKEN asks for the tier; its expiry header warns", args: ["env", "use", "dev"], env: { VARLATCH_TOKEN: "vlt_svc_envAAAAAA" }, files: inRepo(), ...IN_REPO, server: [envList([{ name: "dev", tier: "development", kind: "shared" }], { headers: { "content-type": "application/json", "varlatch-credential-expires": "2026-01-01T00:00:00.000Z" } })], patterns: NOW }),
  session({ id: "env.use.maintenance", title: "maintenance is waited out before the tier is cached", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [{ ...MAINTENANCE, path: ENVS_PATH }, envList([{ name: "dev", tier: "development", kind: "shared" }])], patterns: NOW }),
  session({ id: "env.use.odd-tier", title: "a tier of another type is cached as it is and shown as JavaScript writes it", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev", tier: ["a\u001b", 2] }])], patterns: NOW }),
  session({ id: "env.use.falsy-tier", title: "a tier that is empty: no tier", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "dev", tier: "" }])] }),
  session({ id: "env.use.items-odd", title: "items that are not a list: no tier", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [ok(ENVS_PATH, { items: { dev: 1 } })] }),
  session({ id: "env.use.item-null", title: "a null item before the match: no tier", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([null, { name: "dev", tier: "development" }])] }),
  session({ id: "env.use.first-match", title: "the first Environment of that name", args: ["env", "use", "dev"], files: { ...inRepo(), ...STORE_HERE }, ...IN_REPO, server: [envList([{ name: "x", tier: "production" }, { name: "dev", tier: "staging" }, { name: "dev", tier: "production" }])], patterns: NOW }),
  { id: "env.use.local-null", title: "a local.json holding null is replaced", args: ["env", "use", "dev"], files: inRepo({}, "null\n"), ...IN_REPO },
  { id: "env.use.local-array", title: "a local.json holding an array: its elements spread by index", args: ["env", "use", "dev"], files: inRepo({}, '["a", "b"]\n'), ...IN_REPO },
  { id: "env.use.local-broken", title: "a local.json that is not JSON is replaced", args: ["env", "use", "dev"], files: inRepo({}, "{oops\n"), ...IN_REPO },
  { id: "env.use.name-raw", title: "the name is said as given (it is the person's own argument)", args: ["env", "use", "d\u0007ev"], files: inRepo(), ...IN_REPO },
  { id: "env.use.name-option", title: "a name that looks like an option is still a name", args: ["env", "use", "--json"], files: inRepo(), ...IN_REPO },
  { id: "env.use.subdirectory", title: "from a subdirectory: the repository root's local.json", args: ["env", "use", "dev"], files: { ...inRepo(), "repo/a/b/.keep": "" }, cwd: "repo/a/b" },
  { id: "env.use.no-name", title: "env use without a name: the usage", args: ["env", "use"], files: inRepo(), ...IN_REPO },
  { id: "env.use.outside", title: "outside a repository: no varlatch.toml found", args: ["env", "use", "dev"] },
  { id: "env.use.no-name.outside", title: "the name is checked before the repository", args: ["env", "use"] },
  { id: "env.use.agent-run", title: "inside an agent-safe run the operator's credential is not used: no tier", args: ["env", "use", "dev"], env: { VARLATCH_AGENT_RUN: "run_0123" }, unset: ["VARLATCH_CONFIG_DIR"], files: { ...inRepo(), "home/.config/varlatch/credentials.json": credentials({ "{{server}}": STORED_LIVE }) }, ...IN_REPO },
];

// ---- 5.2: sign-in and approvals --------------------------------------------
//
// Device sign-in (--start, --wait), the browser sign-in through its loopback
// callback, OIDC sign-in with each token source, and step-up approvals
// (through whoami, which talks to its server with the step-up handling).
// pending-sign-ins.json is recorded after each step: a --start case writes
// it, and the --wait cases start from the entry it writes. The device code,
// the hand-off bearer and the OIDC tokens are canaries: they appear in no
// output, only in the files meant to hold them.

const DEVICE_CODE = "dc_canary_" + "x".repeat(33);
const USER_CODE = "WDJB-MJHT";
const STARTED = { deviceCode: DEVICE_CODE, userCode: USER_CODE, verificationUri: "{{server}}/device", expiresIn: 600, interval: 1 };
const ISSUED_DEVICE = { id: "cred_dev", token: "vlt_cli_deviceISSUED", expiresAt: "2100-01-01T00:00:00.000Z" };
const err = (status: number, code: string, details?: Record<string, unknown>) => ({ error: { code, message: code.toLowerCase(), requestId: "req_00000000-0000-4000-8000-000000000000", ...(details ? { details } : {}) } });
const post = (path: string, status: number, answer?: unknown, headers?: Record<string, string>): Exchange => ({ method: "POST", path, status, ...(answer === undefined ? {} : { answer }), ...(headers ? { headers } : {}) });
const startAnswer = (answer: unknown = STARTED, status = 201) => post("/v1/auth/device", status, answer);
const poll = (status: number, answer: unknown) => post("/v1/auth/device/token", status, answer);
const pendingPoll = (interval = 1) => poll(428, err(428, "AUTHORIZATION_PENDING", { interval }));
const DEVICE = [...ONLINE];
const deviceArgs = (...rest: string[]) => ["login", "--server", "{{server}}", ...rest];
const PENDING_ENTRY = { server: "{{server}}", deviceCode: DEVICE_CODE, userCode: USER_CODE, verificationUri: "{{server}}/device", expiresAt: "2100-01-01T00:00:00.000Z", interval: 1, startedAt: "2026-11-01T10:00:00.000Z" };
const pendingFile = (entry: Record<string, unknown> = PENDING_ENTRY) => ({ "config/pending-sign-ins.json": `${JSON.stringify({ servers: { "{{server}}": entry } }, null, 2)}\n` });
const LOGGED_IN = [ok("/v1/meta", LOGIN_META), ORGS];
const device = (c: TranscriptCase): TranscriptCase => ({ ...c, differences: [...(c.differences ?? []), ...DEVICE] });

const deviceStart: TranscriptCase[] = [
  { id: "start", title: "--start: the address, the code and its expiry; the entry written 0600 in a 0700 directory", args: deviceArgs("--start"), server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.json", title: "--start --json: one document", args: deviceArgs("--start", "--json"), server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.ttl", title: "--ttl goes to the server", args: deviceArgs("--start", "--ttl", "120"), server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.ttl-low", title: "--ttl below 60 is refused before any request", args: deviceArgs("--start", "--ttl", "59") },
  { id: "start.ttl-not-whole", title: "--ttl that is not whole seconds", args: deviceArgs("--start", "--ttl", "1e3") },
  { id: "start.timeout", title: "--timeout applies to --wait", args: deviceArgs("--start", "--timeout", "5") },
  { id: "start.oidc-option", title: "--org applies to --oidc", args: deviceArgs("--start", "--org", "acme") },
  { id: "start.assisted", title: "assisted mode with no method starts a device sign-in, in the agent's words", args: ["--assisted", "login", "--server", "{{server}}"], server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.assisted-json", title: "the same, --json", args: ["--assisted", "login", "--server", "{{server}}", "--json"], server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.replaces-earlier", title: "a second --start replaces a live earlier one and says so", args: deviceArgs("--start"), files: pendingFile(), server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.replaces-expired", title: "an expired earlier one is replaced silently", args: deviceArgs("--start"), files: pendingFile({ ...PENDING_ENTRY, expiresAt: "2020-01-01T00:00:00.000Z" }), server: [startAnswer()], patterns: ["now", "now+600"] },
  { id: "start.http-elsewhere", title: "http:// to a host that is not loopback is refused before any request", args: ["login", "--server", "http://varlatch.example.com/base/", "--start"] },
  { id: "start.other-scheme", title: "another scheme is refused", args: ["login", "--server", "ftp://varlatch.example.com", "--start"] },
  { id: "start.not-a-url", title: "a server that is not a URL is refused", args: ["login", "--server", "varlatch.example.com", "--start"], differences: ["server-display"] },
  { id: "start.unsupported", title: "a server without device sign-in (404)", args: deviceArgs("--start"), server: [startAnswer(err(404, "RESOURCE_NOT_FOUND"), 404)] },
  { id: "start.maintenance", title: "a server in maintenance (69)", args: deviceArgs("--start"), server: [startAnswer(err(503, "MAINTENANCE"), 503)] },
  { id: "start.refused", title: "the server refuses (1), its message masked", args: deviceArgs("--start"), server: [startAnswer(err(400, "VALIDATION_FAILED"), 400)] },
  { id: "start.server-error", title: "a server error (69)", args: deviceArgs("--start"), server: [startAnswer(err(500, "INTERNAL"), 500)] },
  { id: "start.redirect", title: "a redirect is never followed: the code is not sent there", args: deviceArgs("--start"), server: [post("/v1/auth/device", 302, undefined, { location: "https://elsewhere.example/v1/auth/device" })] },
  { id: "start.bad-answer", title: "an answer that is not a device sign-in (a user code of another shape)", args: deviceArgs("--start"), server: [startAnswer({ ...STARTED, userCode: "wdjb-mjht" })] },
  { id: "start.https-only-verification", title: "a verification address that is not HTTPS (or loopback) is refused", args: deviceArgs("--start"), server: [startAnswer({ ...STARTED, verificationUri: "http://elsewhere.example/device" })] },
  { id: "start.unreachable", title: "a server that cannot be reached (69)", args: ["login", "--server", "http://127.0.0.1:1", "--start"] },
  { id: "start.agent-run", title: "refused inside an agent-safe run before anything is read or written", args: deviceArgs("--start"), env: { VARLATCH_AGENT_RUN: "run_1" }, files: pendingFile() },
].map(device);

const deviceWait: TranscriptCase[] = [
  { id: "wait.approved", title: "--wait: collected, verified, stored; the entry removed; the first server becomes the default", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(201, ISSUED_DEVICE), ...LOGGED_IN], patterns: ["now"] },
  { id: "wait.json", title: "--wait --json: one document", args: deviceArgs("--wait", "--json"), files: pendingFile(), server: [poll(201, ISSUED_DEVICE), ...LOGGED_IN], patterns: ["now"] },
  { id: "wait.pending-then-approved", title: "pending, then approved after the interval", args: deviceArgs("--wait"), files: pendingFile(), server: [pendingPoll(1), poll(201, ISSUED_DEVICE), ...LOGGED_IN], patterns: ["now"] },
  { id: "wait.deadline", title: "still pending at the deadline: 75, the entry kept with when it polled", args: deviceArgs("--wait", "--timeout", "1"), files: pendingFile(), server: [pendingPoll(1)], patterns: ["now"] },
  { id: "wait.deadline-json", title: "the same, --json", args: deviceArgs("--wait", "--timeout", "1", "--json"), files: pendingFile(), server: [pendingPoll(1)], patterns: ["now"] },
  { id: "wait.slow-down", title: "slow_down: the interval grows and is kept for the next --wait", args: deviceArgs("--wait", "--timeout", "2"), files: pendingFile(), server: [poll(429, err(429, "SLOW_DOWN", { interval: 6 }))], patterns: ["now"] },
  { id: "wait.denied", title: "denied in the browser: 77, the entry removed", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(403, err(403, "ACCESS_DENIED"))] },
  { id: "wait.expired", title: "expired: 77, the entry removed", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(410, err(410, "EXPIRED"))] },
  { id: "wait.expired-collected", title: "expired, with a credential collected earlier: named for revocation", args: deviceArgs("--wait"), files: pendingFile({ ...PENDING_ENTRY, collectedCredentialId: "cred_lost" }), server: [poll(410, err(410, "EXPIRED"))] },
  { id: "wait.consumed-recovery", title: "collected but not stored by an earlier --wait: named for revocation, the entry removed", args: deviceArgs("--wait"), files: pendingFile({ ...PENDING_ENTRY, collectedCredentialId: "cred_lost" }), server: [poll(409, err(409, "CONSUMED", { credentialId: "cred_lost" }))] },
  { id: "wait.consumed-json", title: "the same, --json", args: deviceArgs("--wait", "--json"), files: pendingFile({ ...PENDING_ENTRY, collectedCredentialId: "cred_lost" }), server: [poll(409, err(409, "CONSUMED", { credentialId: "cred_lost" }))] },
  { id: "wait.consumed-unknown", title: "consumed, with no credential named anywhere", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(409, err(409, "CONSUMED"))] },
  { id: "wait.consumed-stored", title: "consumed, and stored already by an earlier --wait: signed in", args: deviceArgs("--wait"), files: { ...pendingFile(), ...storeAt({ "{{server}}": { token: "vlt_cli_deviceISSUED", issuedAt: "2026-11-01T10:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z", credentialId: "cred_dev" } }) }, server: [poll(409, err(409, "CONSUMED", { credentialId: "cred_dev" }))] },
  { id: "wait.verify-fails", title: "collected, but the credential does not verify: not stored, named for revocation, the entry kept with it", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(201, ISSUED_DEVICE), { ...ok("/v1/meta", err(401, "INVALID_CREDENTIAL")), status: 401 }] },
  { id: "wait.replaces", title: "a live stored credential is revoked once the new one is stored", args: deviceArgs("--wait"), files: { ...pendingFile(), ...storeAt({ "{{server}}": STORED_LIVE }) }, server: [poll(201, ISSUED_DEVICE), ...LOGGED_IN, del("/v1/me/credentials/cred_old")], patterns: ["now"] },
  { id: "wait.no-entry", title: "no sign-in started here: 64", args: deviceArgs("--wait") },
  { id: "wait.ttl", title: "--ttl applies to --start", args: deviceArgs("--wait", "--ttl", "120"), files: pendingFile() },
  { id: "wait.timeout-zero", title: "--timeout from 1", args: deviceArgs("--wait", "--timeout", "0"), files: pendingFile() },
  { id: "wait.timeout-high", title: "--timeout to 600", args: deviceArgs("--wait", "--timeout", "601"), files: pendingFile() },
  { id: "wait.refused", title: "a poll the server refuses (1): the entry kept", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(400, err(400, "VALIDATION_FAILED"))], patterns: ["now"] },
  { id: "wait.unavailable", title: "a server unavailable (69): the entry kept", args: deviceArgs("--wait"), files: pendingFile(), server: [poll(503, err(503, "MAINTENANCE"))], patterns: ["now"] },
  { id: "wait.redirect", title: "a redirect is never followed: the entry kept", args: deviceArgs("--wait"), files: pendingFile(), server: [post("/v1/auth/device/token", 307, undefined, { location: "https://elsewhere.example/v1/auth/device/token" })], patterns: ["now"] },
  { id: "wait.agent-run", title: "refused inside an agent-safe run; the entry untouched", args: deviceArgs("--wait"), env: { VARLATCH_AGENT_RUN: "run_1" }, files: pendingFile() },
].map(device);

const HANDOFF = "vlt_browser-handoff-canary";
const ISSUED_CLI = { id: "cred_cli", token: "vlt_cli_browserISSUED", expiresAt: "2100-01-01T00:00:00.000Z" };
const exchange = post("/v1/me/credentials/cli", 201, ISSUED_CLI);
const BROWSER = { VARLATCH_NO_BROWSER: "1" };
const CALLBACK = JSON.stringify({ token: HANDOFF, identityId: "idn_1" });
const browser = (c: TranscriptCase): TranscriptCase => ({ patterns: ["now", "callback"], ...c, differences: [...(c.differences ?? []), ...ONLINE, "loopback-nonce"] });

const browserLogin: TranscriptCase[] = [
  { id: "browser", title: "VARLATCH_NO_BROWSER: the address in two lines; the page's callback is taken once, exchanged and stored", args: deviceArgs(), env: BROWSER, callback: { body: CALLBACK, times: 2 }, server: [exchange, ...LOGGED_IN] },
  { id: "browser.no-opener", title: "without VARLATCH_NO_BROWSER and no opener on PATH: the address is printed all the same", args: deviceArgs(), env: { VARLATCH_NO_BROWSER: "0", PATH: "{{dir}}/no-opener" }, callback: { body: CALLBACK }, server: [exchange, ...LOGGED_IN] },
  { id: "browser.ttl", title: "--ttl goes to the exchange", args: deviceArgs("--ttl", "3600"), env: BROWSER, callback: { body: CALLBACK }, server: [exchange, ...LOGGED_IN] },
  { id: "browser.replaces", title: "a live stored credential is revoked once the new one is stored", args: deviceArgs(), env: BROWSER, files: storeAt({ "{{server}}": STORED_LIVE }), callback: { body: CALLBACK }, server: [exchange, ...LOGGED_IN, del("/v1/me/credentials/cred_old")] },
  { id: "browser.no-token", title: "a callback without a token ends the sign-in", args: deviceArgs(), env: BROWSER, callback: { body: "{}" }, differences: ["uncaught"] },
  { id: "browser.exchange-refused", title: "the exchange refused (77)", args: deviceArgs(), env: BROWSER, callback: { body: CALLBACK }, server: [post("/v1/me/credentials/cli", 401, err(401, "INVALID_CREDENTIAL"))] },
].map(browser);

const ID_TOKEN = "eyJhbGciOiJSUzI1NiJ9.canary-id-token";
const ISSUED_OIDC = { id: "cred_oidc", token: "vlt_ci_oidcISSUED", expiresAt: "2100-01-01T00:00:00.000Z", identityId: "idn_ci" };
const oidcExchange = post("/v1/oidc/token", 201, ISSUED_OIDC);
const ACTIONS = { ACTIONS_ID_TOKEN_REQUEST_URL: "{{server}}/actions-token?api-version=2.0", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "actions-request-canary" };
const oidc = (c: TranscriptCase): TranscriptCase => ({ patterns: ["now"], ...c, differences: [...(c.differences ?? []), ...ONLINE] });
const oidcArgs = (...rest: string[]) => ["login", "--server", "{{server}}", "--oidc", "--org", "acme", ...rest];

const oidcLogin: TranscriptCase[] = [
  { id: "oidc.flag", title: "--oidc-token: exchanged and stored with its expiry", args: oidcArgs("--oidc-token", ID_TOKEN), server: [oidcExchange, ...LOGGED_IN] },
  { id: "oidc.env", title: "VARLATCH_OIDC_TOKEN", args: oidcArgs(), env: { VARLATCH_OIDC_TOKEN: ID_TOKEN }, server: [oidcExchange, ...LOGGED_IN] },
  { id: "oidc.flag-over-env", title: "--oidc-token before VARLATCH_OIDC_TOKEN", args: oidcArgs("--oidc-token", ID_TOKEN), env: { VARLATCH_OIDC_TOKEN: "env-token-not-used" }, server: [oidcExchange, ...LOGGED_IN] },
  { id: "oidc.actions", title: "the GitHub Actions endpoint, with its request token", args: oidcArgs(), env: ACTIONS, server: [ok("/actions-token?api-version=2.0", { value: ID_TOKEN }), oidcExchange, ...LOGGED_IN] },
  { id: "oidc.actions-audience", title: "--audience goes to the GitHub Actions endpoint", args: oidcArgs("--audience", "varlatch ci"), env: ACTIONS, server: [ok("/actions-token?api-version=2.0&audience=varlatch+ci", { value: ID_TOKEN }), oidcExchange, ...LOGGED_IN] },
  { id: "oidc.env-over-actions", title: "VARLATCH_OIDC_TOKEN before the GitHub Actions endpoint", args: oidcArgs(), env: { ...ACTIONS, VARLATCH_OIDC_TOKEN: ID_TOKEN }, server: [oidcExchange, ...LOGGED_IN] },
  { id: "oidc.actions-refused", title: "the GitHub Actions endpoint refuses: the permission it needs", args: oidcArgs(), env: ACTIONS, server: [{ ...ok("/actions-token?api-version=2.0", { message: "no" }), status: 403 }], differences: ["uncaught"] },
  { id: "oidc.actions-no-value", title: "the GitHub Actions endpoint answers without a value", args: oidcArgs(), env: ACTIONS, server: [ok("/actions-token?api-version=2.0", {})], differences: ["uncaught"] },
  { id: "oidc.none", title: "no token source: the sources named", args: oidcArgs(), differences: ["uncaught"] },
  { id: "oidc.no-org", title: "--oidc needs --org", args: ["login", "--server", "{{server}}", "--oidc", "--oidc-token", ID_TOKEN] },
  { id: "oidc.ttl", title: "--ttl goes to the exchange", args: oidcArgs("--oidc-token", ID_TOKEN, "--ttl", "900"), server: [oidcExchange, ...LOGGED_IN] },
  { id: "oidc.refused", title: "the exchange refused (77)", args: oidcArgs("--oidc-token", ID_TOKEN), server: [post("/v1/oidc/token", 401, err(401, "INVALID_CREDENTIAL"))] },
].map(oidc);

const APPROVAL = {
  id: "apr_1",
  state: "pending",
  interval: 1,
  expiresAt: "2100-01-01T00:00:00.000Z",
  url: "{{server}}/approvals/apr_1",
  summary: { title: "Show who you are", changes: [{ field: "policy", from: "observe", to: "enforce", loosens: false }] },
};
const stepUp = (approval: Record<string, unknown> = APPROVAL): Exchange => ({ ...ok("/v1/me", err(403, "STEP_UP_REQUIRED", { approval })), status: 403 });
const approvalPoll = (answer: Record<string, unknown>, status = 200): Exchange => ({ ...ok("/v1/me/approvals/apr_1", status === 200 ? answer : err(status, String(answer.code))), status });
const STORE_APPROVAL = storeAt({ "{{server}}": { token: "vlt_cli_fakeAPPR", issuedAt: "2026-11-01T10:00:00.000Z", expiresAt: "2100-01-01T00:00:00.000Z", credentialId: "cred_a" } });
const WHOAMI = ["whoami", "--server", "{{server}}"];
const approval = (c: TranscriptCase): TranscriptCase => ({ files: STORE_APPROVAL, ...c, differences: [...(c.differences ?? []), ...ONLINE] });

const approvals: TranscriptCase[] = [
  { id: "approval.waits", title: "waits at the approval's interval, then repeats the request with the approval", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "pending" }), approvalPoll({ ...APPROVAL, state: "approved" }), ok("/v1/me", ME_FULL)] },
  { id: "approval.slow-down", title: "SLOW_DOWN while waiting: the interval grows, the wait goes on", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ code: "SLOW_DOWN" }, 429), approvalPoll({ ...APPROVAL, state: "approved" }), ok("/v1/me", ME_FULL)] },
  { id: "approval.assisted", title: "assisted mode: stops at once with the command to run again (75)", args: ["--assisted", ...WHOAMI], server: [ok("/v1/meta", LOGIN_META), stepUp()] },
  { id: "approval.no-url", title: "a server without a public URL: the dashboard and the request's id", args: ["--assisted", ...WHOAMI], server: [ok("/v1/meta", LOGIN_META), stepUp({ ...APPROVAL, url: null })] },
  { id: "approval.expired", title: "expired before anyone approved it (75)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp({ ...APPROVAL, expiresAt: "2020-01-01T00:00:00.000Z" })] },
  { id: "approval.cancelled", title: "cancelled while waiting (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "closed", closeReason: "cancelled" })] },
  { id: "approval.reset", title: "closed by the host operator's reset (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "closed", closeReason: "reset" })] },
  { id: "approval.organization-deleted", title: "closed by its organization's deletion (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "closed", closeReason: "organization-deleted" })] },
  { id: "approval.closed", title: "closed for another reason (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "closed", closeReason: "superseded" })] },
  { id: "approval.used", title: "used already (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ ...APPROVAL, state: "consumed" })] },
  { id: "approval.not-yours", title: "not this person's (77)", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp(), approvalPoll({ code: "RESOURCE_NOT_FOUND" }, 404)] },
  { id: "approval.ctrl-c", title: "Ctrl-C while waiting: the approval cancelled, 130", args: WHOAMI, server: [ok("/v1/meta", LOGIN_META), stepUp({ ...APPROVAL, interval: 30 }), post("/v1/me/approvals/apr_1/cancel", 200, { ...APPROVAL, state: "closed", closeReason: "cancelled" })], signal: { after: "Waiting for your approval" } },
  { id: "approval.resume-reads", title: "--approval: reads go out at once, without the approval", args: ["--approval", "apr_1", ...WHOAMI], server: [ok("/v1/meta", LOGIN_META), ok("/v1/me", ME_FULL)] },
  { id: "approval.option-missing", title: "--approval without an id", args: ["--approval", "--", "whoami"] },
  { id: "approval.option-twice", title: "--approval given twice", args: ["--approval", "apr_1", "--approval", "apr_2", "whoami"] },
].map(approval);

const signIn52: TranscriptCase[] = [...deviceStart, ...deviceWait, ...browserLogin, ...oidcLogin, ...approvals];

// ---- 5.3a: values and import ------------------------------------------------
//
// A repository at repo/ on the fake server, signed in with a fake token.
// Values in these cases are fakes (s3cr3t-...); each case that stores one
// also shows it never reaches stdout or stderr. A generated value is random:
// the "generated" pattern records it by its generator (goKit.ts).

const VTOKEN = "vlt_cli_valuesAAAA";
const SIGNED_IN = { ...repoFiles('server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n'), ...storeAt({ "{{server}}": { token: VTOKEN, ...OK } }) };
const NOT_SIGNED_IN = repoFiles('server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n');
const ENV = "/v1/organizations/acme/projects/web/environments/dev";
const PROD = "/v1/organizations/acme/projects/web/environments/prod";
const CONTRACT_PATH = "/v1/organizations/acme/projects/web/contract";
const item = (name: string, extra: Record<string, unknown> = {}) => ({ name, required: { kind: "never" }, sensitive: true, type: "string", ...extra });
const ACTIVE = {
  id: "crv_active",
  contentHash: "sha256:aaaa",
  active: true,
  contract: { schemaVersion: 1, semanticsVersion: 3, items: [item("API_KEY", { rotationHint: "Issue a new key at the provider, then revoke the old one." }), item("PORT", { sensitive: false, type: "integer" })] },
};
const contractAnswer = (answer: unknown = ACTIVE): Exchange => ok(CONTRACT_PATH, answer);
const effective = (items: unknown[], query = ""): Exchange => ok(`${ENV}/effective-configuration${query}`, { environmentId: "env_1", items });
/** An identifier of the server's shape (a prefix and 26 characters of lower-case base32). */
const sid = (prefix: string, seed: string): string => `${prefix}_${(seed.toLowerCase().replace(/[^a-z2-7]/g, "q") + "a".repeat(26)).slice(0, 26)}`;
const HASH = `sha256:${"0123456789abcdef".repeat(4)}`;
const put = (name: string, status = 200, answer: unknown = { versionId: sid("ver", name) }, base = ENV): Exchange => ({ method: "PUT", path: `${base}/values/${name}`, status, answer });
const denied = (path: string, method = "GET", status = 403, code = "PERMISSION_DENIED"): Exchange => ({ method, path, status, answer: apiError(status, code) });
const v = (c: Omit<TranscriptCase, "differences" | "files" | "cwd"> & { files?: Record<string, string>; cwd?: string; differences?: string[] }): TranscriptCase => ({
  files: SIGNED_IN,
  cwd: "repo",
  ...c,
  differences: [...ONLINE, ...(c.differences ?? [])],
});
const GENERATED = ["generated"];
const VALUE_FREE = ["value-free-usage"];
const DOTENV_FILE = "# app\nAPI_KEY=s3cr3t-api-key-value\nPORT=8080\nDEBUG=true\nHOME_URL=https://example.com\nREF=${PORT}/x\n";
const withFile = (content: string, base: Record<string, string> = SIGNED_IN) => ({ ...base, "repo/.env": content });

const values53a: TranscriptCase[] = [
  // values set: every input form
  v({ id: "set.argument", title: "a plain value on the command line", args: ["values", "set", "PORT", "8080"], server: [put("PORT")] }),
  v({ id: "set.argument.dash", title: "a value that begins with \"-\" after --", args: ["values", "set", "PORT", "--", "-8080"], server: [put("PORT")] }),
  v({ id: "set.argument.options-around", title: "options on either side of the value; -e names the environment", args: ["values", "set", "-e", "prod", "PORT", "8080", "--server", "{{server}}"], server: [put("PORT", 200, { versionId: sid("ver", "prod") }, PROD)] }),
  v({ id: "set.stdin", title: "--stdin: one trailing line break removed, the value never shown", args: ["values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t-from-stdin\n", server: [put("API_KEY")] }),
  v({ id: "set.stdin.crlf", title: "--stdin removes one CRLF", args: ["values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t-crlf\r\n\r\n", server: [put("API_KEY")] }),
  v({ id: "set.stdin.empty", title: "--stdin with only a line break: nothing stored", args: ["values", "set", "API_KEY", "--stdin"], stdin: "\n" }),
  v({ id: "set.stdin.nul", title: "--stdin with a NUL byte: refused without quoting it", args: ["values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t\u0000tail" }),
  v({ id: "set.from-file", title: "--from-file: the file's text, one trailing line break removed", args: ["values", "set", "API_KEY", "--from-file", "key.pem"], files: { ...SIGNED_IN, "repo/key.pem": "-----BEGIN KEY-----\ns3cr3t\n-----END KEY-----\n" }, server: [put("API_KEY")] }),
  v({ id: "set.from-file.missing", title: "--from-file naming no file: its name and the code, never content", args: ["values", "set", "API_KEY", "--from-file", "nosuch.pem"] }),
  v({ id: "set.from-file.directory", title: "--from-file naming a directory", args: ["values", "set", "API_KEY", "--from-file", "."] }),
  v({ id: "set.from-file.empty", title: "--from-file with an empty file", args: ["values", "set", "API_KEY", "--from-file", "empty"], files: { ...SIGNED_IN, "repo/empty": "" } }),
  v({ id: "set.generate", title: "--generate hex:32: a new random value, described, not shown", args: ["values", "set", "API_KEY", "--generate", "hex:32"], server: [put("API_KEY")], patterns: GENERATED }),
  v({ id: "set.generate.alnum", title: "--generate alnum:30", args: ["values", "set", "API_KEY", "--generate", "alnum:30"], server: [put("API_KEY")], patterns: GENERATED }),
  v({ id: "set.generate.base64url", title: "--generate base64url:24", args: ["values", "set", "API_KEY", "--generate", "base64url:24"], server: [put("API_KEY")], patterns: GENERATED }),
  v({ id: "set.generate.weak", title: "--generate below 128 bits is a usage error", args: ["values", "set", "API_KEY", "--generate", "hex:8"] }),
  v({ id: "set.generate.unknown", title: "--generate with an unknown form", args: ["values", "set", "API_KEY", "--generate", "uuid"] }),
  v({ id: "set.two-sources", title: "two value sources are a usage error, before any request", args: ["values", "set", "API_KEY", "s3cr3t-arg", "--stdin"], stdin: "x\n" }),
  v({ id: "set.prompt.not-a-terminal", title: "no value, and standard input is not a terminal: how to give one", args: ["values", "set", "API_KEY"] }),
  // assisted mode
  v({ id: "set.assisted.no-value", title: "assisted mode never prompts: the safe forms instead", args: ["--assisted", "values", "set", "API_KEY"] }),
  v({ id: "set.assisted.no-value.server", title: "the handoff names an overridden server", args: ["--assisted", "values", "set", "API_KEY", "--server", "{{server}}", "-e", "prod"] }),
  v({ id: "set.assisted.secret-argument", title: "assisted mode refuses a Secret's value on the command line, never echoing it", args: ["--assisted", "values", "set", "API_KEY", "s3cr3t-on-the-command-line"], server: [contractAnswer()] }),
  v({ id: "set.assisted.uncontracted-argument", title: "an item outside the Contract is a Secret", args: ["--assisted", "values", "set", "NEW_ITEM", "s3cr3t-on-the-command-line"], server: [contractAnswer()] }),
  v({ id: "set.assisted.no-contract", title: "no active Contract (404): every item is a Secret", args: ["--assisted", "values", "set", "PORT", "8080"], server: [denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND")] }),
  v({ id: "set.assisted.marker", title: "a coding agent's marker turns on assisted mode", args: ["values", "set", "API_KEY", "s3cr3t-on-the-command-line"], env: { CLAUDECODE: "1" }, server: [contractAnswer()] }),
  v({ id: "set.assisted.plain-argument", title: "a plain item's value on the command line in assisted mode; a new item needs no --replace", args: ["--assisted", "values", "set", "PORT", "8080"], server: [contractAnswer(), effective([]), put("PORT")] }),
  v({ id: "set.assisted.existing", title: "replacing an existing value needs --replace (78), before the value is generated", args: ["--assisted", "values", "set", "API_KEY", "--generate", "hex:32"], server: [effective([{ name: "API_KEY", sensitive: true, source: "self" }])] }),
  v({ id: "set.assisted.inherited", title: "a value inherited from the parent counts as existing", args: ["--assisted", "values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t-x\n", server: [effective([{ name: "API_KEY", sensitive: true, source: "parent" }])] }),
  v({ id: "set.assisted.unknown", title: "when the server cannot say, the item counts as existing", args: ["--assisted", "values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t-x\n", server: [denied(`${ENV}/effective-configuration`)] }),
  v({ id: "set.assisted.replace", title: "--replace naming the item: no existence check, the value is stored", args: ["--assisted", "values", "set", "API_KEY", "--from-file", "key", "--replace", "API_KEY"], files: { ...SIGNED_IN, "repo/key": "s3cr3t-file-value\n" }, server: [put("API_KEY")] }),
  // the command line, strictly
  v({ id: "set.replace-other", title: "--replace naming another item is a usage error", args: ["values", "set", "API_KEY", "--replace", "OTHER", "--stdin"] , differences: VALUE_FREE}),
  v({ id: "set.no-item", title: "no item: the usage", args: ["values", "set"] }),
  v({ id: "set.dash-item", title: "an item that begins with \"-\": the usage", args: ["values", "set", "--", "-X"] }),
  v({ id: "set.unknown-option", title: "a mistyped option is refused before anything is read", args: ["values", "set", "PORT", "--env", "prod"] , differences: VALUE_FREE}),
  v({ id: "set.grace", title: "--grace is rotate's", args: ["values", "set", "PORT", "8080", "--grace", "60"] , differences: VALUE_FREE}),
  v({ id: "set.value-like-option", title: "a value that begins with \"-\" before --: refused, and the Go CLI does not echo it", args: ["values", "set", "API_KEY", "-s3cr3tValue"], differences: VALUE_FREE }),
  v({ id: "set.extra-argument", title: "a value in two words: refused, and the Go CLI does not echo either", args: ["values", "set", "API_KEY", "s3cr3t", "words"], differences: VALUE_FREE }),
  v({ id: "set.own-option-equals", title: "--environment=prod: one of the command's options, not parsed that way, is named", args: ["values", "set", "API_KEY", "--environment=prod"] , differences: VALUE_FREE}),
  v({ id: "set.unknown-option-equals", title: "--value=...: an unknown option holding what may be a value is not echoed (Go)", args: ["values", "set", "API_KEY", "--value=s3cr3t-x"], differences: VALUE_FREE }),
  v({ id: "set.missing-value-option", title: "--from-file needs a value", args: ["values", "set", "API_KEY", "--from-file"] }),
  v({ id: "set.environment-twice", title: "-e and --environment both given", args: ["values", "set", "API_KEY", "-e", "a", "--environment", "b", "--stdin"] }),
  // the server
  v({ id: "set.not-signed-in", title: "no credential: 77 once the value is read", args: ["values", "set", "PORT", "8080"], files: NOT_SIGNED_IN }),
  v({ id: "set.outside-repository", title: "outside a repository: the context error", args: ["values", "set", "PORT", "8080"], cwd: "." }),
  v({ id: "set.echoed-value", title: "a server that echoes the value back has it masked", args: ["values", "set", "API_KEY", "--stdin"], stdin: "s3cr3t-echoed-value\n", server: [put("API_KEY", 400, apiError(400, "VALIDATION_FAILED", "value s3cr3t-echoed-value is not accepted"))] }),
  v({ id: "set.denied", title: "a refused write: the error's code and 77", args: ["values", "set", "PORT", "8080"], server: [put("PORT", 403, apiError(403, "PERMISSION_DENIED"))] }),
  v({ id: "set.unreachable", title: "an unreachable server: 69", args: ["values", "set", "PORT", "8080", "--server", "http://127.0.0.1:2"], files: { ...SIGNED_IN, ...storeAt({ "http://127.0.0.1:2": { token: VTOKEN, ...OK } }) } }),
  v({ id: "set.odd-version", title: "a version id with control characters is escaped", args: ["values", "set", "PORT", "8080"], server: [put("PORT", 200, { versionId: "ver\u001b[31m" })] , differences: ["unrecognized-id"]}),
  // values rotate
  v({ id: "rotate.argument", title: "rotate: the Contract's hint before and after, on stderr", args: ["values", "rotate", "API_KEY", "s3cr3t-new"], server: [contractAnswer(), { method: "POST", path: `${ENV}/values/API_KEY/rotations`, status: 200, answer: { primaryVersionId: sid("ver", "two"), rotationDeadline: "2026-11-19T10:00:00Z" } }] }),
  v({ id: "rotate.grace", title: "--grace is sent as a number of seconds", args: ["values", "rotate", "PORT", "--grace", "007", "--stdin"], stdin: "9090\n", server: [contractAnswer(), { method: "POST", path: `${ENV}/values/PORT/rotations`, status: 200, answer: { primaryVersionId: sid("ver", "three"), rotationDeadline: null } }] }),
  v({ id: "rotate.grace-bad", title: "--grace must be a whole number of seconds", args: ["values", "rotate", "PORT", "--grace", "1h", "9090"] , differences: VALUE_FREE}),
  v({ id: "rotate.generate", title: "rotate to a generated value", args: ["values", "rotate", "API_KEY", "--generate", "base64:32"], server: [denied(CONTRACT_PATH), { method: "POST", path: `${ENV}/values/API_KEY/rotations`, status: 200, answer: { primaryVersionId: sid("ver", "four"), rotationDeadline: "not a time" } }], patterns: GENERATED }),
  v({ id: "rotate.unsafe-hint", title: "a hint with control characters is not shown (an answer without a version id stops TypeScript)", args: ["values", "rotate", "API_KEY", "s3cr3t-new"], server: [contractAnswer({ ...ACTIVE, contract: { ...ACTIVE.contract, items: [item("API_KEY", { rotationHint: "line\none" })] } }), { method: "POST", path: `${ENV}/values/API_KEY/rotations`, status: 200, answer: {} }], differences: ["uncaught"] }),
  v({ id: "rotate.assisted.existing", title: "assisted rotate of an existing value needs --replace", args: ["--assisted", "values", "rotate", "API_KEY", "--generate", "hex:32"], server: [effective([{ name: "API_KEY", sensitive: true, source: "self" }])] }),
  v({ id: "rotate.value-like-option", title: "rotate refuses a value before -- without echoing it (Go)", args: ["values", "rotate", "API_KEY", "-s3cr3t"], differences: VALUE_FREE }),
  // values delete
  v({ id: "delete", title: "delete", args: ["values", "delete", "PORT"], server: [{ method: "DELETE", path: `${ENV}/values/PORT`, status: 204 }] }),
  v({ id: "delete.environment", title: "delete in another environment", args: ["values", "delete", "PORT", "-e", "prod"], server: [{ method: "DELETE", path: `${PROD}/values/PORT`, status: 204 }] }),
  v({ id: "delete.assisted", title: "assisted mode: every deletion needs --confirm (78), with the human's command", args: ["--assisted", "values", "delete", "PORT"] }),
  v({ id: "delete.assisted.server", title: "the handoff keeps an overridden server", args: ["--assisted", "values", "delete", "PORT", "--server", "{{server}}"] }),
  v({ id: "delete.assisted.server-variable", title: "VARLATCH_SERVER counts as an overridden server", args: ["--assisted", "values", "delete", "PORT"], env: { VARLATCH_SERVER: "{{server}}" } }),
  v({ id: "delete.assisted.confirmed", title: "--confirm naming the item deletes it", args: ["--assisted", "values", "delete", "PORT", "--confirm", "PORT"], server: [{ method: "DELETE", path: `${ENV}/values/PORT`, status: 204 }] }),
  v({ id: "delete.confirm-other", title: "--confirm naming another item is a usage error", args: ["values", "delete", "PORT", "--confirm", "API_KEY"] }),
  v({ id: "delete.no-item", title: "no item", args: ["values", "delete"] }),
  v({ id: "delete.extra", title: "one item only", args: ["values", "delete", "PORT", "API_KEY"] }),
  v({ id: "delete.unknown-option", title: "a mistyped option", args: ["values", "delete", "PORT", "--env", "prod"] }),
  v({ id: "delete.missing", title: "an item with no value: the server's 404", args: ["values", "delete", "PORT"], server: [denied(`${ENV}/values/PORT`, "DELETE", 404, "NOT_FOUND")] }),
  // values list
  v({ id: "list", title: "names and classification", args: ["values", "list"], server: [effective([{ name: "API_KEY", sensitive: true, source: "self" }, { name: "PORT", sensitive: false, source: "parent", value: "8080" }])] }),
  v({ id: "list.json", title: "--json: names only, rotating as a boolean", args: ["values", "list", "--json"], server: [effective([{ name: "API_KEY", sensitive: true, source: "self", rotating: true, value: "never" }, { name: "PORT", sensitive: false, source: "parent", rotating: "yes" }, { name: "X" }])] }),
  v({ id: "list.empty", title: "no items", args: ["values", "list", "-e", "prod"], server: [ok(`${PROD}/effective-configuration`, {})] }),
  v({ id: "list.rotating", title: "a rotation in progress: a note on stderr with the command that completes it", args: ["values", "list"], server: [effective([{ name: "API_KEY", sensitive: true, source: "self", rotating: true }])] }),
  v({ id: "list.rotating-inherited", title: "an inherited rotation: the note names the parent", args: ["values", "list", "--server", "{{server}}"], server: [effective([{ name: "API_KEY", sensitive: true, source: "parent", rotating: true }]), ok("/v1/organizations/acme/projects/web/environments", { items: [{ id: "env_p", name: "base" }, { id: "env_1", name: "dev", parentEnvironmentId: "env_p" }] })] }),
  v({ id: "list.rotating-no-parent", title: "the parent cannot be found: no command", args: ["values", "list"], server: [effective([{ name: "API_KEY", sensitive: true, source: "parent", rotating: true }]), denied("/v1/organizations/acme/projects/web/environments")] }),
  v({ id: "list.escaped", title: "names with control characters are escaped", args: ["values", "list"], server: [effective([{ name: "A\u001b[31mB", sensitive: 1, source: "self\u202e" }])] }),
  v({ id: "list.lenient", title: "list reads its options leniently", args: ["values", "list", "--nosuch"], server: [effective([])] }),
  v({ id: "list.not-signed-in", title: "no credential", args: ["values", "list"], files: NOT_SIGNED_IN }),
  v({ id: "list.token-variable", title: "VARLATCH_TOKEN is the credential", args: ["values", "list"], env: { VARLATCH_TOKEN: "vlt_svc_envValuesAAAA" }, files: NOT_SIGNED_IN, server: [effective([])] }),
  v({ id: "list.agent-run", title: "inside an agent-safe run the operator's credential is never used", args: ["values", "list"], env: { VARLATCH_AGENT_RUN: "run_1" }, unset: ["VARLATCH_CONFIG_DIR"], files: { ...NOT_SIGNED_IN, "home/.config/varlatch/credentials.json": credentials({ "{{server}}": { token: VTOKEN, ...OK } }) } }),
  // values rotate-complete, and the subcommand
  v({ id: "rotate-complete", title: "rotate-complete", args: ["values", "rotate-complete", "API_KEY"], server: [{ method: "POST", path: `${ENV}/values/API_KEY/rotations/complete`, status: 200, answer: {} }] }),
  v({ id: "rotate-complete.missing", title: "rotate-complete without an item", args: ["values", "rotate-complete"] }),
  v({ id: "rotate-complete.outside", title: "outside a repository the context comes first", args: ["values", "rotate-complete"], cwd: "." }),
  v({ id: "values.none", title: "values without a subcommand", args: ["values"] }),
  v({ id: "values.unknown", title: "an unknown subcommand", args: ["values", "show"] }),
  // validate
  v({ id: "validate.valid", title: "valid: 0", args: ["validate"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: true, complete: true, missing: [], invalid: [], unresolved: [], notEvaluated: [] } }] }),
  v({ id: "validate.invalid", title: "invalid: 1, the reasons on stderr", args: ["validate"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: false, complete: true, missing: ["DATABASE_URL"], invalid: [{ name: "PORT", reason: "expected an integer" }], unresolved: [{ name: "URL", reason: "reference" }], notEvaluated: [] } }] }),
  v({ id: "validate.incomplete", title: "incomplete: 2", args: ["validate", "-e", "prod"], server: [{ method: "POST", path: `${PROD}/validate`, status: 200, answer: { valid: true, complete: false, missing: [], invalid: [], unresolved: [{ name: "U", reason: "authority" }], notEvaluated: [{ name: "API_KEY", requires: "secret.reveal", reason: "requirement" }] } }] }),
  v({ id: "validate.json.valid", title: "--json, valid", args: ["validate", "--json"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: true } }] }),
  v({ id: "validate.json.invalid", title: "--json, invalid: the same status", args: ["validate", "--json"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: false, missing: ["A"], invalid: [{ name: "B", reason: "r" }], unresolved: [] } }] }),
  v({ id: "validate.json.incomplete", title: "--json, incomplete", args: ["validate", "--json"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: false, complete: false, notEvaluated: [{ name: "K", requires: "config.value.read", reason: "permission" }] } }] }),
  v({ id: "validate.escaped", title: "names and reasons are escaped", args: ["validate"], server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: false, missing: ["A\u0007"], invalid: [{ name: "B", reason: "bad\u001b[2J" }] } }] }),
  v({ id: "validate.not-signed-in", title: "no credential", args: ["validate"], files: NOT_SIGNED_IN }),
  v({ id: "validate.denied", title: "refused", args: ["validate"], server: [denied(`${ENV}/validate`, "POST")] }),
  // import
  v({ id: "import.dry-run.offline", title: "--dry-run outside a repository lists names and inferred types", args: ["import", ".env", "--dry-run"], cwd: ".", files: { ".env": DOTENV_FILE } }),
  v({ id: "import.dry-run.not-signed-in", title: "--dry-run without a credential", args: ["import", "--dry-run", ".env"], files: withFile(DOTENV_FILE, NOT_SIGNED_IN) }),
  v({ id: "import.dry-run", title: "--dry-run against the server: sensitivity and existing values, nothing stored", args: ["import", ".env", "--dry-run"], files: withFile(DOTENV_FILE), server: [contractAnswer(), effective([{ name: "PORT", sensitive: false, source: "self", value: "8080" }, { name: "DEBUG", sensitive: false, source: "self", value: "false" }, { name: "API_KEY", sensitive: true, source: "self", value: null }], "?include=values")] }),
  v({ id: "import.dry-run.json", title: "--dry-run --json: names, types and sensitivity, no value", args: ["import", ".env", "--dry-run", "--json", "--delete-source"], files: withFile(DOTENV_FILE), server: [contractAnswer(), effective([], "?include=values")] }),
  v({ id: "import.dry-run.offline.json", title: "--dry-run --json offline", args: ["import", ".env", "--dry-run", "--json"], cwd: ".", files: { ".env": DOTENV_FILE } }),
  v({ id: "import", title: "stores every value, printing names only", args: ["import", ".env"], files: withFile(DOTENV_FILE), server: [contractAnswer(), effective([], "?include=values"), put("API_KEY"), put("PORT"), put("DEBUG"), put("HOME_URL"), put("REF")] }),
  v({ id: "import.json", title: "--json", args: ["import", ".env", "--json"], files: withFile("A=s3cr3t-a\nB=s3cr3t-b\n"), server: [denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND"), effective([], "?include=values"), put("A"), put("B")] }),
  v({ id: "import.delete-source", title: "--delete-source removes the file once every value is stored", args: ["import", ".env", "--delete-source"], files: withFile("API_KEY=s3cr3t-a\n"), server: [contractAnswer(), effective([], "?include=values"), put("API_KEY")] }),
  v({ id: "import.contract", title: "--contract adds new items, --plain marks one plain", args: ["import", ".env", "--contract", "--plain", "DEBUG"], files: withFile(DOTENV_FILE), server: [contractAnswer(), effective([], "?include=values"), { method: "POST", path: `${CONTRACT_PATH}/revisions`, status: 201, answer: { id: sid("rev", "new"), contentHash: HASH, active: false } }, put("API_KEY"), put("PORT"), put("DEBUG"), put("HOME_URL"), put("REF")] }),
  v({ id: "import.contract.json", title: "--contract --json with no active Contract", args: ["import", ".env", "--contract", "--json"], files: withFile("A=s3cr3t-one\n"), server: [denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND"), effective([], "?include=values"), { method: "POST", path: `${CONTRACT_PATH}/revisions`, status: 201, answer: { id: sid("rev", "one"), contentHash: HASH, active: true } }, put("A")] }),
  v({ id: "import.contract.all-known", title: "--contract when every item is in the Contract", args: ["import", ".env", "--contract", "--dry-run"], files: withFile("PORT=1\n"), server: [contractAnswer(), effective([], "?include=values")] }),
  v({ id: "import.contract.forbidden", title: "--contract without contract.read: 77", args: ["import", ".env", "--contract"], files: withFile("A=s3cr3t-one\n"), server: [denied(CONTRACT_PATH)] }),
  v({ id: "import.contract-unreadable", title: "without --contract, an unreadable Contract is a warning", args: ["import", ".env", "--dry-run"], files: withFile("A=s3cr3t-one\n"), server: [denied(CONTRACT_PATH), denied(`${ENV}/effective-configuration?include=values`, "GET", 404, "NOT_FOUND")] }),
  v({ id: "import.plain-without-contract", title: "--plain needs --contract", args: ["import", ".env", "--plain", "A"], files: withFile("A=s3cr3t-one\n") }),
  v({ id: "import.plain-sensitive", title: "--plain naming an item the Contract marks sensitive", args: ["import", ".env", "--contract", "--plain", "API_KEY"], files: withFile("API_KEY=s3cr3t\n"), server: [contractAnswer(), effective([], "?include=values")] }),
  v({ id: "import.problems", title: "every problem with the names at once, by line, never a value", args: ["import", ".env", "--replace", "NOPE", "--contract", "--plain", "ALSO_NOPE"], files: withFile("VARLATCH_TOKEN=s3cr3t-t\nlower=s3cr3t-l\nA=1\nA=s3cr3t-2\n") }),
  v({ id: "import.parse-error", title: "a line that is not NAME=value: the line number only", args: ["import", ".env"], files: withFile("A=1\nSECRET_VALUE_WITHOUT_NAME\n") }),
  v({ id: "import.unclosed-quote", title: "an unclosed quote", args: ["import", ".env"], files: withFile("A=\"s3cr3t\nmore\n") }),
  v({ id: "import.missing-file", title: "no such file", args: ["import", "nosuch.env"] }),
  v({ id: "import.empty", title: "a file that sets nothing", args: ["import", ".env", "--delete-source"], files: withFile("# nothing\n") }),
  v({ id: "import.empty.json", title: "a file that sets nothing, --json", args: ["import", ".env", "--json"], files: withFile("") }),
  v({ id: "import.existing", title: "outside assisted mode an existing value is replaced, and said so", args: ["import", ".env"], files: withFile("PORT=9090\nDEBUG=true\n"), server: [contractAnswer(), effective([{ name: "PORT", sensitive: false, source: "self", value: "8080" }, { name: "DEBUG", sensitive: false, source: "self", rawValue: "true", value: "x" }], "?include=values"), put("PORT"), put("DEBUG")] }),
  v({ id: "import.assisted.existing", title: "assisted: an existing value needs --replace for it (78), nothing stored", args: ["--assisted", "import", ".env", "--delete-source"], files: withFile("API_KEY=s3cr3t-a\nPORT=1\n"), server: [contractAnswer(), effective([{ name: "API_KEY", sensitive: true, source: "self" }], "?include=values")] }),
  v({ id: "import.assisted.replace", title: "assisted with --replace for each existing item", args: ["--assisted", "import", ".env", "--replace", "API_KEY"], files: withFile("API_KEY=s3cr3t-a\nPORT=1\n"), server: [contractAnswer(), effective([{ name: "API_KEY", sensitive: true, source: "self" }], "?include=values"), put("API_KEY"), put("PORT")] }),
  v({ id: "import.assisted.unreadable", title: "assisted, when what the environment has cannot be read: every item needs --replace", args: ["--assisted", "import", ".env"], files: withFile("A=s3cr3t-one\nB=s3cr3t-two\n"), server: [contractAnswer(), denied(`${ENV}/effective-configuration?include=values`)] }),
  v({ id: "import.store-failure", title: "a failure part way: what was stored, what was not, and why (a code, never a value)", args: ["import", ".env", "--delete-source"], files: withFile("A=s3cr3t-a\nB=s3cr3t-b\nC=s3cr3t-c\n"), server: [contractAnswer(), effective([], "?include=values"), put("A"), put("B", 500, apiError(500, "INTERNAL", "could not store s3cr3t-b"))] }),
  v({ id: "import.store-failure.assisted", title: "the same in assisted mode: the retry needs approval again", args: ["--assisted", "import", ".env"], files: withFile("A=s3cr3t-a\nB=s3cr3t-b\n"), server: [contractAnswer(), effective([], "?include=values"), put("A"), put("B", 403, apiError(403, "PERMISSION_DENIED"))] }),
  v({ id: "import.not-signed-in", title: "no credential: 77", args: ["import", ".env"], files: withFile("A=s3cr3t-one\n", NOT_SIGNED_IN) }),
  v({ id: "import.outside", title: "outside a repository without --dry-run: the context error", args: ["import", ".env"], cwd: ".", files: { ".env": "A=1\n" } }),
  v({ id: "import.environment", title: "-e names the environment", args: ["import", "-e", "prod", ".env", "--dry-run"], files: withFile("A=s3cr3t-one\n"), server: [contractAnswer(), ok(`${PROD}/effective-configuration?include=values`, { items: [] })] }),
  v({ id: "import.usage.none", title: "no file", args: ["import"] }),
  v({ id: "import.usage.two-files", title: "two files", args: ["import", "a.env", "b.env"] }),
  v({ id: "import.usage.unknown", title: "an unknown option", args: ["import", ".env", "--force"] }),
  v({ id: "import.usage.replace-missing-value", title: "--replace needs a value", args: ["import", ".env", "--replace"] }),
];

// ---- 5.3b: Contracts ---------------------------------------------------------
//
// contract push, activate and show against the fake server, in the 5.3a
// repository. Every valid Contract of lib/contract's normalization vectors
// is pushed with --file, so Go sends the same revision TypeScript does.

const NORMALIZE_VECTORS = (JSON.parse(readFileSync(new URL("../../../go/lib/contract/testdata/ts-vectors.json", import.meta.url), "utf8")) as {
  normalize: { name: string; input: string; canonical?: string }[];
}).normalize.filter((n) => n.canonical !== undefined);
const REVISIONS = `${CONTRACT_PATH}/revisions`;
const META_PATH = "/v1/meta";
const ENVS = "/v1/organizations/acme/projects/web/environments";
const pushed = (extra: Record<string, unknown> = {}): Exchange => ({ method: "POST", path: REVISIONS, status: 201, answer: { id: sid("rev", "pushed"), contentHash: HASH, active: false, semanticsVersion: 3, ...extra } });
const meta = (semanticsVersions: unknown = [1, 2, 3]): Exchange => ok(META_PATH, { serverVersion: "0.22.0", apiMajor: 1, capabilities: [], semanticsVersions });
const NO_ACTIVE = denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND");
const usesInteger = (input: string): boolean => /"type":\s*"integer"/.test(input);
const ENV_LIST = ok(ENVS, { items: [
  { id: sid("env", "dev"), name: "development", parentEnvironmentId: null },
  { id: sid("env", "prod"), name: "production", parentEnvironmentId: null },
  { id: sid("env", "preview"), name: "pr-1", parentEnvironmentId: sid("env", "dev") },
], nextCursor: null });
const SCHEMA_FULL = "# @defaultSensitive=false\n\n# Primary database connection string\n# @required\n# @sensitive\n# @type=url\nDATABASE_URL=\n\n# @type=number\nPORT=3000\n\n# @required=env(production)\n# @sensitive\nSTRIPE_SECRET_KEY=op(op://vault/stripe)\n\n# @required=tier(staging)\n# @rotationGrace=3600\n# @rotationHint=Issue a new DSN, then revoke the old one.\nSENTRY_DSN=\n";
const SCHEMA_PLAIN = "# @defaultSensitive=false\n\n# @type=integer\nWORKERS=4\n\n# @type=enum(debug, info)\nLOG_LEVEL=info\n";
const ITEMS_INTEGER = `${JSON.stringify({ schemaVersion: 1, items: [{ name: "WORKERS", required: { kind: "never" }, sensitive: false, type: "integer" }] })}\n`;
const withSchema = (text: string, name = ".env.schema") => ({ ...SIGNED_IN, [`repo/${name}`]: text });
const SCHEMA_VALUE_FREE = ["env-schema-value-free"];

const contracts53b: TranscriptCase[] = [
  // contract push --file: every vector Contract
  ...NORMALIZE_VECTORS.map((n, i): TranscriptCase => v({
    id: `push.file.${i}`,
    title: `--file: the normalization vector "${n.name}" is sent as the file holds it`,
    args: ["contract", "push", "--file", "c.json"],
    files: { ...SIGNED_IN, "repo/c.json": n.input },
    server: usesInteger(n.input) ? [meta(), NO_ACTIVE, pushed()] : [pushed()],
  })),
  v({ id: "push.file.json", title: "--json: the revision's id, hash, state and version", args: ["contract", "push", "--file", "c.json", "--json"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [pushed({ extra: "not shown" })] }),
  v({ id: "push.file.active", title: "an active revision: no activation hint", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [pushed({ active: true })] }),
  v({ id: "push.file.no-version", title: "an answer without a semantics version", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [pushed({ semanticsVersion: undefined })] }),
  v({ id: "push.file.missing", title: "no such file", args: ["contract", "push", "--file", "nosuch.json"] }),
  v({ id: "push.file.not-json", title: "a file that is not JSON (TypeScript lets the SyntaxError escape)", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": "{ nope" }, differences: ["uncaught"] }),
  v({ id: "push.file.bom", title: "a file that begins with a byte order mark: JSON.parse refuses it (TypeScript lets the SyntaxError escape)", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": `\uFEFF${NORMALIZE_VECTORS[0]?.input ?? "{}"}` }, differences: ["uncaught"] }),
  v({ id: "push.file.array", title: "a Contract that is not an object is sent as it is; the server refuses it", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": "[1, 2]" }, server: [{ method: "POST", path: REVISIONS, status: 400, answer: apiError(400, "VALIDATION_FAILED", "Invalid Configuration Contract") }] }),
  // --semantics
  v({ id: "push.semantics.latest", title: "--semantics latest pins the server's newest version", args: ["contract", "push", "--file", "c.json", "--semantics", "latest"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [meta(), pushed()] }),
  v({ id: "push.semantics.number", title: "--semantics 2", args: ["contract", "push", "--file", "c.json", "--semantics", "2"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [meta(), pushed({ semanticsVersion: 2 })] }),
  v({ id: "push.semantics.unknown", title: "--semantics the server does not evaluate: a usage error naming its versions", args: ["contract", "push", "--file", "c.json", "--semantics", "9"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [meta()] }),
  v({ id: "push.semantics.not-a-number", title: "--semantics that is not a number", args: ["contract", "push", "--file", "c.json", "--semantics", "two"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [meta()] }),
  v({ id: "push.semantics.old-server", title: "a server without semantics versions", args: ["contract", "push", "--file", "c.json", "--semantics", "latest"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [ok(META_PATH, { serverVersion: "0.10.0", apiMajor: 1, capabilities: [] })] }),
  // the version check (ADR-0042)
  v({ id: "push.integer.first", title: "an integer item, no active revision: the newest version suffices", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), NO_ACTIVE, pushed()] }),
  v({ id: "push.integer.active-v2", title: "an integer item, the active revision at version 2: refused before the push", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), contractAnswer({ ...ACTIVE, semanticsVersion: 2 })] }),
  v({ id: "push.integer.pinned-v2", title: "an integer item with --semantics 2: refused", args: ["contract", "push", "--file", "c.json", "--semantics", "2"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), meta(), NO_ACTIVE] }),
  v({ id: "push.integer.active-v3", title: "an integer item, the active revision at version 3: pushed", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), contractAnswer({ ...ACTIVE, semanticsVersion: 3 }), pushed()] }),
  v({ id: "push.integer.pinned-v3", title: "an integer item, --semantics 3 over an active version 1: pushed", args: ["contract", "push", "--file", "c.json", "--semantics", "3"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), meta(), contractAnswer({ ...ACTIVE, semanticsVersion: 1 }), pushed()] }),
  v({ id: "push.integer.old-server", title: "an integer item on a server without version 3", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta([1, 2]), NO_ACTIVE] }),
  v({ id: "push.integer.active-denied", title: "the active revision unreadable (403): the error", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": ITEMS_INTEGER }, server: [meta(), denied(CONTRACT_PATH)] }),
  // --schema
  v({ id: "push.schema", title: "--schema: parsed, env(...) resolved to root ids, pushed with its provenance", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema(SCHEMA_FULL), server: [ENV_LIST, pushed()] }),
  v({ id: "push.schema.no-environments", title: "a schema naming no environment needs no environment list", args: ["contract", "push", "--schema", ".env.schema", "--json"], files: withSchema(SCHEMA_PLAIN), server: [meta(), NO_ACTIVE, pushed()] }),
  v({ id: "push.schema.unknown-environment", title: "an unknown and a derived name fail loudly, listing the roots", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema("# @required=env(nosuch, pr-1)\nA=\n"), server: [ENV_LIST] }),
  v({ id: "push.schema.parse-error", title: "a decorator twice: the line and the reason", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema("# @rotationGrace=1\n# @rotationGrace=2\nA=\n") , differences: SCHEMA_VALUE_FREE}),
  v({ id: "push.schema.unrecognized-line", title: "a line that is not an item: the Go CLI does not quote it", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema("api_key=s3cr3t-schema-value\n"), differences: SCHEMA_VALUE_FREE }),
  v({ id: "push.schema.text-after-value", title: "text after a quoted value: not quoted (Go)", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema("A='it\\'s-s3cr3t'\n"), differences: SCHEMA_VALUE_FREE }),
  v({ id: "push.schema.environments-shape", title: "an environment without an id: refused before the push (TypeScript lets the Contract's error escape)", args: ["contract", "push", "--schema", ".env.schema"], files: withSchema("# @required=env(production)\nA=\n"), server: [ok(ENVS, { items: [{ name: "production", parentEnvironmentId: null }], nextCursor: null })], differences: ["uncaught"] }),
  v({ id: "push.schema.missing", title: "no such file", args: ["contract", "push", "--schema", "nosuch.schema"] }),
  v({ id: "push.schema.over-file", title: "--schema wins over --file", args: ["contract", "push", "--file", "c.json", "--schema", ".env.schema"], files: { ...withSchema(SCHEMA_PLAIN.replace("integer", "number")), "repo/c.json": "{}" }, server: [pushed()] }),
  v({ id: "push.schema.empty-flag", title: "an empty --schema is none: --file is read", args: ["contract", "push", "--schema", "", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": NORMALIZE_VECTORS[0]?.input ?? "{}" }, server: [pushed()] }),
  // the command line and the server
  v({ id: "push.usage", title: "neither --schema nor --file", args: ["contract", "push"] }),
  v({ id: "push.usage.last", title: "--file as the last argument has no value", args: ["contract", "push", "--file"] }),
  v({ id: "push.not-signed-in", title: "no credential: 77", args: ["contract", "push", "--file", "c.json"], files: { ...NOT_SIGNED_IN, "repo/c.json": "{}" } }),
  v({ id: "push.denied", title: "a refused push", args: ["contract", "push", "--file", "c.json"], files: { ...SIGNED_IN, "repo/c.json": "{}" }, server: [{ method: "POST", path: REVISIONS, status: 403, answer: apiError(403, "PERMISSION_DENIED") }] }),
  v({ id: "push.outside", title: "outside a repository: the context error first", args: ["contract", "push", "--file", "c.json"], cwd: "." }),
  v({ id: "push.environment", title: "-e changes nothing a push sends", args: ["contract", "push", "--file", "c.json", "-e", "prod"], files: { ...SIGNED_IN, "repo/c.json": "{}" }, server: [pushed()] }),
  v({ id: "activate", title: "activate a revision", args: ["contract", "activate", sid("rev", "pushed")], server: [{ method: "POST", path: `${REVISIONS}/${sid("rev", "pushed")}/activate`, status: 200, answer: { ...ACTIVE, id: sid("rev", "pushed") } }] }),
  v({ id: "activate.odd-id", title: "an id of another shape is not repeated (Go)", args: ["contract", "activate", "rev-not-the-shape"], server: [{ method: "POST", path: `${REVISIONS}/rev-not-the-shape/activate`, status: 200, answer: {} }], differences: ["unrecognized-id"] }),
  v({ id: "activate.missing", title: "activate without an id", args: ["contract", "activate"] }),
  v({ id: "activate.unknown", title: "an unknown revision: the server's 404", args: ["contract", "activate", "rev_nosuch"], server: [denied(`${REVISIONS}/rev_nosuch/activate`, "POST", 404, "NOT_FOUND")] }),
  v({ id: "show", title: "show prints the active revision as the server sent it", args: ["contract", "show"], server: [contractAnswer()] }),
  v({ id: "show.server", title: "--server names the server", args: ["contract", "show", "--server", "{{server}}"], server: [contractAnswer()] }),
  v({ id: "show.sensitive-default", title: "a sensitive item's default is shown as [redacted] (Go)", args: ["contract", "show"], server: [contractAnswer({ ...ACTIVE, contract: { ...ACTIVE.contract, items: [item("API_KEY", { defaultValue: "s3cr3t-default" }), item("PORT", { sensitive: false, defaultValue: "8080" })] } })], differences: ["contract-show-sensitive-default"] }),
  v({ id: "show.none", title: "no active Contract: the server's 404", args: ["contract", "show"], server: [NO_ACTIVE] }),
  v({ id: "show.not-signed-in", title: "show without a credential", args: ["contract", "show"], files: NOT_SIGNED_IN }),
  v({ id: "contract.none", title: "contract without a subcommand", args: ["contract"] }),
  v({ id: "contract.unknown", title: "an unknown subcommand", args: ["contract", "list"] }),
];

// varlatch types (5.3c): typesCommand.test.ts's and typesCli.test.ts's
// cases, and every message. A module the CLI writes names its release: the
// "release" pattern records it as `varlatch {{release}}`, and a case's
// input "generated by this CLI" is written with that placeholder.
const RELEASE = ["release"];
const REV_ID = sid("rev", "types");
const REVISIONS_PATH = `${CONTRACT_PATH}/revisions`;
const typesRevision = (items = ITEMS, opts: Parameters<typeof revision>[1] = {}) => revision(items, { id: REV_ID, ...opts });
const SERVED = typesRevision();
const RETYPED = typesRevision(ITEMS.map((i) => (i.name === "PORT" ? { ...i, type: "string" } : i)));
/** The module this CLI writes for a revision: generated with a stand-in release, then given the placeholder. */
const SENTINEL = "0.0.0-release";
const moduleText = (rev: ReturnType<typeof revision>, language: "ts" | "py" = "ts", release = SENTINEL): string => {
  const text = (language === "py" ? generatePythonModule : generateTypesModule)(rev, { generatorVersion: release });
  return release === SENTINEL ? text.split(`varlatch ${SENTINEL}`).join("varlatch {{release}}") : text;
};
const t = (c: Omit<TranscriptCase, "differences" | "files" | "cwd"> & { files?: Record<string, string>; cwd?: string; differences?: string[] }): TranscriptCase =>
  v({ patterns: RELEASE, ...c });
const withOutput = (path: string, content: string) => ({ ...SIGNED_IN, [`repo/${path}`]: content });
const UNRECOGNIZED = ["unrecognized-id"];
const PRINTABLE = ["types-printable"];
const c = String.fromCharCode;
/** Lone surrogates in a Contract's text: a written module holds U+FFFD there. */
const LONE = typesRevision([contractItem("LONE", { description: `high ${c(0xd800)} low ${c(0xdfff)} end`, example: c(0xdbff), defaultValue: `x${c(0xdc00)}` })]);
/** A file as `types` writes it: UTF-8, a lone surrogate as U+FFFD. */
const asWritten = (text: string) => Buffer.from(text, "utf8").toString("utf8");

const types53c: TranscriptCase[] = [
  // Writing: each extension, the directories made, an absolute path, any Environment.
  t({ id: "write.ts", title: "--out <file.ts>: one request, the module written", args: ["types", "--out", "src/config.ts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.mts", title: "--out <file.mts>: TypeScript", args: ["types", "--out", "config.mts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.cts", title: "--out <file.cts>: TypeScript", args: ["types", "--out", "config.cts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.py", title: "--out <file.py>: the Python module", args: ["types", "--out", "app/varlatch_config.py"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.nested", title: "the directories to the file are made", args: ["types", "--out", "a/b/c/config.ts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.absolute", title: "an absolute --out", args: ["types", "--out", "{{dir}}/out/config.ts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.dot-dot-ts", title: "a file named ..ts is a TypeScript file", args: ["types", "--out", "..ts"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.any-environment", title: "-e and --environment are ignored: the module is the same for every Environment", args: ["types", "--out", "config.ts", "-e", "production", "--environment", "staging"], server: [contractAnswer(SERVED)] }),
  t({ id: "write.version-3", title: "an integer item at semantics version 3", args: ["types", "--out", "config.ts"], server: [contractAnswer(typesRevision([contractItem("WORKERS", { type: "integer", required: { kind: "always" } })], { semanticsVersion: 3 }))] }),
  t({ id: "write.empty", title: "an empty Contract", args: ["types", "--out", "config.py"], server: [contractAnswer(typesRevision([]))] }),
  t({ id: "write.stale-replaced", title: "a stale file is replaced", args: ["types", "--out", "config.ts"], files: withOutput("config.ts", moduleText(RETYPED)), server: [contractAnswer(SERVED)] }),
  t({ id: "write.over-other", title: "a file that is no module is replaced", args: ["types", "--out", "config.ts"], files: withOutput("config.ts", "export const x = 1;\n"), server: [contractAnswer(SERVED)] }),
  t({ id: "write.server-flag", title: "--server names the server", args: ["types", "--out", "config.ts", "--server", "{{server}}"], files: { ...repoFiles('organization = "acme"\nproject = "web"\n'), ...storeAt({ "{{server}}": { token: VTOKEN, ...OK } }) }, server: [contractAnswer(SERVED)] }),
  t({ id: "write.lone-surrogate", title: "lone surrogates in the Contract's text are written as U+FFFD", args: ["types", "--out", "config.ts"], server: [contractAnswer(LONE)] }),
  t({ id: "write.lone-surrogate.py", title: "lone surrogates (Python): U+FFFD, so the module stays UTF-8", args: ["types", "--out", "config.py"], server: [contractAnswer(LONE)] }),
  t({ id: "current.lone-surrogate", title: "a module written with U+FFFD for lone surrogates is current", args: ["types", "--out", "config.py", "--check"], files: withOutput("config.py", asWritten(moduleText(LONE, "py"))), server: [contractAnswer(LONE)] }),
  // Current files: left alone, this release's or another's.
  t({ id: "current.unchanged", title: "an unchanged revision: left unchanged", args: ["types", "--out", "config.ts"], files: withOutput("config.ts", moduleText(SERVED)), server: [contractAnswer(SERVED)] }),
  t({ id: "current.unchanged.py", title: "an unchanged revision (Python): left unchanged", args: ["types", "--out", "config.py"], files: withOutput("config.py", moduleText(SERVED, "py")), server: [contractAnswer(SERVED)] }),
  t({ id: "current.other-release", title: "another release's file, only its Generator lines differ: current, left alone", args: ["types", "--out", "config.ts"], files: withOutput("config.ts", moduleText(SERVED, "ts", "0.13.0")), server: [contractAnswer(SERVED)] }),
  t({ id: "current.other-release.py", title: "another release's Python file: current, left alone", args: ["types", "--out", "config.py"], files: withOutput("config.py", moduleText(SERVED, "py", "0.13.0")), server: [contractAnswer(SERVED)] }),
  t({ id: "current.other-release.changed", title: "another release's file with one other line changed: stale, rewritten", args: ["types", "--out", "config.ts"], files: withOutput("config.ts", moduleText(SERVED, "ts", "0.13.0").replace("/* eslint-disable */", "/* eslint-disable */ ")), server: [contractAnswer(SERVED)] }),
  t({ id: "current.generator-unprintable", title: "a Generator line naming no printable release: stale", args: ["types", "--out", "config.ts", "--check"], files: withOutput("config.ts", moduleText(SERVED, "ts", "0.13.0").replace("varlatch 0.13.0\n", "varlatch 0.13.0;rm\n")), server: [contractAnswer(SERVED)] }),
  t({ id: "current.generator-missing", title: "no Generator line: stale", args: ["types", "--out", "config.ts", "--check"], files: withOutput("config.ts", moduleText(SERVED, "ts", "0.13.0").replace(/^\/\/ Generator:.*$/m, "// Generator:")), server: [contractAnswer(SERVED)] }),
  // --check
  t({ id: "check.current", title: "--check: current", args: ["types", "--out", "config.ts", "--check"], files: withOutput("config.ts", moduleText(SERVED)), server: [contractAnswer(SERVED)] }),
  t({ id: "check.current.py", title: "--check (Python): current", args: ["types", "--out", "config.py", "--check"], files: withOutput("config.py", moduleText(SERVED, "py")), server: [contractAnswer(SERVED)] }),
  t({ id: "check.other-release", title: "--check: another release's file is current", args: ["types", "--out", "config.ts", "--check"], files: withOutput("config.ts", moduleText(SERVED, "ts", "0.13.0")), server: [contractAnswer(SERVED)] }),
  t({ id: "check.stale", title: "--check: one type changed, stale; nothing written", args: ["types", "--out", "config.ts", "--check"], files: withOutput("config.ts", moduleText(RETYPED)), server: [contractAnswer(SERVED)] }),
  t({ id: "check.missing", title: "--check: no file", args: ["types", "--out", "config.ts", "--check"], server: [contractAnswer(SERVED)] }),
  t({ id: "check.stale.revision", title: "--check with --revision: the hint repeats it", args: ["types", "--out", "config.ts", "--check", "--revision", REV_ID], files: withOutput("config.ts", moduleText(RETYPED)), server: [ok(`${REVISIONS_PATH}/${REV_ID}`, SERVED)] }),
  t({ id: "check.stale.revision-odd", title: "--check with a --revision of no server shape: the hint does not repeat it (Go)", args: ["types", "--out", "config.ts", "--check", "--revision", "crv_older"], files: withOutput("config.ts", moduleText(RETYPED)), server: [ok(`${REVISIONS_PATH}/crv_older`, SERVED)], differences: UNRECOGNIZED }),
  // --revision
  t({ id: "revision.by-id", title: "--revision fetches that revision, and nothing else", args: ["types", "--out", "config.ts", "--revision", REV_ID], server: [ok(`${REVISIONS_PATH}/${REV_ID}`, SERVED)] }),
  t({ id: "revision.not-found", title: "--revision of no revision: the server's 404 said plainly", args: ["types", "--out", "config.ts", "--revision", REV_ID], server: [denied(`${REVISIONS_PATH}/${REV_ID}`, "GET", 404, "NOT_FOUND")] }),
  t({ id: "revision.not-found.odd", title: "--revision of no server shape, not found: not repeated (Go)", args: ["types", "--out", "config.ts", "--revision", "crv_gone"], server: [denied(`${REVISIONS_PATH}/crv_gone`, "GET", 404, "NOT_FOUND")], differences: UNRECOGNIZED }),
  t({ id: "revision.empty", title: "an empty --revision is none: the active revision", args: ["types", "--out", "config.ts", "--revision", ""], server: [contractAnswer(SERVED)] }),
  // The server's answers
  t({ id: "server.denied", title: "403: needs contract.read", args: ["types", "--out", "config.ts"], server: [denied(CONTRACT_PATH)] }),
  t({ id: "server.no-active", title: "404: no active Contract", args: ["types", "--out", "config.ts"], server: [denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND")] }),
  t({ id: "server.error", title: "a server error: the client's message", args: ["types", "--out", "config.ts"], server: [denied(CONTRACT_PATH, "GET", 500, "INTERNAL")] }),
  t({ id: "server.version-1", title: "a version 1 revision: the fix named, nothing written", args: ["types", "--out", "config.ts"], server: [contractAnswer(typesRevision(ITEMS, { semanticsVersion: 1 }))] }),
  t({ id: "server.version-1.py", title: "a version 1 revision (Python)", args: ["types", "--out", "config.py"], server: [contractAnswer(typesRevision(ITEMS, { semanticsVersion: 1 }))] }),
  t({ id: "server.version-9", title: "a semantics version this CLI does not implement", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, semanticsVersion: 9 })] }),
  t({ id: "server.tampered", title: "a Contract that does not match its hash", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, contract: { ...SERVED.contract, items: [contractItem("OTHER")] } })] }),
  t({ id: "server.invalid-contract", title: "a Contract that is not valid", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, contract: { schemaVersion: 1, semanticsVersion: 2, items: [{ name: "lower" }] } })] }),
  t({ id: "server.id-unprintable", title: "an id the CLI does not accept", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, id: "crv_1\n*/ evil" })] }),
  t({ id: "server.hash-unprintable", title: "a content hash the CLI does not accept", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, contentHash: "sha256:*/" })] }),
  t({ id: "server.version-escape", title: "a semantics version holding a terminal escape: not shown (Go)", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, semanticsVersion: `${c(0x1b)}]0;pwned${c(7)}` })], differences: PRINTABLE }),
  t({ id: "server.version-fraction", title: "a semantics version that is not a whole number: not shown (Go)", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, semanticsVersion: 2.5 })], differences: PRINTABLE }),
  t({ id: "server.contract-key-escape", title: "a Contract key holding a terminal escape: escaped (Go)", args: ["types", "--out", "config.ts"], server: [contractAnswer({ ...SERVED, contract: { ...SERVED.contract, [`${c(0x1b)}[31mred`]: 1 } })], differences: PRINTABLE }),
  t({ id: "server.id-odd", title: "an id of no server shape: written, the id not repeated (Go)", args: ["types", "--out", "config.ts"], server: [contractAnswer(revision(ITEMS, { id: "crv_types1" }))], differences: UNRECOGNIZED }),
  // What --out may name
  t({ id: "out.js", title: "--out naming a .js file: refused before any request", args: ["types", "--out", "config.js"] }),
  t({ id: "out.proto", title: "--out naming .__proto__", args: ["types", "--out", "config.__proto__"] }),
  t({ id: "out.dotfile", title: "--out naming .ts (no extension)", args: ["types", "--out", ".ts"] }),
  t({ id: "out.no-extension", title: "--out naming a file without an extension", args: ["types", "--out", "config"] }),
  t({ id: "out.directory", title: "--out naming a directory: not a regular file", args: ["types", "--out", "config.ts"], files: { ...SIGNED_IN, "repo/config.ts/keep": "" }, server: [contractAnswer(SERVED)] }),
  // The command line
  t({ id: "usage.none", title: "types without --out", args: ["types"] }),
  t({ id: "usage.out-last", title: "--out as the last argument", args: ["types", "--out"] }),
  t({ id: "usage.out-flag", title: "--out followed by an option", args: ["types", "--out", "--check"] }),
  t({ id: "not-signed-in", title: "no credential", args: ["types", "--out", "config.ts"], files: NOT_SIGNED_IN }),
  t({ id: "no-repository", title: "outside a repository", args: ["types", "--out", "config.ts"], files: {} }),
];

// varlatch run (5.4b): a default run, --export-context, --omit, and assisted
// masking. The command is `node -e PRINT`, which prints its arguments and the
// variables it was given (fake values only), so each case shows what the
// command received; an assisted run's output is the masked one.
const RUN_SECRET = "s3cr3t-run-api-key-value";
const RUN_PIN = "1234";
const RUN_PRINT =
  "const o={args:process.argv.slice(1)};for(const k of ['API_KEY','PORT','PIN','REGION','LEGACY_KEY','VARLATCH_RUN_CONTEXT'])if(process.env[k]!==undefined)o[k]=process.env[k];console.log(JSON.stringify(o))";
const runChildArgs = (...args: string[]) => ["--", "node", "-e", RUN_PRINT, ...args];
const DISCLOSURES = `${ENV}/disclosures`;
const PROD_ENV = "/v1/organizations/acme/projects/web/environments/prod";
const RUN_REV = sid("rev", "run");
const RUN_HASH = `sha256:${"ab".repeat(32)}`;
const runItems = (extra: unknown[] = []) => [
  { name: "API_KEY", sensitive: true, source: "self", value: null },
  { name: "PORT", sensitive: false, source: "self", value: "8080" },
  ...extra,
];
const PIN_ITEM = { name: "PIN", sensitive: true, source: "self", value: null };
const effectiveAt = (base: string, items: unknown[], extra: Record<string, unknown> = {}): Exchange =>
  ok(`${base}/effective-configuration?include=values`, { environmentId: "env_1", items, ...extra });
const disclosed = (items: { name: string; value: string }[], extra: Record<string, unknown> = {}, path = DISCLOSURES): Exchange => ({
  method: "POST",
  path,
  status: 200,
  answer: { items: items.map((i) => ({ ...i, versionId: sid("ver", i.name) })), withheld: [], ...extra },
});
const API_KEY_DISCLOSED = disclosed([{ name: "API_KEY", value: RUN_SECRET }]);
const MANIFEST = {
  manifestVersion: 1,
  projectId: "prj_1",
  environment: { id: "env_1", rootId: "env_root", parentId: null, tier: "development", expiresAt: null },
  contract: { revisionId: RUN_REV, contentHash: RUN_HASH, semanticsVersion: 2 },
  items: [],
};
const DIGEST_A = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const RUN_CONTRACT = {
  schemaVersion: 1,
  semanticsVersion: 2,
  items: [item("API_KEY"), item("PORT", { sensitive: false }), item("REGION", { sensitive: false }), item("VARLATCH_RUN_CONTEXT", { sensitive: false })],
};
const revisionAnswer = (extra: Record<string, unknown> = {}): Exchange =>
  ok(`${CONTRACT_PATH}/revisions/${RUN_REV}`, { id: RUN_REV, contentHash: RUN_HASH, semanticsVersion: 2, active: true, contract: RUN_CONTRACT, ...extra });
const exportedEffective = (digest = DIGEST_A) => effectiveAt(ENV, runItems(), { stateDigest: digest, manifest: MANIFEST });
const ASSISTED = { VARLATCH_ASSISTED: "1" };
const CONTRACT_NONE = denied(CONTRACT_PATH, "GET", 404, "NOT_FOUND");
// A stored value with an unpaired surrogate (JSON allows it, UTF-8 cannot):
// the command gets it as Node.js's spawn encodes it, one U+FFFD, and
// assisted masking matches that form.
const SURROGATE_VALUE = "surrogate-\uD83D-value";
const SURROGATE_ITEMS = [{ name: "SURR", sensitive: true, source: "self", value: null }];
const SURROGATE_DISCLOSED = disclosed([{ name: "SURR", value: SURROGATE_VALUE }]);
const PRINT_SURROGATE = ["--", "node", "-e", "console.log('s='+process.env.SURR+' bytes='+Buffer.from(process.env.SURR).toString('hex'))"];

const run54b: TranscriptCase[] = [
  // The command line
  v({ id: "usage.no-separator", title: "run without --", args: ["run", "node"] }),
  v({ id: "usage.separator-last", title: "run with nothing after --", args: ["run", "--"] }),
  v({ id: "usage.unknown-option", title: "an unknown option before --: refused, nothing fetched", args: ["run", "--bogus", ...runChildArgs()] }),
  v({ id: "usage.allow-unmasked-equals", title: "--allow-unmasked=NAME is not parsed", args: ["run", "--allow-unmasked=PIN", ...runChildArgs()] }),
  v({ id: "usage.no-redact-equals", title: "--no-redact=... is not parsed", args: ["run", "--no-redact=1", ...runChildArgs()] }),
  v({ id: "usage.allow-unmasked-no-name", title: "--allow-unmasked followed by an option", args: ["run", "--allow-unmasked", "--omit", "PIN", ...runChildArgs()] }),
  v({ id: "usage.allow-unmasked-bad-name", title: "--allow-unmasked with a name no item can have", args: ["run", "--allow-unmasked", "pin", ...runChildArgs()] }),
  v({ id: "usage.omit-bad-name", title: "--omit with a name no item can have", args: ["run", "--omit", "pin", ...runChildArgs()] }),
  v({ id: "usage.omit-and-allow", title: "--omit and --allow-unmasked naming the same item", args: ["run", "--omit", "PIN", "--allow-unmasked", "PIN", ...runChildArgs()] }),
  v({ id: "usage.omit-and-inherit", title: "--omit and --allow-inherited naming the same item", args: ["run", "--omit", "PIN", "--allow-inherited", "PIN", ...runChildArgs()] }),
  v({ id: "usage.redact-and-no-redact", title: "--redact with --no-redact", args: ["run", "--redact", "--no-redact", ...runChildArgs()] }),
  v({ id: "usage.target", title: "--target outside an agent-safe run", args: ["run", "--target", "API_KEY=header:authorization", ...runChildArgs()] }),
  v({ id: "usage.allow-inherited", title: "--allow-inherited outside a strict run", args: ["run", "--allow-inherited", "PIN", ...runChildArgs()] }),
  v({ id: "usage.export-and-strict", title: "--export-context with --strict", args: ["run", "--export-context", "--strict", ...runChildArgs()] }),
  v({ id: "usage.twice", title: "--export-context given twice", args: ["run", "--export-context", "--export-context", ...runChildArgs()] }),
  v({ id: "usage.allow-and-no-redact", title: "outside assisted mode, --allow-unmasked does not combine with --no-redact", args: ["run", "--allow-unmasked", "PIN", "--no-redact", ...runChildArgs()] }),
  // A default run
  v({ id: "run.plain", title: "a default run: the stored values over the inherited ones, the arguments as given", args: ["run", ...runChildArgs("a", "b c", "--", "-e")], env: { PORT: "1", REGION: "inherited" }, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "run.environment", title: "-e names the environment", args: ["run", "-e", "prod", ...runChildArgs()], server: [effectiveAt(PROD_ENV, runItems()), disclosed([{ name: "API_KEY", value: RUN_SECRET }], {}, `${PROD_ENV}/disclosures`)] }),
  v({ id: "run.environment-long", title: "--environment names the environment", args: ["run", "--environment", "prod", ...runChildArgs()], server: [effectiveAt(PROD_ENV, runItems()), disclosed([{ name: "API_KEY", value: RUN_SECRET }], {}, `${PROD_ENV}/disclosures`)] }),
  v({ id: "run.server", title: "--server names the server", args: ["run", "--server", "{{server}}", ...runChildArgs()], files: { ...repoFiles('organization = "acme"\nproject = "web"\ndefault_environment = "dev"\n'), ...storeAt({ "{{server}}": { token: VTOKEN, ...OK } }) }, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "run.exit-status", title: "the command's own status", args: ["run", "--", "node", "-e", "process.exit(3)"], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "run.no-redact", title: "--no-redact outside assisted mode: a default run", args: ["run", "--no-redact", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "run.agent-options-ignored", title: "agent-safe options without --agent-safe change nothing", args: ["run", "--agent", "coder", "--allow-host", "api.example.com", "--broker-credential-file", "broker.json", "--agent-network", "strict", "--ttl", "60", "--agent-metadata", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "run.inherited-context", title: "an inherited VARLATCH_RUN_CONTEXT is removed, and none is injected", args: ["run", ...runChildArgs()], env: { VARLATCH_RUN_CONTEXT: '{"v":1,"mode":"exported"}' }, server: [effectiveAt(ENV, runItems([{ name: "VARLATCH_RUN_CONTEXT", sensitive: false, source: "self", value: "stored" }])), API_KEY_DISCLOSED] }),
  v({ id: "run.disclosure-denied", title: "the disclosure refused: the plain values only, said", args: ["run", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), { ...denied(DISCLOSURES, "POST") }] }),
  v({ id: "run.disclosure-tailnet", title: "the disclosure refused for the tailnet: the plain values only", args: ["run", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), denied(DISCLOSURES, "POST", 403, "TAILNET_CONTEXT_REQUIRED")] }),
  v({ id: "run.disclosure-error", title: "any other refusal stops the run", args: ["run", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), denied(DISCLOSURES, "POST", 500, "INTERNAL")] }),
  v({ id: "run.withheld", title: "a value the server withholds is named", args: ["run", ...runChildArgs()], server: [effectiveAt(ENV, runItems([{ name: "REGION", sensitive: false, source: "self", value: null }])), API_KEY_DISCLOSED] }),
  v({ id: "run.empty", title: "nothing stored: the command still starts", args: ["run", ...runChildArgs()], server: [effectiveAt(ENV, []), disclosed([])] }),
  v({ id: "run.not-signed-in", title: "no credential: 77, nothing started", args: ["run", ...runChildArgs()], files: NOT_SIGNED_IN }),
  v({ id: "run.surrogate", title: "a value with an unpaired surrogate reaches the command as one U+FFFD", args: ["run", ...PRINT_SURROGATE], server: [effectiveAt(ENV, SURROGATE_ITEMS), SURROGATE_DISCLOSED] }),
  v({ id: "run.no-command", title: "a command that does not exist: spawn ... ENOENT (TypeScript lets the error escape)", args: ["run", "--", "varlatch-no-such-command-5-4b"], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED], differences: ["spawn-error"] }),
  // --omit
  v({ id: "omit.secret", title: "--omit a Secret: never asked for, and the inherited copy removed", args: ["run", "--omit", "API_KEY", ...runChildArgs()], env: { API_KEY: "inherited" }, server: [effectiveAt(ENV, runItems())] }),
  v({ id: "omit.secret-one-of-two", title: "--omit one Secret: the disclosure names the others", args: ["run", "--omit", "PIN", ...runChildArgs()], server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }])] }),
  v({ id: "omit.plain", title: "--omit a plain item, twice", args: ["run", "--omit", "PORT", "--omit", "PORT", ...runChildArgs()], env: { PORT: "1" }, server: [effectiveAt(ENV, runItems()), disclosed([{ name: "API_KEY", value: RUN_SECRET }])] }),
  v({ id: "omit.contract-item", title: "--omit a Contract item that is not stored: the Contract is read", args: ["run", "--omit", "REGION", ...runChildArgs()], env: { REGION: "inherited" }, server: [effectiveAt(ENV, runItems()), contractAnswer({ ...ACTIVE, contract: RUN_CONTRACT }), disclosed([{ name: "API_KEY", value: RUN_SECRET }])] }),
  v({ id: "omit.unknown", title: "--omit a name neither stored nor in the Contract: 64, nothing disclosed", args: ["run", "--omit", "NOPE", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), CONTRACT_NONE] }),
  v({ id: "omit.unknown-no-contract", title: "--omit, and the manifest says no Contract is active: not read", args: ["run", "--omit", "NOPE", ...runChildArgs()], server: [effectiveAt(ENV, runItems(), { manifest: { ...MANIFEST, contract: null } })] }),
  // --export-context
  v({ id: "export.context", title: "--export-context: the command gets the run context", args: ["run", "--export-context", ...runChildArgs()], env: { REGION: "inherited" }, server: [exportedEffective(), revisionAnswer(), disclosed([{ name: "API_KEY", value: RUN_SECRET }], { stateDigest: DIGEST_A })] }),
  v({ id: "export.omit", title: "--export-context with --omit: an omitted item is absent", args: ["run", "--export-context", "--omit", "API_KEY", "--omit", "REGION", ...runChildArgs()], env: { REGION: "inherited" }, server: [exportedEffective(), contractAnswer({ ...ACTIVE, contract: RUN_CONTRACT }), revisionAnswer()] }),
  v({ id: "export.retry", title: "the state changed once: both read again, then the run starts", args: ["run", "--export-context", ...runChildArgs()], server: [exportedEffective(), revisionAnswer(), disclosed([{ name: "API_KEY", value: RUN_SECRET }], { stateDigest: DIGEST_B }), exportedEffective(DIGEST_B), revisionAnswer(), disclosed([{ name: "API_KEY", value: RUN_SECRET }], { stateDigest: DIGEST_B })] }),
  v({
    id: "export.inconsistent",
    title: "the state changed on every attempt: refused before the command starts",
    args: ["run", "--export-context", ...runChildArgs()],
    server: [1, 2, 3].flatMap(() => [exportedEffective(), revisionAnswer(), disclosed([{ name: "API_KEY", value: RUN_SECRET }], { stateDigest: DIGEST_B })]),
  }),
  v({ id: "export.no-digest", title: "a disclosure without a digest is not agreement", args: ["run", "--export-context", ...runChildArgs()], server: [1, 2, 3].flatMap(() => [exportedEffective(), revisionAnswer(), API_KEY_DISCLOSED]) }),
  v({ id: "export.disclosure-denied", title: "nothing disclosed: the context describes the values delivered", args: ["run", "--export-context", ...runChildArgs()], server: [exportedEffective(), revisionAnswer(), denied(DISCLOSURES, "POST")] }),
  v({ id: "export.no-manifest", title: "a server without a manifest: refused, nothing disclosed", args: ["run", "--export-context", ...runChildArgs()], server: [effectiveAt(ENV, runItems())] }),
  v({ id: "export.no-contract", title: "no active Contract: refused", args: ["run", "--export-context", ...runChildArgs()], server: [effectiveAt(ENV, runItems(), { stateDigest: DIGEST_A, manifest: { ...MANIFEST, contract: null } })] }),
  v({ id: "export.contract-denied", title: "no contract.read: refused, nothing disclosed", args: ["run", "--export-context", ...runChildArgs()], server: [exportedEffective(), denied(`${CONTRACT_PATH}/revisions/${RUN_REV}`)] }),
  v({ id: "export.oversize", title: "a run context over 64 KB: refused before any Secret is disclosed", args: ["run", "--export-context", ...runChildArgs()], server: [exportedEffective(), revisionAnswer({ contract: { ...RUN_CONTRACT, items: Array.from({ length: 260 }, (_, i) => item(`N${String(i).padStart(3, "0")}_${"A".repeat(250)}`)) } })] }),
  v({ id: "export.contract-mismatch", title: "a revision of another hash: refused", args: ["run", "--export-context", ...runChildArgs()], server: [exportedEffective(), revisionAnswer({ contentHash: HASH })] }),
  // Assisted mode
  v({ id: "assisted.masked", title: "assisted mode masks the delivered Secret in the command's output", args: ["run", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, contractAnswer({ ...ACTIVE, contract: RUN_CONTRACT })] }),
  v({ id: "assisted.sensitive-number", title: "an item marked sensitive by any truthy value is masked", args: ["run", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, [{ name: "API_KEY", sensitive: 1, source: "self", value: null }, { name: "PORT", sensitive: false, source: "self", value: "8080" }]), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "assisted.surrogate", title: "assisted mode masks a Secret with an unpaired surrogate as the command echoes it", args: ["run", "--", "node", "-e", "console.log('s='+process.env.SURR)"], env: ASSISTED, server: [effectiveAt(ENV, SURROGATE_ITEMS), SURROGATE_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "assisted.option", title: "--assisted masks too", args: ["--assisted", "run", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "assisted.inherited", title: "an inherited value under a Contract Secret's name is masked too", args: ["run", ...runChildArgs()], env: { ...ASSISTED, LEGACY_KEY: "inherited-legacy-value" }, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, contractAnswer({ ...ACTIVE, contract: { ...RUN_CONTRACT, items: [...RUN_CONTRACT.items, item("LEGACY_KEY")] } })] }),
  v({ id: "assisted.contract-denied", title: "no contract.read: masked under stored names only, said", args: ["run", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, denied(CONTRACT_PATH)] }),
  v({ id: "assisted.short", title: "a Secret too short to mask: 78, the remedies, nothing started", args: ["run", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }]), CONTRACT_NONE] }),
  v({ id: "assisted.short-two", title: "two Secrets too short: both named", args: ["run", "-e", "dev", "--omit", "PORT", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems([PIN_ITEM, { name: "PIN2", sensitive: true, source: "self", value: null }])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }, { name: "PIN2", value: "5678" }]), CONTRACT_NONE] }),
  v({ id: "assisted.short-server", title: "the remedies name an overridden server", args: ["run", "--server", "{{server}}", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }]), CONTRACT_NONE] }),
  v({ id: "assisted.allow-refused", title: "--allow-unmasked in assisted mode: refused, the human's command printed", args: ["run", "--allow-unmasked", "PIN", "--omit", "PORT", ...runChildArgs()], env: ASSISTED }),
  v({ id: "assisted.no-redact-refused", title: "--no-redact in assisted mode: refused", args: ["run", "--no-redact", "--export-context", ...runChildArgs()], env: ASSISTED }),
  v({ id: "assisted.no-values", title: "nothing stored: said as a fact", args: ["run", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, []), disclosed([]), CONTRACT_NONE] }),
  v({ id: "assisted.dotenv", title: "a .env file is named, never read", args: ["run", ...runChildArgs()], env: ASSISTED, files: { ...SIGNED_IN, "repo/.env": "API_KEY=never-read-value\n" }, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "assisted.omit", title: "--omit in assisted mode: the agent is told to name it", args: ["run", "--omit", "PORT", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems()), disclosed([{ name: "API_KEY", value: RUN_SECRET }]), CONTRACT_NONE] }),
  // The human's override outside assisted mode
  v({ id: "override.allow-unmasked", title: "--allow-unmasked PIN: PIN shown, every other Secret masked", args: ["run", "--allow-unmasked", "PIN", ...runChildArgs()], server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }]), CONTRACT_NONE] }),
  v({ id: "override.unused", title: "an allowance that names no short Secret: said, ignored", args: ["run", "--allow-unmasked", "PORT", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "override.short-other", title: "another short Secret still stops the run", args: ["run", "--allow-unmasked", "PIN", ...runChildArgs()], server: [effectiveAt(ENV, runItems([PIN_ITEM, { name: "PIN2", sensitive: true, source: "self", value: null }])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }, { name: "PIN2", value: "5678" }]), CONTRACT_NONE] }),
];

// varlatch run --redact (5.4c): output redaction outside assisted mode
// (ADR-0038 Decision 10), with every option it meets, and its refusals.
// The command is RUN_PRINT, or a writer of the delivered Secret.
const REDACT_SPLIT =
  "const v=process.env.API_KEY;process.stdout.write('k='+v.slice(0,6));setTimeout(()=>process.stdout.write(v.slice(6)+'\\n'),100)";
const REDACT_STDERR = "console.error('err='+process.env.API_KEY);console.log('out='+process.env.API_KEY)";
const redact54c: TranscriptCase[] = [
  v({ id: "surrogate.redact", title: "--redact masks a Secret with an unpaired surrogate as the command prints it (run.surrogate: one U+FFFD)", args: ["run", "--redact", "--", "node", "-e", "console.log('s='+process.env.SURR)"], server: [effectiveAt(ENV, SURROGATE_ITEMS), SURROGATE_DISCLOSED] }),
  v({ id: "redact.masked", title: "--redact masks the delivered Secret in the command's output; plain values are shown", args: ["run", "--redact", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "redact.stderr", title: "--redact masks stderr too", args: ["run", "--redact", "--", "node", "-e", REDACT_STDERR], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "redact.split", title: "a Secret split across two writes is masked once", args: ["run", "--redact", "--", "node", "-e", REDACT_SPLIT], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "redact.short", title: "a Secret too short to mask passes unchanged, and is named", args: ["run", "--redact", ...runChildArgs()], server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }])] }),
  v({ id: "redact.nothing-sensitive", title: "nothing sensitive delivered: the output as written", args: ["run", "--redact", ...runChildArgs()], server: [effectiveAt(ENV, [{ name: "PORT", sensitive: false, source: "self", value: "8080" }]), disclosed([])] }),
  v({ id: "redact.inherited", title: "an inherited value is not masked: only what Varlatch delivered", args: ["run", "--redact", ...runChildArgs()], env: { LEGACY_KEY: "inherited-legacy-value" }, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "redact.disclosure-denied", title: "the disclosure refused: nothing to mask, said", args: ["run", "--redact", ...runChildArgs()], server: [effectiveAt(ENV, runItems()), denied(DISCLOSURES, "POST")] }),
  v({ id: "redact.exit-status", title: "the command's own status passes through", args: ["run", "--redact", "--", "node", "-e", "process.exit(3)"], server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "redact.omit", title: "--redact with --omit: the omitted Secret is never asked for", args: ["run", "--redact", "--omit", "API_KEY", ...runChildArgs()], server: [effectiveAt(ENV, runItems())] }),
  v({ id: "redact.export-context", title: "--redact with --export-context: the context given, the Secret masked", args: ["run", "--redact", "--export-context", ...runChildArgs()], server: [exportedEffective(), revisionAnswer(), disclosed([{ name: "API_KEY", value: RUN_SECRET }], { stateDigest: DIGEST_A })] }),
  v({ id: "redact.allow-unmasked", title: "--redact with the human's --allow-unmasked: the override's masking", args: ["run", "--redact", "--allow-unmasked", "PIN", ...runChildArgs()], server: [effectiveAt(ENV, runItems([PIN_ITEM])), disclosed([{ name: "API_KEY", value: RUN_SECRET }, { name: "PIN", value: RUN_PIN }]), CONTRACT_NONE] }),
  v({ id: "redact.assisted", title: "--redact in assisted mode: assisted masking", args: ["run", "--redact", ...runChildArgs()], env: ASSISTED, server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "redact.agent-safe", title: "--redact with --agent-safe: refused, nothing fetched", args: ["run", "--redact", "--agent-safe", "--agent", "coder", ...runChildArgs()] }),
  v({ id: "redact.agent-safe-assisted", title: "--redact with --agent-safe in assisted mode: refused too", args: ["run", "--redact", "--agent-safe", ...runChildArgs()], env: ASSISTED }),
  v({ id: "redact.twice", title: "--redact given twice", args: ["run", "--redact", "--redact", ...runChildArgs()] }),
  v({ id: "redact.equals", title: "--redact=... is not parsed (the value shown as [redacted] by Go)", args: ["run", "--redact=1", ...runChildArgs()], differences: ["option-value"] }),
  // On a terminal: refused before anything is fetched, unless assisted mode gives the command pipes
  v({ id: "terminal.both", title: "--redact when stdout and stderr are a terminal: refused, nothing fetched", args: ["run", "--redact", ...runChildArgs()], terminal: "both" }),
  v({ id: "terminal.stdout", title: "--redact when stdout is a terminal: refused", args: ["run", "--redact", ...runChildArgs()], terminal: "stdout" }),
  v({ id: "terminal.stderr", title: "--redact when stderr is a terminal: refused", args: ["run", "--redact", ...runChildArgs()], terminal: "stderr" }),
  v({ id: "terminal.agent-safe", title: "--redact with --agent-safe on a terminal: the agent-safe refusal", args: ["run", "--redact", "--agent-safe", ...runChildArgs()], terminal: "both" }),
  v({ id: "terminal.assisted", title: "--redact in assisted mode on a terminal: runs, masked", args: ["run", "--redact", ...runChildArgs()], env: ASSISTED, terminal: "both", server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED, CONTRACT_NONE] }),
  v({ id: "terminal.no-redact", title: "--no-redact on a terminal: a default run", args: ["run", "--no-redact", ...runChildArgs()], terminal: "both", server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
  v({ id: "terminal.plain", title: "a default run on a terminal: unmasked", args: ["run", ...runChildArgs()], terminal: "stderr", server: [effectiveAt(ENV, runItems()), API_KEY_DISCLOSED] }),
];

// ---- 5.4e: scan --find-files --------------------------------------------------
//
// Files that look like copies of secrets, by name, each with whether Git
// ignores it: 1 when one is found, 2 when none is but the search was
// incomplete, 0 otherwise; every failure is 1, as for all of scan. The
// repositories are written file by file (a transcript makes no links and
// runs no git init); trees with links, modes and unusual repositories are in
// the find-files vectors (go/cmd/varlatch/testdata/vectors/findfiles.json).

const FF = (...rest: string[]) => ["scan", "--find-files", ...rest];
const gitRepo = (at: string, ignore?: string): Record<string, string> => ({
  [`${at}/.git/HEAD`]: "ref: refs/heads/main\n",
  [`${at}/.git/config`]: "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
  [`${at}/.git/objects/.keep`]: "",
  [`${at}/.git/refs/.keep`]: "",
  ...(ignore === undefined ? {} : { [`${at}/.gitignore`]: ignore }),
});
const COPIES = { ...gitRepo("repo", ".env\n"), "repo/.env": "A=1\n", "repo/.env.local": "B=2\n", "repo/keys/id.key": "k\n", "repo/.env.example": "A=\n", "loose/server.pem": "p\n" };
const DEEP = { [`deep/${"d/".repeat(21)}notes.md`]: "x\n" };

const findFiles54e: TranscriptCase[] = [
  { id: "found", title: "copies found: each with its Git state, and what to do; 1", args: FF("."), files: COPIES },
  { id: "found.json", title: "the same with --json", args: FF(".", "--json"), files: COPIES },
  { id: "found.repo", title: "searching the repository alone", args: FF("repo"), files: COPIES },
  { id: "found.cwd", title: "no directory: the working directory", args: FF(), files: COPIES, cwd: "repo" },
  { id: "clean", title: "nothing that looks like a copy: 0", args: FF("."), files: { "src/app.ts": "x\n", ".env.example": "A=\n" } },
  { id: "clean.json", title: "the same with --json", args: ["scan", "--json", "--find-files", "."], files: { "src/app.ts": "x\n" } },
  { id: "incomplete", title: "nothing found, but a directory was below the depth bound: 2", args: FF("deep"), files: DEEP },
  { id: "incomplete.json", title: "the same with --json", args: FF("deep", "--json"), files: DEEP },
  { id: "found-and-incomplete", title: "a copy found and a directory not searched: 1", args: FF("."), files: { ...DEEP, ".env": "A=1\n" } },
  { id: "global-config", title: "GIT_CONFIG_GLOBAL names the global configuration, and its core.excludesFile", args: FF("repo"), files: { ...COPIES, "g/config": "[core]\n\texcludesFile = ~/my-ignore\n", "home/my-ignore": "*.key\n" }, env: { GIT_CONFIG_GLOBAL: "{{dir}}/g/config" } },
  { id: "global-config.include", title: "a global configuration that includes another: every state unknown", args: FF("repo"), files: { ...COPIES, "g/config": "[include]\n\tpath = other\n" }, env: { GIT_CONFIG_GLOBAL: "{{dir}}/g/config" } },
  { id: "xdg", title: "XDG_CONFIG_HOME: git/ignore there is the default excludes file", args: FF("repo"), files: { ...COPIES, "xdg/git/ignore": "*.key\n" }, env: { XDG_CONFIG_HOME: "{{dir}}/xdg" } },
  { id: "home-gitconfig", title: "~/.gitconfig's core.excludesFile", args: FF("repo"), files: { ...COPIES, "home/.gitconfig": "[core]\n\texcludesFile = ~/ign\n", "home/ign": ".env.local\n" } },
  { id: "unusual", title: "an include in the repository's configuration: unknown, with why", args: FF("repo"), files: { ...COPIES, "repo/.git/config": "[include]\n\tpath = x\n" } },
  { id: "missing", title: "a directory that does not exist: 1", args: FF("nope") },
  { id: "not-a-directory", title: "a file, not a directory: 1", args: FF("notes.md"), files: { "notes.md": "x\n" } },
  { id: "usage.two", title: "two directories: 1, with the usage", args: FF("a", "b") },
  { id: "usage.staged", title: "--find-files with --staged", args: FF("--staged") },
  { id: "usage.environment", title: "--find-files with -e", args: FF("-e", "dev") },
  { id: "usage.unknown", title: "an unknown option", args: FF("--bogus") },
  { id: "usage.needs-value", title: "-e without its value", args: ["scan", "-e", "--find-files"] },
  { id: "usage.size", title: "a size that is no size, before the find-files rule", args: FF("--max-file-size", "lots") },
  { id: "after-dashes", title: "after --, a directory named --find-files... is a path", args: ["scan", "--find-files", "--", "-odd"], files: { "-odd/.env": "A=1\n" } },
];

// ---- 5.6a: the guardrail hook ---------------------------------------------------
//
// `agents hook --format <agent>` as a coding agent runs it: one pre-tool-use
// event on stdin, the answer on stdout. The events name no directory, so the
// case's directory is the tool call's; every other event is in the hook
// vectors (go/cmd/varlatch/testdata/vectors/hook.json).

const hookEvent = (tool_name: string, tool_input: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ session_id: "s", hook_event_name: "PreToolUse", tool_name, tool_input, ...extra });
const HOOK = (format: string) => ["agents", "hook", "--format", format];
const ENV_FILE = { ".env": "API_KEY=fake\n" };

const hook56a: TranscriptCase[] = [
  { id: "hook.claude.denied", title: "Claude Code: reading .env is denied, on stdout with status 0", args: HOOK("claude"), stdin: hookEvent("Bash", { command: "cat .env" }), files: ENV_FILE },
  { id: "hook.codex.denied", title: "Codex: the same decision", args: HOOK("codex"), stdin: hookEvent("Bash", { command: "cat .env" }), files: ENV_FILE },
  { id: "hook.allowed", title: "an allowed call: no decision, nothing printed", args: HOOK("claude"), stdin: hookEvent("Bash", { command: "npm test" }) },
  { id: "hook.store", title: "the credential store is denied", args: HOOK("claude"), stdin: hookEvent("Read", { file_path: "{{dir}}/home/.config/varlatch/credentials.json" }) },
  { id: "hook.run-env", title: "printing the environment of a varlatch run is denied", args: HOOK("codex"), stdin: hookEvent("Bash", { command: "varlatch run -- env" }) },
  { id: "hook.search", title: "a recursive search that would print .env lines is denied", args: HOOK("claude"), stdin: hookEvent("Bash", { command: "grep -r KEY ." }), files: { ...ENV_FILE, "src/app.ts": "x\n" } },
  { id: "hook.other-event", title: "another event: no decision", args: HOOK("claude"), stdin: hookEvent("Bash", { command: "cat .env" }, { hook_event_name: "PostToolUse" }), files: ENV_FILE },
  { id: "hook.garbage", title: "input it cannot read: no decision, status 0", args: HOOK("claude"), stdin: "garbage" },
  { id: "hook.empty", title: "nothing on stdin: no decision", args: HOOK("codex") },
  { id: "hook.no-format", title: "--format is needed", args: ["agents", "hook"], stdin: hookEvent("Bash", { command: "cat .env" }) },
  { id: "hook.unknown-format", title: "--format names one of the two", args: HOOK("cursor"), stdin: hookEvent("Bash", { command: "cat .env" }) },
  { id: "hook.extra", title: "no argument after the options", args: [...HOOK("claude"), "extra"], stdin: hookEvent("Bash", { command: "cat .env" }) },
  { id: "hook.unknown-option", title: "an unknown option", args: [...HOOK("claude"), "--json"], stdin: hookEvent("Bash", { command: "cat .env" }) },
  { id: "hook.assisted", title: "the same under --assisted", args: ["--assisted", ...HOOK("claude")], stdin: hookEvent("Bash", { command: "cat .env" }), files: ENV_FILE },
];

// varlatch run --strict (5.4f): one strict retrieval, the environment the
// command would receive resolved and validated against its Contract
// Revision, and 78 with every violation (names, classes and reasons, never a
// value) before anything starts. The command prints what it received.
const STRICT_PRINT =
  "const o={};for(const k of ['API_KEY','PORT','LEVEL','REGION','NUM','EXTRA','VARLATCH_RUN_CONTEXT'])if(process.env[k]!==undefined)o[k]=process.env[k];console.log(JSON.stringify(o))";
const strictChild = ["--", "node", "-e", STRICT_PRINT];
const STRICT_SECRET = "s3cr3t-strict-api-key-value";
const RETRIEVALS = `${ENV}/retrievals`;
const STRICT_META = ok("/v1/meta", { serverVersion: "0.22.0", apiVersion: 1, capabilities: ["retrieval.strict"] });
const ALWAYS = { required: { kind: "always" } };
const STRICT_ITEMS = [
  item("API_KEY", ALWAYS),
  item("PORT", { ...ALWAYS, sensitive: false, type: "number" }),
  item("LEVEL", { sensitive: false, type: "enum", enumValues: ["debug", "info", "warn"], defaultValue: "info" }),
  item("REGION", { sensitive: false }),
  item("NUM", { sensitive: false, type: "number" }),
];
const strictContract = (items: unknown[] = STRICT_ITEMS, semanticsVersion = 2) => ({ schemaVersion: 1, semanticsVersion, items });
type Stored = { name: string; sensitive: boolean; value: string | null };
const STORED: Stored[] = [
  { name: "API_KEY", sensitive: true, value: STRICT_SECRET },
  { name: "PORT", sensitive: false, value: "8080" },
];
const strictRetrieval = (o: { stored?: Stored[]; contract?: unknown; revision?: unknown; semanticsVersion?: number; withheld?: unknown[]; unexpanded?: unknown[] } = {}): Exchange => {
  const stored = o.stored ?? STORED;
  const semanticsVersion = o.semanticsVersion ?? 2;
  return {
    method: "POST",
    path: RETRIEVALS,
    status: 200,
    answer: {
      environmentId: "env_1",
      manifest: {
        manifestVersion: 1,
        projectId: "prj_1",
        environment: { id: "env_1", rootId: "env_root", parentId: null, tier: "development", expiresAt: null },
        contract: o.revision === undefined ? { revisionId: RUN_REV, contentHash: RUN_HASH, semanticsVersion } : o.revision,
        items: stored.map((i) => ({ name: i.name, source: "self", valueRowId: sid("val", i.name), versionId: sid("ver", i.name) })),
      },
      stateDigest: DIGEST_A,
      contract: o.contract === undefined ? strictContract(STRICT_ITEMS, semanticsVersion) : o.contract,
      items: stored.map((i) => ({ ...i, source: "self", versionId: sid("ver", i.name) })),
      callerView: { withheld: o.withheld ?? [], unexpanded: o.unexpanded ?? [], contractWithheld: false },
      validation: { invalid: [], unresolved: [], notEvaluated: [], missing: [] },
    },
  };
};
const strictRun = (o: Parameters<typeof strictRetrieval>[0] = {}): Exchange[] => [STRICT_META, strictRetrieval(o)];
const withheldKey = (reason = "permission", requires = "secret.reveal") => ({ stored: [{ name: "API_KEY", sensitive: true, value: null }, STORED[1] as Stored], withheld: [{ name: "API_KEY", reason, requires }] });
const s = (c: Omit<TranscriptCase, "args"> & { args?: string[]; options?: string[] }): TranscriptCase =>
  v({ ...c, args: c.args ?? ["run", "--strict", ...(c.options ?? []), ...strictChild] });
const strict54f: TranscriptCase[] = [
  // Starting
  s({ id: "start.valid", title: "a valid configuration starts the command: delivered values, the Contract default, the run context", env: { VARLATCH_RUN_CONTEXT: "inherited-context" }, server: strictRun() }),
  s({ id: "start.outside-contract", title: "a stored item outside the Contract is delivered as usual, and counted", server: strictRun({ stored: [...STORED, { name: "EXTRA", sensitive: false, value: "extra" }] }) }),
  s({ id: "start.allow-inherited", title: "--allow-inherited accepts the parent's value, validated", options: ["--allow-inherited", "REGION"], env: { REGION: "eu-west" }, server: strictRun() }),
  s({ id: "start.withheld-allowed", title: "an allowed inherited value stands in for a withheld one", options: ["--allow-inherited", "API_KEY"], env: { API_KEY: "parent-api-key-value" }, server: strictRun(withheldKey()) }),
  s({ id: "start.omit-optional", title: "--omit of an item that is not required: absent, and the parent's copy removed", options: ["--omit", "REGION"], env: { REGION: "eu-west" }, server: strictRun() }),
  s({ id: "start.capability-string", title: "capabilities given as a string: includes() finds a substring", server: [ok("/v1/meta", { serverVersion: "0.22.0", capabilities: "x retrieval.strict y" }), strictRetrieval()] }),
  s({ id: "start.retry", title: "a server failure: the retrieval is made once more", server: [STRICT_META, { method: "POST", path: RETRIEVALS, status: 500, answer: apiError(500, "INTERNAL") }, strictRetrieval()] }),
  s({ id: "start.assisted", title: "assisted mode masks the delivered Secret in the command's output", env: ASSISTED, server: strictRun() }),
  // Each kind of violation: 78, nothing started
  s({ id: "violation.no-contract", title: "contract: no active Contract", server: strictRun({ revision: null }) }),
  s({ id: "violation.contract-unreadable", title: "contract: the Contract is not readable by this identity", server: strictRun({ contract: null }) }),
  s({ id: "violation.semantics", title: "semantics: a version this CLI does not know", server: strictRun({ semanticsVersion: 9 }) }),
  s({ id: "violation.reserved", title: "reserved: a stored item and a Contract item named VARLATCH_RUN_CONTEXT", server: strictRun({ stored: [...STORED, { name: "VARLATCH_RUN_CONTEXT", sensitive: false, value: "x" }], contract: strictContract([...STRICT_ITEMS, item("VARLATCH_RUN_CONTEXT", { sensitive: false })]) }) }),
  s({ id: "violation.unresolved-reference", title: "unresolved-reference: a reference left literal for this identity", server: strictRun({ unexpanded: [{ name: "API_KEY", references: ["OTHER_KEY", "THIRD"] }] }) }),
  s({ id: "violation.withheld", title: "withheld: a required Secret this identity cannot read; no default stands in", server: strictRun(withheldKey()) }),
  s({ id: "violation.withheld-requirement", title: "withheld: a Requirement such as a Tailnet Constraint is not met", server: strictRun(withheldKey("requirement", "secret.reveal")) }),
  s({ id: "violation.withheld-parent", title: "withheld: the parent sets it, which --allow-inherited would accept", env: { API_KEY: "parent-api-key-value" }, server: strictRun(withheldKey()) }),
  s({ id: "violation.inherited", title: "inherited: an item set only in the parent environment", env: { REGION: "eu-west" }, server: strictRun() }),
  s({ id: "violation.missing", title: "missing: a required item not stored", server: strictRun({ stored: [STORED[0] as Stored] }) }),
  s({ id: "violation.invalid-delivered", title: "invalid: the delivered value, named, never shown", server: strictRun({ stored: [STORED[0] as Stored, { name: "PORT", sensitive: false, value: "eighty-eighty" }] }) }),
  s({ id: "violation.invalid-inherited", title: "invalid: the allowed inherited value", options: ["--allow-inherited", "NUM"], env: { NUM: "not-a-number" }, server: strictRun() }),
  s({ id: "violation.invalid-default", title: "invalid: the Contract default", server: strictRun({ contract: strictContract([...STRICT_ITEMS.filter((i) => i.name !== "LEVEL"), item("LEVEL", { sensitive: false, type: "enum", enumValues: ["debug", "info"], defaultValue: "loud" })]) }) }),
  s({ id: "violation.omitted", title: "omitted: --omit of a required item", options: ["--omit", "API_KEY"], server: strictRun() }),
  s({ id: "violation.context", title: "context: a run context over 64 KB is never truncated", server: strictRun({ contract: strictContract([...STRICT_ITEMS, ...Array.from({ length: 260 }, (_, i) => item(`N${String(i).padStart(3, "0")}_${"A".repeat(250)}`))]) }) }),
  s({ id: "violation.many", title: "every violation at once, in Contract order", env: { REGION: "eu-west" }, server: strictRun({ stored: [{ name: "PORT", sensitive: false, value: "eighty" }], unexpanded: [] }) }),
  s({ id: "violation.assisted", title: "assisted mode: the same violations, before any masking", env: ASSISTED, server: strictRun({ stored: [STORED[0] as Stored] }) }),
  // Refusals before the command
  s({ id: "refused.old-server", title: "a server without strict retrieval: 78, never a default run", server: [ok("/v1/meta", { serverVersion: "0.10.0", apiVersion: 1, capabilities: [] })] }),
  s({ id: "refused.old-server-no-version", title: "no version given: an older release", server: [ok("/v1/meta", { capabilities: ["identity.whoami"] })] }),
  s({ id: "refused.allow-inherited-unknown", title: "--allow-inherited names that are not Contract items: 64", options: ["--allow-inherited", "NOPE", "--allow-inherited", "ALSO_NOT", "--allow-inherited", "NOPE"], server: strictRun() }),
  s({ id: "refused.omit-unknown", title: "--omit of a name neither stored nor in the Contract: 64", options: ["--omit", "NOPE"], server: strictRun() }),
  s({ id: "refused.retrieval-denied", title: "the retrieval refused: the error's status", server: [STRICT_META, denied(RETRIEVALS, "POST")] }),
  s({ id: "refused.short-assisted", title: "assisted mode: a Secret too short to mask still stops the run", env: ASSISTED, server: strictRun({ stored: [{ name: "API_KEY", sensitive: true, value: "1234" }, STORED[1] as Stored] }) }),
];

// ---- 5.6b: varlatch mcp ----------------------------------------------------------
//
// The server as an MCP host runs it: JSON-RPC lines on stdin, all sent at
// once and stdin then closed, so each case also shows that the server
// answers what it holds before it exits. One call that reaches the server
// per case, since concurrent calls reach the fake server in any order. The
// protocol itself (every message, every tool's checks) is in the MCP
// vectors (go/cmd/varlatch/testdata/vectors/mcp.json).

const MCP_TOKEN = "vlt_cli_mcpAAAA";
const MCP = (...rest: string[]) => ["mcp", "--server", "{{server}}", ...rest];
const MCP_ENV = { VARLATCH_TOKEN: MCP_TOKEN };
const MCP_DIFFERENCES = ["user-agent", "mcp-version"];
const rpc = (id: unknown, method: string, params?: unknown) => JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) });
const INITIALIZE = rpc(0, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "host", version: "1" } });
const INITIALIZED = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" });
const lines = (...l: string[]) => `${l.join("\n")}\n`;
const callTool = (id: number, name: string, args: Record<string, unknown> = {}) => rpc(id, "tools/call", { name, arguments: args });
const mcpSession = (...calls: string[]) => lines(INITIALIZE, INITIALIZED, ...calls);
const mcp = (c: TranscriptCase): TranscriptCase => ({ env: MCP_ENV, ...c, differences: [...(c.differences ?? []), ...MCP_DIFFERENCES] });
const ORG_PATH = "/v1/organizations/acme";
const MCP_META = { serverVersion: "0.22.0", apiMajor: 1, capabilities: [] as string[] };
const MCP_META_WHOAMI = { ...MCP_META, capabilities: ["identity.whoami"] };
const VALUE_PATH = `${ENV}/values`;
const CONTRACT_ITEMS = (items: unknown[]) => contractAnswer({ ...ACTIVE, contract: { ...ACTIVE.contract, items } });
const PLAIN = item("PORT", { sensitive: false });
const mcpPut = (name: string, body: Record<string, unknown> = { versionId: sid("ver", name) }): Exchange => ({ method: "PUT", path: `${VALUE_PATH}/${name}`, status: 200, answer: body });
const IN_MCP_REPO = repoFiles('server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n');

const mcp56b: TranscriptCase[] = [
  // Startup: the options, the variables, and each refusal.
  { id: "help", title: "--help prints the usage", args: ["mcp", "--help"] },
  { id: "help.short", title: "-h too", args: ["mcp", "-h"] },
  { id: "help.then-unknown", title: "every argument is read before --help is acted on", args: ["mcp", "--help", "--nope"] },
  { id: "unknown-option", title: "an unknown option: 64 and the usage", args: ["mcp", "--json"] },
  { id: "equals-form", title: "--server=<url> is not a form mcp reads", args: ["mcp", "--server={{server}}"] },
  { id: "needs-value", title: "--server needs a value", args: ["mcp", "--server"] },
  { id: "needs-value.org", title: "--org needs a value", args: ["mcp", "--org"] },
  { id: "allow-disclose", title: "--allow-disclose is refused, not ignored", args: MCP("--allow-disclose"), env: MCP_ENV },
  { id: "allow-disclose.env", title: "VARLATCH_MCP_ALLOW_DISCLOSE=1 is refused", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_DISCLOSE: "1" } },
  { id: "allow-disclose.env-any", title: "any value but empty or 0 is refused", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_DISCLOSE: "false" } },
  mcp({ id: "allow-disclose.env-zero", title: "VARLATCH_MCP_ALLOW_DISCLOSE=0 starts the server", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_DISCLOSE: "0" }, stdin: lines(rpc(1, "ping")) }),
  mcp({ id: "allow-disclose.env-empty", title: "an empty VARLATCH_MCP_ALLOW_DISCLOSE starts the server", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_DISCLOSE: "" }, stdin: lines(rpc(1, "ping")) }),
  { id: "no-server", title: "outside a repository with no server: 64", args: ["mcp"], env: MCP_ENV },
  { id: "no-server.empty-variable", title: "an empty VARLATCH_SERVER is no server", args: ["mcp"], env: { ...MCP_ENV, VARLATCH_SERVER: "" } },
  { id: "not-signed-in", title: "no credential for the server: 77", args: MCP() },
  { id: "not-signed-in.userinfo", title: "the server's user name and password are never shown", args: ["mcp", "--server", "http://user:pw-canary@127.0.0.1:9"], differences: ["server-display"] },
  { id: "agent-run.writes", title: "inside an agent-safe run --allow-writes is refused", args: MCP("--allow-writes"), env: { ...MCP_ENV, VARLATCH_AGENT_RUN: "run_1" } },
  { id: "agent-run.writes-env", title: "and so is VARLATCH_MCP_ALLOW_WRITES=1", args: MCP(), env: { ...MCP_ENV, VARLATCH_AGENT_RUN: "run_1", VARLATCH_MCP_ALLOW_WRITES: "1" } },
  { id: "agent-run.no-credential", title: "inside an agent-safe run without the run's credential: 77 with the --agent-metadata hint", args: MCP(), env: { VARLATCH_AGENT_RUN: "run_1" } },
  mcp({ id: "agent-run.read-only", title: "inside an agent-safe run with its credential: the read tools", args: MCP(), env: { ...MCP_ENV, VARLATCH_AGENT_RUN: "run_1" }, stdin: lines(rpc(1, "tools/list")) }),

  // The protocol: what the host sees without the server.
  mcp({ id: "session.basics", title: "initialize, initialized, tools/list and ping", args: MCP(), stdin: mcpSession(rpc(1, "tools/list"), rpc(2, "ping")) }),
  mcp({ id: "session.versions", title: "each supported version is echoed, any other gets the latest", args: MCP(), stdin: lines(
    rpc(1, "initialize", { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "h", version: "1" } }),
    rpc(2, "initialize", { protocolVersion: "1999-01-01", capabilities: {}, clientInfo: { name: "h", version: "1" } })) }),
  mcp({ id: "session.malformed", title: "lines that are not JSON-RPC are dropped without a word; a method it lacks is -32601", args: MCP(), stdin: lines("garbage", "{}", '{"jsonrpc":"2.0","id":1,"result":{}}', rpc(1.5, "ping"), rpc(1, "resources/list"), JSON.stringify({ jsonrpc: "2.0", method: "notifications/unknown" }), rpc(2, "ping")) }),
  mcp({ id: "session.invalid-params", title: "a request its method's schema refuses: -32603 with zod's issues", args: MCP(), stdin: lines(rpc(1, "initialize", {}), rpc(2, "tools/call", { arguments: [] })) }),
  mcp({ id: "session.task", title: "task creation is refused", args: MCP(), stdin: lines(rpc(1, "tools/call", { name: "varlatch_whoami", task: {} })) }),
  mcp({ id: "session.no-trailing-newline", title: "a last line without a line break is never read", args: MCP(), stdin: `${rpc(1, "ping")}\n${rpc(2, "ping")}` }),
  mcp({ id: "session.empty", title: "nothing on stdin: exits 0", args: MCP() }),
  mcp({ id: "tools.writes-flag", title: "--allow-writes adds the two write tools", args: MCP("--allow-writes"), stdin: lines(rpc(1, "tools/list")) }),
  mcp({ id: "tools.writes-env", title: "so does VARLATCH_MCP_ALLOW_WRITES=1", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_WRITES: "1" }, stdin: lines(rpc(1, "tools/list")) }),
  mcp({ id: "tools.writes-env-other", title: "VARLATCH_MCP_ALLOW_WRITES=true does not", args: MCP(), env: { ...MCP_ENV, VARLATCH_MCP_ALLOW_WRITES: "true" }, stdin: lines(rpc(1, "tools/list"), callTool(2, "varlatch_set_value", { item: "A", value: "1" })) }),
  mcp({ id: "tools.unknown", title: "an unknown tool, and a name every JavaScript object has", args: MCP(), stdin: lines(callTool(1, "varlatch_reveal_value"), callTool(2, "toString")) }),

  // whoami and the defaults.
  mcp({ id: "whoami.no-capability", title: "whoami on a server that cannot say who a credential belongs to", args: MCP("--org", "acme"), stdin: lines(callTool(1, "varlatch_whoami")), server: [ok("/v1/meta", MCP_META)] }),
  mcp({ id: "whoami.caller", title: "whoami with the caller", args: MCP("--organization", "acme", "--project", "web", "--environment", "dev"), stdin: lines(callTool(1, "varlatch_whoami")), server: [ok("/v1/meta", MCP_META_WHOAMI), ok("/v1/me", ME_FULL)] }),
  mcp({ id: "whoami.caller-refused", title: "whoami when /v1/me refuses the credential", args: MCP("-e", "prod"), stdin: lines(callTool(1, "varlatch_whoami")), server: [ok("/v1/meta", MCP_META_WHOAMI), { method: "GET", path: "/v1/me", status: 401, answer: apiError(401, "UNAUTHENTICATED", "credential expired") }] }),
  mcp({ id: "whoami.repo", title: "in a repository: the defaults from its context, and --env over them", args: ["mcp", "--env", "staging"], files: IN_MCP_REPO, cwd: "repo", stdin: lines(callTool(1, "varlatch_whoami")), server: [ok("/v1/meta", MCP_META)] }),
  mcp({ id: "whoami.empty-flag", title: "--org \"\" is a default, an empty one", args: MCP("--org", ""), stdin: lines(callTool(1, "varlatch_whoami"), callTool(2, "varlatch_list_projects")), server: [ok("/v1/meta", MCP_META)] }),
  mcp({ id: "whoami.meta-malformed", title: "a meta answer without a capability list: the TypeError's message", args: MCP(), stdin: lines(callTool(1, "varlatch_whoami")), server: [ok("/v1/meta", { serverVersion: "0.22.0", capabilities: 5 })] }),
  mcp({ id: "whoami.unreachable", title: "a server that cannot be reached", args: ["mcp", "--server", "http://127.0.0.1:9"], stdin: lines(callTool(1, "varlatch_whoami")) }),

  // The read tools.
  mcp({ id: "read.organizations", title: "list organizations", args: MCP(), stdin: lines(callTool(1, "varlatch_list_organizations")), server: [ok("/v1/organizations", { items: [{ id: "org_1", slug: "acme", name: "Acme" }], nextCursor: null })] }),
  mcp({ id: "read.projects", title: "list projects, the organization from the arguments", args: MCP(), stdin: lines(callTool(1, "varlatch_list_projects", { organization: "a c/me" })), server: [ok("/v1/organizations/a%20c%2Fme/projects", { items: [], nextCursor: null })] }),
  mcp({ id: "read.projects.none", title: "no organization anywhere: the tool says so, no request", args: MCP(), stdin: lines(callTool(1, "varlatch_list_projects")) }),
  mcp({ id: "read.environments", title: "list environments", args: MCP("--org", "acme", "--project", "web"), stdin: lines(callTool(1, "varlatch_list_environments")), server: [ok(ENVS_PATH, { items: ALL_ENVS.slice(0, 2), nextCursor: null })] }),
  mcp({ id: "read.effective", title: "effective configuration with includeValues", args: MCP("--org", "acme", "--project", "web", "-e", "dev"), stdin: lines(callTool(1, "varlatch_effective_configuration", { includeValues: true })), server: [effective([{ name: "PORT", sensitive: false, source: "self", value: "8080" }], "?include=values")] }),
  mcp({ id: "read.effective.metadata", title: "and without", args: MCP("--org", "acme", "--project", "web", "-e", "dev"), stdin: lines(callTool(1, "varlatch_effective_configuration")), server: [effective([{ name: "API_KEY", sensitive: true, source: "self" }])] }),
  mcp({ id: "read.validate", title: "validate an environment (POST with an empty body)", args: MCP("--org", "acme", "--project", "web", "-e", "dev"), stdin: lines(callTool(1, "varlatch_validate_environment")), server: [{ method: "POST", path: `${ENV}/validate`, status: 200, answer: { valid: true, issues: [], notEvaluated: [] } }] }),
  mcp({ id: "read.contract", title: "the active contract", args: MCP("--org", "acme", "--project", "web"), stdin: lines(callTool(1, "varlatch_get_active_contract")), server: [contractAnswer()] }),
  mcp({ id: "read.audit", title: "audit events with a limit and a cursor (form-encoded)", args: MCP("--org", "acme"), stdin: lines(callTool(1, "varlatch_list_audit_events", { limit: 5, cursor: "a b/c+é" })), server: [ok(`${ORG_PATH}/audit-events?limit=5&cursor=a+b%2Fc%2B%C3%A9`, { items: [], nextCursor: null })] }),
  mcp({ id: "read.audit.invalid", title: "a limit out of range: the input's error, no request", args: MCP("--org", "acme"), stdin: lines(callTool(1, "varlatch_list_audit_events", { limit: 500 })) }),
  mcp({ id: "read.refused", title: "an API error as the tool's error", args: MCP(), stdin: lines(callTool(1, "varlatch_list_organizations")), server: [denied("/v1/organizations")] }),
  mcp({ id: "read.empty-answer", title: "an answer with no body: the SDK refuses the result", args: MCP(), stdin: lines(callTool(1, "varlatch_list_organizations")), server: [{ method: "GET", path: "/v1/organizations", status: 200, headers: {} }] }),
  mcp({ id: "read.cancelled", title: "a call cancelled while its request is out gets no answer", args: MCP(), stdin: lines(callTool(1, "varlatch_list_organizations"), JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1, reason: "host" } }), rpc(2, "ping")), server: [ok("/v1/organizations", { items: [], nextCursor: null })] }),
  mcp({ id: "read.cancelled-before", title: "a cancellation before the call changes nothing", args: MCP(), stdin: lines(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 1 } }), callTool(1, "varlatch_list_organizations")), server: [ok("/v1/organizations", { items: [], nextCursor: null })] }),

  // The writes.
  ...((): TranscriptCase[] => {
    const w = (id: string, title: string, args: Record<string, unknown>, server: Exchange[]): TranscriptCase =>
      mcp({ id: `write.${id}`, title, args: MCP("--org", "acme", "--project", "web", "-e", "dev", "--allow-writes"), stdin: lines(callTool(1, `varlatch_${id.startsWith("delete") ? "delete" : "set"}_value`, args)), server });
    return [
      w("set.secret", "a Secret's value is refused, after reading only the contract", { item: "API_KEY", value: "s3cr3t-canary" }, [CONTRACT_ITEMS([item("API_KEY")])]),
      w("set.uncontracted", "an item outside the contract counts as a Secret", { item: "OTHER", value: "x" }, [CONTRACT_ITEMS([PLAIN])]),
      w("set.no-contract", "no active contract (404): a Secret", { item: "PORT", value: "1" }, [denied(CONTRACT_PATH, "GET", 404, "RESOURCE_NOT_FOUND")]),
      w("set.contract-error", "a contract read that fails otherwise: the API error", { item: "PORT", value: "1" }, [denied(CONTRACT_PATH, "GET", 500, "INTERNAL")]),
      w("set.present", "replacing a value the environment has needs replace", { item: "PORT", value: "1" }, [CONTRACT_ITEMS([PLAIN]), effective([{ name: "PORT", sensitive: false, source: "self" }])]),
      w("set.inherited", "and so does overriding an inherited one", { item: "PORT", value: "1" }, [CONTRACT_ITEMS([PLAIN]), effective([{ name: "PORT", sensitive: false, source: "parent" }])]),
      w("set.unknown", "presence that cannot be checked counts as existing", { item: "PORT", value: "1" }, [CONTRACT_ITEMS([PLAIN]), denied(`${ENV}/effective-configuration`)]),
      w("set.absent", "a new value is stored, with expectedVersionId", { item: "PORT", value: "1", expectedVersionId: "ver_x" }, [CONTRACT_ITEMS([PLAIN]), effective([]), mcpPut("PORT")]),
      w("set.replace", "replace naming the item skips the presence check", { item: "PORT", value: "2", replace: "PORT" }, [CONTRACT_ITEMS([PLAIN]), mcpPut("PORT")]),
      w("set.replace-other", "replace naming another item: refused before any request", { item: "PORT", value: "2", replace: "HOST" }, []),
      w("set.malformed-contract", "a contract whose items are not a list: the TypeError's message", { item: "PORT", value: "1" }, [contractAnswer({ ...ACTIVE, contract: { items: "x" } })]),
      w("set.malformed-effective", "an effective configuration whose items are not a list", { item: "PORT", value: "1" }, [CONTRACT_ITEMS([PLAIN]), ok(`${ENV}/effective-configuration`, { items: 5 })]),
      w("set.conflict", "a version conflict from the server", { item: "PORT", value: "1", replace: "PORT", expectedVersionId: "ver_old" }, [CONTRACT_ITEMS([PLAIN]), { method: "PUT", path: `${VALUE_PATH}/PORT`, status: 409, answer: apiError(409, "VERSION_CONFLICT", "the value changed") }]),
      w("delete", "a deletion with confirm", { item: "PORT", confirm: "PORT" }, [{ method: "DELETE", path: `${VALUE_PATH}/PORT`, status: 204, headers: {} }]),
      w("delete.no-confirm", "a deletion without confirm: refused, no request", { item: "PORT" }, []),
      w("delete.refused", "a deletion the server refuses", { item: "PORT", confirm: "PORT" }, [denied(`${VALUE_PATH}/PORT`, "DELETE")]),
    ];
  })(),
  mcp({ id: "write.without-flag", title: "without --allow-writes the write tools do not exist", args: MCP("--org", "acme", "--project", "web", "-e", "dev"), stdin: lines(callTool(1, "varlatch_delete_value", { item: "PORT", confirm: "PORT" })) }),
  mcp({ id: "write.expired", title: "a credential the server no longer takes", args: MCP("--org", "acme", "--project", "web", "-e", "dev", "--allow-writes"), stdin: lines(callTool(1, "varlatch_set_value", { item: "PORT", value: "1" })), server: [{ method: "GET", path: CONTRACT_PATH, status: 401, answer: apiError(401, "UNAUTHENTICATED", "credential expired") }] }),
];

// ---------------------------------------------------------------------------
// 5.7a: Organization administration, people, identities and resources
// (org list/create, project create/list/rename, env-create, env-delete,
// identity list/rename/retire/reactivate/reach, credential
// list/revoke/issue, invite, member, tailnet, audit list).

const ORG = "/v1/organizations/acme";
const exch = (method: string, path: string, status: number, answer?: unknown): Exchange => ({ method, path, status, ...(answer === undefined ? { headers: {} } : { answer }) });
const a = (c: Omit<TranscriptCase, "differences" | "files" | "cwd"> & { files?: Record<string, string>; cwd?: string; differences?: string[] }): TranscriptCase => v(c);
const OUTSIDE = { files: storeAt({ "{{server}}": { token: VTOKEN, ...OK } }), cwd: "" };
const ADA = sid("idn", "ada");
const BOB = sid("idn", "bob");
const OLD = sid("idn", "old");
const SAM1 = sid("idn", "samone");
const SAM2 = sid("idn", "samtwo");
const SVC = sid("idn", "deployer");
const TWIN1 = sid("idn", "twinone");
const TWIN2 = sid("idn", "twintwo");
const REQ1 = sid("req", "one");
const REQ2 = sid("req", "two");
const IDENTITIES = [
  { id: ADA, name: "Ada", kind: "human", disabled: false, orgRole: "admin", removedAt: null, lastSeenAt: "2026-11-01T10:00:00.000Z" },
  { id: BOB, name: "Bob", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: OLD, name: "Old", kind: "human", disabled: false, orgRole: null, removedAt: "2026-10-01T10:00:00.000Z", lastSeenAt: null },
  { id: SAM1, name: "Sam", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: SAM2, name: "Sam", kind: "human", disabled: false, orgRole: "member", removedAt: null, lastSeenAt: null },
  { id: SVC, name: "deployer", kind: "service", disabled: false, orgRole: null, lastSeenAt: "2026-11-02T10:00:00.000Z" },
  { id: TWIN1, name: "twin", kind: "service", disabled: false, orgRole: null, lastSeenAt: null },
  { id: TWIN2, name: "twin", kind: "workload", disabled: true, orgRole: null, lastSeenAt: null },
];
const LIST_IDENTITIES = ok(`${ORG}/identities`, { items: IDENTITIES, nextCursor: null });
const ENVS_WEB = ok("/v1/organizations/acme/projects/web/environments", {
  items: [
    { id: "env_dev", name: "dev", tier: "development", kind: "shared", parentEnvironmentId: null },
    { id: "env_prod", name: "prod", tier: "production", kind: "shared", parentEnvironmentId: null },
    { id: "env_prodpr", name: "prod-pr-7", tier: "production", kind: "preview", parentEnvironmentId: "env_prod" },
  ],
  nextCursor: null,
});
const META_ADMIN = ok("/v1/meta", { serverVersion: "0.22.0", apiVersion: 1, capabilities: ["members.lifecycle", "identity.reach", "identity.credentials.issue"] });
const META_OLD = ok("/v1/meta", { serverVersion: "0.19.0", apiVersion: 1, capabilities: [] });
const REACH = {
  identity: { id: SVC, name: "deployer", kind: "service", state: "live", disabledReason: null, liveCredentials: 1 },
  organizationActions: [{ action: "audit.read", grants: [{ grantId: "grt_3", viaGroupId: null, roleId: null }], conditions: [] }],
  projects: [
    {
      id: "prj_1",
      slug: "api",
      name: "API",
      actions: [{ action: "contract.read", grants: [], conditions: [] }],
      environments: [
        { id: "env_dev", name: "development", tier: "development", kind: "shared", parentEnvironmentId: null, actions: [{ action: "config.value.read", grants: [], conditions: [] }] },
        {
          id: "env_prod",
          name: "production",
          tier: "production",
          kind: "shared",
          parentEnvironmentId: null,
          actions: [
            { action: "config.metadata.read", grants: [], conditions: [] },
            { action: "secret.use", grants: [], conditions: [REQ1, REQ2] },
          ],
        },
      ],
    },
  ],
  requirements: [
    { id: REQ1, version: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"] }, condition: "needs tailnet example.ts.net: tag:prod" },
    { id: REQ2, version: 1, target: { kind: "environments", environmentIds: ["env_prod"] }, selector: { tailnet: "example.ts.net", nodes: ["nAbc"] }, condition: "needs tailnet example.ts.net: node:nAbc" },
  ],
  notes: ["Grants through a group are listed with the group's own."],
};
const REACH_DISABLED = {
  identity: { id: TWIN2, name: "twin", kind: "workload", state: "disabled", disabledReason: "organization-deletion", liveCredentials: 0 },
  organizationActions: [],
  projects: [],
  requirements: [],
  notes: [],
};
const REVIEW = {
  syncTargets: [{ id: "snt_1", projectId: "prj_1", environmentId: "env_dev", platform: "coolify", state: "active", changes: ["created", "destination_changed", "other_change"] }],
  connections: [
    { id: "pcn_1", name: "shared", platform: "coolify", credentialKind: "token", revoked: false, changes: ["credential_replaced"] },
    { id: "pcn_2", name: "app", platform: "github", credentialKind: "github-app", revoked: true, changes: ["created"] },
  ],
  webhooks: [{ id: "whk_1", host: "sink.example", revoked: false }, { id: "whk_2", host: "", revoked: true }],
  oidcBindings: [{ id: "oib_1", identityName: "ci", issuer: "https://token.actions.githubusercontent.com", revoked: false }],
  credentials: [{ id: "crd_1", name: "deploy", identityId: SVC, identityName: "deployer", state: "valid" }, { id: "crd_2", name: null, identityId: SVC, identityName: "deployer", state: "revoked" }],
  personalEnvironments: [{ id: "env_bob", name: "development/bob", projectId: "prj_1" }],
};
const EMPTY_REVIEW = { syncTargets: [], connections: [], webhooks: [], oidcBindings: [], credentials: [], personalEnvironments: [] };
const REMOVAL = { left: false, grantsRevoked: 3, groupsLeft: 1, invitationsRevoked: 0, review: REVIEW };
const EXPOSURE = {
  member: { identityId: OLD, name: "Old", role: null, removedAt: "2026-10-01T10:00:00.000Z" },
  coverage: { complete: false, from: "2026-01-01T00:00:00.000Z", to: "2026-10-30T00:00:00.000Z" },
  received: [
    {
      itemName: "TOKEN",
      versionId: "ver_1",
      owningEnvironmentId: "env_dev",
      projectId: "prj_1",
      state: "served",
      servedAs: "current",
      retiringUntil: null,
      notServedBecause: null,
      served: true,
      confirmation: null,
      rotationHint: "Issue a new token in the provider console.",
      receipts: [
        { environmentId: "env_dev", way: "revealed", firstAt: "2026-09-01T10:00:00.000Z", lastAt: "2026-09-02T10:00:00.000Z" },
        { environmentId: "env_gone", way: "delivered", firstAt: "2026-09-03T10:00:00.000Z", lastAt: "2026-09-03T10:00:00.000Z" },
      ],
    },
    {
      itemName: "OLD_KEY",
      versionId: "ver_2",
      owningEnvironmentId: "env_prod",
      projectId: "prj_1",
      state: "not-served",
      servedAs: null,
      retiringUntil: null,
      notServedBecause: "replaced",
      served: false,
      confirmation: null,
      rotationHint: null,
      receipts: [{ environmentId: "env_prod", way: "export", firstAt: "2026-08-01T10:00:00.000Z", lastAt: "2026-08-01T10:00:00.000Z" }],
    },
    {
      itemName: "ROTATED",
      versionId: "ver_3",
      owningEnvironmentId: "env_dev",
      projectId: "prj_1",
      state: "served",
      servedAs: "retiring",
      retiringUntil: "2026-12-01T00:00:00.000Z",
      notServedBecause: null,
      served: true,
      confirmation: { confirmedAt: "2026-11-02T00:00:00.000Z" },
      rotationHint: null,
      receipts: [{ environmentId: "env_dev", way: "written", firstAt: "2026-07-01T10:00:00.000Z", lastAt: "2026-07-01T10:00:00.000Z" }],
    },
  ],
  authorityAtRemoval: {
    removalId: "mrm_1",
    removedAt: "2026-10-01T10:00:00.000Z",
    role: "member",
    left: false,
    environments: [
      { environmentId: "env_prod", actions: [{ action: "secret.reveal", sources: [] }, { action: "config.metadata.read", sources: [] }], conditionalOn: [REQ1] },
      { environmentId: "env_dev", actions: [{ action: "config.value.read", sources: [] }], conditionalOn: [] },
    ],
    requirements: [{ requirementId: REQ1, requirementVersion: 1, target: { kind: "tier", tier: "production" }, selector: { tailnet: "example.ts.net", tags: ["tag:prod"], users: ["ada@example.com"] } }],
  },
  indirect: { ...EMPTY_REVIEW, webhooks: [{ id: "whk_1", host: "sink.example", revoked: false }] },
};
const EXPOSURE_ME = {
  member: { identityId: ADA, name: "Ada", role: "admin", removedAt: null },
  coverage: { complete: true, from: null, to: null },
  received: [],
  authorityAtRemoval: null,
  indirect: EMPTY_REVIEW,
};
const NAMES = [ok(`${ORG}/projects`, { items: [{ slug: "web", name: "Web", contractAuthority: "git" }], nextCursor: null }), ENVS_WEB];
const ISSUED = { id: sid("crd", "issued"), token: "vlt_svc_issuedTOKENcanary", name: "deploy", expiresAt: null, maxUses: null, kind: "service" };

/** An invitation token in the servers' format: vlt_invite_ and 43 base64url characters. */
const inviteToken = (tag: string) => `vlt_invite_${tag}${"0".repeat(43 - tag.length)}`;

const admin57a: TranscriptCase[] = [
  // invite
  a({ id: "invite.member", title: "invite: a one-time enrollment link for a member", args: ["invite", "Alice"], server: [exch("POST", `${ORG}/invitations`, 201, { id: "inv_1", token: inviteToken("canaryTOKEN"), expiresAt: "2026-11-08T10:00:00.000Z" })] }),
  a({ id: "invite.admin", title: "invite --role admin", args: ["invite", "Bob", "--role", "admin"], server: [exch("POST", `${ORG}/invitations`, 201, { token: inviteToken("canaryADMIN"), expiresAt: "2026-11-08T10:00:00.000Z" })] }),
  a({ id: "invite.role-last", title: "--role with no value: a member", args: ["invite", "Carol", "--role"], server: [exch("POST", `${ORG}/invitations`, 201, { token: inviteToken("canaryCAROL"), expiresAt: "soon" })] }),
  a({ id: "invite.usage", title: "invite without a name", args: ["invite"] }),
  a({ id: "invite.refused", title: "invite refused by the server", args: ["invite", "Dan"], server: [exch("POST", `${ORG}/invitations`, 403, apiError(403, "PERMISSION_DENIED"))] }),
  a({ id: "invite.not-signed-in", title: "invite without a credential", args: ["invite", "Eve"], files: NOT_SIGNED_IN }),
  a({ id: "invite.outside", title: "invite outside a repository: the context error", args: ["invite", "Eve"], ...OUTSIDE }),

  // tailnet
  a({ id: "tailnet.require.tags", title: "tailnet require: production by default, tags", args: ["tailnet", "require", "--tailnet", "corp.ts.net", "--tags", "tag:ci,tag:prod"], server: [exch("POST", `${ORG}/requirements`, 201, { id: REQ1 })] }),
  a({ id: "tailnet.require.all", title: "tailnet require: a tier, nodes, users and tags, empty parts dropped", args: ["tailnet", "require", "--tier", "staging", "--tailnet", "corp.ts.net", "--nodes", "n1,,n2", "--users", "ada@example.com", "--tags", "tag:a"], server: [exch("POST", `${ORG}/requirements`, 201, { id: REQ2 })] }),
  a({ id: "tailnet.require.no-tailnet", title: "tailnet require without --tailnet", args: ["tailnet", "require", "--tags", "tag:a"] }),
  a({ id: "tailnet.require.no-selector", title: "tailnet require with no tags, nodes or users", args: ["tailnet", "require", "--tailnet", "corp.ts.net", "--tags", ","] }),
  a({ id: "tailnet.requirements", title: "tailnet requirements", args: ["tailnet", "requirements"], server: [ok(`${ORG}/requirements`, { items: [{ id: REQ1, kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "corp.ts.net", tags: ["tag:\u001b[31m"] } }], nextCursor: null })] }),
  a({ id: "tailnet.requirements.json", title: "tailnet requirements --json", args: ["tailnet", "requirements", "--json"], server: [ok(`${ORG}/requirements`, { items: [{ id: REQ1, kind: "tailnet", target: { kind: "tier", tier: "production" }, selector: { tailnet: "corp.ts.net" } }], nextCursor: null })] }),
  a({ id: "tailnet.requirements.none", title: "tailnet requirements with none", args: ["tailnet", "requirements"], server: [ok(`${ORG}/requirements`, { items: [], nextCursor: null })] }),
  a({ id: "tailnet.remove", title: "tailnet remove", args: ["tailnet", "remove", REQ1], server: [exch("DELETE", `${ORG}/requirements/${REQ1}`, 204)] }),
  a({ id: "tailnet.remove.usage", title: "tailnet remove without an id", args: ["tailnet", "remove"] }),
  a({ id: "tailnet.unknown", title: "an unknown tailnet subcommand", args: ["tailnet", "list"] }),
  a({ id: "tailnet.none", title: "tailnet without a subcommand", args: ["tailnet"] }),

  // audit list
  a({ id: "audit.list", title: "audit list: time, decision, type and actor", args: ["audit", "list"], server: [ok(`${ORG}/audit-events?limit=50`, { items: [
    { id: "aud_1", occurredAt: "2026-11-01T10:00:00.000Z", decision: "allow", eventType: "secret.disclosed", actorIdentityId: ADA },
    { id: "aud_2", occurredAt: "not a time", decision: "deny", eventType: "grant.created\u0007", actorIdentityId: null },
  ], nextCursor: null })] }),
  a({ id: "audit.list.json", title: "audit list --json", args: ["audit", "list", "--json"], server: [ok(`${ORG}/audit-events?limit=50`, { items: [{ id: "aud_1", occurredAt: "2026-11-01T10:00:00.000Z", decision: "allow", eventType: "secret.disclosed", actorIdentityId: ADA }], nextCursor: null })] }),
  a({ id: "audit.list.server", title: "audit list --server: the server named, the repository's organization", args: ["audit", "list", "--server", "{{server}}"], server: [ok(`${ORG}/audit-events?limit=50`, { items: [], nextCursor: null })] }),
  a({ id: "audit.unknown", title: "an unknown audit subcommand", args: ["audit", "show"] }),
  a({ id: "audit.none", title: "audit without a subcommand", args: ["audit"] }),

  // org
  a({ id: "org.list", title: "org list", args: ["org", "list"], server: [ok("/v1/organizations", { items: [{ id: "org_1", slug: "acme", name: "Acme" }, { id: "org_2", slug: "beta", name: "Beta\u001b[0m" }], nextCursor: null })] }),
  a({ id: "org.list.json", title: "org list --json", args: ["org", "list", "--json"], server: [ok("/v1/organizations", { items: [{ id: "org_1", slug: "acme", name: "Acme", createdAt: "2026-01-01T00:00:00.000Z" }], nextCursor: null })] }),
  a({ id: "org.list.none", title: "org list with none", args: ["org", "list"], server: [ok("/v1/organizations", { items: [], nextCursor: null })] }),
  a({ id: "org.list.server", title: "org list --server outside a repository", args: ["org", "list", "--server", "{{server}}"], ...OUTSIDE, server: [ok("/v1/organizations", { items: [{ id: "org_1", slug: "acme", name: "Acme" }], nextCursor: null })] }),
  a({ id: "org.list.only-credential", title: "org list outside a repository: the only stored credential's server", args: ["org", "list"], ...OUTSIDE, server: [ok("/v1/organizations", { items: [], nextCursor: null })] }),
  a({ id: "org.create", title: "org create with a name", args: ["org", "create", "beta", "Beta Co"], server: [exch("POST", "/v1/organizations", 201, { id: "org_2", slug: "beta", name: "Beta Co" })] }),
  a({ id: "org.create.slug-name", title: "org create without a name: the slug is the name", args: ["org", "create", "beta"], server: [exch("POST", "/v1/organizations", 201, { id: "org_2", slug: "beta", name: "beta" })] }),
  a({ id: "org.create.refused", title: "org create: the slug is taken", args: ["org", "create", "acme"], server: [exch("POST", "/v1/organizations", 409, apiError(409, "CONFLICT", "slug taken"))] }),
  a({ id: "org.create.usage", title: "org create without a slug", args: ["org", "create"] }),
  a({ id: "org.unknown", title: "an unknown org subcommand", args: ["org", "rename"] }),
  a({ id: "org.none", title: "org without a subcommand", args: ["org"] }),
  a({ id: "org.no-server", title: "outside a repository, no server and no credential", args: ["org", "list"], files: {}, cwd: "" }),
  a({ id: "org.no-server.repo", title: "a repository without a server", args: ["org", "list"], files: { ...repoFiles(TOML_NO_SERVER), ...storeAt({ "{{server}}": { token: VTOKEN, ...OK } }) } }),
  a({ id: "org.not-signed-in", title: "org list without a credential for the server", args: ["org", "list"], files: NOT_SIGNED_IN }),

  // project
  a({ id: "project.create", title: "project create --org", args: ["project", "create", "api", "--org", "acme"], server: [exch("POST", `${ORG}/projects`, 201, { id: "prj_2", slug: "api", name: "api", contractAuthority: "git" })] }),
  a({ id: "project.create.managed", title: "project create with a name, --managed and --server", args: ["project", "create", "api", "API Service", "--org", "acme", "--managed", "--server", "{{server}}"], server: [exch("POST", `${ORG}/projects`, 201, { id: "prj_2", slug: "api", name: "API Service", contractAuthority: "managed" })] }),
  a({ id: "project.create.no-org", title: "project create without --org", args: ["project", "create", "api"] }),
  a({ id: "project.create.usage", title: "project create without a slug", args: ["project", "create"] }),
  a({ id: "project.list", title: "project list", args: ["project", "list"], server: [ok(`${ORG}/projects`, { items: [{ slug: "web", name: "Web", contractAuthority: "git" }, { slug: "api", name: "API", contractAuthority: "managed" }], nextCursor: null })] }),
  a({ id: "project.list.json", title: "project list --json", args: ["project", "list", "--json"], server: [ok(`${ORG}/projects`, { items: [{ id: "prj_1", slug: "web", name: "Web", contractAuthority: "git" }], nextCursor: null })] }),
  a({ id: "project.rename", title: "project rename", args: ["project", "rename", "web", "Web App"], server: [exch("PATCH", `${ORG}/projects/web`, 200, { slug: "web", name: "Web App", contractAuthority: "git" })] }),
  a({ id: "project.rename.no-name", title: "project rename without the new name", args: ["project", "rename", "web"] }),
  a({ id: "project.rename.usage", title: "project rename without a slug", args: ["project", "rename"] }),
  a({ id: "project.unknown", title: "an unknown project subcommand", args: ["project", "show"] }),

  // env-create
  a({ id: "env-create.root", title: "env-create a root environment with --tier", args: ["env-create", "qa", "--tier", "staging"], server: [exch("POST", "/v1/organizations/acme/projects/web/environments", 201, { id: "env_qa", name: "qa", tier: "staging", kind: "shared" })] }),
  a({ id: "env-create.parent", title: "env-create a personal child of dev", args: ["env-create", "alice-dev", "--parent", "dev", "--kind", "personal"], server: [ENVS_WEB, exch("POST", "/v1/organizations/acme/projects/web/environments", 201, { id: "env_ad", name: "alice-dev", tier: "development", kind: "personal" })] }),
  a({ id: "env-create.parent-id", title: "env-create with the parent named by its id, no --kind", args: ["env-create", "pr-8", "--parent", "env_prod"], server: [ENVS_WEB, exch("POST", "/v1/organizations/acme/projects/web/environments", 201, { id: "env_pr8", name: "pr-8", tier: "production", kind: "preview" })] }),
  a({ id: "env-create.no-parent", title: "env-create with a parent that does not exist", args: ["env-create", "x", "--parent", "nope"], server: [ENVS_WEB] }),
  a({ id: "env-create.no-tier", title: "env-create a root without --tier", args: ["env-create", "qa"] }),
  a({ id: "env-create.usage", title: "env-create without a name", args: ["env-create"] }),

  // env-delete
  a({ id: "env-delete.dev", title: "env-delete a development environment", args: ["env-delete", "dev"], server: [ENVS_WEB, exch("DELETE", "/v1/organizations/acme/projects/web/environments/dev", 204)] }),
  a({ id: "env-delete.prod-refused", title: "env-delete a production root without --confirm", args: ["env-delete", "prod"], server: [ENVS_WEB] }),
  a({ id: "env-delete.prod-wrong", title: "env-delete a production root with --confirm naming another", args: ["env-delete", "prod", "--confirm", "dev"], server: [ENVS_WEB] }),
  a({ id: "env-delete.prod", title: "env-delete a production root with --confirm", args: ["env-delete", "prod", "--confirm", "prod"], server: [ENVS_WEB, exch("DELETE", "/v1/organizations/acme/projects/web/environments/prod", 204)] }),
  a({ id: "env-delete.prod-child", title: "a production child needs no --confirm", args: ["env-delete", "prod-pr-7"], server: [ENVS_WEB, exch("DELETE", "/v1/organizations/acme/projects/web/environments/prod-pr-7", 204)] }),
  a({ id: "env-delete.missing", title: "env-delete an environment that does not exist", args: ["env-delete", "nope"], server: [ENVS_WEB] }),
  a({ id: "env-delete.usage", title: "env-delete without a name", args: ["env-delete"] }),

  // identity
  a({ id: "identity.list", title: "identity list: active and retired, last seen", args: ["identity", "list"], server: [LIST_IDENTITIES] }),
  a({ id: "identity.list.json", title: "identity list --json", args: ["identity", "list", "--json"], server: [LIST_IDENTITIES] }),
  a({ id: "identity.list.none", title: "identity list with none", args: ["identity", "list"], server: [ok(`${ORG}/identities`, { items: [], nextCursor: null })] }),
  a({ id: "identity.rename", title: "identity rename", args: ["identity", "rename", SVC, "deployer-2"], server: [exch("PATCH", `${ORG}/identities/${SVC}`, 200, { id: SVC, name: "deployer-2" })] }),
  a({ id: "identity.rename.no-name", title: "identity rename without the new name", args: ["identity", "rename", SVC] }),
  a({ id: "identity.rename.usage", title: "identity rename without an id", args: ["identity", "rename"] }),
  a({ id: "identity.retire.refused", title: "identity retire without --confirm", args: ["identity", "retire", SVC], server: [LIST_IDENTITIES] }),
  a({ id: "identity.retire.wrong", title: "identity retire with --confirm naming another", args: ["identity", "retire", SVC, "--confirm", "twin"], server: [LIST_IDENTITIES] }),
  a({ id: "identity.retire", title: "identity retire with --confirm", args: ["identity", "retire", SVC, "--confirm", "deployer"], server: [LIST_IDENTITIES, exch("POST", `${ORG}/identities/${SVC}/retire`, 200, { id: SVC, disabled: true })] }),
  a({ id: "identity.retire.unknown", title: "identity retire an identity that does not exist", args: ["identity", "retire", "idn_nope"], server: [LIST_IDENTITIES] }),
  a({ id: "identity.retire.usage", title: "identity retire without an id", args: ["identity", "retire"] }),
  a({ id: "identity.reactivate", title: "identity reactivate", args: ["identity", "reactivate", TWIN2], server: [exch("POST", `${ORG}/identities/${TWIN2}/reactivate`, 200, { id: TWIN2, disabled: false })] }),
  a({ id: "identity.reactivate.usage", title: "identity reactivate without an id", args: ["identity", "reactivate"] }),
  a({ id: "identity.unknown", title: "an unknown identity subcommand", args: ["identity", "show"] }),
  a({ id: "identity.reach", title: "identity reach by id: projects, environments, conditions, notes", args: ["identity", "reach", SVC], server: [META_ADMIN, ok(`${ORG}/identities/${SVC}/reach`, REACH)] }),
  a({ id: "identity.reach.json", title: "identity reach --json", args: ["identity", "reach", SVC, "--json"], server: [META_ADMIN, ok(`${ORG}/identities/${SVC}/reach`, REACH)] }),
  a({ id: "identity.reach.name", title: "identity reach by name: resolved through the listing", args: ["identity", "reach", "deployer", "--server", "{{server}}"], server: [META_ADMIN, LIST_IDENTITIES, ok(`${ORG}/identities/${SVC}/reach`, REACH)] }),
  a({ id: "identity.reach.disabled", title: "identity reach of a machine disabled by the organization's deletion", args: ["identity", "reach", TWIN2], server: [META_ADMIN, ok(`${ORG}/identities/${TWIN2}/reach`, REACH_DISABLED)] }),
  a({ id: "identity.reach.ambiguous", title: "identity reach by a name two machines have", args: ["identity", "reach", "twin"], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "identity.reach.unknown", title: "identity reach by a name no machine has (a person's)", args: ["identity", "reach", "Ada"], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "identity.reach.old-server", title: "identity reach on a server without the capability", args: ["identity", "reach", SVC], server: [META_OLD] }),
  a({ id: "identity.reach.usage", title: "identity reach without a target", args: ["identity", "reach"] }),
  a({ id: "identity.reach.unknown-option", title: "identity reach is parsed strictly", args: ["identity", "reach", SVC, "--jsn"] }),

  // credential
  a({ id: "credential.list", title: "credential list", args: ["credential", "list", SVC], server: [ok(`${ORG}/identities/${SVC}/credentials`, { items: [
    { id: "crd_1", kind: "service", name: "deploy", createdAt: "2026-10-01T10:00:00.000Z", expiresAt: "2027-10-01T10:00:00.000Z", revokedAt: null, lastUsedAt: "2026-11-01T10:00:00.000Z" },
    { id: "crd_2", kind: "service", name: null, createdAt: "2026-09-01T10:00:00.000Z", expiresAt: null, revokedAt: "2026-09-02T10:00:00.000Z", lastUsedAt: null },
  ], nextCursor: null })] }),
  a({ id: "credential.list.json", title: "credential list --json", args: ["credential", "list", SVC, "--json"], server: [ok(`${ORG}/identities/${SVC}/credentials`, { items: [{ id: "crd_1", kind: "service", createdAt: "2026-10-01T10:00:00.000Z" }], nextCursor: null })] }),
  a({ id: "credential.list.none", title: "credential list with none", args: ["credential", "list", SVC], server: [ok(`${ORG}/identities/${SVC}/credentials`, { items: [], nextCursor: null })] }),
  a({ id: "credential.list.usage", title: "credential list without an id", args: ["credential", "list"] }),
  a({ id: "credential.revoke", title: "credential revoke", args: ["credential", "revoke", SVC, "crd_1"], server: [exch("DELETE", `${ORG}/identities/${SVC}/credentials/crd_1`, 204)] }),
  a({ id: "credential.revoke.no-id", title: "credential revoke without the credential id", args: ["credential", "revoke", SVC] }),
  a({ id: "credential.unknown", title: "an unknown credential subcommand", args: ["credential", "show"] }),
  a({ id: "credential.issue", title: "credential issue: the token only in the --out file, 0600", args: ["credential", "issue", SVC, "--name", "deploy", "--out", "token.txt"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 201, ISSUED)] }),
  a({ id: "credential.issue.json", title: "credential issue --json with --ttl and --max-uses", args: ["credential", "issue", SVC, "--name", "ci", "--ttl", "600", "--max-uses", "3", "--out", "token.txt", "--json"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 201, { ...ISSUED, name: "ci", expiresAt: "2026-11-01T10:10:00.000Z", maxUses: 3 })] }),
  a({ id: "credential.issue.default-lifetime", title: "credential issue without --ttl, an expiry: the organization's default", args: ["credential", "issue", SVC, "--name", "deploy", "--max-uses", "1", "--out", "token.txt"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 201, { ...ISSUED, expiresAt: "2026-12-01T10:00:00.000Z", maxUses: 1 })] }),
  a({ id: "credential.issue.assisted", title: "credential issue in assisted mode: said not to read the file", args: ["--assisted", "credential", "issue", SVC, "--name", "deploy", "--out", "token.txt"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 201, ISSUED)] }),
  a({ id: "credential.issue.exists", title: "credential issue never replaces a file", args: ["credential", "issue", SVC, "--name", "deploy", "--out", "token.txt"], files: { ...SIGNED_IN, "repo/token.txt": "old\n" } }),
  a({ id: "credential.issue.no-dir", title: "credential issue never creates the directory", args: ["credential", "issue", SVC, "--name", "deploy", "--out", "missing/token.txt"] }),
  a({ id: "credential.issue.not-found", title: "credential issue for an identity that cannot hold one: the file removed", args: ["credential", "issue", SVC, "--name", "deploy", "--out", "token.txt"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 404, apiError(404, "RESOURCE_NOT_FOUND"))] }),
  a({ id: "credential.issue.lifetime", title: "credential issue above the organization's maximum lifetime", args: ["credential", "issue", SVC, "--name", "deploy", "--ttl", "999999", "--out", "token.txt"], server: [META_ADMIN, exch("POST", `${ORG}/identities/${SVC}/credentials`, 422, { error: { code: "CREDENTIAL_LIFETIME_EXCEEDED", message: "too long", requestId: "req_00000000-0000-4000-8000-000000000000", details: { maxTtlSeconds: 86400 } } })] }),
  a({ id: "credential.issue.old-server", title: "credential issue on a server without the capability", args: ["credential", "issue", SVC, "--name", "deploy", "--out", "token.txt"], server: [META_OLD] }),
  a({ id: "credential.issue.no-name", title: "credential issue without --name", args: ["credential", "issue", SVC, "--out", "token.txt"] }),
  a({ id: "credential.issue.no-out", title: "credential issue without --out", args: ["credential", "issue", SVC, "--name", "deploy"] }),
  a({ id: "credential.issue.bad-ttl", title: "credential issue with a --ttl that is not a whole number", args: ["credential", "issue", SVC, "--name", "deploy", "--ttl", "1.5", "--out", "token.txt"] }),
  a({ id: "credential.issue.bad-uses", title: "credential issue with --max-uses out of range", args: ["credential", "issue", SVC, "--name", "deploy", "--max-uses", "0", "--out", "token.txt"] }),
  a({ id: "credential.issue.long-name", title: "credential issue with a --name over 200 characters", args: ["credential", "issue", SVC, "--name", "x".repeat(201), "--out", "token.txt"] }),
  a({ id: "credential.issue.usage", title: "credential issue without an identity", args: ["credential", "issue", "--name", "deploy", "--out", "token.txt"] }),

  // member
  a({ id: "member.list", title: "member list: people only, former members marked", args: ["member", "list"], server: [LIST_IDENTITIES] }),
  a({ id: "member.list.json", title: "member list --json", args: ["member", "list", "--json"], server: [LIST_IDENTITIES] }),
  a({ id: "member.list.none", title: "member list with no people", args: ["member", "list"], server: [ok(`${ORG}/identities`, { items: [IDENTITIES[5]], nextCursor: null })] }),
  a({ id: "member.remove.no-confirm", title: "member remove without --confirm: the command to confirm it", args: ["member", "remove", "Bob"] }),
  a({ id: "member.remove.no-confirm.assisted", title: "in assisted mode, the human's decision (78)", args: ["--assisted", "member", "remove", "Bob"] }),
  a({ id: "member.remove.no-confirm.server", title: "with --server, the command names it", args: ["member", "remove", "Bob Smith", "--server", "{{server}}"] }),
  a({ id: "member.remove.wrong", title: "member remove with --confirm naming another", args: ["member", "remove", "Bob", "--confirm", "Ada"] }),
  a({ id: "member.remove", title: "member remove: what it did and what to review", args: ["member", "remove", "Bob", "--confirm", "Bob"], server: [META_ADMIN, LIST_IDENTITIES, exch("DELETE", `${ORG}/members/${BOB}`, 200, REMOVAL)] }),
  a({ id: "member.remove.id", title: "member remove by identity id, nothing to review", args: ["member", "remove", BOB, "--confirm", BOB], server: [META_ADMIN, LIST_IDENTITIES, exch("DELETE", `${ORG}/members/${BOB}`, 200, { left: false, grantsRevoked: 1, groupsLeft: 0, invitationsRevoked: 2, review: EMPTY_REVIEW })] }),
  a({ id: "member.remove.former", title: "member remove of a former member's id", args: ["member", "remove", OLD, "--confirm", OLD], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "member.remove.machine", title: "member remove of a machine's id", args: ["member", "remove", SVC, "--confirm", SVC], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "member.remove.ambiguous", title: "member remove of a name two members have", args: ["member", "remove", "Sam", "--confirm", "Sam"], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "member.remove.unknown", title: "member remove of a name no member has", args: ["member", "remove", "Zed", "--confirm", "Zed"], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "member.remove.old-server", title: "member remove on a server without the capability", args: ["member", "remove", "Bob", "--confirm", "Bob"], server: [META_OLD] }),
  a({ id: "member.leave", title: "member leave --confirm the organization", args: ["member", "leave", "--confirm", "acme"], server: [META_ADMIN, exch("DELETE", `${ORG}/members/me`, 200, { ...REMOVAL, left: true, review: EMPTY_REVIEW })] }),
  a({ id: "member.leave.no-confirm", title: "member leave without --confirm", args: ["member", "leave"] }),
  a({ id: "member.leave.no-confirm.assisted", title: "member leave in assisted mode without --confirm", args: ["--assisted", "member", "leave"] }),
  a({ id: "member.leave.wrong", title: "member leave --confirm naming another organization", args: ["member", "leave", "--confirm", "beta"] }),
  a({ id: "member.role.admin", title: "member role admin", args: ["member", "role", "Bob", "admin"], server: [META_ADMIN, LIST_IDENTITIES, exch("PATCH", `${ORG}/members/${BOB}`, 200, { identityId: BOB, role: "admin", previousRole: "member" })] }),
  a({ id: "member.role.member", title: "member role member: grants stay", args: ["member", "role", "Ada", "member"], server: [META_ADMIN, LIST_IDENTITIES, exch("PATCH", `${ORG}/members/${ADA}`, 200, { identityId: ADA, role: "member", previousRole: "admin" })] }),
  a({ id: "member.role.same", title: "member role to the role they have", args: ["member", "role", "Ada", "admin"], server: [META_ADMIN, LIST_IDENTITIES, exch("PATCH", `${ORG}/members/${ADA}`, 200, { identityId: ADA, role: "admin", previousRole: "admin" })] }),
  a({ id: "member.role.confirm", title: "member role takes no --confirm", args: ["member", "role", "Bob", "admin", "--confirm", "Bob"] }),
  a({ id: "member.role.bad", title: "member role with a role that is not one", args: ["member", "role", "Bob", "owner"] }),
  a({ id: "member.json-misuse", title: "--json is for member list and member exposure", args: ["member", "remove", "Bob", "--json"] }),
  a({ id: "member.exposure", title: "member exposure: received, reach at removal, indirect paths, environments named", args: ["member", "exposure", "Old"], server: [META_ADMIN, LIST_IDENTITIES, ok(`${ORG}/members/${OLD}/exposure`, EXPOSURE), ...NAMES] }),
  a({ id: "member.exposure.json", title: "member exposure --json: NDJSON, the member and coverage first", args: ["member", "exposure", OLD, "--json"], server: [META_ADMIN, ok(`${ORG}/members/${OLD}/exposure`, EXPOSURE)] }),
  a({ id: "member.exposure.me", title: "member exposure me: the caller's own", args: ["member", "exposure", "me"], server: [META_ADMIN, ok(`${ORG}/members/me/exposure`, EXPOSURE_ME), ...NAMES] }),
  a({ id: "member.exposure.no-projects", title: "member exposure when the projects cannot be listed: ids stay", args: ["member", "exposure", OLD], server: [META_ADMIN, ok(`${ORG}/members/${OLD}/exposure`, EXPOSURE), exch("GET", `${ORG}/projects`, 403, apiError(403, "PERMISSION_DENIED"))] }),
  a({ id: "member.exposure.machine", title: "member exposure of a machine's id is refused by the listing's rule", args: ["member", "exposure", "deployer"], server: [META_ADMIN, LIST_IDENTITIES] }),
  a({ id: "member.exposure.confirm", title: "member exposure takes no --confirm", args: ["member", "exposure", "Old", "--confirm", "Old"] }),
  a({ id: "member.exposure.old-server", title: "member exposure on a server without the capability", args: ["member", "exposure", "Old"], server: [META_OLD] }),
  a({ id: "member.unknown", title: "an unknown member subcommand", args: ["member", "invite"] }),
  a({ id: "member.none", title: "member without a subcommand", args: ["member"] }),
  a({ id: "member.unknown-option", title: "member is parsed strictly", args: ["member", "list", "--all"] }),
];

// ---- 5.8a: guided init, and what it never does off a terminal ---------------
//
// Guided `init` runs only with a terminal on both ends, outside assisted
// mode; a transcript has none, so these cases show the flags path taking
// over: a usage error (64), nothing written, nothing asked. The guided run
// itself is in the guided-init vectors (go/cmd/varlatch/testdata/vectors/
// guided-init.json) and the Go pseudo-terminal tests.

const guided58a: TranscriptCase[] = [
  { id: "init.no-flags", title: "off a terminal, init without --org and --project is a usage error; nothing is asked or written", args: ["init"] },
  { id: "init.no-project", title: "--org alone: --project is needed", args: ["init", "--org", "acme"] },
  { id: "init.no-org", title: "--project alone: the usage", args: ["init", "--project", "web"] },
  { id: "init.server-only", title: "--server alone: the usage", args: ["init", "--server", "https://varlatch.example.com"] },
  { id: "init.assisted", title: "assisted mode: the same, a terminal or not", args: ["--assisted", "init"] },
  { id: "init.marker", title: "a coding agent's marker: the same", args: ["init", "--org", "acme"], env: { CLAUDECODE: "1" } },
];

export const AREAS: Record<string, TranscriptCase[]> = {
  "5.1a-framework": framework,
  "5.1b-context": context51b,
  "5.1c-api-client": apiClient51c,
  "5.1d-agent-files": agentFiles51d,
  "5.1e-session": session51e,
  "5.2-sign-in": signIn52,
  "5.3a-values": values53a,
  "5.3b-contracts": contracts53b,
  "5.3c-types": types53c,
  "5.4b-run": run54b,
  "5.4c-redact": redact54c,
  "5.4e-find-files": findFiles54e,
  "5.4f-strict": strict54f,
  "5.6a-hook": hook56a,
  "5.6b-mcp": mcp56b,
  "5.7a-admin": admin57a,
  "5.8a-guided-init": guided58a,
};
