// SPDX-License-Identifier: Apache-2.0
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
    { id: `help.${topic}`, title: `help ${topic}`, args: ["help", topic] },
    { id: `help.${topic}.option`, title: `${topic} --help`, args: [topic, "--help"] },
    { id: `help.${topic}.short`, title: `${topic} -h`, args: [topic, "-h"] },
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
  { id: "status.array-servers", title: "servers as an array: its elements are listed by index", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": [{"token": "vlt_cli_fakeAAAA", "name": "first"}]}\n' } },
  { id: "status.string-servers", title: "servers as a string: one entry per character", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": "ab"}\n' } },
  { id: "status.array-store", title: "a store that is an array holds no servers", args: ["status", "--json"], files: { "config/credentials.json": "[1, 2]\n" } },
  { id: "status.null-entry", title: "an entry that is null stops status (TypeScript throws a TypeError)", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": {"https://a.example": null}}\n' }, differences: ["uncaught"] },
  { id: "status.c1-name", title: "C1 control characters in a name are escaped", args: ["status"], files: { "config/credentials.json": '{"servers": {"https://a.example": {"token": "t", "name": "a\u0082b\u009fc"}}}\n' } },
  { id: "status.lone-surrogate", title: "a lone surrogate in a server: escaped in JSON, U+FFFD in text", args: ["status", "--json"], files: { "config/credentials.json": '{"servers": {"https://a.example/\\ud800": {"token": "t"}}}\n' } },
  { id: "status.lone-surrogate.text", title: "the same, human", args: ["status"], files: { "config/credentials.json": '{"servers": {"https://a.example/\\ud800": {"token": "t"}}}\n' } },
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
  { id: "server.repo.odd-override.json", title: "a local override that is not a string is passed through", args: ["server", "--json"], files: repoFiles(TOML_FULL, { serverOverride: { url: "x" } }), ...IN_REPO },
  { id: "server.repo.odd-override", title: "the same, human", args: ["server"], files: repoFiles(TOML_FULL, { serverOverride: 42 }), ...IN_REPO },
  { id: "server.repo.null-local", title: "a local.json holding null stops server (TypeScript throws a TypeError)", args: ["server"], files: repoFiles(TOML_FULL, "null\n"), ...IN_REPO, differences: ["uncaught"] },
  { id: "server.odd-settings", title: "a default that is not a non-empty string is no default", args: ["server", "--json"], files: { "config/credentials.json": STORE_SEVERAL, "config/settings.json": '{"defaultServer": ""}\n' } },
  // A special scheme's backslash starts the path: no user name or password, so shown as it is.
  { id: "server.backslash-path.json", title: "a server whose path follows a backslash is no user name and password", args: ["server", "--json"], files: { "config/credentials.json": credentials({ "https://example.com\\path@segment": { token: "vlt_cli_fakeAAAA" } }), "config/settings.json": '{"defaultServer": "https://example.com\\\\path@segment"}\n' } },
  { id: "status.backslash-path.json", title: "the same server in status --json", args: ["status", "--json"], files: { "config/credentials.json": credentials({ "https://example.com\\path@segment": { token: "vlt_cli_fakeAAAA" } }) } },
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
  { id: "server.use.not-a-url", title: "server use refuses what is not a URL", args: ["server", "use", "b.example"] },
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
  { id: "context.odd-local.json", title: "a local selection and override that are not strings are passed through", args: ["context", "--json"], files: repoFiles(TOML_FULL, { selectedEnvironment: 5, serverOverride: ["a", "b"], selectedTier: "x" }), ...IN_REPO },
  { id: "context.odd-local", title: "the same, human", args: ["context"], files: repoFiles(TOML_FULL, { selectedEnvironment: 5, serverOverride: ["a", "b"] }), ...IN_REPO },
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
  probe({ id: "probe.whoami.odd-shapes", title: "identity fields of any JSON type are shown as they are; an organization that is a string", files: storeAt({ "{{server}}": PROBED }), server: [ok("/v1/meta", META_WHOAMI), ok("/v1/me/credentials", { items: [CURRENT] }), ok("/v1/me", { identity: { id: 7, name: ["a", { b: 1 }], kind: "a\u0007b " }, organization: "acme" })] }),
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
  probe({ id: "probe.unreachable.not-a-url", title: "a stored server that is not a URL: fetch's own message", files: storeAt({ "not a url": PROBED }) }),
  probe({ id: "probe.token-latin1", title: "a stored token with Latin-1 characters and surrounding spaces is sent", files: storeAt({ "{{server}}": { ...PROBED, token: " vlt_cli_é " } }), server: VALID }),
  probe({ id: "probe.token-number", title: "a stored token that is a number is sent as text", files: storeAt({ "{{server}}": { ...PROBED, token: 12345 } }), server: VALID }),
  probe({ id: "probe.in-repo", title: "inside a repository, the repository's context follows", files: { ...storeAt({ "{{server}}": PROBED }), "repo/varlatch.toml": 'server = "{{server}}"\norganization = "acme"\nproject = "web"\ndefault_environment = "dev"\n' }, cwd: "repo", server: VALID }),
  probe({ id: "probe.assisted", title: "assisted mode marks the User-Agent", args: ["--assisted", "status", "--probe", "--json"], files: storeAt({ "{{server}}": PROBED }), server: VALID }),
  { id: "probe.null-entry", title: "a null stored entry: TypeScript throws before probing", args: ["status", "--probe"], files: storeAt({ "{{server}}": null }), differences: ["uncaught"] },
];

export const AREAS: Record<string, TranscriptCase[]> = {
  "5.1a-framework": framework,
  "5.1b-context": context51b,
  "5.1c-api-client": apiClient51c,
};
