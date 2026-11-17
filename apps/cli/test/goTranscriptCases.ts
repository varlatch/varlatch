// SPDX-License-Identifier: Apache-2.0
import type { TranscriptCase } from "./goKit.js";

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

export const AREAS: Record<string, TranscriptCase[]> = {
  "5.1a-framework": framework,
};
