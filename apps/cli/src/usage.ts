// SPDX-License-Identifier: Apache-2.0

/**
 * The CLI's usage text, and per-command help cut from it: `varlatch --help`
 * prints all of it, `varlatch <command> --help` the entries for that
 * command, both on stdout with status 0 (ADR-0043 Decision 10).
 */
export const USAGE = `varlatch — self-host-first secrets and configuration

Usage:
  varlatch <command> --help                            # one command's usage (also: varlatch help <command>)
  varlatch --assisted <command>...                      # a coding agent drives the CLI (or VARLATCH_ASSISTED=1):
               run masks Secrets in the command's output by default and refuses one too short to mask
               (exit 78; --allow-unmasked <NAME> is the human's override, --no-redact turns masking off);
               values set/rotate never take a Secret's value from the command line
  varlatch login --server <url> [--ttl <s>]              # browser passkey sign-in
  varlatch login --server <url> --token <credential>
  varlatch login --server <url> --oidc --org <organization> [--audience <aud>] [--oidc-token <jwt>] [--ttl <s>]
  varlatch logout [--server <url>|--all]                 # revokes server-side, removes locally
  varlatch status [--json] [--probe]                     # stored credentials + repo context; offline unless --probe
  varlatch init --org <slug> --project <slug> [--server <url>]
  varlatch context [--json]
  varlatch env <use <name>|list [--json]>
  varlatch run [-e <env>] [--export-context] [--redact] [--no-redact] [--allow-unmasked <NAME>]... -- <command> [args...]
               (--export-context: also give the command VARLATCH_RUN_CONTEXT, names only, for the Typed Accessor;
                --redact: mask the Secrets delivered to the command in its piped stdout and stderr,
                refused when either is a terminal, and with --agent-safe)
  varlatch run --strict [--allow-inherited <NAME>]... [--redact] -- <command> [args...]
               (validate exactly what the command receives; exit 78 and start nothing on any violation;
                combine with --agent-safe for the agent-safe preflight: Secrets stay placeholders)
  varlatch run --agent-safe --agent <identity> --allow-host <host[:port]>...
               --target <NAME=header:<name>|query:<name>|json:<pointer>|form:<name>>... --omit <NAME>...
               [--broker-credential-file <path>] [--agent-network strict] [--ttl <s>]
               [--agent-metadata] -- <command>...
               (every stored Secret needs a --target or an --omit; it is substituted only there; the Agent gets its own
                empty configuration directory, so a varlatch command it starts never uses the operator's credential)
  varlatch request [-X <method>] [-H '<name>: <value>']... [-d <data>|@<file>|@-] [--json <data>|@<file>|@-]
                   [-o <file>] [-i] <https-url>
               (inside an agent-safe run: send the request through the Broker, which substitutes Secrets at their
                targets and scrubs the response; exit 0 on any response, 1 when the Broker refuses, 69 unreachable)
  varlatch validate [-e <env>] [--json]  (exit 1 invalid; 2 incomplete: items this identity may not read)
  varlatch values <set <ITEM> [<value>]|list [--json]|delete <ITEM>|rotate <ITEM> [<new-value>] [--grace <s>]|rotate-complete <ITEM>>
                  set/rotate: --stdin | --from-file <path> | --generate <hex|base64|base64url:<bytes>|alnum:<chars>>,
                  or no value in a terminal for a hidden prompt
  varlatch import <file> [--dry-run] [--contract [--plain <NAME>]...] [--delete-source] [--json]
               (store a dotenv file's values without printing them; --contract adds new items to a Contract
                revision, Secrets unless --plain; --delete-source removes the file once every value is stored)
  varlatch contract <push --schema <.env.schema> | push --file <json> | activate <rev> | show>
                   push [--semantics <version|latest>]   (pin Contract Semantics; default keeps the active version)
                   push [--json]                         (the new revision as JSON; show always prints JSON)
  varlatch types --out <file.ts|file.py> [--revision <id>] [--check]
                 (one TypeScript or Python module, by extension, with typed config and the Typed Accessor,
                  from the active Contract; --check exits 1 when the file is stale)
  varlatch sync push --platform <github-actions|coolify|convex> --base <owner|https://origin>
                     (--repo <name> [--gh-environment <name>] | --app <uuid> [--build-time true|false]
                      | nothing for convex: --base is the deployment URL)
                     [--token-env VAR] [--map NAME[=DEST]]... [--exclude NAME|PREFIX*]... [-e <env>]
                     # client-side push for installations without server egress (ADR-0031)
  varlatch admin backup create|verify|restore|status [--dir <compose-directory>]
  varlatch setup [--dir <compose-directory>] [--ingress public|tailnet|external] [--public-url <url>]
                 [--tailnet-machine <name>] [--tailscale-auth-key-file <f>] [--port <web-port>] [--no-wait]
                 [--escrow passphrase|shamir|copy] [--escrow-passphrase-file <f>] [--attest]
                                                       # install: one command, resumable
  varlatch adopt [--dir <compose-directory>] [--apply] [--only <step>] [--revert <step>] [--secrets-dir <dir>]
                                                       # existing installation → managed, step by step
  varlatch doctor [--dir <compose-directory>] [--json] [--wait <s>] [--gate]
                                                       # read-only installation health on this host
  varlatch scan (--staged | <path>...) [-e <env>] [--json] [--baseline <file>] [--write-baseline]
                [--max-file-size <size>] [--max-total-size <size>]
               (look for this identity's Secrets in staged files or build output; one audited disclosure;
                exit 1 findings, 2 some files not scanned; never prints values or line contents)
  varlatch scan --install-hook [-e <env>]              # pre-commit hook running varlatch scan --staged
  varlatch invite <name> [--role member|admin]
  varlatch tailnet <require --tailnet <tn> --tags tag:prod|requirements [--json]|remove <id>>
  varlatch audit <list [--json]|export>
  varlatch org <list [--json]|create <slug> [name]> [--server <url>]
  varlatch project <create <slug> --org <org> --server <url> [--managed]|list [--json]|rename <slug> <new-name>>
  varlatch env-create <name> --tier <tier> | --parent <env> [--kind personal|preview]
  varlatch env-delete <name> [--confirm <name>]        # --confirm required for production-tier roots
  varlatch identity <list [--json]|rename <id> <new-name>|retire <id> [--confirm <name>]|reactivate <id>>
                                                       # --confirm required: retire revokes all credentials
  varlatch credential <list <identity-id> [--json]|revoke <identity-id> <credential-id>>
  varlatch --version                                   # CLI release; refresh it after every upgrade
  varlatch self-update [<version>] [--check [--json]] [--yes [--allow-unverified]] [--repo <owner/repo>]
                                                       # replace this CLI with a release build (checksum, signature)
  varlatch upgrade [<version>] [--dir <compose-dir>] [--check] [--repo <owner/repo>]
                   [--bek-file <path> | --bek-passphrase-file <path>] --kek-file <path> [--yes]
                   # backup-gated compose upgrade on this host (run where docker-compose.yml lives)

Exit status: 0 success; 1 failure; 64 the command line is wrong; 69 the server cannot be reached or is in
maintenance; 77 not authenticated or denied; 78 strict startup violation, or assisted mode cannot mask a Secret.
Kept as before: validate 1 invalid, 2 incomplete; scan 1 findings, 2 not everything scanned; types --check 1 stale;
run returns the command's own status once the command has started.`;

/**
 * The usage entries for `command`: each entry starts at a line
 * `  varlatch <command> ...` and runs through the more deeply indented
 * lines under it. Null when the command has none.
 */
export function commandHelp(command: string): string | null {
  const lines = USAGE.split("\n");
  const entries: string[][] = [];
  let current: string[] | null = null;
  for (const line of lines) {
    const start = /^ {2}varlatch (\S+)/.exec(line);
    if (start) {
      current = start[1] === command ? [line] : null;
      if (current) entries.push(current);
    } else if (current && /^ {3,}\S/.test(line)) {
      current.push(line);
    } else {
      current = null;
    }
  }
  if (entries.length === 0) return null;
  return ["Usage:", ...entries.flat()].join("\n");
}
