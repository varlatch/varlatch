# Scripting the CLI: JSON output, exit statuses, and help

The `varlatch` CLI is meant to be driven by scripts, CI, and coding agents
as well as people. For them it offers JSON output on every read command,
distinct exit statuses, and help that never fails.

## JSON output

Add `--json` to print one JSON document on stdout instead of the human
format. Diagnostics stay on stderr. Every document has `"version": 1`; a
change that removes or renames a field raises it. The human formats do not
change either: scripts that parse them keep working.

| Command | Document |
| --- | --- |
| `varlatch status --json` | stored credentials and the repository context |
| `varlatch context --json` | the resolved context |
| `varlatch env list --json` | `environments`: name, tier, kind, selected |
| `varlatch values list --json` | `environment`, `items`: name, sensitive, source (never a value) |
| `varlatch validate --json` | `environment`, `result` (`valid`, `invalid`, `incomplete`), `complete`, `missing`, `invalid`, `unresolved`, `notEvaluated`, `exitCode` |
| `varlatch import <file> --json` | `file`, `dryRun`, `target`, `offline`, `items` (name, type, sensitive, inContract, line), `references`, `contract` (newItems, revision), `stored`, `deleted` (never a value) |
| `varlatch contract push --json` | `revision`: id, contentHash, active, semanticsVersion |
| `varlatch contract show` | the active revision (always JSON) |
| `varlatch org list --json` | `organizations`: id, slug, name |
| `varlatch project list --json` | `organization`, `projects`: slug, name, contractAuthority |
| `varlatch identity list --json` | `organization`, `identities`: id, name, kind, retired, lastSeenAt |
| `varlatch credential list <identity> --json` | `identity`, `credentials`: id, kind, name, createdAt, expiresAt, revokedAt, lastUsedAt |
| `varlatch audit list --json` | `organization`, `events`: the audit events as the API returns them |
| `varlatch tailnet requirements --json` | `organization`, `requirements`: as the API returns them |
| `varlatch scan --json` | findings and files not scanned; see [secret scanning](secret-scanning.md) |
| `varlatch doctor --json` | the installation health report |
| `varlatch self-update --check --json` | the available release |
| `varlatch login --start --json` | `verificationUri`, `userCode`, `expiresAt` (never the sign-in's private device code) |
| `varlatch login --wait --json` | `state`: `signed-in` (with `credentialId`, `expiresAt`), `pending`, `denied`, `expired`, or `consumed` (with `credentialId`) |

`varlatch audit export` always prints NDJSON.

## Exit statuses

| Status | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | Any other failure: a server error, a file that cannot be read, a failed write. |
| 64 | The command line is wrong: an unknown command or subcommand, a missing argument, flags that conflict, or a value given the way assisted mode refuses. Checked before any credential is needed, so it is 64 whether or not you are signed in. Nothing was changed. |
| 69 | The server cannot be reached, or is in maintenance or overloaded (502, 503, 504), including an error page from a proxy in front of it. Try again later. |
| 75 | `varlatch login --wait` reached its deadline while the sign-in still waits for approval. The sign-in is kept: run `--wait` again. |
| 77 | Not authenticated, or the server denied the request (401, 403). |
| 78 | Strict startup found a violation, or assisted mode cannot mask a Secret shorter than 8 bytes. The command was not started. |

These keep the meanings they always had:

- `varlatch validate`: 1 when the environment is invalid, 2 when not every
  item could be evaluated with this identity's access. With `--json` too.
- `varlatch scan`: 1 for findings or when the scan could not run, for any
  reason; 2 when some files were not scanned.
- `varlatch types --check`: 1 when the file is stale or missing.
- `varlatch login --wait`: 0 once the credential is stored; 75 when the
  sign-in is still waiting for approval at the deadline (60 seconds, or
  `--timeout` up to 600); 77 when it was denied, expired, or already
  collected; 69 when the server cannot be reached (the sign-in is kept). It
  never exits 0 before a credential is stored.
- `varlatch request`: 0 when the destination answered, whatever the HTTP
  status (as curl), and the response was written whole; 1 when the Broker
  refused the request, or the response was cut off or could not be written;
  77 when the Broker did not accept the per-run proxy credential; 69 when the
  Broker cannot be reached.
- `varlatch run`: once the command has started, the command's own status
  (128 plus the signal's number when a signal ended it). Before that, the
  statuses above: a run refused for its flags exits 64, one that cannot
  authenticate 77. Its own options, before `--`, are checked strictly in
  every mode before anything is fetched or started: an unknown option
  (a misspelling such as `--allow-unmask`, or `--environment=<name>`, which
  is not supported), an option without its value, an option given twice
  (`--allow-unmasked`, `--allow-inherited`, `--allow-host`, `--target`, and
  `--omit` repeat), or an argument before `--` exits 64. So does an
  `--omit` name that is neither stored in the environment nor in its
  Contract, checked before the command starts (in a default run, before any
  Secret is disclosed). Everything after `--` goes to the command unchanged.

## Help

- `varlatch --help`, `varlatch -h`, `varlatch help`, and `varlatch` alone
  print the usage on stdout with status 0.
- `varlatch <command> --help` and `varlatch help <command>` print that
  command's entries, also with status 0, and contact no server.
- A `--help` after `--` in `varlatch run -- <command>` belongs to the
  command.
- An unknown command exits 64, with the usage on stderr.
