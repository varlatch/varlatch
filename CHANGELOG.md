# Changelog

Notable changes to Varlatch, newest first. Varlatch is before 1.0: a minor
release may change the `/v1` API, the CLI, configuration, or the database
schema, and its entry says what to do. Only the latest release receives
fixes.

## Unreleased (0.14.0)

### Coding agents

- **Assisted mode** for a coding agent driving the CLI with your credential
  (Claude Code, Codex, Cursor, and others). Turn it on with `varlatch
  --assisted <command>` in every command, or `VARLATCH_ASSISTED=1`. A coding
  agent's own shell marker (`CLAUDECODE`, `CODEX_THREAD_ID`, `CURSOR_AGENT`,
  `COPILOT_CLI`, `COPILOT_AGENT`, `GEMINI_CLI`, `OPENCODE`, `AGENT`,
  `AI_AGENT`) turns it on as a backstop; `VARLATCH_ASSISTED=0` turns marker
  detection off but never overrides `--assisted`. It changes the CLI's
  behaviour only, never authorization. See
  [assisted mode](docs/reference/assisted-mode.md).
- In assisted mode, `varlatch run` masks Secrets in the command's output by
  default, on a terminal too (the command then writes to pipes). The filter
  also holds inherited values under names Varlatch knows as Secrets. A
  Secret shorter than 8 bytes, which cannot be masked, stops the run with
  status 78 before the command starts, naming the item.
- In assisted mode, `values set` and `values rotate` refuse a Secret's value
  on the command line, storing nothing, and never prompt.
- **Behaviour change for agent sessions:** a `varlatch run` started by a
  coding agent that sets one of those markers now masks Secrets in its
  output, and may stop with status 78 on a Secret shorter than 8 bytes. Set
  `VARLATCH_ASSISTED=0` to keep the previous behaviour in such a shell.
- **The Varlatch skill for coding agents**, built into the CLI: one skill in
  the open Agent Skills format, plus a block for `AGENTS.md`, telling a
  coding agent to use `varlatch --assisted`, never read `.env` files or put
  a secret in a command, and hand the human the steps that are theirs. It
  names no coding agent's tools. See
  [coding agents](docs/reference/coding-agents.md).
- New `varlatch agents install` writes the skill to `.agents/skills/varlatch/`
  and `.claude/skills/varlatch/`, the block to `AGENTS.md` (keeping
  everything outside its markers), and small adapters: an `@AGENTS.md`
  import in an existing `CLAUDE.md`, `context.fileName` in
  `.gemini/settings.json` (only when the edit keeps the file's formatting),
  and `read:` in `.aider.conf.yml` (only when its layout makes appending
  safe). Existing files keep every byte, and `--remove` gives them back
  exactly as they were. `--check` exits 1 when the files differ,
  for CI; `--remove` takes back what it wrote; `--scope user` installs the
  skill for every repository on the machine; `--agent <name>` creates an
  adapter's file.
- New `varlatch agents guide [topic]` prints the skill or one of its
  references, for a coding agent without skill support.
- From the first agent evaluation (it failed; see the coding-agents docs):
  the skill now has the whole onboarding pattern in its main file
  (`import <file> --contract --plain <non-secret> --delete-source`, then
  `contract activate`); requires the human's approval, for the named item
  only, before an existing value is replaced or an item's sensitivity
  changes; gives the human-terminal command for a missing value
  (`varlatch values set <NAME> -e <environment>`); shows `--allow-unmasked`
  before `--`; and says, in the skill and the AGENTS.md block, that inside
  an agent-safe run Placeholders belong in `varlatch --assisted request`
  targets, with an example.
- **Behaviour change:** `varlatch import` takes its options on either side
  of the filename (`import --dry-run .env` exited 64 although the skill
  showed it) and now refuses an unknown option, a missing option value, or
  a second filename with status 64; before, it ignored an option it did not
  know.
- **Behaviour change:** `varlatch values set` and `values rotate` check
  their command line strictly, in every mode, before anything is read,
  prompted for, or written. An unknown option, an option without its value,
  an option given twice (`-e` and `--environment` count as one), an extra
  argument, or a `--grace` that is not a whole number exits 64 and stores
  nothing. Before, an unknown option was taken as the value: in a terminal,
  `values set STRIPE_KEY --env production` stored the literal `--env` in
  the default environment. A value that begins with `-` now goes after
  `--` (`values set OFFSET -- -1`); `--json`, which these commands never
  supported, is refused. `import` also counts `-e` and `--environment` as
  one option.
- `values set` and `values rotate` refusals in assisted mode (a value on
  the command line, or no value) now name the environment in every command
  they suggest, and put first the human-terminal command for a value from
  elsewhere: `varlatch values set <ITEM> -e <environment>`. Before, the
  suggested command had no `-e` and targeted the default environment.
- The exit-78 message for a Secret too short to mask now says every remedy
  is the human's decision, for that item only (replacing the value
  overwrites it), and shows the override as a command with the option
  before `--`. Both suggested commands name the refused run's environment,
  and its server when overridden; the retry also keeps `--strict`,
  `--allow-inherited`, and earlier allowances. Before, a remedy for a
  production refusal replaced or showed the default environment's value.
- From the second agent evaluation (it failed; see the coding-agents docs):
  the AGENTS.md block and the skill now say that a repository with
  `varlatch.toml` needs no `varlatch init`; that a `.env` file may hold
  values not yet in Varlatch or older copies, so names are compared first
  and an existing value is replaced only with the human's approval for that
  item; that `varlatch --assisted validate -e <environment> --json` answers
  whether an environment is ready (listing values does not check the
  Contract); that a run with no stored values gets only what it inherits;
  and that inside an agent-safe run only the listed Placeholders are safe to
  show.
- **Behaviour change:** in assisted mode, `varlatch import` refuses (78,
  storing nothing and deleting nothing) to replace a value the target
  environment already has, unless that item is named with `--replace
  <NAME>`; a leftover file may be an older copy of a value rotated since.
  The dry run, in every mode, marks names the environment already has
  (`existing` in its JSON); an identical plain value, compared in its stored
  form, is not a replacement. A retry after a partial import needs the
  same approval for the values it now finds stored. An import outside
  assisted mode still replaces.
- Inside an agent-safe run, `varlatch context --json` lists the variables
  holding Placeholders (`agentRun.placeholders`, names only), and a nested
  `varlatch run` masks the run's own credentials (the agent-run credential,
  the Broker's proxy credential) in its command's output.
- In assisted mode, `varlatch run` says on stderr, before the command
  starts, when no values are stored in Varlatch for the environment (the
  command gets only what it inherits), and when a `.env` file exists in the
  project that the run does not read (only its existence is checked, never
  its content), with the value-free command to compare its names.
- `varlatch init` in a repository that is already set up still exits 1, and
  now says what to do next: compare a `.env` file's names, or validate an
  environment.
- The skill tells a coding agent that status 69 can come from a sandbox
  blocking the connection, and to ask the human to allow it rather than
  work around it.
- From the third agent evaluation (it failed): the AGENTS.md block again
  has the whole onboarding pattern (compare names first, `--contract`,
  `--plain` only for items the human confirmed are not secret,
  `--delete-source` only once every value is stored, then activate the
  revision), tells the agent never to add `--allow-unmasked` or
  `--no-redact`, and gives the human-terminal command for a value the human
  provides (`varlatch values set <NAME> -e <environment>`).
- **Behaviour change:** assisted mode refuses `--allow-unmasked` and
  `--no-redact` (64, nothing started): showing a Secret is the human's
  decision, in their own terminal. Outside assisted mode,
  `varlatch run --allow-unmasked <NAME> -- <command>` is that override: it
  shows only the named short Secrets and keeps every other known Secret,
  inherited ones included, masked; another short one still stops the run.
  Before, `--allow-unmasked` applied only in assisted mode. The option is
  checked strictly in every mode: a missing name or the
  `--allow-unmasked=<NAME>` spelling exits 64 before anything is fetched,
  never a run without masking. The exit-78 message and this refusal present
  every remedy as the human's command for their own terminal (no
  `--assisted`), with the run's environment, server, and startup options
  (`--strict`, `--allow-inherited`, `--export-context`), and say the agent
  stops and waits.
- **Behaviour change:** `varlatch run` checks its own options, before
  `--`, strictly in every mode, an agent-safe run and a run nested inside
  one included: an unknown option (`--allow-unmask PIN` gave a run that
  masked nothing), an option without its value, an option given twice
  (the repeatable ones excepted), or an argument before `--` exits 64
  before anything is fetched or started. Before, `run` ignored an option
  it did not know. The command's arguments after `--` are passed
  unchanged.
- **Behaviour change:** in assisted mode, `values set` and `values rotate`
  refuse (78, nothing stored) to replace an existing value unless the item
  is named with `--replace <ITEM>`. The check comes after the command line
  (value source, `--generate` form, a missing value: 64, no request) and
  before any value is read, prompted for, generated, or written. A value
  inherited from the parent environment counts as existing, and so does one
  whose existence cannot be checked. `--replace` records the override's
  intent, not an approval. Outside assisted mode they replace as before.
- **Behaviour change:** `varlatch init` now also writes the agent files. Pass
  `--no-agent-files` to skip them. `init` and `agents` refuse an unknown
  option, a missing option value, or an extra argument with status 64,
  before writing anything; before, `init` ignored an option it did not know.

### MCP

- The MCP server ships inside the CLI as `varlatch mcp`, in every release
  and under the CLI's version. See [the MCP server](docs/reference/mcp.md).
- **Removed: secret disclosure through MCP.** `varlatch_disclose_secrets` is
  gone, and `--allow-disclose` and `VARLATCH_MCP_ALLOW_DISCLOSE` are refused
  with status 64. No MCP host can keep a tool result out of the model's
  context.
- `varlatch_set_value` refuses a Secret's value (a sensitive item, an item
  outside the Contract, or any item when the Contract cannot be read) and
  writes nothing.
- Inside an agent-safe run the server uses only the agent-run credential,
  never the operator's stored one, and refuses `--allow-writes`.
- The old `varlatch-mcp` entry point runs the same code with a deprecation
  notice; replace it with `varlatch mcp`.

### CLI

- `--json` on the read commands that lacked it: `values list`, `validate`,
  `org list`, `project list`, `identity list`, `credential list`,
  `audit list`, and `tailnet requirements`, plus `contract push` and
  `import`. Each prints one JSON document with `"version": 1`; no command
  prints a value. See [scripting](docs/reference/scripting.md).
- **Changed exit statuses:** a wrong command line now exits 64 (it exited
  1), not being signed in or a denied request 77, and a server that cannot
  be reached, or is in maintenance or overloaded, 69 instead of 1 or a
  stack trace. Kept as before: `validate` 1 and 2, `scan` 1 (every failure)
  and 2, `types --check` 1, strict startup 78, and the command's own status
  from `varlatch run`. A script that checks for exactly 1 on these errors
  needs updating. A malformed command is 64 whether or not a credential is
  stored, and a proxy's HTML error page keeps its HTTP status (a 502 is 69)
  instead of ending in a stack trace.
- `varlatch --help`, `-h`, `help`, and `<command> --help` (or
  `help <command>`) print on stdout and exit 0; before, `--help` exited 1.
  An unknown command exits 64 with the usage on stderr.

### Values

- `values set` and `values rotate` take the value from `--stdin`,
  `--from-file <path>`, or `--generate hex|base64|base64url:<bytes>` or
  `alnum:<characters>` (from the system's secure random source, never
  shown), or, with no value in a terminal, from a hidden prompt, where
  Backspace removes a whole character and arrow keys are ignored. The value
  then never appears on a command line.
- New `varlatch import <file>` stores a dotenv file's values without
  printing them: names, counts, inferred types, and sensitivity only.
  `--dry-run` shows the plan (and lists names even outside a repository),
  `--contract` adds the file's new items to a Contract revision as Secrets
  unless `--plain <NAME>`, and `--delete-source` deletes the file once every
  value is stored. A file that is not valid UTF-8 is refused before anything
  is stored or deleted. See [importing](docs/reference/import.md).

### Agent-safe runs

- New `varlatch request`, a curl-like client for the Agent inside an
  agent-safe run: `-X`, `-H`, `-d`, `--json`, `-o`, `-i`. It sends each
  request to the run's Broker in the form substitution needs, so the Secret
  is substituted at its targets, TLS is originated by the Broker, and the
  response is scrubbed. Clients that tunnel HTTPS with CONNECT (curl,
  `fetch`, most SDKs) get a 502, whose explanation now names
  `varlatch request`. It refuses outside an agent-safe run. See
  [agent-safe runs](docs/reference/agent-safe-runs.md#sending-requests-through-the-broker).

- The Agent gets its own empty configuration directory
  (`VARLATCH_CONFIG_DIR`, removed when the run ends) and the run's
  identifier (`VARLATCH_AGENT_RUN`). A `varlatch` command the Agent starts
  never reads or writes the operator's credential store: before, a nested
  `varlatch run -- printenv <SECRET>` found the operator's stored credential
  and printed the Secret. A nested `varlatch run` now starts its command
  with the run's environment, Placeholders included, and discloses nothing;
  other commands use the `--agent-metadata` credential or stop.

### Fixes

- An agent-safe run's Broker no longer stops when a client resets its
  connection after a refused `CONNECT` (407 without the proxy credential,
  502 for an allowed destination, 403 with `--agent-network strict`). curl
  does this after the 502; the unhandled socket error ended the Broker, and
  with it every tunnel the Agent's own traffic used. The refusals are
  unchanged.

- Output redaction, response scrubbing, and `varlatch scan` no longer fail
  when a stored Secret holds an unpaired UTF-16 surrogate, which the API
  accepts and UTF-8 cannot carry: such a value is matched as a command
  receives it, with U+FFFD in place of the surrogate. Before, building the
  matcher threw, so `varlatch run --redact` stopped before starting the
  command.

## 0.13.0 (2026-09-30)

### Projects

- A project's display name can now be changed: `varlatch project rename
  <slug> "<new name>"`, **Rename** in the project's menu on the dashboard, or
  `PATCH /v1/organizations/{org}/projects/{project}` (capability
  `projects.rename`). It needs `project.manage`. The slug, which the CLI,
  URLs, contracts and grants use, never changes. The audit event
  `project.renamed` records the previous and the new name.

### Contracts

- A new item type, `integer`, holds whole numbers: ports, counts, sizes. It
  accepts an optional `-` and ASCII digits only, so `3.0`, `3.5`, `+1`, and
  `1e3` are invalid ("must be a whole number"), within the same bound as
  `number` (2^53 - 1). Declare it with `@type=integer` in `.env.schema`, or
  pick it on the dashboard. `number` does not change: existing items keep
  accepting fractions.
- `integer` comes with Contract Semantics version 3, which is version 2 plus
  the new type. A project's first revision now gets version 3. Existing
  Contracts keep their version until you move them.
- An `integer` item in a Contract at version 1 or 2 is refused.
  `varlatch contract push` says so before sending anything and names the
  fix: `--semantics latest`, or the dashboard's move action.
- On the dashboard, a Contract on older rules offers **Move to the newest
  rules**. It creates a revision with the same items at the newest version
  and shows the difference and what changes, and you activate it in a
  separate step. For a Git-managed Contract, later pushes from the
  repository keep the new version.
- Generated types: an `integer` is a `number` in TypeScript and an `int` in
  Python.

### Fixed

- Generated Python configuration (`varlatch types`) no longer fails on a
  whole number written with more than 4300 digits, such as `1` after 4300
  leading zeros. Python refused to convert that much text to an `int`
  (`ValueError`), while the server and the TypeScript module accept it as
  `1`. A `number` or `integer` item now converts the same way in all three.
  Regenerate Python type files to pick up the fix.

### Upgrading

No database migration: 0.13.0 uses migration 22, like 0.12.0 and 0.11.0.

- From 0.12.0 or 0.11.0: download `varlatch-cli-0.13.0.cjs` from the
  `v0.13.0` release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.13.0.cjs upgrade 0.13.0 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. Then replace the host CLI
  with `varlatch-cli-0.13.0.cjs`, or run `varlatch self-update`.
- From 0.10.1 or older: follow the 0.11.0 instructions below with the
  0.13.0 CLI and version.
- 0.13.0 restores everything 0.12.0 restores, and archives from 0.12.0.
- Moving a project to Contract Semantics version 3 is a coordinated step.
  Regenerate type files with `varlatch types`: `--check` fails until you
  do. Upgrade every CLI that runs `varlatch run --strict` for the project,
  CI included: an older CLI refuses a version 3 Contract. Nothing changes
  for a project until you move it.

## 0.12.0 (2026-09-29)

### Type generation

- `varlatch types --out app/varlatch_config.py` generates typed
  configuration for Python: one module, for Python 3.10 or later and the
  standard library only, with a frozen `Config` dataclass, `load_config()`,
  and a lazily loaded `config`. It checks and converts values with the same
  rules as the TypeScript module and the server: a whole number is an `int`,
  a number with a fraction a `float`, and a boolean a `bool`. Sensitive items
  are left out of `repr()`. A URL with an internationalized host name needs
  the optional `ada-url` package to be checked, and is reported, never
  accepted unchecked, without it. See
  [Type generation](docs/reference/type-generation.md#python).
- Python 3.10 is supported until the first release after 31 October 2026,
  when its upstream support has ended; that release requires Python 3.11.

### Fixed

- On Coolify, `varlatch adopt` can now move Convex's trust to `varlatchd`.
  Coolify had put the Convex backend on another network than the name
  `varlatchd`, so the step refused to change anything. The Coolify Compose
  file now puts Convex on the stack's default network, as it already did
  for the dashboard.
- `varlatch doctor` no longer reports the Convex supervisor as stale after
  every Coolify deploy. It compared times, and Coolify rewrites the
  supervisor file, unchanged, after starting the containers. The supervisor
  now records a hash of the file it loaded, and `varlatch doctor` and
  `varlatch upgrade` compare content. A supervisor from an older release is
  still judged by time.
- After a restore, the dashboard and the other remaining services start
  without waiting for varlatchd's Docker health check. On a host where that
  check kept failing, a restore waited up to 10 minutes first.

### Upgrading

No database migration: 0.12.0 uses migration 22, like 0.11.0. Python
generation is entirely in the CLI, so the server does not need to be
upgraded for it.

- From 0.11.0: download `varlatch-cli-0.12.0.cjs` from the `v0.12.0`
  release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.12.0.cjs upgrade 0.12.0 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. Then replace the host CLI
  with `varlatch-cli-0.12.0.cjs`, or run `varlatch self-update`.
- From 0.10.0 or 0.10.1, or older: follow the 0.11.0 instructions below with
  the 0.12.0 CLI and version.
- 0.12.0 restores everything 0.11.0 restores, and archives from 0.11.0.

## 0.11.0 (2026-09-28)

### Contracts

- `.env.schema` conditions name your Varlatch environments directly:
  `@required=env(production, staging)` requires an item in those
  environments, and `@required=tier(production)` in every environment of a
  tier. Names are resolved to environment IDs when you push, and an unknown
  name fails the push and lists the environments that exist. A pushed
  revision keeps the IDs: renaming or deleting an environment later never
  changes it. A later push resolves the names again, so if a name was reused
  by a new environment, that push selects the new one.
- `forEnv(...)` is no longer accepted in `.env.schema`. The parse error names
  the replacement: `@required=forEnv(prod)` becomes
  `@required=env(production)`, using the project's environment names, or
  `@required=tier(production)`.
- A comment after a value is now a comment: `PORT=8080 # listen port` gives
  the default `8080`. Before, the comment became part of the default. A
  decorator after a value, text after a quoted value, and an unterminated
  quote are now errors instead of being read into the default. A `#` with no
  whitespace before it, or inside quotes, is still part of the value.
- The environment-name mapping is removed. It only translated `forEnv(...)`
  names, which schemas no longer use. Removed with it:
  - the `varlatch varlock-mapping` command;
  - the mapping card on the dashboard's contract page;
  - the `GET`, `PUT`, and `DELETE` endpoints under
    `/v1/organizations/{org}/projects/{project}/varlock-mapping`, which now
    answer `404`;
  - the SDK methods `getVarlockMapping`, `setVarlockMapping`, and
    `removeVarlockMapping`.

  Deleting an environment is no longer blocked by a mapping entry. It is
  still blocked while the active contract references the environment.
- Contract revisions record their Contract Semantics version: the rules for
  requiredness, validation, and conversion they are evaluated with. Every
  existing revision is version 1 and keeps its content hash. A new project's
  first revision gets version 2, which adds conversion to typed values and
  bounds numbers: a number whose magnitude exceeds 9007199254740991
  (2^53 - 1) is invalid. A push or edit keeps the active revision's version,
  and `varlatch contract push --semantics latest` moves to the newest.
  Contract revisions in the API carry `semanticsVersion`, and `/v1/meta`
  lists `semanticsVersions`. See
  [Contract Semantics](docs/reference/contract-semantics.md).
- The dashboard's type help now matches the rules. It said booleans accept
  `yes` and `no`, which validation never accepted.
- Validation checks values as `varlatch run` delivers them, with `${NAME}`
  references expanded. Before, it checked the stored text: `${BASE}0` was
  reported as an invalid number although it is delivered as `8080`, and a
  value whose reference stays literal when delivered passed. Such a value
  is now reported as `unresolved`, and `varlatch validate` exits 1, or 2
  when only the caller's missing read access to non-sensitive values keeps
  it literal. Values read only to expand a reference are audited before
  they are decrypted.

### Security

- Every retrieval (effective configuration, disclosure, validation, and
  Capability exercise) reads everything from one read-only database
  snapshot: the organization, project, and environment, authorization
  inputs, the active contract revision, values, and the ciphertext it may
  decrypt. A write, rotation, contract activation, or Grant change that
  commits while a request is in flight is invisible to that request, never
  half-applied.
- Each decryption follows an audit commit that names its exact version, and
  a failed commit stops the request. Values decrypted only to expand
  `${NAME}` references used to be audited after they were decrypted. They
  are now audited before, one reference level at a time.
- Authorization is effective at the snapshot boundary: a revocation that
  commits after a request's snapshot began does not affect that request.
  The next request sees it.
- Server-side sync delivery audits before it decrypts. Each reconcile that
  decrypts values (on a trigger, or the six-hourly repair pass) first
  commits a new `sync.values_decrypted` event naming the exact versions,
  even when it then pushes nothing, and stops if that commit fails. The
  existing `sync.push_attempted` event still precedes every push.
- The agent-safe Broker substitutes a Secret only at the targets you name,
  and only there. Before, it replaced a Placeholder wherever it appeared in
  the headers or a text body sent to an allowed destination, so an Agent
  could have it write a Secret into a field that destination stores or
  publishes. varlatchd records the targets on the Capability when it issues
  it, and the Broker enforces the recorded ones, so the Agent cannot add or
  widen one. Anything unclear where a Secret may go blocks the request, and
  a failed request sends the destination nothing. See
  [Agent-safe runs](docs/reference/agent-safe-runs.md).
- The Broker scrubs responses to the requests it substituted into: a Secret
  the destination echoes back, in its status line, headers, or body, as
  written, JSON-escaped, percent-encoded, or base64-encoded, reaches the
  Agent as its Placeholder. `gzip`, `deflate`, and `br` responses are
  decoded to do so. This is a second line of defense with stated gaps, not
  a guarantee; see [Agent-safe runs](docs/reference/agent-safe-runs.md).
- An agent-safe run removes stored Secrets and Contract Secrets from the
  environment the Agent inherits from your shell. Before, a Secret already
  set in your shell reached the Agent as plaintext.
- A Capability exercise returns only the Secrets the request places. A
  Secret it references is decrypted to expand the placed value, after an
  audit event naming its version, and is not returned.

### Retrieval

- Strict retrieval: `POST
  /v1/organizations/{org}/projects/{project}/environments/{environment}/retrievals`
  with `{"mode": "strict"}` returns, from one snapshot and in one request,
  every value the caller may receive, the state manifest and its
  `stateDigest`, the caller view, the active contract (with
  `contract.read`), and the validation of exactly the values returned. Each
  class of value is authorized separately: without `secret.reveal`, the
  non-sensitive values still arrive and the Secrets are reported as
  withheld. A failure after the snapshot returns an error and no values.
  SDK: `strictRetrieval()`. `/v1/meta` lists `retrieval.strict`.
- Effective configuration responses, and disclosure responses for callers
  who can read metadata, carry the state manifest, `stateDigest`, and a
  caller view (`retrieval.manifest`). The manifest lists the environment,
  the active contract revision and its semantics version, and every item's
  source and version IDs. It holds identifiers only, never values or
  anything derived from them, and its digest is the same for every caller
  looking at the same state. The caller view lists what this caller was not
  given and which references stayed literal for it.

### API

- A disclosure request may declare `"purpose": "scan"`. The disclosure's
  `secret.disclosed` audit event, and any `value.disclosed` event for a
  reference it expands, record it as `purpose`. Only listed purposes are
  accepted; anything else is refused with `VALIDATION_FAILED` before
  anything is audited or decrypted. A purpose grants nothing, and without
  one nothing changes. SDK: `discloseSecrets()` takes `purpose`. `/v1/meta`
  lists `secrets.disclosure-purpose`.
- Strict retrieval takes `{"mode": "preflight"}` (capability
  `retrieval.preflight`): the non-sensitive values and, for a caller with
  `secret.reveal`, a verdict per Secret, never a Secret value. Its responses
  carry `stateDigests`, one digest per category of the state.
- Capability issuance accepts a `precondition` (the state a preflight saw).
  When the state changed, it refuses with the new error code
  `STATE_CHANGED` (HTTP 409), naming only the categories that changed; on a
  match its response adds `preflightItems`: per item, whether it is stored
  and whether the Agent holds `secret.use`.
- Capability issuance requires `targets`: per item, one to four of
  `header:<name>`, `query:<name>`, `json:<pointer>`, and `form:<name>`.
  Transport-owned headers such as `Host`, `Content-Length`, and
  `Content-Type` are refused. The issuance response, every exercise
  response, and the `capability.issued` audit event carry the targets.
- A Capability exercise requires `placements`, the item and target of each
  substitution the Broker makes, and returns only those items. A placement
  the Capability does not hold is denied with the reason
  `placement-not-targeted`, and `capability.exercised` records the
  placements. `/v1/meta` lists `capabilities.targets`.
- `GET /v1/organizations/{org}/projects/{project}/contract/revisions/{revision}`
  returns one stored Contract revision, active or not, with its content hash
  and semantics version. It needs `contract.read`. SDK:
  `getContractRevision()`. `/v1/meta` lists `contracts.revision-by-id`.

### CLI

- `varlatch self-update` replaces the CLI with a release's single-file
  build, as installing it by hand does: it downloads
  `varlatch-cli-<version>.cjs` and `SHA256SUMS`, checks the signature on
  `SHA256SUMS` with cosign when the release is signed, checks the file
  against it, shows what it verified, and asks before replacing the file
  it runs from. `--check` only reports whether a newer release exists
  (`--json` for scripts). It refuses a CLI run from a source checkout, and
  never installs an older release. With `--yes`, a release whose signature
  was not checked needs `--allow-unverified` as well. While the repository
  is private, set `GITHUB_TOKEN` or `GH_TOKEN`. An installation on the same
  host still upgrades with `varlatch upgrade`.
- `varlatch run --strict` starts the command only if the environment it
  would receive satisfies the active Contract. It retrieves everything in
  one request, applies Contract defaults only to items with no stored value
  (never to withheld ones), takes values from your shell only for names
  given with `--allow-inherited NAME`, and validates every value exactly as
  the command will receive it. Any violation (missing, withheld,
  parent-only, invalid, or a `${NAME}` reference left literal, and also no
  active Contract, no `contract.read`, or an unsupported semantics version)
  starts nothing and exits 78, listing every violation by name, never by
  value. The command receives `VARLATCH_RUN_CONTEXT`, which records what the
  server did and how each item was delivered. See
  [Strict startup](docs/reference/strict-startup.md).
- `varlatch run --strict --agent-safe` applies the same checks while the
  Agent receives Placeholders for Secrets. The operator's preflight
  validates each Secret without returning it (it needs `secret.reveal`),
  the Broker's Capability is issued against the state the preflight saw,
  and the Agent starts only if the Agent holds `secret.use`, every Secret
  is valid, and no Contract Secret would come from your shell.
  `--allow-inherited` cannot name a Secret in an agent-safe run.
- `varlatch run --redact` masks the Secrets delivered to the command in
  its stdout and stderr, which become pipes. Each occurrence, as written,
  JSON-escaped, percent-encoded, or in base64 or base64url, becomes
  `[REDACTED:<NAME>]`, and overlapping values become one marker. Output is
  matched as bytes, so binary output passes through unchanged unless it
  contains a Secret. Bytes that could be the start of a Secret wait for the
  command's next write and are never released on a timer: they are
  released unchanged when the output ends, and discarded if the run is
  interrupted. Values shorter than 8 bytes are not masked, and the run
  names them. stdin, signals, and the exit code pass through; the relative
  order of stdout and stderr is not kept. It works with `--strict`, refuses
  to start when stdout or stderr is a terminal, and cannot be combined with
  `--agent-safe`, whose Agent receives Placeholders, not Secrets. See
  [Output redaction](docs/reference/output-redaction.md).
- `varlatch scan --staged` checks what the next commit records, and
  `varlatch scan <path>...` checks build output, for the Secrets of the
  selected environment that your identity may retrieve, at their current
  and retiring versions. The values come from one disclosure, audited with
  `purpose: "scan"`, and stay in memory. The Git index is read, not the
  working tree, so a Secret staged and then edited or deleted is still
  found. Files are scanned as bytes, across line breaks, in the same
  encoded forms that `--redact` masks. Each finding names the file, line,
  column, item, version, and form, never the value or the line. A file
  over the size bounds, or one that cannot be read, is listed as not
  scanned, never as clean. The exit status is 1 for findings and 2 when
  some files were not scanned. `varlatch:allow NAME` markers and a baseline
  file of paths, items, and version IDs accept known occurrences, and
  `varlatch scan --install-hook` installs a pre-commit hook that runs the
  scan. See [Secret scanning](docs/reference/secret-scanning.md).
- `varlatch run --agent-safe` takes `--target NAME=kind:location`
  (repeatable) and `--omit NAME`. Every stored Secret needs one or the
  other. The Agent's environment gains `NODE_USE_ENV_PROXY=1`, so Node's
  `fetch` goes through the Broker, and `NO_PROXY` and `no_proxy` each gain
  the Broker's own address. The run reports blocked requests, stray
  Placeholders, and the inherited Secrets it removed, never values.
- `varlatch types --out <file.ts>` generates one TypeScript module from the
  active Contract Revision, or from `--revision <id>`: a type for every
  Contract item, a type of the non-sensitive items, and the Typed Accessor,
  a small runtime that reads `process.env`, converts values with the
  revision's Contract Semantics, and throws one error that lists every
  problem by item name, never by value. The module is self-contained, so the
  application needs nothing else. Generation needs `contract.read`, makes
  one request, fetches no values, rewrites the file only when it changes,
  and never writes through a symbolic link. `--check` exits 1 when the file
  is stale, for CI. A revision at Contract Semantics version 1 is refused,
  because version 1 defines no conversion. See
  [Type generation](docs/reference/type-generation.md).
- `varlatch run --export-context` gives the command `VARLATCH_RUN_CONTEXT`
  from a default run, with `mode: "exported"`, so the Typed Accessor can
  check requiredness for the environment and tell withheld items from absent
  ones. The run is otherwise unchanged. It needs `contract.read` and an
  active Contract, and fetches the Contract Revision before any Secret is
  disclosed. The context always describes the values the command receives:
  the run checks that the configuration and the disclosure of its Secrets
  saw the same state (the same `stateDigest`), and when a write, rotation,
  deletion, or Contract activation lands between the two requests it makes
  both again, up to three times in all, each time an audited disclosure. If
  they never agree, it starts nothing and exits 1. A run without the flag
  makes the same two requests as before and checks nothing.
- When a signal ends the command, `varlatch run` exits with 128 plus the
  signal's number, as a shell reports it, in every mode: 130 for SIGINT
  (Ctrl-C), 129 for SIGHUP, 131 for SIGQUIT, 139 for SIGSEGV. Before, every
  signal except SIGKILL gave 143, the status for SIGTERM, so a run
  interrupted with Ctrl-C looked like a run that was stopped.
- `varlatch run` forwards SIGHUP, SIGQUIT, SIGUSR1, and SIGUSR2 to the
  command, as well as SIGINT and SIGTERM, and keeps running until the
  command ends. A service manager can now reload a service it starts
  through `varlatch run` (`ExecReload=kill -HUP $MAINPID`), and a log
  rotation signal reaches the service. On Windows only SIGINT and SIGTERM
  are forwarded.

### Upgrading

Database schema: migrations 21 and 22.

- From 0.10.0 or 0.10.1: download `varlatch-cli-0.11.0.cjs` from the
  `v0.11.0` release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.11.0.cjs upgrade 0.11.0 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. The upgrade captures and
  verifies an archive while the installation keeps serving, applies
  migrations 21 and 22, and completes only once the new release passes its
  health gate.
- From 0.8.0 or 0.9.0: the same command. As for 0.10.0, the archive is taken
  with the installation briefly paused, so plan a short maintenance window.
  From the published 0.7.0, the offline path described under 0.8.0 still
  applies with this CLI.
- Then replace the host CLI with `varlatch-cli-0.11.0.cjs`. Agent-safe runs
  need the 0.11.0 CLI and server together (see below).
- 0.11.0 restores archives from 0.7.0 (migrations 16 and 18), 0.8.0
  (migrations 18 and 19), 0.9.0 (migrations 19 and 20), 0.10.0 and 0.10.1
  (migration 20), and builds made between 0.10.1 and 0.11.0 (migrations 21
  and 22).

The changes below need attention when you upgrade.

- **`varlatch run` exits 130, not 143, when interrupted with Ctrl-C.** Any
  signal that ends the command now gives 128 plus its number. SIGTERM still
  gives 143 and SIGKILL 137. A script that looks for 143 to detect an
  interrupted run should look for 130, or for any status above 128.
- **SIGHUP, SIGQUIT, SIGUSR1, and SIGUSR2 sent to `varlatch run` reach
  the command.** Before, they ended `varlatch run` itself and left the
  command running without it. A command that does not handle one of them
  now ends by it, with 128 plus its number.
- **Agent-safe runs need targets.** A run in which a stored Secret has
  neither `--target` nor `--omit` does not start; add
  `--target NAME=header:authorization` (or `query:`, `json:`, `form:`) for
  each Secret the Agent uses, and `--omit NAME` for the rest. Requests that
  relied on substitution into a `text/*` body, or into a header not known in
  advance, have no replacement.
- Agent-safe runs need a 0.11.0 server and CLI together. varlatchd refuses
  to issue a Capability without targets, naming CLI 0.11.0, and a 0.11.0
  CLI refuses an older server. A Capability issued before the upgrade has no
  targets and is refused at its next exercise with the reason
  `capability-without-targets`; restart the agent-safe run with the new
  CLI. Revocation and expiry work as before. The CLI refuses an older server
  for every agent-safe run, including one with no Secrets, because removing
  inherited Secrets relies on the server's account of the active Contract.
- `--target` and `--omit` must name Secrets stored in the environment. A
  name that is unknown, not stored there, or not a Secret is a usage error,
  and nothing starts.
- A Secret with a `json:` or `form:` target constrains every request that
  carries its Placeholder: if such a request has a body, it must be a valid
  body of that kind (a matching `Content-Type`, UTF-8, no
  `Content-Encoding`), even when the Placeholder is only in a header.
  Otherwise the Broker answers `403`. Give body targets only to Secrets the
  Agent sends in bodies.
- With an active Contract, an agent-safe run needs `contract.read`, to know
  which inherited names are Secrets. Without it the run does not start.
- Responses to substituted requests change on the wire: the request asks
  for identity content without `Range`; a response that is coded, has no
  length, or is over 2 MiB arrives chunked and uncoded, without validators
  or digests; a coding other than `gzip`, `deflate`, or `br` is a `502`. A
  substituted response is cut off after 64 MiB of decoded content or 120
  seconds without data from the destination, so long-polling and
  server-sent events streams need a heartbeat more often than that.
- A Node Agent that set `HTTPS_PROXY` and used `fetch` for an allowed
  destination now gets the Broker's `CONNECT` refusal instead of reaching
  the destination directly with the Placeholder. Send absolute-URI requests
  to the Broker instead. With `--agent-network strict`, Node's `fetch` to
  other destinations is now blocked like other traffic, except for hosts
  your shell's `NO_PROXY` or `no_proxy` exempts: those exemptions are kept
  and still bypass the Broker. The run adds only the Broker's own address,
  and a spelling your shell did not set becomes that address alone.
- Every `varlatch run`, including a default one, now removes a
  `VARLATCH_RUN_CONTEXT` inherited from an outer run. This is the one change
  to a default run. The name is reserved: the server refuses a Contract item
  or a stored value called `VARLATCH_RUN_CONTEXT`.

- A disclosure or Capability exercise whose references are nested now
  records one `value.disclosed` event with `mode: "reference-expansion"` per
  reference level, instead of one for all levels.
- The upgrade drops existing environment-name mapping entries (a new schema
  migration). Contract revisions are unchanged: they store environment IDs,
  not names. Audit history keeps its `contract.varlock_mapping_set` and
  `contract.varlock_mapping_removed` events. Backups taken with 0.10.0 or
  0.10.1 restore into this release and are migrated forward.
- Existing projects keep version 1 rules. To adopt version 2, push with
  `varlatch contract push --semantics latest` and review the activation,
  which shows the version change.
- Validation results can change for values that contain references: they
  are now checked as delivered, and a reference that stays literal makes the
  report invalid. The validation report gains an `unresolved` list.
- A `.env.schema` with comments after values gives different defaults when
  pushed with this release's CLI. Review the activation's changes before
  activating. A file that uses `forEnv(...)` must switch to `env(...)` or
  `tier(...)` first.

## 0.10.1 (2026-09-27)

### Fixed

- A restore now leaves the whole installation running. Before, it started
  only the database, varlatchd, and Convex, so after restoring onto a stopped
  or new host the dashboard and the ingress proxy stayed down until you ran
  `docker compose up -d`, and `varlatch doctor --gate` failed. When restore
  finishes it now points you to `varlatch doctor` and a fresh archive. On a
  slow host it no longer reports that not every service started when
  varlatchd's health check is still recovering from the restore.
- Installations that use the tailnet ingress with secrets in files no longer
  print `The "VARLATCH_RUNTIME_PASSWORD" variable is not set` on every
  Compose command.
- `varlatch upgrade --release-dir` no longer says it is fetching the release
  from GitHub. It reads only the files in that directory.
- `varlatch upgrade` now runs the new release's own upgrade gate when Docker
  runs in a user namespace, as rootless Docker does. It copied that
  release's CLI out of the running varlatchd container, which fails there
  because Docker cannot remount the container's read-only secret files, and
  quietly used the gate of the CLI you ran instead. It now copies the CLI
  from varlatchd's image.

### Upgrading

No database migration: 0.10.1 uses migration 20, like 0.10.0.

- From 0.10.0: download `varlatch-cli-0.10.1.cjs` from the `v0.10.1`
  release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.10.1.cjs upgrade 0.10.1 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. Then replace the host CLI
  with `varlatch-cli-0.10.1.cjs`.
- From 0.8.0 or 0.9.0: follow the 0.10.0 instructions below with the 0.10.1
  CLI and version.
- 0.10.1 restores everything 0.10.0 restores, and archives from 0.10.0.

## 0.10.0 (2026-09-25)

**Before upgrading:** validation changed. `varlatch validate` and the
dashboard now evaluate only the items the caller may read, and report the
rest as not evaluated. The CLI then prints `INCOMPLETE` and exits with a new
code, `2`, where it used to report a verdict. CI jobs that validate with an
identity lacking `secret.reveal` or `config.value.read` need those actions
granted, or must treat exit code `2` as incomplete. See Security and
Upgrading below.

### Project

- Varlatch is open source: AGPL-3.0-or-later for the secret store daemon, the
  dashboard, and the dashboard backend functions, and Apache-2.0 for
  everything else. See [`LICENSE`](LICENSE).
- Vulnerabilities are reported privately, as [`SECURITY.md`](SECURITY.md)
  describes.

### Security

- Validation no longer reveals anything about values you cannot read. Before,
  anyone who could see an environment could validate it and learn whether
  each value, Secrets included, passed its contract checks. Now each check
  needs the right to read what it describes: `secret.reveal` for Secrets
  (including any Tailnet Requirement), `config.value.read` for other values,
  and `config.metadata.read` to report missing items. `secret.use` alone is
  not enough.
- Items you cannot read are listed as not evaluated, with the permission they
  need, and an environment is reported as valid only when every item was
  checked. `varlatch validate` prints `INCOMPLETE` and exits with a new code,
  `2`, in that case; `1` still means invalid. The dashboard shows
  valid, invalid, or incomplete.
- Every decryption for validation is recorded in the audit log first
  (`secret.validated` and `value.validated`, naming the item versions). The
  results themselves are never logged.

### Self-hosting

- `varlatch setup` creates an installation interactively or from flags:
  generated secrets kept in files rather than environment variables, an
  escrow of the root key, and a choice of access. **Public** gets HTTPS
  certificates automatically, **tailnet** serves HTTPS on your Tailscale
  network only, and **external** sits behind your own proxy.
- `varlatch adopt` brings an existing installation under the same
  management, step by step and reversibly.
- `varlatch doctor` checks an installation's health without changing
  anything. `varlatch upgrade` completes only when the new release passes its
  health gate, and refreshes the access overlays the installation uses.
- The dashboard reaches its live backend on the same origin (`/convex`), so an
  installation needs one public address. The dashboard and the API keep
  working while the live backend is down, and fail fast instead of hanging.
- The Coolify deployment is generated from the canonical Compose files, and
  each service receives only its own secrets.

### Backups

- Backups no longer pause the service: the secret store keeps serving while a
  consistent snapshot is taken.
- Archives hold the secret store only. The dashboard backend is rebuilt on
  restore instead of restored, which makes archives smaller and restores
  simpler.
- API clients, the CLI, and the dashboard wait out maintenance windows and
  say so, instead of failing.

### Releases

- Images for linux/amd64 and linux/arm64, each with a provenance attestation
  and an SBOM. Releases from the public repository sign the images and
  `SHA256SUMS`; [verifying a release](docs/operations/verify-release.md)
  explains how to check.
- `THIRD-PARTY-NOTICES.md` lists every third-party component with its
  license, in each image and release.
- Smaller images: the daemon image no longer ships test tooling, and the
  deploy image installs only runtime dependencies.
- `pnpm dev:up` runs the whole stack from a checkout, with synthetic data.

### Fixed

- The values editor commits against the versions you reviewed. Before, when
  another client changed a value while the review dialog was open, the
  dashboard's live update made your commit overwrite that change without a
  conflict. Now it is rejected as changed since review, and your draft is
  kept.

### Upgrading

Releases now come from `varlatch/varlatch` on GitHub. Database schema:
migration 20.

- From 0.8.0 or 0.9.0: download `varlatch-cli-0.10.0.cjs` from the `v0.10.0`
  release, check it against `SHA256SUMS`, and run `node
  varlatch-cli-0.10.0.cjs upgrade 0.10.0 --dir /YOUR/COMPOSE/DIRECTORY
  --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`. The upgrade captures and
  verifies an archive before applying migration 20, and completes only once
  the new release passes its health gate. That archive is still taken the
  old way, with the installation briefly paused, because online capture
  needs 0.10.0 to be running; plan a short maintenance window.
- From the published 0.7.0: the offline path described under 0.8.0 still
  applies with this CLI.
- Then replace the host CLI with `varlatch-cli-0.10.0.cjs`.
- Installations set up by hand keep working as they are. `varlatch doctor`
  lists them as not adopted, and `varlatch adopt` moves them to managed
  configuration one reversible step at a time.
- 0.10.0 restores archives from 0.7.0 (migrations 16 and 18), 0.8.0
  (migrations 18 and 19), 0.9.0 (migration 19), and builds made between
  0.9.0 and 0.10.0 (migration 20).

CI jobs that run `varlatch validate` with an identity that lacks
`secret.reveal` or `config.value.read` on the environment now get exit code
`2` (incomplete) instead of a verdict. Grant the identity those actions if it
should validate every item.

## 0.9.0 (2026-09-23)

### Machine identities

- Revoke individual service and OIDC credentials of a machine identity,
  including your own, and list credential metadata.
- Retire an identity, revoking all of its credentials in one transaction,
  and reactivate it later; its credentials stay revoked. Identities are never
  deleted.
- Rename identities; the audit log records the old and the new name.
- Last-used times for credentials and identities.
- CLI: `varlatch identity list|rename|retire|reactivate` (retiring requires
  `--confirm <name>`) and `varlatch credential list|revoke`. The dashboard's
  Machines tab has the same actions.

Database schema: migration 19.

### Backup operations

- The operator CLI is a release asset, `varlatch-cli-0.9.0.cjs`: one file,
  Node 22 or newer, no checkout or build. The varlatchd image carries the same
  file at `/opt/varlatch/varlatch.cjs`.
- The reference host job verifies every archive right after capture, and a
  failed check fails the run.
- The remote-copy warning appears only when the latest remote check failed
  or none passed within 30 days.
- Reference systemd tooling (`infra/host-backup`) takes its scripts and CLI
  from the running release, so upgrades need no host step.
  `verify-remote.sh` verifies the remote copy periodically.
- The SDK retries `503 MAINTENANCE` responses and honors `Retry-After`.
- PostgreSQL's healthcheck probes over TCP, closing a first-boot race, and
  the dashboard and Tailscale containers gained healthchecks.

### Upgrading

- From 0.8.0: download `varlatch-cli-0.9.0.cjs`, check it against
  `SHA256SUMS`, and run `node varlatch-cli-0.9.0.cjs upgrade 0.9.0 --dir
  /YOUR/COMPOSE/DIRECTORY --bek-file /YOUR/BEK --kek-file /YOUR/ROOT-KEK`.
  The upgrade captures and verifies an archive before applying migration 19.
- From 0.7.0: the offline path described under 0.8.0 applies unchanged with
  this CLI.
- Then replace the host CLI with `varlatch-cli-0.9.0.cjs`. With the reference
  host tooling, reinstall `run.sh` and `verify-remote.sh` from this release
  once; later releases update them automatically.
- 0.9.0 restores archives from 0.7.0 (migrations 16 and 18) and 0.8.0
  (migration 18).

## 0.8.0 (2026-09-22)

### Installation backup and recovery

- Encrypted backups that only the operator can create, standalone
  verification, delivery to S3-compatible storage, and restore onto a fresh
  host.
- A restore stays isolated through daemon failures and host restarts, and an
  interrupted restore can be retried.
- The Installation settings page shows delivery and verification for each
  archive.
- Verification checks integrity, compatibility, and that the keys match. It
  does not load the dumps, so it is no substitute for a restore rehearsal
  against your own storage.

### Upgrading

- Keep the root key and a separate backup encryption key off the host.
  Recovery needs both keys, the archive, and a compatible release.
- Upgrade with the 0.8.0 CLI. From the published 0.7.0 (migration 16), the
  upgrade takes an offline capture: services stay stopped until it succeeds,
  so plan downtime. A source-built 0.7.0 at migration 18 takes an ordinary
  capture. Other versions are refused. The target schema is migration 18, on
  PostgreSQL 17.
- Both Compose variants need the shared `varlatch-state` volume and the
  Convex supervisor file.
- Turn off automatic deployments that change the schema, for example in
  Coolify. The old unencrypted `pg_dumpall` job is removed; existing dump
  volumes are kept.
- To retry a failed upgrade, restore the original archive. Never run older
  binaries against a database that has been migrated forward.

See [backups and recovery](docs/operations/backup.md) and the
[first-time B2 setup](docs/operations/backup-b2.md).

## 0.7.0 (2026-09-17)

- **Sync Targets.** varlatchd pushes an environment's configuration to other
  platforms, so a rotation reaches every place that uses the value. A
  platform connection authenticates once per account; a sync target binds one
  environment to one destination as an explicit, audited disclosure, allowed
  only for someone who may read those values.
- Pushes converge on the destination's state, deletions are opt-in, and a
  periodic repair pass fixes drift.
- Adapters for GitHub Actions (encrypted secrets), Coolify (host-pinned, with
  optional redeploy), and Convex. There is deliberately no generic
  push-to-URL.
- Sync is opt-in at every level. `VARLATCH_SYNC=off` disables it for an
  installation, and `varlatch sync push` pushes from the CLI where the server
  may not reach out.
- Dashboard: integrations per environment with delivery state per value, and
  connections per organization.

## 0.6.0 (2026-09-16)

- Roles, groups, teams, requirements, and audit webhooks can be edited in
  place, protected against concurrent edits, with the old and new values in
  the audit log. Editing a role updates every grant that uses it.
- Changing a grant replaces it atomically, and authorization audit events
  record the facts each decision used.
- Search configuration item names across projects. Search matches names only,
  never values, and only in environments you may read.

## 0.5.0 (2026-09-16)

- **Rotation without downtime.** A rotated secret keeps its previous value
  available alongside the new one for a grace period.
- **Custom roles, groups, and teams.** A role is a named set of actions, a
  group a set of identities, and a team a group that owns projects. All of
  them resolve to plain grants, so access stays default-deny.

## 0.4.0 (2026-09-16)

- OIDC sign-in for CI, with GitHub Actions supported out of the box.
- Time limits and use budgets for service credentials.
- Signed audit webhooks.
- Value references (`${NAME}`), expanded on the server.
- Escrow for the root key: a passphrase-protected export, or k-of-n shares.
- An MCP server, `@varlatch/mcp-server`, read-only by default.
- The dashboard updates live from the audit stream.

## 0.3.1 (2026-09-09)

- `varlatch run --agent-metadata`: the broker gives an agent a read-only
  credential, valid for at most an hour, to read configuration metadata,
  revoked when the run ends.

## 0.3.0 (2026-09-09)

- **The credential broker.** `varlatch run --agent-safe` starts an agent with
  placeholders and no Varlatch credential. A local broker substitutes the real
  values only in requests to allowed destinations, and varlatchd authorizes
  and audits every use before decrypting anything.
- The dashboard lists and revokes the capabilities agents hold.

## 0.2.0 (2026-09-09)

- The complete dashboard: changes applied as one set, explicit disclosure of
  secrets, a matrix of values per environment, access management for people
  and machines, the audit timeline, the contract editor, a command palette,
  passkey management, and a getting-started checklist.
- Grants scoped to a single environment.

## 0.1.0 (2026-09-08)

The first release:

- The encrypted secret store, with `kek verify` for the root key.
- Passkey-only sign-in, with bootstrap, recovery, and invitations as
  enrollment links.
- Grants and requirements, including retrieval restricted to your Tailscale
  network.
- Configuration contracts, managed in the dashboard or kept in the
  repository, with validation.
- The append-only audit log with NDJSON export.
- The `/v1` API, the SDK, and the CLI, including sign-in through the browser.
- The dashboard, with its live backend on Convex.
- Deployment with Docker Compose or Coolify, and digest-pinned release images.
