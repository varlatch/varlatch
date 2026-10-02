# Assisted mode: a coding agent driving the CLI

When a coding agent such as Claude Code, Codex, or Cursor runs `varlatch`
commands for you, it uses your own credential, and everything a command
prints goes into what the agent reads. Assisted mode keeps Secret values out
of that output by accident-proofing the commands an agent uses:

- `varlatch run` masks Secrets in the command's output by default, and
  refuses to start when it cannot mask one.
- `values set` and `values rotate` never take a Secret's value from the
  command line, and never prompt.
- `values delete` deletes only an item named again with `--confirm`.
- `login` with no sign-in method starts a device sign-in that the human
  approves in a browser, instead of waiting for a browser on this machine.

Assisted mode changes only what the CLI does on your machine. It never
changes what you are allowed to do, and the server never sees it.

## Turning it on

```
varlatch --assisted <command> [args...]
```

- **`--assisted` is the documented form.** Put it in every command: many
  coding agents start a fresh shell for each command, so an exported variable
  does not carry over. The option may appear anywhere before a `--`, and it
  works in every shell, including PowerShell.
  The [Varlatch skill](coding-agents.md), which `varlatch init` and
  `varlatch agents install` put where coding agents look, tells them to.
- **`VARLATCH_ASSISTED=1`** turns it on too, for tools that can set the
  environment of every shell an agent starts.
- **Coding agents' own markers are a backstop.** The CLI also enters
  assisted mode when it sees one of the variables coding agents set in their
  shells: `CLAUDECODE`, `CODEX_THREAD_ID`, `CURSOR_AGENT`, `COPILOT_CLI`,
  `COPILOT_AGENT`, `GEMINI_CLI`, `OPENCODE`, `AGENT`, or `AI_AGENT` (set,
  and not empty or `0`). A coding agent that sets none of them is protected
  only while it passes `--assisted`.
- **`VARLATCH_ASSISTED=0` turns marker detection off,** for example when an
  unrelated tool sets `AGENT` in your shell. It never overrides an explicit
  `--assisted`.

## `varlatch run`

- **Output is masked by default.** The command's stdout and stderr go
  through [output redaction](output-redaction.md), as with `--redact`, even
  when your output is a terminal: the command then writes to pipes instead
  of the terminal, which a coding agent captures anyway.
- **Inherited Secrets are masked too.** Besides the Secrets delivered in the
  run, the filter holds the value of every name the command inherits from
  your shell that Varlatch knows to be a Secret: a Secret stored in the
  environment (including one withheld from you), or an item the active
  Contract marks sensitive. Reading the Contract needs `contract.read`;
  without it, only stored Secret names count, and the run says so. Nothing
  is fetched to build the filter.
- **Before the command starts, the run says** (on stderr) when no values
  are stored in Varlatch for the environment (the command still gets what it
  inherits), and when a `.env` file exists in the project that the run does
  not read, with the value-free command to compare its names. Only the
  file's existence is checked, never its content: it may hold values already
  stored, or older copies.
- **A Secret too short to mask stops the run.** Values shorter than 8 bytes
  cannot be masked (masking them would corrupt unrelated output, and the
  masks would give the value away). The run names those items and exits
  with status 78 before the command starts. For `run -e production`:

  ```
  varlatch: this Secret is shorter than 8 bytes, so its value cannot be masked in the command's output: PIN
    Stop and ask the human what to do about PIN. Approval for one item or action never covers another.
    - Only if they approve replacing PIN with a new random value (it overwrites the current one):
        varlatch --assisted values set PIN -e production --replace PIN --generate hex:32
      A credential a provider issued is never generated: the human enters it, in their own terminal: varlatch values set PIN -e production
    - Only if they approve marking PIN as not secret (a Contract change, for the whole project): varlatch --assisted agents guide contract
    - Showing it unmasked is the human's alone, in their own terminal (assisted mode refuses it; every other Secret stays masked):
        varlatch run -e production --allow-unmasked PIN -- <command>
  Nothing was started.
  ```

  First the agent stops and asks. Each remedy is the human's decision, for
  the named item (and environment) only. After that approval, a safe remedy
  is the agent's own command, with `--assisted`: a new random value
  replaces the item with `--replace` naming it. A credential a provider
  issued is the human's to enter, in their own terminal, and showing a
  Secret unmasked stays the human's alone. Every command names the refused
  run's environment (always, even when it came from the default), its
  server when the run overrode it (`--server` or `VARLATCH_SERVER`), and
  for the human's retry its `--strict`, `--allow-inherited`,
  `--export-context`, and earlier `--allow-unmasked` options.
- **Marking an item as not secret** changes the Contract, for every
  environment of the project: show the active revision
  (`contract show`), write its `contract` field to a file in a new
  temporary directory, change only that item's `sensitive`, push the file
  (`contract push --file <contract.json> --json`), and activate the
  returned revision. When the refused run overrode the server, the message
  says so (`add --server <url> to every contract command`): every contract
  command needs it, or it changes the default server's Contract. The
  coding-agent guide prints the steps: `varlatch agents guide contract`.
- The CLI cannot tell a human from a coding agent that leaves out
  `--assisted` in a shell without a marker. A command printed for the
  human's own terminal is theirs; the instructions tell agents never to run
  one. This is guidance, not an enforced boundary.
- **`--allow-unmasked` and `--no-redact` are refused** in assisted mode
  (status 64, nothing started): showing a Secret is the human's decision.
  The refusal prints the human's override for their own terminal, with the
  same environment, server, and startup options (`--strict`,
  `--allow-inherited`, `--export-context`), so the override never weakens
  the run's policy.
- **The human's override,** outside assisted mode:
  `varlatch run --allow-unmasked <NAME> -- <command>` (repeatable) lets the
  named short Secrets through unmasked in that run, and keeps everything else
  assisted mode protects: every other known Secret, inherited ones included,
  stays masked, and another Secret too short to mask still stops the run.
  It is not an unmasked run, and it cannot be combined with `--no-redact`.
  The option is checked strictly, in every mode, before anything is fetched:
  each `--allow-unmasked` needs an item's name after it, and the
  `--allow-unmasked=<NAME>` spelling is not supported. A malformed form, or
  a misspelled option such as `--allow-unmask`, exits with status 64 and
  starts nothing; it never falls back to a run without masking. (Every
  option of `varlatch run` is checked this way; see
  [scripting](scripting.md).)
- These are protections against accidents, not a boundary: an agent that
  deliberately turns assisted mode off is outside what they cover.
- **`--agent-safe` runs are unchanged:** the Agent holds Placeholders, not
  Secrets, and redaction does not apply there. See
  [Agent-safe runs](agent-safe-runs.md).

## `values set` and `values rotate`

- **A Secret's value on the command line is refused** with status 64, and
  nothing is stored. An item counts as a Secret when the active Contract marks it
  sensitive, when it is not in the Contract, or when the Contract cannot be
  read. The refusal names the safe forms below, and suggests asking the
  human to run `varlatch values set <ITEM> -e <environment>` in their own
  terminal, or to use the dashboard. Non-sensitive items are unaffected.
- **There is no prompt** when no value is given: a coding agent cannot type
  into one. The refusal gives the same command for the human.
- Every command a refusal suggests names the environment the agent's
  command resolved (`-e`), so a handed-over command targets the same
  environment. The human's command has no `--assisted`, so it prompts
  without showing the value.
- **Replacing an existing value needs `--replace <ITEM>`** (status 78
  otherwise, nothing stored). The command line is checked first, including
  the value source (one only) and the `--generate` form, and a missing value
  (assisted mode never prompts): any of these is status 64, with no request.
  The existence check comes next, before any value is read from a file or
  standard input, prompted for, generated, or written. A value the
  environment inherits from its parent environment counts as existing:
  setting the item in the child overrides it, which changes what the child
  uses. When the server cannot say whether the item has a value (denied,
  for instance), it counts as existing.
  `--replace` must name the item the command sets or rotates; approval for
  one item never covers another. It records the override's intent: it is
  not proof that a human approved, nor an authentication or a permission.
  Outside assisted mode, `values set` and `values rotate` replace as before.

## `values delete`

```
varlatch --assisted values delete <ITEM> [-e <environment>] --confirm <ITEM>
```

- **Every deletion needs `--confirm <ITEM>`** in assisted mode, for a
  plain value and a Secret alike (status 78 otherwise, with no request and
  nothing deleted). Nothing is inferred from whether the item has a value
  or how the Contract classifies it.
- **`--confirm` must name the item** the command deletes; another name is
  status 64. Approval for one item never covers another.
- **It records the deletion's intent.** It is not proof that a human
  approved, nor an authentication or a permission. A coding agent adds it
  only after the human approved deleting that item in that environment.
- The refusal names the environment, and gives the human's command for
  their own terminal, with the environment and an overridden server.
- **The command line is checked strictly**, in every mode, before any
  request: an unknown option (`--env`), an option without its value, an
  option given twice, or an extra argument is status 64. Outside assisted
  mode a deletion needs no `--confirm`, as before.
- The MCP server's `varlatch_delete_value` tool has the same rule: see
  [MCP](mcp.md).

## Signing in

```
varlatch --assisted login --server <url> --start
varlatch --assisted login --server <url> --wait [--timeout <seconds>]
```

A coding agent cannot wait for a browser sign-in on your machine: its shell
commands time out, and the browser may be elsewhere. Device sign-in splits
sign-in into two short commands:

- **`--start`** prints an address and a code, and exits. In assisted mode,
  `login` with no sign-in method does this. The agent gives you both; you
  open the address in a browser on any device, sign in with your passkey,
  enter the code, check who asks (the address and client that started it,
  and how long the credential lasts), and approve with your passkey again,
  or deny. The code lasts 10 minutes.
- **`--wait`** collects the credential once you approved it, stores it like
  every login, and exits 0. Still waiting for your approval after 60
  seconds (`--timeout`, at most 600), it exits 75 and keeps the sign-in for
  the next `--wait`. Denied, expired, or already collected: 77, and nothing
  is stored. The skill tells the agent to run `--wait` only after you say
  you approved.
- **The sign-in's private code** never appears in output: the CLI keeps it
  in `pending-sign-ins.json` in its configuration directory, readable only
  by you. Device sign-in runs only over HTTPS, or to a loopback address in
  local development, and follows no redirect.
- **Approving signs that CLI in as you**, with your access. Approve only a
  sign-in you started yourself, or one your coding agent started for you
  just now; a code someone sends you is a phishing attempt.
- `--token-stdin`, `--token`, and `--oidc` work as before in assisted mode.
- **Inside an agent-safe run there is no sign-in:** every `login` exits 64
  before sending anything. The run's read access comes from
  `--agent-metadata`.

## Giving a value without the command line

These work in every mode, and keep the value out of shell history, process
lists, and anything that records the command.

```
varlatch values set API_KEY --generate hex:32          # a new random value, never shown
varlatch values set TLS_KEY --from-file key.pem        # a file's content
op read op://vault/item/key | varlatch values set API_KEY --stdin
varlatch values set API_KEY                            # in a terminal: a hidden prompt
varlatch values rotate API_KEY --stdin --grace 3600 < new-key.txt
op read op://vault/varlatch/token | varlatch login --server https://varlatch.example.com --token-stdin
```

- **`--generate <encoding>:<size>`** creates the value from the operating
  system's secure random source: `hex:<bytes>`, `base64:<bytes>`,
  `base64url:<bytes>` (16 to 4096 random bytes), or `alnum:<characters>` (22
  to 4096 letters and digits). The output says which generator was used,
  never the value.
- **`--stdin` and `--from-file`** remove one trailing line break, which
  `echo` and most editors add. The value must be UTF-8 text without NUL
  bytes, and not empty. `--stdin` refuses a terminal; leave the value out
  for a hidden prompt instead.
- **The hidden prompt** shows nothing as you type. Backspace removes the
  last whole character (an emoji or an accented letter included), and arrow
  and function keys are ignored rather than stored.
- **`login --token-stdin`** reads a credential the same way, removing one
  trailing line break; it refuses a terminal, an empty credential, and one
  with whitespace in it. Sign-in stays the human's step: in a terminal,
  `varlatch login --server <url>` signs in in the browser.
- **Give the value one way only.** Two sources are refused. A value that is
  not well-formed Unicode text is refused from every source.
- **The command line is checked strictly**, in every mode, before anything
  is read, prompted for, or written. An unknown option (`--env`, or
  `--environment=production`, which is not supported), an option without
  its value, an option given twice (`-e` and `--environment` count as one),
  or an extra argument exits with status 64 and stores nothing. A typo can
  never become the stored value. A value that begins with `-` goes after
  `--`: `varlatch values set OFFSET -- -1`. `--grace` (rotate only) takes a
  whole number of seconds.

## Limits

Assisted mode protects against accidents. It is not a boundary: a coding
agent runs as your operating-system user, and your approval of its actions
is the control against deliberate misuse.

- It covers the values Varlatch delivers or knows by name. A secret already
  in the agent's environment under a name Varlatch does not know passes
  through.
- Masking recognises the value as written and the encodings listed in
  [output redaction](output-redaction.md). Hex, other escapings, compressed
  output, and values the command derives or deliberately encodes are not
  masked.
- A coding agent that sets no marker and leaves out `--assisted` gets the
  default behaviour.
