# Assisted mode: a coding agent driving the CLI

When a coding agent such as Claude Code, Codex, or Cursor runs `varlatch`
commands for you, it uses your own credential, and everything a command
prints goes into what the agent reads. Assisted mode keeps Secret values out
of that output by accident-proofing the commands an agent uses:

- `varlatch run` masks Secrets in the command's output by default, and
  refuses to start when it cannot mask one.
- `values set` and `values rotate` never take a Secret's value from the
  command line, and never prompt.

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
    Stop and ask the human. Each choice is theirs, for PIN only, made in their own terminal:
    - replace the value with a longer one, which overwrites the current value: varlatch values set PIN -e production --generate hex:32
    - if it is not a secret, correct its sensitivity in the Contract
    - show it unmasked in one run, every other Secret still masked: varlatch run -e production --allow-unmasked PIN -- <command>
    An agent reports this and waits: it runs none of these itself, and approval for one item does not cover another.
  Nothing was started.
  ```

  The remedies are the human's commands, for their own terminal (no
  `--assisted`). They act on the refused run's values: they name its
  environment (always, even when it came from the default), its server when
  the run overrode it (`--server` or `VARLATCH_SERVER`), and for a retry its
  `--strict`, `--allow-inherited`, and earlier `--allow-unmasked` options.
- **`--allow-unmasked` and `--no-redact` are refused** in assisted mode
  (status 64, nothing started): showing a Secret is the human's decision.
  The refusal prints the human's override for their own terminal.
- **The human's override,** outside assisted mode:
  `varlatch run --allow-unmasked <NAME> -- <command>` (repeatable) lets the
  named short Secrets through unmasked in that run, and keeps everything else
  assisted mode protects: every other known Secret, inherited ones included,
  stays masked, and another Secret too short to mask still stops the run.
  It is not an unmasked run, and it cannot be combined with `--no-redact`.
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
  otherwise, nothing stored). The check runs after the command line is
  checked and before any value is read from a file or standard input,
  prompted for, generated, or written. When the server cannot say whether
  the item has a value (denied, for instance), it counts as existing.
  `--replace` must name the item the command sets or rotates; approval for
  one item never covers another. It records the override's intent: it is
  not proof that a human approved, nor an authentication or a permission.
  Outside assisted mode, `values set` and `values rotate` replace as before.

## Giving a value without the command line

These work in every mode, and keep the value out of shell history, process
lists, and anything that records the command.

```
varlatch values set API_KEY --generate hex:32          # a new random value, never shown
varlatch values set TLS_KEY --from-file key.pem        # a file's content
op read op://vault/item/key | varlatch values set API_KEY --stdin
varlatch values set API_KEY                            # in a terminal: a hidden prompt
varlatch values rotate API_KEY --stdin --grace 3600 < new-key.txt
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
