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
- **A Secret too short to mask stops the run.** Values shorter than 8 bytes
  cannot be masked (masking them would corrupt unrelated output, and the
  masks would give the value away). The run names those items and exits
  with status 78 before the command starts:

  ```
  varlatch: this Secret is shorter than 8 bytes, so its value cannot be masked in the command's output: PIN
    Replace the value with a longer one, for example: varlatch --assisted values set PIN --generate hex:32
    If an item is not a secret, correct its sensitivity in the Contract.
    Or the human may approve showing it unmasked in this run: --allow-unmasked PIN
    (the human's decision: an agent asks for it rather than adding it).
  Nothing was started.
  ```

  `--allow-unmasked <NAME>` (repeatable) lets that item through unmasked in
  this run, and the run says so. It is refused outside assisted mode.
- **`--no-redact`** turns masking off for one run and prints a warning.
- **`--agent-safe` runs are unchanged:** the Agent holds Placeholders, not
  Secrets, and redaction does not apply there. See
  [Agent-safe runs](agent-safe-runs.md).

## `values set` and `values rotate`

- **A Secret's value on the command line is refused** with status 64, and
  nothing is stored. An item counts as a Secret when the active Contract marks it
  sensitive, when it is not in the Contract, or when the Contract cannot be
  read. The refusal names the safe forms below, and suggests asking the
  human to run `varlatch values set <ITEM>` in their own terminal, or to use
  the dashboard. Non-sensitive items are unaffected.
- **There is no prompt** when no value is given: a coding agent cannot type
  into one.

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
