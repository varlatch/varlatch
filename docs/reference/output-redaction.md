# Output redaction: `varlatch run --redact`

`varlatch run --redact` masks the Secrets delivered to your command in what
the command writes to stdout and stderr. Use it where that output is kept:
CI logs, files, and pipes into other tools.

```
varlatch run [--strict] --redact -- <command> [args...]
```

```
$ varlatch run --redact -- ./deploy.sh 2>&1 | tee deploy.log
calling https://api.example.com with [REDACTED:API_KEY]
```

**It masks only the Secrets that Varlatch delivered to the command in this
run.** A Secret that reaches the command any other way is not masked: a value
inherited from your shell, including one you accept with `--allow-inherited`
in a strict run, a file the command reads, or anything the command fetches
itself.

A run without `--redact` is unchanged: the command writes directly to your
terminal, files, or pipes, and nothing is masked. In
[assisted mode](assisted-mode.md), when a coding agent drives the CLI,
redaction is the default; see [In assisted mode](#in-assisted-mode).

## What is masked

- **Exactly the Secrets this run delivered to the command.** In a default
  run these are the Secrets Varlatch disclosed to you for the command; with
  `--strict`, the Secrets the strict retrieval delivered. Nothing extra is
  fetched to build the filter. Non-sensitive values, values the command
  inherits from your shell (including one accepted with
  `--allow-inherited`), and anything the command reads from elsewhere are
  not masked.
- **Each occurrence becomes `[REDACTED:<NAME>]`,** with the item's name.
  No character of the value is kept, and nothing the command writes can
  switch masking off.
- **Common encodings are found too:** the value as written, JSON-escaped
  (with or without `\/`), percent-encoded (upper- or lower-case hex), and in
  base64 or base64url, also inside a longer encoded string at any alignment,
  so `user:secret` inside a Basic credential is found.
- **Overlapping values** are replaced by one marker covering both. It names
  the value that starts first (on a tie, the longer one, then the name that
  sorts first). No byte of either value is kept.
- **Values shorter than 8 bytes are not masked,** because masking them
  would corrupt unrelated output. Before the command starts, the run names
  those items on stderr, never their values:

  ```
  varlatch: --redact does not mask values shorter than 8 bytes; these pass through unchanged: PIN
  ```

- If no Secret was delivered (for example, your identity may not read
  Secrets in this environment), the run says so and relays the output
  unchanged.

## How output is relayed

- **Bytes, not text.** Output is never decoded or re-encoded. Binary output
  (`pg_dump -Fc`, `tar`) passes through byte for byte unless it contains a
  Secret, and a character split across two writes cannot hide one.
- **stdout and stderr are masked separately.** Their relative order is not
  preserved: a line on stderr may appear before or after stdout lines it
  followed.
- **Possible starts of a Secret are held back.** When the output so far
  ends with bytes that could be the beginning of a Secret, those bytes wait
  for the command's next write, however long that takes. They are never
  released on a timer, so a command that pauses in the middle of a line can
  appear to stall until it writes again or exits. Output that ends each
  write with a newline is rarely held.
- **When the output ends, held bytes are released unchanged,** because they
  can no longer become a Secret. Output that ends with only the start of a
  Secret is therefore not masked: the guarantee covers complete values.
- **When `varlatch run` is interrupted** by SIGINT, SIGTERM, SIGHUP, or
  SIGQUIT, it forwards the signal to the command as always, and bytes still
  held when the output ends are discarded, never released. Output the
  command writes after the signal, while shutting down, is still relayed
  and masked. SIGUSR1 and SIGUSR2 are forwarded too, but do not count as an
  interruption.
- **When whatever reads the output goes away** (for example `| head`),
  held bytes are discarded and reading from the command stops, so the
  command's next write to that stream fails as it would on a closed pipe.
- **stdin, signals, and the exit code pass through unchanged.** As in every
  `varlatch run`, a command ended by a signal gives 128 plus the signal's
  number, as a shell reports it: 130 for SIGINT (Ctrl-C), 143 for SIGTERM.
- **The command writes to pipes, not a terminal.** A command that checks
  for a terminal may drop colours or buffer its output differently. Many
  tools have a flag to keep colours, such as `--color=always`.
- **The run ends when the command has exited and its stdout and stderr have
  closed.** A background process that the command leaves running with the
  same stdout or stderr keeps the run open, as it would in a shell
  pipeline.

## When `--redact` refuses to start

In both cases the run refuses before it fetches anything, starts nothing,
and exits with status 64 (a usage error; see [scripting](scripting.md)).

- **stdout or stderr is a terminal.** Masking terminal output is not
  supported: piping it would break colours, interactive programs, and
  terminal detection. Redirect both streams:

  ```
  varlatch run --redact -- make test 2>&1 | tee test.log
  varlatch run --redact -- make test > test.log 2> test.err
  ```

- **`--agent-safe` is also given.** The Agent receives Placeholders, not
  Secrets, so no Secret is delivered to it to mask, and an agent-safe run
  never fetches Secrets just to build a filter. The Agent's protections are
  Placeholders, substitution targets, and response scrubbing; see
  [Agent-safe runs](agent-safe-runs.md).

## In assisted mode

In [assisted mode](assisted-mode.md) (`varlatch --assisted`, or a coding
agent's marker), every `varlatch run` redacts without `--redact`, with these
differences:

- **Inherited Secrets are masked too:** the value of every name the command
  inherits from your shell that Varlatch knows to be a Secret, stored in the
  environment or marked sensitive in the active Contract.
- **A Secret shorter than 8 bytes stops the run** with status 78 before the
  command starts, naming the item. When the command does not need it,
  `--omit <NAME>` leaves it out: the command does not get it, so it no
  longer stops the run. The other remedies are the human's, in their
  own terminal; there, `varlatch run --allow-unmasked <NAME> -- <command>`
  lets that item through unmasked and keeps every other Secret masked.
- **A terminal is not refused:** the command writes to pipes instead.
- **`--no-redact` and `--allow-unmasked` are refused** in assisted mode.
- Silent when there is nothing to mask.

## Limits

- The filter holds only what the command gets. A Secret left out with
  `--omit`, or withheld from you, is not in it, and is not masked if the
  command reads it some other way. With `--redact`, `--omit` simply means
  one Secret fewer to deliver and to mask.
- Redaction protects where the output is written. It does not protect a
  Secret from the command itself, which holds the value in its environment.
  It guards against accidents, such as a Secret printed in a debug line or
  an error message. It is not a defense against a command that deliberately
  leaks a Secret.
- Only the command's stdout and stderr are masked: not files it writes,
  network traffic, or output written directly to the terminal device
  (`/dev/tty`).
- Not masked: values shorter than 8 bytes, a value in hex, arbitrary
  `\uXXXX` escapes, another character set, compressed output, a value split
  by other text (for example across two log fields), or anything derived
  from a value.
