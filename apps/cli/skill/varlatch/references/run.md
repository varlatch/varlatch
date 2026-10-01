# Running commands and managing values

## Running

```sh
varlatch --assisted run -- npm run dev
varlatch --assisted run -e staging -- ./scripts/migrate.sh
varlatch --assisted run --strict -- node server.js
```

- The command gets the environment's configuration in its environment
  variables. Nothing is written to disk.
- Assisted mode masks the Secrets it delivered, and inherited values under
  names it knows as Secrets, in the command's output: you see
  `[REDACTED:NAME]`.
- `--strict` checks the configuration against the active Contract first and
  starts nothing on a violation (exit 78, naming the items).
- Exit 78 also means a Secret is shorter than 8 bytes and cannot be masked.
  Report the item to the human and wait. Each remedy is theirs, for that
  item only: replace it (`values set <NAME> -e <environment> --generate hex:32`
  overwrites the current value, which suits development values), correct
  its sensitivity in the Contract, or show it unmasked in one run with
  `varlatch --assisted run -e <environment> --allow-unmasked <NAME> -- <command>`
  (the option before `--`). The refusal prints both commands with the
  refused run's environment; use them as printed, so they act on the same
  values. Approval for one item does not cover another.
  That flag is theirs to add, never yours.
- Once the command has started, `run` exits with the command's own status.

## Storing values

Never put a secret value in a command. Store a Secret without seeing it:

```sh
varlatch --assisted values set SESSION_SECRET --generate hex:32
varlatch --assisted values set TLS_KEY --from-file key.pem
some-tool --print-key | varlatch --assisted values set API_KEY --stdin
```

A non-secret value may go on the command line:

```sh
varlatch --assisted values set LOG_LEVEL debug
```

When only the human knows a Secret, give them this command for their own
terminal, with the environment it belongs to (it prompts without echoing;
without `--assisted`, since assisted mode never prompts), and wait:

```text
varlatch values set API_KEY -e production
```

## Rotating

```sh
varlatch --assisted values rotate API_KEY --generate hex:32 --grace 3600
varlatch --assisted values rotate-complete API_KEY
```

The previous value keeps working for the grace period, so running services
move over before it is retired.

## Reading state

```sh
varlatch --assisted values list --json
varlatch --assisted validate --json
varlatch --assisted context --json
```

`values list` gives names and sensitivity, never values.

## Exit statuses

| Status | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Any other failure |
| 64 | The command line is wrong |
| 69 | The server cannot be reached, or is in maintenance |
| 77 | Not signed in, or denied |
| 78 | The configuration cannot run as it is |

On 69, the server may be down, or a sandbox around your commands may be
blocking the connection. Tell the human which server the command tried to
reach (`varlatch --assisted context --json` shows it), and ask them to allow
that connection or check the server.
