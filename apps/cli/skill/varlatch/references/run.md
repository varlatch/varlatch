# Running commands and managing values

## Running

```sh
varlatch --assisted run -- npm run dev
varlatch --assisted run -e staging -- ./scripts/migrate.sh
varlatch --assisted run --strict -- node server.js
```

- The command gets the environment's configuration in its environment
  variables. Nothing is written to disk.
- Run in the environment the human named, or the project's default
  (`varlatch --assisted context --json` shows `environment` and `server`).
  When values are missing there, report them and hand them over; never run
  in another environment or server instead, and never add values just to
  make the run work.
- Assisted mode masks the Secrets it delivered, and inherited values under
  names it knows as Secrets, in the command's output: you see
  `[REDACTED:NAME]`.
- `--strict` checks the configuration against the active Contract first and
  starts nothing on a violation (exit 78, naming the items).
- Exit 78 also means a Secret is shorter than 8 bytes and cannot be masked.
  Report the item to the human and ask. Each remedy is their decision, for
  that item only, and approval for one item or action never covers another.
  The refusal prints the remedies with the refused run's environment and
  options:
  - With their approval to replace it with a new random value (overwriting
    the current one), run it yourself:

    ```sh
    varlatch --assisted values set <NAME> -e <environment> --replace <NAME> --generate hex:32
    ```

    A credential a provider issued is never generated: the human enters it
    in their own terminal, where it prompts without showing the value:

    ```text
    varlatch values set <NAME> -e <environment>
    ```
  - With their approval to mark it as not secret: change the Contract, for
    the whole project, as `varlatch --assisted agents guide contract`
    describes.
  - Showing it unmasked is the human's alone, in their own terminal; never
    run it yourself (assisted mode refuses `--allow-unmasked` and
    `--no-redact`):

    ```text
    varlatch run -e <environment> --allow-unmasked <NAME> -- <command>
    ```
- Once the command has started, `run` exits with the command's own status.

## Storing values

Create a value only when the task asks for it (setting up, importing, or a
requested new value), in the environment it is for, or after the human
approves that item in that environment; such a task needs no second
approval. Never put a secret value in a command. Store a Secret without
seeing it:

```sh
varlatch --assisted values set SESSION_SECRET --generate hex:32
varlatch --assisted values set TLS_KEY --from-file key.pem
some-tool --print-key | varlatch --assisted values set API_KEY --stdin
```

Replacing an existing value is the human's decision for that item: in
assisted mode `values set` and `values rotate` refuse (78) to replace one
unless it is named with `--replace <NAME>`, added only with their approval.
A value the environment inherits from its parent counts too: setting it
here overrides it. The check comes before any value is read, prompted for,
or generated.

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
varlatch --assisted values rotate API_KEY --replace API_KEY --generate hex:32 --grace 3600
varlatch --assisted values rotate-complete API_KEY
```

Rotating replaces the current value, so it needs the human's approval for
that item (`--replace API_KEY`). The previous value keeps working for the
grace period, so running services move over before it is retired.

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
