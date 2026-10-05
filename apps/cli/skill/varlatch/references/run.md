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
- `--omit <NAME>` (repeatable) leaves an item out of the run: the command
  does not get it, not even a copy inherited from your shell. Use it only
  when the command's code or documentation shows that it does not use the
  item; if you are not sure, do not. A Secret left out is not masked if
  the command reads it some other way (from a provider's own settings, for
  example), so never leave a Secret out to hide it from a command that can
  read it there. A name that is neither stored in the environment nor in
  its Contract stops the run (exit 64); with `--strict`, leaving out an
  item the Contract requires is a violation (exit 78).
- Exit 78 also means a Secret is shorter than 8 bytes and cannot be masked.
  Leave that item out and rerun only when the command's code or
  documentation shows that the command does not use it. That needs no
  approval: the command then never gets the value.

  ```sh
  varlatch --assisted run -e <environment> --omit <NAME> -- <command>
  ```

  Then name every item you left out in your answer, and say whether the
  task itself was done. Getting past exit 78 does not show that it was: a
  command that ran without an item it needs may fail, or seem to work and
  do the wrong thing.

  If you are not sure, or the command uses the item, report it to the
  human and ask. Each
  remedy is their decision, for that item only, and approval for one item
  or action never covers another. The refusal prints the remedies with the
  refused run's environment and options:
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

## Comparing a platform with Varlatch

To check whether a platform still holds the values Varlatch has, never print
the environment through `varlatch run` and compare: assisted mode masks every
Secret, so each one would look different, and a printed value is a leak.
Compare inside Varlatch instead:

```sh
varlatch --assisted sync check --platform coolify --base https://coolify.example.com --app <uuid> -e production --token-env COOLIFY_TOKEN --json
varlatch --assisted sync check --platform convex --base https://happy-animal-123.convex.cloud -e production --token-env CONVEX_DEPLOY_KEY --json
```

- It reads the platform's current values and compares them in memory with
  the environment's, for every key of the Contract, and prints one status
  per key: `match`, `differs`, `missing-on-platform`, `extra-on-platform`,
  `unreadable`, or `absent`. Never a value or a hash, so it also works when
  the environment holds a Secret too short to mask.
- Exit 0: in sync. 1: drift. 2: not everything could be checked (the
  platform could not be read, or a value is not readable). GitHub Actions
  secrets are write-only, so they are never compared.
- `--token-env` names the variable that holds the platform's credential.
  When that credential is stored in Varlatch, start the check inside a run
  that delivers it, in the project that stores it:
  `varlatch --assisted run -e production -- varlatch --assisted sync check ... --token-env COOLIFY_TOKEN`.
- Report the statuses. Fixing drift writes to the platform: do it only when
  the task asks for it, or after the human approves.

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
| 75 | `login --wait`: the sign-in is still waiting for the human's approval |
| 77 | Not signed in, or denied |
| 78 | The configuration cannot run as it is |

On 69, the server may be down, or a sandbox around your commands may be
blocking the connection. Tell the human which server the command tried to
reach (`varlatch --assisted context --json` shows it), and ask them to allow
that connection or check the server.
