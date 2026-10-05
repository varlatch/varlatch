# Comparing a platform with Varlatch: `varlatch sync check`

`varlatch sync check` answers one question: does a platform still hold the
values the Environment holds? It reads the platform's current values,
compares them in memory with the Environment's, and prints one status per
key. It never prints a value, a hash, a length, or anything else derived
from one, so it works in [assisted mode](assisted-mode.md) too, including
when the Environment holds a Secret too short to mask.

Use it instead of printing the environment through `varlatch run` and
comparing it with the platform. In assisted mode that output is masked, so
every Secret looks different, and outside it every value ends up in a log.

```
varlatch sync check --platform coolify --base https://coolify.example.com --app <uuid> -e production --token-env COOLIFY_TOKEN
varlatch sync check --platform convex --base https://happy-animal-123.convex.cloud -e production --token-env CONVEX_DEPLOY_KEY --json
```

The options are those of `varlatch sync push`, without `--build-time`:
`--platform`, `--base`, the destination (`--app <uuid>` for Coolify;
`--repo <name>` and `--gh-environment <name>` for GitHub Actions; nothing
for Convex, whose `--base` is the deployment URL), `-e <env>`,
`--server <url>`, `--token-env VAR` (the variable holding the platform's
credential, `VARLATCH_SYNC_TOKEN` by default), `--map NAME[=DEST]`,
`--exclude NAME|PREFIX*`, and `--json`. Options are checked strictly: an
unknown or misspelled option exits with status 64 and checks nothing.

## Which keys

- Every item of the active Contract, less `--exclude`. A key on the
  platform that is not in the Contract (Coolify's own `COOLIFY_FQDN`, for
  example) is never compared or reported.
- With `--map NAME[=DEST]`, exactly the mapped items, each compared with
  the platform key `DEST` (default: the same name). A name that is neither
  stored in the Environment nor in its Contract exits with status 64: a
  misspelled name must not pass as "absent".
- Without an active Contract (or without `contract.read`), the stored
  items, and the command says so; `extra-on-platform` is then not reported.
- Coolify keeps a preview-deployment copy of every variable. Only the
  production rows are compared, as `sync push` writes only those.

## Statuses

| Status | Meaning |
| --- | --- |
| `match` | Both hold the key, with the same value, byte for byte |
| `differs` | Both hold the key, with different values (whitespace counts) |
| `missing-on-platform` | Stored in Varlatch, not on the platform |
| `extra-on-platform` | On the platform, a Contract key Varlatch does not store |
| `unreadable` | Not compared: the platform's values are write-only (`platform-write-only`, GitHub Actions secrets), this identity may not read the value in Varlatch (`withheld`), or the platform cannot store the name (`invalid-name`) |
| `absent` | Neither holds it; not drift |

## Exit status

- **0**: every compared key matches.
- **1**: drift: at least one key differs, is missing on the platform, or is
  extra on it. Drift wins over keys that could not be compared.
- **2**: not everything could be checked, and no drift was found: the
  platform could not be read (no credential in the `--token-env` variable,
  a refused credential, an unreadable response), or some key is
  `unreadable`.
- Varlatch's own failures keep their usual statuses: 64 for a wrong command
  line, 69 when the Varlatch server cannot be reached, 77 when you are not
  signed in or the request is denied. See [scripting](scripting.md).

`--json` prints one document: `result` (`match`, `drift`, `incomplete`, or
`unchecked`), the platform, base, destination, and environment, `keySet`
(`contract`, `stored`, or `map`), `counts` per status, `keys` (each with
`name`, `destination`, `status`, and for `unreadable` a `reason`), and
`exitCode`. It never holds a value.

## What it reads and discloses

1. The Environment's metadata and non-sensitive values, and the active
   Contract. No Secret yet.
2. The platform's values, with the credential from `--token-env`, through
   the same adapter `sync push` uses (https only, no redirects followed, the
   host pinned). If the platform cannot be read, the command stops here:
   nothing is disclosed. A failure is reported by its status or error class,
   never by the platform's response, which may quote values.
3. Only the Secrets the platform also holds, by name, in one requested
   disclosure. It needs `secret.reveal` and is audited like every
   disclosure. A Secret that is missing on the platform is reported without
   its value being read.

The values stay in the command's memory and are compared exactly; nothing
is written anywhere.

## Limits

- The platform credential can read the platform's values, so whoever holds
  it can already see what the platform holds. The check adds one fact per
  key: whether Varlatch's value is the same.
- It is an equality test. Someone who can write the platform could test
  guesses by setting a value and running the check, one audited disclosure
  per guess. That is deliberate misuse, outside what assisted mode protects
  against.
- GitHub Actions secrets cannot be read back, so they are never compared
  (status `unreadable`, exit 2).
