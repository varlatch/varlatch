# Importing a dotenv file: `varlatch import`

`varlatch import` stores the values of a dotenv file (`.env`) in the
selected environment. The CLI reads the file itself, so the values never
appear on a command line or in its output: it prints names, counts, inferred
types, and sensitivity, never a value, including in every error.

```
varlatch import <file> [--dry-run] [--contract [--plain <NAME>]...] [--replace <NAME>]... [--delete-source] [--json] [-e <env>]
```

The options may come before or after the one filename (`import --dry-run
.env` and `import .env --dry-run` are the same). An unknown option, an
option without its value, or a second filename exits 64 and stores nothing.

```
$ varlatch import .env --dry-run
Dry run: would import 4 value(s) (3 secret, 1 plain) from .env into acme/web (development):
  API_TOKEN     string   secret  in the Contract
  DATABASE_URL  url      secret
  PORT          string   plain  in the Contract
  DEBUG         boolean  secret
Dry run: nothing was stored.
```

## Options

- **`--dry-run`** shows the plan and stores nothing. Outside a repository or
  without a sign-in, it still lists the names and inferred types.
- **`--contract`** adds the file's items that are not yet in the active
  Contract to a new Contract revision, pushed before any value is stored.
  Items already in the Contract keep their definition, sensitivity included.
  New items are Secrets, the default for anything outside a Contract, and
  are optional in every environment. The revision is not activated: activate
  it with `varlatch contract activate <revision>`, as after `varlatch
  contract push`.
- **`--plain <NAME>`** (repeatable, only with `--contract`) makes a new item
  non-sensitive. It cannot change an item the Contract already marks
  sensitive: change that in the Contract.
- **`--delete-source`** deletes the file once every value was stored, and
  only if the file did not change while importing.
- **`--replace <NAME>`** (repeatable) approves replacing the value the target
  environment already has for that item. The plan marks such names
  ("already has a value"; `existing` in the JSON): a leftover file may be an
  older copy of a value rotated since. In assisted mode an import that
  would replace an existing value without `--replace` for it stores
  nothing, deletes nothing, and exits 78; outside assisted mode the import
  replaces it, as before. A plain value identical to the stored one (in its
  stored form, before references are expanded) is not a replacement: the
  comparison reads the environment's non-sensitive values, a read the
  server audits. A Secret's stored value is never fetched, and a plain
  value the caller may not read is unknown, so either always counts.
  `--replace` must name an entry of the file. It records the override's
  intent: it is not proof that a human approved. After a partial import, a
  retry in assisted mode finds the values already stored as existing, and
  each needs the human's approval again: one may have changed since.

## What is stored

- Every entry, in file order, with its exact value. Sensitivity is not a
  property of a stored value: it comes from the Contract, and an item
  outside the Contract is a Secret.
- The type shown is inferred from this file's value (`boolean` for `true`
  or `false`; then `integer` when the Contract's rules include it, `number`,
  `url`, `email`; otherwise `string`), or taken from the Contract for an item
  it already has. With `--contract`, new items get the inferred type.
- A value containing `${NAME}` is stored as written; Varlatch reads it as a
  reference to another item, and the import says which items have one.

## The file format

```
# comments and blank lines are ignored
NAME=value                 unquoted: trimmed; whitespace then # starts a comment
export NAME=value          the export prefix is ignored
NAME = value               spaces around = are allowed
NAME='literal $X'          single quotes and backticks: as written, may span lines
NAME="line\nnext"          double quotes: \n \r \t \" \\ are escapes, may span lines
NAME=                      an empty value
```

Nothing is expanded. The file must be valid UTF-8: a file that is not is
refused, naming the first invalid line, so no value is ever stored with its
bytes changed. Names must be valid item names: upper-case letters, digits,
and `_`, starting with a letter. Names starting with `VARLATCH_` are
reserved for the CLI and refused.

## When it stops

- **A problem in the file** stops the import before anything is stored, and
  the file is never deleted. Errors give the line number and the reason
  (including text that is not valid UTF-8), and every name problem
  (invalid, reserved, or set twice) is listed at once.
- **A failed write** stops the import. It names the items stored, the item
  that failed with the error code, and the items not attempted, and does not
  delete the file. Running the import again after fixing the cause stores
  the same values again.
