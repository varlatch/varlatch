# Type generation: `varlatch types` and the Typed Accessor

`varlatch types` turns a Contract Revision into one TypeScript module. The
module declares a type for every Contract item and carries the Typed
Accessor, a small runtime that reads `process.env`, converts each value with
the revision's Contract Semantics, and checks it. The module is
self-contained: your application imports it and needs nothing else from
Varlatch.

```
varlatch types --out <file.ts> [--revision <id>] [--check]
```

## Generating the module

`varlatch types` reads the active Contract Revision of the project named in
`varlatch.toml`, or the revision given with `--revision`. It makes that one
request and nothing else. It needs `contract.read` on the project, and it
never fetches a value. No environment needs to be selected: the output is the
same for every environment.

- **`--out`** names the file to write. It must end in `.ts`, `.mts`, or
  `.cts`.
- **Only on change.** The file is written only when its content changes. An
  unchanged file keeps its modification time, so build tools do not rebuild.
- **Never through a symbolic link.** If the output path is a symbolic link,
  `varlatch types` refuses and writes nothing. New content goes to a new file
  in the same directory, which then replaces the old one, and the old file's
  permissions are kept. No shared temporary directory is used.
- **`--check`** generates the module in memory and compares it byte for byte
  with the file. It writes nothing, and exits 1 when the file is stale or
  missing. Run it in CI to catch a Contract change that nobody regenerated.
- **`--revision <id>`** generates from a stored revision that need not be
  active. It needs a server running Varlatch 0.11.0 or later.
- **Semantics versions.** Types need conversion, which Contract Semantics
  version 1 does not define. A revision at version 1 is refused; push the
  Contract again with `varlatch contract push --semantics latest` and
  activate it. A version this CLI does not implement is refused too; upgrade
  the CLI. See [Contract Semantics](contract-semantics.md).

`varlatch types` runs only when you run it. `varlatch run` never regenerates
types.

The file's header records the Contract Revision ID, its content hash, the
semantics version, and the CLI release that generated it. The output depends
only on the revision and the CLI release, so `--check` in CI should use the
same CLI release as the developers who generate the file.

**Updating the accessor.** The Typed Accessor is part of the generated file,
not a package your application installs, so a fix to it reaches your
application only when you regenerate. After upgrading the CLI, run
`varlatch types` again and commit the new file. `varlatch types --check` fails
until you do whenever the new release generates a different module.

## What the module contains

| Contract type | TypeScript type |
| --- | --- |
| `string`, `email` | `string` |
| `url` | `string`, validated as a URL |
| `number` | `number` |
| `boolean` | `boolean` |
| `enum` | a union of the listed values |

- **`Config`** has one property per Contract item. A property is required
  only when the Contract requires the item in every environment and gives it
  no default. Every other item is optional, because it can be absent: a
  default is applied only in the cases below, and never replaces a value the
  server withheld.
- **Conditions are kept.** An item required only in some environments, by
  tier or by environment, is optional in the type, and its condition is kept
  in the module as data. The accessor checks it whenever a run context names
  the environment.
- **Documentation.** Each property's comment carries the item's description,
  its example, its requiredness, a `@default` tag naming a default, and a
  `@sensitive` tag for Secrets. Contract text is cleaned before it reaches a
  comment: line breaks are normalized, control and bidirectional formatting
  characters are removed, and `*/` is neutralized, so no description can end
  the comment early or hide text in it.
- **`PublicConfig`** has only the non-sensitive items. It is empty for a
  Contract of Secrets only.
- **`config`**, **`loadConfig()`**, **`ConfigError`**, and
  **`generatedFrom`** (the revision the file was generated from) are the
  runtime exports.

The file starts with `// @ts-nocheck` and `/* eslint-disable */`. The runtime
at its end is bundled JavaScript that your compiler and linter settings
should not check. The exported types are exact all the same, and the file
compiles under strict settings as an ES module or as CommonJS, without Node
or DOM type definitions. The runtime is licensed under Apache-2.0, and the
file carries its notice.

Commit the file like any other source. It contains Contract metadata (item
names, descriptions, examples, defaults, enum values, and the environment IDs
in conditions) and never a value. Contract defaults and examples are
metadata that anyone with metadata access can read; never put a secret in
them.

## Reading configuration

```ts
import { config } from "./config/varlatch.js";

server.listen(config.PORT); // a number
```

- **`config`** reads and validates every item the first time it is used,
  with the default options.
- **`loadConfig(options)`** reads and validates now. It returns `config`,
  and a report: `defaulted`, `notEvaluated`, `context`, and `warnings`.

The accessor follows these rules:

- **It only reads.** Values come from `process.env`, or from the `env`
  option. The accessor never writes to `process.env` and adds no variable to
  it, so every value there stays the string Varlatch delivered. Converted
  values exist only in the accessor's object.
- **One error, never a value.** Every item is validated on first use. Any
  problem throws one `ConfigError` whose `issues` list each item by name and
  reason, never by value. After a failed first use, every later use of
  `config` throws the same error, so an item that failed never reads as
  `undefined`.
- **Read-only.** `Object.keys`, `in`, `JSON.stringify`, and spreading see the
  items. Any assignment, `delete`, or `Object.defineProperty` throws a
  `TypeError`, in strict and sloppy code alike.
- **Presence comes from `process.env`.** An item that is present is always
  read and validated, whatever the run context says about how it got there.
  For example, a Secret the server withheld that the shell supplied through
  `varlatch run --strict --allow-inherited API_KEY` is returned like any
  other value.
- **Read once.** `config` reads `process.env` on first use. A later change to
  `process.env` is not reflected; call `loadConfig()` again to read it.

### Defaults

The accessor fills an absent item with its Contract default only when you
ask for it with `applyDefaults: true`, and reports each filled item in
`defaulted`.

| The application was started by | Defaults applied by the accessor |
| --- | --- |
| `varlatch run --strict` | None. Strict startup already applied defaults where they belong, and `applyDefaults` has no effect. An absent item is an error only if it is required in this environment. |
| `varlatch run --export-context` | With `applyDefaults: true` only, and never for an item the server withheld. |
| anything else, with no run context | With `applyDefaults: true` only. The accessor cannot tell why an item is absent. |

### The run context

When `VARLATCH_RUN_CONTEXT` is set (see [Strict
startup](strict-startup.md#the-run-context)), the accessor checks
requiredness for the environment that run used, and knows which items the
server withheld.

- An unknown context version, malformed JSON, or a malformed field throws.
- A semantics version other than the module's throws.
- A different content hash means the types are stale. The accessor warns
  (a `VarlatchWarning` through `process.emitWarning`), or throws with
  `staleTypes: "throw"`. It compares content hashes, not revision IDs, so an
  identical Contract activated again as a new revision is not stale.
- An item the context records as delivered but that is absent from
  `process.env`, because the application removed it, is treated as absent.
- Without a context, types and items required in every environment are
  checked, and an absent item that is required only in some environments is
  listed in `notEvaluated`. `requireContext: true` makes a missing context
  an error.

### Options

| Option | Default | Effect |
| --- | --- | --- |
| `env` | `process.env` | Where values are read. It is never written to. |
| `applyDefaults` | `false` | Fill absent items with Contract defaults, as described above. |
| `staleTypes` | `"warn"` | `"throw"` makes a content-hash mismatch an error. |
| `requireContext` | `false` | Throw when `VARLATCH_RUN_CONTEXT` is not set. |
| `onWarning` | `process.emitWarning` | Receives each warning. |

## Exporting the run context from a default run

```
varlatch run --export-context -- <command> [args...]
```

`--export-context` makes an ordinary `varlatch run` also give the command
`VARLATCH_RUN_CONTEXT`, with `"mode": "exported"`. The run is otherwise
unchanged: the same values, the same precedence (a delivered value replaces
your shell's, anything else is inherited), no defaults, and no failure
because of the Contract. The context records, for each Contract item, what
the server did and how the item reached the command, with names and
identifiers only.

- It fetches the Contract Revision that the configuration response names,
  before any Secret is disclosed. It needs `contract.read`, an active
  Contract, and a server running Varlatch 0.11.0 or later; otherwise the run
  starts nothing.
- A context larger than 64 KiB fails the run; it is never truncated.
- It applies only to default runs. A `--strict` run always gives the command
  its run context.

Without `--export-context`, a default run removes a `VARLATCH_RUN_CONTEXT`
inherited from an outer run, so the command never sees a context that
describes another environment.

## Limits

- The accessor is a correctness check, not a confidentiality control. A
  process can read everything in its environment, and logging `config`
  prints its values, Secrets included, as logging `process.env` would.
- Without a run context the accessor cannot tell a withheld item from one
  that is not stored, and does not check conditions that depend on the
  environment.
- Types are generated from server revisions only, and in TypeScript only.
