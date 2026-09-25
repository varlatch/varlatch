# The `.env.schema` contract file

A project with a git-authored contract keeps it in the repository as a
`.env.schema` file and pushes it with
`varlatch contract push --schema .env.schema`. This page defines the format
Varlatch accepts. Anything it does not list is unsupported.

Varlatch parses the file on your machine, resolves the environment names it
uses against the project's environments, and pushes the result as a contract
revision. The server stores and enforces that contract, never the file
itself. Values never come from `.env.schema`: they live in Varlatch, and
`varlatch run` delivers them.

## Fail loudly

A decorator the parser does not understand is an error, never ignored. So is
a decorator written after a value, text after a quoted value, and an
unterminated quote. An environment name in `env(...)` that the project does
not have is an error when you push, and the error lists the names that exist.
The only accepted no-op decorators are the presentation-only `@docs`,
`@icon`, and `@tag`.

## Supported syntax

Root decorators, on comment lines before the first item:

| Decorator | Meaning |
| --- | --- |
| `@defaultSensitive=true` or `false` | Default sensitivity for items without an explicit marker. If absent, the default is **true**: items are Secrets unless marked otherwise. |
| `@defaultRequired=true`, `false`, or `infer` | Default requiredness. `infer` is treated as `false`: requiredness is never inferred from whether a value is present. |

Item decorators, on comment lines directly above an item, one per line:

| Decorator | Contract field |
| --- | --- |
| `@required` or `@required=true` | required in every environment |
| `@required=false` or `@optional` | never required |
| `@required=env(production, staging)` | required in these environments of the project, by name |
| `@required=tier(production)` | required in every environment of this tier: `development`, `staging`, or `production` |
| `@sensitive` or `@sensitive=true` | sensitive |
| `@sensitive=false` or `@public` | not sensitive |
| `@type=string`, `number`, `boolean`, `url`, or `email` | type |
| `@type=enum(a, b, ...)` | enum type with these values |
| `@example=...` | example (quotes stripped) |

Items:

- `NAME=` declares an item with no default.
- `NAME=literal` or `NAME="literal"` sets the default value.
- `NAME=fn(...)` declares an item whose value comes from elsewhere. Varlatch
  never runs the function and records no default.
- After a value, whitespace followed by `#` starts a comment:
  `PORT=8080 # listen port` gives the default `8080`. A `#` with no
  whitespace before it stays part of the value (`P=p@ss#w0rd` gives
  `p@ss#w0rd`), and so does a `#` inside quotes.
- Plain `# text` comment lines directly above an item become its
  description.
- A blank line resets pending decorators and description.

Item names must match `^[A-Z][A-Z0-9_]*$`. A leading UTF-8 byte-order mark
is ignored, and a file with CR-only line endings is rejected.

## Environment names

`env(...)` names root environments of the project, the ones created without
a parent. A preview or personal environment follows its root. When you push,
each name is resolved to that environment's ID, and the contract revision
stores the IDs, not the names:

- Renaming or deleting an environment later never changes a stored revision.
- The next push resolves the names again. After a rename, the old name fails
  the push. If a name was freed by deleting its environment and then reused
  by a new one, the push selects the new environment. The change shows up as
  a requiredness change when the revision is activated.

Use `tier(...)` when an item is required in every environment of a tier
rather than in specific ones.

`forEnv(...)` is not supported. A file that uses it fails with the
replacement: name the project's environments with `env(...)`, or use
`tier(...)`. For example, `@required=forEnv(prod)` becomes
`@required=env(production)`.

## Known limitations

- **Escape sequences are not interpreted.** `MULTI="a\nb"` gives the literal
  default `a\nb`, not a newline. Multi-line values are not supported.
- **One decorator per line.** A comment line with several decorators is
  rejected, not split.

## What the format cannot express

Anything outside the contract model: value sources and their arguments,
imports, code generation settings, and per-environment `.env.*` files.
