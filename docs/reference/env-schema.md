# The `.env.schema` contract file

A project with a git-authored contract keeps it in the repository as a
`.env.schema` file and pushes it with
`varlatch contract push --schema .env.schema`. This page defines the format
Varlatch accepts. Anything it does not list is unsupported.

Varlatch parses the file on your machine, resolves the environment names it
uses through the project's Environment Name Mapping, and pushes the result
as a contract revision. The server stores and enforces that contract, never
the file itself. Values never come from `.env.schema`: they live in
Varlatch, and `varlatch run` delivers them.

## Fail loudly

A decorator the parser does not understand is an error, never ignored. An
environment name in `forEnv(...)` that the project has not mapped is also an
error when you push. The only accepted no-op decorators are the
presentation-only `@docs`, `@icon`, and `@tag`.

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
| `@required=forEnv(a, b)` | required in the environments `a` and `b` map to |
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
- Plain `# text` comment lines directly above an item become its
  description.
- A blank line resets pending decorators and description.

Item names must match `^[A-Z][A-Z0-9_]*$`. A leading UTF-8 byte-order mark
is ignored, and a file with CR-only line endings is rejected.

## Known limitations

- **Trailing comments and inline decorators become part of the value.**
  `API_KEY=abc # @sensitive=false` gives the default
  `abc # @sensitive=false`, and the decorator is not applied.
  `PORT="8080" # listen port` gives the default `"8080" # listen port`,
  quotes included. Put decorators and comments on their own lines.
- **Escape sequences are not interpreted.** `MULTI="a\nb"` gives the literal
  default `a\nb`, not a newline. Multi-line values are not supported.
- **One decorator per line.** A comment line with several decorators is
  rejected, not split.

A `#` with no whitespace before it stays part of the value: `P=p@ss#w0rd`
gives `p@ss#w0rd`.

## What the format cannot express

Anything outside the contract model: value sources and their arguments,
imports, code generation settings, and per-environment `.env.*` files.
