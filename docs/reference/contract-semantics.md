# Contract Semantics

Contract Semantics are the rules that decide what a Contract means for a
value: whether an item is required in an environment, when an item with no
value is reported missing, and whether a value is valid for the item's type.
From version 2 they also define how a value converts to a typed value, and
version 3 adds the `integer` type.

The rules are defined once, in the `@varlatch/contract` package. The
server's validation, strict startup, and the Typed Accessor that
[`varlatch types`](type-generation.md) generates all evaluate them. Test
vectors in `packages/contract/test/vectors/` pin every version, and run
against the server's rules and the built accessor alike. Version 2 also has
portability vectors: its existing results on inputs where languages' regular
expressions and parsers commonly differ, such as non-ASCII digits, Unicode
case folding and whitespace, a trailing newline, and URL hosts. They hold any
implementation of the rules in another language to the same results.

## Versions

Every contract revision records the semantics version it is evaluated with.
The version is fixed when the revision is created, and a released version
never changes: different results for any input make a new version.
`GET /v1/meta` lists the versions a server supports as `semanticsVersions`,
and every contract revision in the API carries its `semanticsVersion`.

| | Version 1 | Version 2 | Version 3 |
| --- | --- | --- | --- |
| Used by | every revision created before 0.11.0 | a new project's first revision, from 0.11.0 to 0.12.0 | a new project's first revision, from 0.13.0 |
| Conversion to typed values | none | numbers and booleans | numbers, integers, and booleans |
| Number magnitude | unbounded | at most 9007199254740991 (2^53 - 1) | at most 9007199254740991 (2^53 - 1) |
| The `integer` type | not available | not available | available |

Version 3 is version 2 plus the `integer` type: its other rules are
version 2's. Rules not in the table are the same in all three versions.

### Which version a revision gets

- A push or edit keeps the version of the project's active revision, so
  editing a description never changes the rules.
- A project's first revision gets the newest version.
- `varlatch contract push --semantics latest` moves to the newest version,
  and `--semantics 1` pins version 1. A contract pushed with `--file` can
  set `semanticsVersion` itself. A version the server does not support is
  refused.
- On the dashboard, a Contract on older rules offers **Move to the newest
  rules**. It creates a revision with the same items at the newest version
  and shows the difference and its consequences, and you activate it
  separately. It works for Git-managed Contracts too: later pushes from the
  repository keep the version, so the file needs no change.
- A type a version does not define is refused. An `integer` item in a
  revision at version 1 or 2 fails the push, and `varlatch contract push`
  says so before sending anything, naming the fix: push with
  `--semantics latest`, or move the Contract on the dashboard first.
- The version is part of the content hash, so the same items at another
  version are a different revision. Activating it shows the version change
  like any other contract change.

## Requiredness

An item is required `always`, `never`, in named root environments, or in
every environment of a tier. A derived environment, such as a preview or
personal environment, follows its root.

An item with no value is reported missing when it is required in the
environment and has no contract default. An empty string is a value, not a
missing one, and is validated like any other.

## Types

| Type | Valid values | Converts to, from version 2 |
| --- | --- | --- |
| `string` | anything, including the empty string | the string |
| `number` | an optional `-`, ASCII digits, and an optional `.` followed by digits. No exponent, no leading `+`, no spaces. | a number |
| `integer` (version 3) | an optional `-` and ASCII digits, nothing else: no decimal point, so `3.0` is not an integer, and no exponent, leading `+`, separator, or spaces | the whole number |
| `boolean` | `true`, `false`, `1`, or `0`, in any case | `true` for `true` and `1`, `false` for `false` and `0` |
| `url` | anything the WHATWG URL parser accepts, so `localhost:3000` is a URL with the scheme `localhost:` | the string |
| `email` | text with one `@` and a dot after it. This is a pattern check, not an address parser. | the string |
| `enum` | exactly one of the listed values, case-sensitive | the string |

### Numbers in version 2

Version 2 bounds a number so that every valid number converts to the value
it is written as, or to the nearest double for a fraction, and never to a
different integer or to infinity:

- The magnitude of the exact decimal value must be at most
  9007199254740991. It is checked on the digits before any rounding, so
  `9007199254740993`, `9007199254740993.0`, and `9007199254740991.5` are
  invalid, while `9007199254740991.0` is valid and converts to
  9007199254740991.
- Within that bound, a fraction converts to the nearest double, and digits
  beyond its precision are not preserved:
  `0.1000000000000000055511151231257827` converts to `0.1`.
- `-0` converts to negative zero.

### Integers in version 3

An `integer` holds a whole number, such as a port, a count, or a size.

- Only an optional `-` and ASCII digits are valid. `3.0`, `3.5`, `+1`,
  `1e3`, `1_000`, ` 1`, and non-ASCII digits are all invalid, with the
  reason "must be a whole number". Leading zeros are allowed: `0080` is 80.
- The magnitude must be at most 9007199254740991 (2^53 - 1), checked on
  the digits, as for `number`. `-0` converts to 0.
- `number` does not change: it keeps accepting `3.5` in every version. An
  item rejects fractions only once its Contract declares it `integer`.
- Generated types make an `integer` a `number` in TypeScript and an `int`
  in Python.

### Moving a Contract to version 3

Moving to newer rules changes how every value is checked, so plan it:

- Generated type files become stale; regenerate them with `varlatch types`,
  and `varlatch types --check` fails until you do.
- `varlatch run --strict` from a CLI that does not implement version 3
  refuses to start the command, naming the version. Upgrade the CLI
  wherever strict runs use the project, CI included.
- A module generated for an older version refuses a run context for
  version 3 and asks for regeneration.

## Validation reports

Validation checks each value in the form `varlatch run` delivers it to
the caller, with references expanded:

- A non-sensitive value expands references to non-sensitive values only.
- A Secret expands references to Secrets and, when the caller may read
  them, to non-sensitive values.

A value that would keep a reference literal gets no type verdict. It is
listed in the report's `unresolved` list:

- `authority`: a Secret references non-sensitive values the caller may not
  read. A caller who may read them gets it expanded, so the report is
  incomplete, and `varlatch validate` exits 2.
- `reference`: anything else, such as a reference to an item with no
  value, a non-sensitive value that references a Secret (never expanded),
  or a cycle. The report is invalid, and `varlatch validate` exits 1.

`$${NAME}` is an escaped reference: it is delivered as the literal text
`${NAME}` and validated as such.

Values read only to expand a reference are audited before they are
decrypted, like the values being validated.

A validation reason never contains the value or any part of it, for any
item. An enum reason lists the contract's allowed values, never the
rejected one.
