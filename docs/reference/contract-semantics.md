# Contract Semantics

Contract Semantics are the rules that decide what a Contract means for a
value: whether an item is required in an environment, when an item with no
value is reported missing, and whether a value is valid for the item's type.
From version 2 they also define how a value converts to a typed value.

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

| | Version 1 | Version 2 |
| --- | --- | --- |
| Used by | every revision created before 0.11.0 | a new project's first revision, from 0.11.0 |
| Conversion to typed values | none | numbers and booleans |
| Number magnitude | unbounded | at most 9007199254740991 (2^53 - 1) |

All other rules are the same in both versions.

### Which version a revision gets

- A push or edit keeps the version of the project's active revision, so
  editing a description never changes the rules.
- A project's first revision gets the newest version.
- `varlatch contract push --semantics latest` moves to the newest version,
  and `--semantics 1` pins version 1. A contract pushed with `--file` can
  set `semanticsVersion` itself. A version the server does not support is
  refused.
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

| Type | Valid values | Version 2 converts to |
| --- | --- | --- |
| `string` | anything, including the empty string | the string |
| `number` | an optional `-`, ASCII digits, and an optional `.` followed by digits. No exponent, no leading `+`, no spaces. | a number |
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
