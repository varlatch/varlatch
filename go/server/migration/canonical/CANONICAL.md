# canonical-v1: the migration's canonical encoding

How a migration writes a value, a row and a digest's input
(docs/design/go-step7.md decisions 3 and 7). Both sides write them:

- the TypeScript server's export, on the 0.22 line, in
  `services/varlatchd/src/migration/canonical.ts`;
- varlatchd, in this package.

Equal values give equal bytes. `testdata/vectors.json` holds the cases.
Both encoders reproduce every output byte for byte and refuse every
refused input; `services/varlatchd/test/migration/canonical-vectors.json`
is the same file.

## Values

A value is written as JSON, by its column's PostgreSQL type, as the
manifest (`../manifest/v1.json`) names it. SQL NULL is `null` in every
type, so it is never confused with an empty string, an empty array or a
jsonb `null`.

| Type | Written as | Refused |
| --- | --- | --- |
| `text` | A JSON string, quoted as ECMAScript's `JSON.stringify` quotes it (below) | Bytes that are not UTF-8, a lone surrogate, U+0000 |
| `timestamp with time zone` | The integer number of microseconds since 1970-01-01T00:00:00Z, in decimal: no exponent, no leading zero, `-` for an earlier time | |
| `integer` | The integer in decimal | A value outside -2147483648..2147483647 |
| `bigint` | The integer in decimal | |
| `boolean` | `1` for true, `0` for false | |
| `jsonb` | A JSON string holding the value's canonical jsonb text (below) | Text that is not JSON; what jsonb refuses (a lone surrogate, U+0000) |
| `text[]` | A JSON array of the elements, each a quoted string or `null` | A nested array, or an element that is not a string or null; an element `text` refuses |
| `bytea` | A JSON string holding the bytes in base64 (RFC 4648, the standard alphabet, padded) | |

Any other type is refused until this document defines it.

**Integers are never passed through a double.** A timestamp past 2^53
microseconds (after the year 2255), or a bigint, would lose digits:
- the TypeScript encoder reads them as `bigint` (PostgreSQL's
  `extract(epoch …)` in microseconds, or the column as text) and writes
  `String(n)`;
- varlatchd reads them as `int64`.

**Quoting** is `JSON.stringify`'s, so it matches the TypeScript server
with no extra code:
- these characters are escaped:
  - `"` and `\`;
  - `\b`, `\f`, `\n`, `\r` and `\t`;
  - every other character below U+0020, as `\u00xx` in lowercase hex;
- everything else is written as it is: `<`, `>`, `&`, U+007F, U+2028,
  U+2029 and every non-ASCII character.

Go's `encoding/json` escapes some of these, so varlatchd uses `jsvalue.Quote`.

**Canonical jsonb text** is the value as both servers read jsonb:
1. Parse the text as `JSON.parse` does: numbers become ECMAScript
   numbers, and a repeated key keeps its last value.
2. Order every object's members as PostgreSQL's jsonb stores them: shorter
   keys first, keys of one length by their bytes, both measured in
   **UTF-8 bytes**. A TypeScript encoder must measure UTF-8 bytes, not
   UTF-16 code units, so `"é"` (two bytes) sorts after `"z"`.
3. Write the result as `JSON.stringify` writes it: no space, numbers in
   `Number.prototype.toString`'s form (`1.0` is `1`, `1e21` is `1e+21`,
   `-0` is `0`).

PostgreSQL's own spelling (`{"a": 1}`, with spaces) and varlatchd's
compact text therefore give the same canonical text. `JsonbText` in this
package is `jsvalue.Canonical` with jsonb's refusals.

## Rows

A row is a JSON array of its values in the manifest's column order, with
no space and no trailing newline: `["id_1",42,1,"{\"k\":[1,2]}","AA=="]`.
A table's rows are taken in the manifest's `orderBy` order, or in the
source's physical order where the manifest says `physicalOrder`.

## Digest input

Decision 7's keyed digest (HMAC-SHA256 under the migration's run key) is
computed over the canonical JSON of `{class, ids, plaintext}` for one
decrypted item:
- the members are in jsonb's order, so `ids`, then `class`, then
  `plaintext`;
- `ids` is an object of strings, its members in jsonb's order too;
- `plaintext` is the plaintext's bytes in base64.

For example:

```json
{"ids":{"orgId":"org_1","itemId":"itm_2"},"class":"value","plaintext":"aGVsbG8="}
```

## Versioning

Any change to this encoding is a new encoding name (`canonical-v2`),
named by a new manifest version. A migration never mixes two.
