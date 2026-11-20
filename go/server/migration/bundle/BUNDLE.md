# bundle-v1: the migration's bundle

The stream one side of a migration writes and the other reads
(docs/design/go-step7.md decision 2): the TypeScript server's export
writes the **source bundle** (direction `forward`), varlatchd's
`admin migrate export --reverse` writes the **reverse bundle** (direction
`reverse`). Both are the same format. Every row in it is a canonical-v1
row (`../canonical/CANONICAL.md`) of a table of the manifest
(`../manifest/v1.json`), in the manifest's column order.

`testdata/small.jsonl` is a valid bundle and `testdata/refused.json` lists
bundles a reader refuses, each with the reason. A writer in either
language reproduces `small.jsonl` byte for byte from the rows it holds;
a reader in either language refuses every refused case.

## Lines

A bundle is UTF-8 text, one JSON value per line, each line ending in `\n`
(never `\r\n`), no blank line, nothing after the end line:

1. **The header**, exactly these members in this order:

   ```json
   {"bundle":"varlatch-migration","format":1,"manifest":1,"encoding":"canonical-v1","direction":"forward","release":"0.23.0","frozenPoint":{"auditPosition":42,"snapshot":"00000003-0000001B-1"},"sequences":[]}
   ```

   - `format` is this document's version, 1.
   - `manifest` and `encoding` are the manifest's `version` and
     `encoding`; a reader refuses others.
   - `direction` is `forward` or `reverse`.
   - `release` is the release that wrote the bundle: for `forward`, the
     TypeScript release the manifest names as its source.
   - `frozenPoint` is where the writer read from: `auditPosition`, the
     last audit position (an integer, 0 for none), and, for `forward`,
     `snapshot`, the PostgreSQL snapshot exported at the barrier
     (decision 6). A reverse bundle has no `snapshot` member.
   - `sequences` lists the source's sequences. It is always empty
     (decision 16: every id is made by the application); a reader refuses
     a bundle that lists one, so a later one cannot be missed.

2. **For each table** the manifest copies or transforms, in the manifest's
   order (by name), each exactly once, whether it has rows or not:
   - a table line, `{"table":"<PostgreSQL table>","rows":<n>}`;
   - then its `n` rows, one canonical row per line, in the manifest's
     `orderBy` order, or the source's physical order where the manifest
     says `physicalOrder`. `orderBy` sorts as SQLite does: ascending, NULL
     first, integers by value, text and bytes by their bytes (in
     PostgreSQL, `ORDER BY c COLLATE "C" ASC NULLS FIRST` for each column),
     so both sides write the same rows in the same order.

   A table the manifest leaves out never appears. In a reverse bundle the
   `session` table has no rows: every Go browser session ends
   (transformation `browser-sessions-end`).

3. **The end line**:

   ```json
   {"end":{"tables":62,"rows":1234,"sha256":"<64 lowercase hex digits>"}}
   ```

   `tables` and `rows` are the counts above; `sha256` is SHA-256 of every
   byte before the end line, header included. A bundle without its end
   line, or whose digest or counts do not hold, is cut short or damaged:
   a reader refuses it whole, never part of it.

## Member order and spelling

Control lines (the header, table lines, the end line) are written exactly
as above: members in the order shown, no space, integers in decimal,
strings quoted as JSON.stringify quotes them. A reader parses them
strictly: an unknown or missing member is refused.
