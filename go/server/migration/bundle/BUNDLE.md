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

   A column the manifest leaves out (`leftOut`, the session's token) is
   written as `null` in every row: the 0.23.0 export never reads it, and a
   reader refuses a row that carries a value there. A table the manifest
   leaves out never appears. In a reverse bundle the
   `session` table has no rows: every Go browser session ends
   (transformation `browser-sessions-end`).

3. **The digest section** (decision 7): a line `{"digests":<n>}`, then
   `n` lines, one per encrypted item the writer holds, each

   ```json
   {"class":"org-kek","ids":{"organizationId":"org_..."},"hmac":"<64 lowercase hex digits>"}
   ```

   - `class` is the item's encryption class, `ids` the item's envelope
     context without its `purpose` (a value's `organizationId`,
     `secretId`, `versionId`; the canary's `installationId`; ...), members
     in jsonb's order (shorter keys first, then by bytes), every member a
     string.
   - `hmac` is HMAC-SHA256, under the migration's run key, of the digest
     input `canonical.DigestInput(class, ids, plaintext)`
     (`../canonical/CANONICAL.md`, "Digest input"). The run key itself is
     never in the bundle: `migrate` hands it to each side on a pipe.
   - Lines are sorted by `class`, then by the bytes of `ids` as written;
     no two lines are the same item.
   - The classes and the items each covers are `../check/CHECKS.md`'s.

   A reverse bundle's digest section is empty until the reverse checks
   (slice 7.6) fill it.

4. **The decision section** (decision 8): a line
   `{"decisions":<n>,"at":<Unix microseconds>}`, then `n` lines, each one
   decision of the writer's evaluator at `at`:

   ```json
   {"credential":"crd_...","state":"active","organization":"org_...","project":"prj_...","environment":"env_...","action":"secret.reveal","tailnet":null,"allowed":true,"code":null}
   ```

   - `state` is the credential state the decision assumes: `active`,
     `expired` or `revoked`.
   - `project` and `environment` are `null` for an action on the
     Organization (or the Project); an environment is always in a Project.
   - `tailnet` is `null`, or the Tailnet Context the decision assumes:
     `{"tailnet":"...","nodeId":"...","tags":[...],"userLogin":null}`
     (`userLogin` a string or `null`).
   - `allowed` is the answer; `code` is the error code of a denial
     (`PERMISSION_DENIED`, `RESOURCE_NOT_FOUND`, `UNAUTHENTICATED`,
     `TAILNET_CONTEXT_REQUIRED`, ...), `null` when allowed.

   Lines are in the writer's order. A reverse bundle's decision section
   is empty until the reverse checks fill it.

5. **The end line**:

   ```json
   {"end":{"tables":62,"rows":1234,"digests":5,"decisions":40,"sha256":"<64 lowercase hex digits>"}}
   ```

   `tables`, `rows`, `digests` and `decisions` are the counts above;
   `sha256` is SHA-256 of every byte before the end line, header
   included. A bundle without its end line, or whose digest or counts do
   not hold, is cut short or damaged: a reader refuses it whole, never
   part of it.

## Member order and spelling

Control lines (the header, table lines, the section lines, digest and
decision lines, the end line) are written exactly as above: members in
the order shown, no space, integers in decimal, strings quoted as
JSON.stringify quotes them. A reader parses them strictly: an unknown or
missing member is refused, and a digest or decision line not written
exactly so is refused too.
