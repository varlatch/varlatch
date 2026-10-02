# Correcting an item's sensitivity in the Contract

An item's sensitivity (Secret or plain) is part of the project's Contract. It
applies to the item in every environment of the project, not only the one
you work in. Change it only for the item the human approved, after they
confirmed it is not secret (or is), knowing that it changes the whole
project. Marking an item plain means its value is no longer masked and may
be shown.

There is no one-step command. Edit the Contract and push it as a new
revision, then activate that revision:

```sh
varlatch --assisted contract show > revision.json
jq '.contract' revision.json > contract.json
varlatch --assisted contract push --file contract.json --json
varlatch --assisted contract activate <revision>
```

1. `contract show` prints the active revision, metadata only: its `id`,
   `contentHash`, `semanticsVersion`, and the Contract itself, under
   `contract`. It holds no values.
2. Write the `contract` field, unchanged, to its own file (`jq '.contract'`,
   or any JSON tool). Do not push the whole revision.
3. In that file, change only `"sensitive"` on the approved item. Keep every
   other item, field, and the `semanticsVersion` as they are.
4. `contract push --file contract.json --json` creates a revision and prints
   its id (`revision.id`). Activate that id. Until then, the old revision
   stays active.
5. Remove `revision.json` and `contract.json` (they hold no values), and run
   the command again.

Re-importing a `.env` file with `--plain` does not change an item the
Contract already has, and `contract update` does not exist.
