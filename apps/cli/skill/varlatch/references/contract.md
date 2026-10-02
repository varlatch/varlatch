# Correcting an item's sensitivity in the Contract

An item's sensitivity (Secret or plain) is part of the project's Contract. It
applies to the item in every environment of the project, not only the one
you work in. Change it only for the item the human approved, after they
confirmed it is not secret (or is), knowing that it changes the whole
project. Marking an item plain means its value is no longer masked and may
be shown.

There is no one-step command. Edit the Contract and push it as a new
revision, then activate that revision. Work in a new temporary directory,
so no file in the project is overwritten or deleted:

```sh
dir=$(mktemp -d)
varlatch --assisted contract show > "$dir/revision.json"
jq '.contract' "$dir/revision.json" > "$dir/contract.json"
varlatch --assisted contract push --file "$dir/contract.json" --json
varlatch --assisted contract activate <revision>
rm -r "$dir"
```

1. **Keep the server.** When the exit-78 message names a server
   (`add --server <url> to every contract command`), add that
   `--server <url>` to `contract show`, `contract push`, and
   `contract activate`. Without it they act on the project's default
   server, and change another server's Contract.
2. `contract show` prints the active revision, metadata only: its `id`,
   `contentHash`, `semanticsVersion`, and the Contract itself, under
   `contract`. It holds no values.
3. Write the `contract` field, unchanged, to its own file (`jq '.contract'`,
   or any JSON tool). Do not push the whole revision.
4. In that file, change only `"sensitive"` on the approved item. Keep every
   other item, field, and the `semanticsVersion` as they are.
5. `contract push --file "$dir/contract.json" --json` creates a revision and
   prints its id (`revision.id`). Activate that id. Until then, the old
   revision stays active.
6. Remove the temporary directory, and only it (the files hold no values),
   then run the command again.

Re-importing a `.env` file with `--plain` does not change an item the
Contract already has, and `contract update` does not exist.
