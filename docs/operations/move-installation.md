# Moving an installation to another address

An installation's public URL (`VARLATCH_PUBLIC_URL`) is the address people
open in the browser. Use `varlatch move` to change it: for a new domain, or
to go from a tailnet address to a public one.

## What a move changes

Passkeys belong to an address: the browser registers each one for the
host of the public URL (the WebAuthn relying party) and never offers it
anywhere else. So a move is a re-enrollment event:

- **Every passkey stops working, and every browser session ends.** The move
  removes the passkeys of the old address, so nothing mistakes them for
  working ones.
- **Each person enrolls a new passkey on the same identity**, with a
  one-time link the move prints. Their access, memberships, grants, and
  audit history stay as they are.
- **Passkeys and the dashboard stop working at the old address.** With the
  public or tailnet ingress it stops answering. With the external ingress,
  your own proxy decides.

What keeps working:

- **CLI, agent, and machine credentials.** Their tokens don't name an
  address. Change the server address where it is configured: `server` in
  each `varlatch.toml`, `VARLATCH_SERVER`, and `--server` in CI jobs.
  People sign in again with `varlatch login --server <new address>`.
- **OIDC bindings.** They match the external identity provider's issuer and
  audience, not this address. Only the jobs' `--server` changes.
- **Sync Targets and webhooks.** They store where Varlatch sends values and
  events, not this address.

Two things need a decision before you move:

- **Tailnet Constraints**, when you leave the tailnet ingress. Without it,
  nothing reaches the tailnet listener, so the access they guard is denied
  until you remove them (`varlatch tailnet requirements`, then `varlatch
  tailnet remove <id>`).
- **Open invitations.** Their links keep working, but they name the old
  address. Send people the same link with the new address in front of
  `/enroll#`.

## Before you start

- The new address works: for the public ingress, its DNS record points at
  this host and ports 80 and 443 are reachable, as in the
  [deployment guide](../../infra/compose/README.md).
- The backup key (or its passphrase file) and the Root KEK file, as for an
  upgrade: the move takes an archive first and verifies it.
- A way to send each person their link that you trust, and a word to them
  that their passkey will stop working.

## Move

From the Compose directory, on the host:

```sh
varlatch move --public-url https://vault.example.org \
  --bek-file /path/to/backup-key --kek-file /path/to/varlatch-kek
```

Add `--ingress public` or `--ingress external` when the ingress changes too,
for example when you leave the tailnet. The command:

1. Reads what the move affects and prints it: the number of people,
   passkeys, and sessions, and any Tailnet Constraints or open invitations.
   It asks before it changes anything (`--yes` skips the question).
2. Takes an archive in the Compose directory's `backups/` and verifies it
   against the release the installation runs. Restoring it is the way back.
3. Writes the new address to `varlatch-install.json` and `.env`, and starts
   the installation with it. With the public ingress, it waits for the
   certificate.
4. Gives the Application Plane (Convex) the new token issuer.
5. Removes the passkeys of the old address, ends every browser session, and
   revokes the dashboard's tokens.
6. Prints one link per person, Installation Admins first, and waits until an
   Installation Admin has enrolled a passkey. Then it checks the
   installation's health, as setup does.

Open your own link first. Then send each person theirs. A link works once,
for that person only, and expires after 24 hours (`--reenroll-hours`, up to
168).

Need new links, for someone who missed theirs or for a person who lost a
passkey later:

```sh
varlatch admin reenroll --identity <identity-id>   # or --all
```

A new link for a person revokes the unused one before it.

## If the move stops

Run `varlatch move` again, without `--public-url`. `varlatch-move.json`
records how far the move got, so a rerun takes no second archive, issues no
new links, and never removes passkeys people already enrolled at the new
address. The server also records the address of the last move, and refuses
to remove passkeys a second time. `varlatch setup` refuses to run while a
move is open.

## Going back

Give the move up:

```sh
varlatch move --abandon
```

It puts the old address back in `varlatch-install.json` and `.env` and
closes the move. It says whether the old passkeys were already removed:

- **Not removed yet** (the move stopped before step 5): run `varlatch setup`,
  and the installation is back at its old address.
- **Removed**: restore the archive the move took (it prints the path, see
  [Backup and recovery](backup.md)), then run `varlatch setup`. Passkeys
  enrolled at the new address are not in that archive, and would not work at
  the old address anyway.

## Afterwards

- Point the old DNS name elsewhere, or remove it.
- Leaving the tailnet: remove the old node in the Tailscale admin console.
  Its state stays in the `tailscale-state` volume until you remove it.
- With the public ingress, the old address's certificate stays in Caddy's
  data volume, unused.

## Limits

- **Moving to the tailnet ingress is not supported yet.** The Tailscale node
  keeps its own name and state. Set up a new installation on the tailnet and
  restore an archive into it instead.
- **Changing only the ingress, at the same address, is not supported yet.**
  Every passkey would keep working, so it is not a move.
- **Coolify installations** have no `varlatch-install.json`, so there is no
  `varlatch move`. Do the same steps by hand: take and verify an archive;
  change `VARLATCH_PUBLIC_URL` in Coolify and redeploy (each deploy runs
  `convex-deploy`, which gives Convex the new issuer); then run, in the
  `varlatchd` container, `node dist/cli.js admin public-url-changed --from
  <old address>` once (a second run is refused) and `node dist/cli.js admin
  reenroll --all`.
