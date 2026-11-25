# Moving an installation to another address

An installation's public URL ([`public_url`](../self-hosting/configuration.md#public_url))
is the address people open in the browser. Use `varlatch move` to change it,
for example for a new domain. To move to another host at the same address,
[restore a backup](backup.md#restore-on-a-fresh-host-or-retry-an-interrupted-restore)
there instead. To move from 0.23.0 to 0.50, [migrate](migrate-to-0.50.md).

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
- **Passkeys and the dashboard stop working at the old address.** With
  public HTTPS it stops answering. With your own proxy, the proxy decides.

What keeps working:

- **CLI, agent, and machine credentials.** Their tokens don't name an
  address. Change the server address where it is configured: `server` in
  each `varlatch.toml`, `VARLATCH_SERVER`, and `--server` in CI jobs.
  People sign in again with `varlatch login --server <new address>`.
- **OIDC bindings.** They match the external identity provider's issuer and
  audience, not this address. Only the jobs' `--server` changes.
- **Sync Targets and webhooks.** They store where Varlatch sends values and
  events, not this address.
- **The tailnet node,** if there is one: it keeps its name and state.

Open invitations need a decision before you move. Their links keep working,
but they name the old address. Send people the same link with the new
address in front of `/enroll#`.

## Before you start

- The new address works. With public HTTPS, its DNS record points at this
  host and ports 80 and 443 are reachable. With your own proxy, the proxy
  forwards the new address to `varlatchd`.
- You have a way to send each person their link that you trust, and have
  told them that their passkey will stop working.

## Move

On the host:

```sh
sudo varlatch move --public-url https://vault.example.org
```

Add `--ingress public` or `--ingress external` when that changes too:
`public` is `varlatchd`'s own HTTPS, `external` is your own proxy. A
localhost installation needs one of them. The command:

1. Reads what the move affects and prints it: the number of people,
   passkeys, and sessions. It asks before it changes anything (`--yes`
   skips the question, and is needed without a terminal).
2. Takes an archive, verifies it and prints its path. Restoring it is the
   way back. **Copy it out of `/var/lib/varlatch/backups` now:** there it is
   an ordinary archive, which later backups push out
   ([`backup_keep`](../self-hosting/configuration.md#backup_keep)).
3. Writes the new address to `/etc/varlatch/varlatchd.conf`, and restarts
   `varlatchd` with it.
4. Removes the passkeys of the old address, and ends every browser session.
5. Prints one link per person, Installation Admins first, and waits until an
   Installation Admin has enrolled a passkey. With `--no-wait` it exits 75
   instead.

Open your own link first. Then send each person theirs. A link works once,
for that person only, and expires after 24 hours (`--reenroll-hours`, up to
168).

Need new links, for someone who missed theirs or for a person who lost a
passkey later:

```sh
sudo varlatch admin reenroll --identity <identity-id>   # or --all
```

A new link for a person revokes the unused one before it.

## If the move stops

Run `sudo varlatch move` again, without `--public-url`. The host records
how far the move got, so a rerun takes no second archive, issues no new
links, and never removes passkeys people already enrolled at the new
address.

## Going back

Give the move up:

```sh
sudo varlatch move --abandon
```

It puts the old address back in `varlatchd.conf`, restarts `varlatchd`, and
says whether the old passkeys were already removed. If they were, restore
the archive the move took. It prints the archive's path.
[Close every way in](backup.md#keep-clients-away) first:

```sh
sudo systemctl stop varlatchd
sudo varlatch admin backup restore --in <your copy of it>
```

Only when it says `Restore completed`:

```sh
sudo systemctl start varlatchd
```

Every change since the move began is lost with it, revocations included. The
installation is held: put right what changed, then run
`sudo varlatch admin restore resume` and open it again
([Put an archive back](backup.md#put-an-archive-back-on-the-same-host), which
also says what to do when the restore is refused). Passkeys enrolled at the
new address are not in that archive, and would not work at the old address
anyway.

## Afterwards

- Point the old DNS name elsewhere, or remove it.
- With public HTTPS, the old address's certificate stays in
  `/var/lib/varlatch/acme`, unused.

## Limits

- **Moving to the tailnet ingress is not supported:** the tailnet node
  keeps its own name and state.
- **Changing only the ingress, at the same address, is not a move:** every
  passkey keeps working. Edit `varlatchd.conf` and restart.
- **In the container image,** `varlatch move` does not apply: it drives the
  systemd service. Do the same steps by hand. Take an archive
  (`varlatchd admin backup run`), change `public_url` in the configuration
  file and restart the container, then run `varlatchd admin
  public-url-changed --from <old address>` once in it (a second run is
  refused), and `varlatchd admin reenroll --all`.
