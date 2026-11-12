# Passkeys and sessions

Varlatch has no passwords. You sign in with a passkey kept on your
device, in a password manager, or on a security key.

## Your passkeys

Your passkeys are listed in the dashboard under your account, then
Security. Keep at least two, for example a laptop and a security key, so
losing one device never locks you out.

Each passkey is either **trusted** or **unconfirmed**:

- **Trusted:** a passkey you created from a link: setting up the
  installation, an invitation, or a link from whoever runs the server
  (`varlatch admin reenroll`, or `admin recover` for an Installation
  Admin). Passkeys that existed before Varlatch began recording this are
  trusted too.
- **Unconfirmed:** a passkey you added in the dashboard while signed in.
  To make it trusted, choose **Confirm with another passkey** and use one of
  your trusted passkeys with its PIN, fingerprint or face.

Why the difference: someone who stole your signed-in browser session could
add a passkey of their own. They cannot confirm it without one of your
trusted passkeys.

Signing in and approving a CLI sign-in work with any of your passkeys, and
you can remove any of them, as before. What only a trusted passkey can do
is approve a change that needs your approval, such as turning an
organization's security control down or off ([Security controls and
approvals](security-controls.md)). Once security controls can be
enforced, an organization will also be able to require a sign-in with a
trusted passkey that verified you.

If none of your passkeys is trusted, you cannot confirm one yourself: ask
whoever runs the server for a link (`varlatch admin reenroll --identity
<your identity id>`). The passkey you create with it is trusted.

Organization admins can see on the organization's **Security** page
whether every admin has a trusted passkey, along with the security
controls and what each would do ([The Security
page](security-controls.md#the-security-page)).

## Signing in from the CLI

`varlatch login --server <url>` opens your browser, or prints the address
to open, and you sign in with your passkey.

On a machine without a browser, such as a server over SSH or a container,
sign in with a code instead, approving it with your passkey on any other
device:

```sh
varlatch login --server https://vault.example.com --start   # prints an address and a code
varlatch login --server https://vault.example.com --wait    # after you approved it
```

`varlatch status` shows where you are signed in and when the credential
expires. Without `--server`, `varlatch login` signs in again to the server
a command here would use: the repository's, or your default server.

## The default server

The first server you sign in to becomes your **default server**. Commands
outside a repository use it when you give no `--server` and set no
`VARLATCH_SERVER`, such as `varlatch org create` or `varlatch project
create`, and `varlatch init` writes it into `varlatch.toml`. With no
default, they use the only server you are signed in to.

A repository never uses it: its `varlatch.toml` names its own server, so
signing in somewhere else never moves where a repository's values go. A
`varlatch.toml` without a server is an error that names the line to add.

Signing in to another server never replaces the default. To see it, and
to change it:

```sh
varlatch server                            # the server a command here uses, and the default
varlatch server use https://vault.example.com   # a server you are signed in to
```

Signing out of the default server forgets it. The setting lives in
`settings.json`, next to your credentials
([What Varlatch puts on your machine](uninstall.md#what-varlatch-puts-on-your-machine)).

## Signing out

Signing out of the dashboard ends the browser's access at once: the
short-lived tokens the dashboard took from that browser session stop
working immediately, and so do those of a session you end from another
browser. The CLI sign-in is a credential of its own (12 hours by default,
`--ttl` to shorten it): signing out of the browser you signed in with does
not end it. Run `varlatch logout`, or revoke it under your account's
**Active sessions** in the dashboard.
