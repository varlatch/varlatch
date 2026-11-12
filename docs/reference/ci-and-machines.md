# CI and other machines

Machines never use a person's passkey. Create a machine identity in the
dashboard, under Access, then Machines, and grant it the environments it
needs: like a person, it starts with no access.

## CI that issues OIDC tokens

CI that issues OIDC tokens, such as GitHub Actions, needs no stored secret
at all. Give a `ci` identity an OIDC binding: the token issuer (filled in
for GitHub Actions), an audience you choose, and the subject your jobs'
tokens carry, such as `repo:acme/api:*`. In the job,
[install the CLI](install-the-cli.md), then sign in and run; on GitHub
Actions, the job needs the `id-token: write` permission:

```sh
varlatch login --server https://vault.example.com --oidc --org acme --audience <audience>
varlatch run -e production -- ./deploy.sh
```

On another CI system, pass its token with `--oidc-token`.

## Servers and other workloads

Servers and other workloads use a credential shown once when you create
the identity. Store it where the machine keeps its secrets, and sign in
with `varlatch login --server <url> --token-stdin < credential-file`.

Programs on one host can share an identity and its grants, each with a
credential of its own that you revoke on its own. Issue another one in
the machine's Credentials panel in the dashboard, or with the CLI, which
writes the token only to a new file that only you can read, never to
its output:

```sh
varlatch credential issue <identity-id> --name "backup job" --out backup-job.token
varlatch credential list <identity-id>                  # every credential, by name
varlatch credential revoke <identity-id> <credential-id>
```

To find credentials that may no longer be needed, run
`varlatch security report` (`--json` for the whole document). It lists
the organization's machine credentials that were never used, have not
been used for 30 days, or never expire, each with its identity and when
it was last used. It only reports: nothing is revoked or retired for
you. It needs `identity.manage`, as `credential list` does. Short-lived
credentials from OIDC sign-ins and agent-safe runs expire within an hour
and are left out.

To replace a credential, issue the new one, move the program to it, then
revoke the old one.

A credential issued with an expiry (`--ttl`) warns ahead: in its last 7
days, however long it was issued for, the machine's Credentials panel
marks it, every API response to it carries a `Varlatch-Credential-Expires`
header, and the CLI, given it in `VARLATCH_TOKEN`, prints a warning on
stderr (never on stdout).
[Credential expiry warnings](scripting.md#credential-expiry-warnings)
has the details.

A program can ask Varlatch which identity its credential belongs to:
`GET /v1/me` answers with the identity, its organization, and the
credential's own name, and needs no grant. On the command line,
`varlatch whoami` prints the same for the credential the CLI would use
(`VARLATCH_TOKEN`, else the stored one). A program that relies on the
answer should use another way only when the server lacks the
`identity.whoami` capability. A refused credential, a server error, or
an identity it does not expect (another organization, a name outside its
convention: identities can be renamed) is an error to report. Each call
spends a use of a use-limited credential, so ask once and keep the
answer.

## What a machine can reach

Open it in Access, then Machines, or ask the CLI:

```sh
varlatch identity reach deployer        # an identity ID or name; --json for the whole document
```

It lists the machine's state and, per project and environment, what its
grants allow. Reading values where a tailnet requirement applies shows the
requirement as a condition, such as
`needs tailnet example.ts.net: tag:prod`: a request must come from a
device that meets it. The list checks no device and never shows a value.
It needs permission to read identities and policy.

## Platforms that keep their own copy

Varlatch can also push an environment's values to GitHub Actions, Coolify,
or Convex, for platforms that keep their own copy: add an integration on the
environment's Integrations tab. [Integrations](integrations.md)
lists the credential each platform needs and where to find every field.
