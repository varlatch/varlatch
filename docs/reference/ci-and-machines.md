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

An organization can bound how long machine credentials last with the
`credential-lifetime` security control. While it is enforced, a credential
issued without `--ttl` (or without a lifetime in the dashboard) gets the
organization's default lifetime, and a longer `--ttl` than its maximum is
refused, with nothing issued. Credentials that already exist keep their
expiry. See [Credential
lifetime](security-controls.md#credential-lifetime).

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

## Brokers on many machines

A control plane that schedules jobs on many machines can decide, per job,
which secrets a machine's broker may use, without the machine being able to
widen that. This needs the Go server (0.50.0 or later): check that `/v1/meta`
lists `capabilities.delegate`, `capabilities.single-use` and
`auth.oidc.limits` first, since a server without them ignores the limits
below.

Set it up once, as an admin:

1. An identity for the orchestrator (`service` or `workload`), with a grant
   of `capability.issue` on the environments it schedules for. The grant
   reads no value; no built-in role holds the action, so it is always given
   explicitly, by someone who may manage policy. It has no effect for people
   and agents.
2. An `agent` identity with `secret.use` on those environments. Every use is
   checked against its grants, whoever issued the Capability: give each kind
   of job an agent of its own to keep what can be reached small.
3. A `broker` identity (one for all machines, or one each), with an OIDC
   binding and no grants:

   ```http
   POST /v1/organizations/acme/identities/{broker}/oidc-bindings
   { "issuer": "https://tokens.example.com", "audience": "varlatch",
     "subject": "machine:*", "exerciseOnly": true, "runIdClaim": "job_id" }
   ```

Then, for each job:

1. The orchestrator issues a Capability for the broker, with its own
   credential:

   ```http
   POST /v1/organizations/acme/projects/api/environments/production/capabilities
   { "brokerIdentityId": "{broker}", "agentIdentityId": "{agent}",
     "items": ["API_KEY"], "destinations": ["api.example.com"],
     "targets": { "API_KEY": ["header:authorization"] },
     "ttlSeconds": 1800, "runId": "job-4711", "singleUse": true }
   ```

   The answer's `id` and `secret` go to the machine with the job. Leave
   `singleUse` out for a job that needs the value more than once.
2. The machine exchanges the token its platform gave it, whose `job_id` claim
   is `job-4711`:

   ```http
   POST /v1/oidc/token
   { "token": "eyJ…", "organization": "acme" }
   ```

   It gets a credential for at most an hour, tied to that run. The token
   exchanges once: a machine that loses the answer needs a new token.
3. The machine's broker exercises the Capability with that credential:

   ```http
   POST …/environments/production/capabilities/{id}/exercises
   { "capabilitySecret": "{secret}", "destination": { "host": "api.example.com", "port": 443 },
     "placements": [{ "item": "API_KEY", "target": "header:authorization" }] }
   ```

   Anything else the credential asks for is refused, reads included. A
   granted exercise of a single-use Capability uses it up even when the
   answer is lost: issue another one then. A refused exercise, or one that
   delivers no item (none of the placed items has a value), does not.
4. The orchestrator revokes what it issued when the job ends
   (`DELETE …/capabilities/{id}`), and sees what it issued with
   `GET …/capabilities`. Expiry is the fallback.

Removing the orchestrator's grant refuses every Capability it issued from
the next exercise on; retiring it revokes them, and reactivating it brings
none back. Revoking an OIDC binding stops new token
exchanges immediately, while credentials already exchanged from it stay valid
until they expire (at most an hour) unless you revoke the credential or
retire the identity. If the orchestrator also signs the machines' tokens, it
can act as their broker too: keep the signing key apart from the credential
that issues. The
[threat model](../THREAT-MODEL.md#6-agent-safety-the-credential-broker-shipped)
says what each party can still do when compromised.

An identity's live OIDC bindings for one issuer must be all limited
(`exerciseOnly` or `singleExchange`) or all unlimited, so a rollback to an
earlier server cannot fall back to an unlimited binding for that issuer. To
move from unlimited to limited bindings without downtime, create a separate
identity with the limited binding, switch workloads to it, and revoke the old
one; to switch an existing identity in place, revoke its unlimited bindings
for that issuer before creating the limited one. Rotating between two limited
bindings on the same identity and issuer works with overlap: a token gets the
limits of every binding it matches, and those of the ones left once one is
revoked. Where they are
mixed all the same (an earlier server, which knows no limits, can add an
unlimited one after a rollback), no token of that issuer exchanges as that
identity (`mixed-bindings` in the audit log) until the bindings of one kind
are revoked.

An application that needs a person's API key does not have to handle it: it
makes an [entry link](entry-links.md), the person enters the key in Varlatch,
and a Capability uses it. A pending link ends when the credential that made it
is revoked, so replace a credential an hour after the last link was made with
it.

A machine that uses an API behind OAuth gets the access token the same way:
the Capability names an [OAuth connection](oauth-connections.md), and the
exercise gives the token and when it ends, refreshed first when
`minValiditySeconds` asks for more than it has left.

A machine that has to pass a site's two-factor sign-in gets the code the same
way: the Capability names an item that holds a
[one-time code](one-time-codes.md)'s seed, and the exercise gives the code.

`singleExchange` on its own, without `exerciseOnly`, makes each token of an
ordinary binding exchange once. It is off by default: a CI job that runs
`varlatch login --oidc` more than once with one token needs it off.

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
