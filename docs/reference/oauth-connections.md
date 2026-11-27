# OAuth connections

An automation that uses somebody else's API (a mailbox, a drive, an ERP)
needs an OAuth access token, which ends after an hour or so and is made anew
from a refresh token that the provider may replace at every use. Two machines
with a copy each break the connection. Varlatch can hold the connection as an
item of an environment: it keeps the client secret and the refresh token,
refreshes in one place, and gives a broker the access token and when it ends.
Nothing delivers the refresh token or the client secret, to anyone.

This needs the Go server (0.50.0 or later): `/v1/meta` lists
`oauth.connections`.

What to register at the provider: [Google](oauth-google.md),
[Microsoft](oauth-microsoft.md), [another provider](oauth-generic.md).

## Making one

In the dashboard: an environment's page, **Add an OAuth connection**. Over
the API, with `config.value.write` there (a connection to a person's account
is made by a person; a machine may make a client's own):

```http
POST /v1/organizations/acme/projects/mail/environments/production/oauth-connections
{ "item": "MAIL_TOKEN",
  "provider": { "preset": "google" },
  "clientId": "…", "clientSecret": "…",
  "scopes": ["https://www.googleapis.com/auth/gmail.send"],
  "hosts": ["gmail.googleapis.com"] }
```

- **`provider`**: a preset, or `generic` with an `issuer` or the endpoints.
  The provider's metadata is read once, now. The endpoints in it are pinned:
  the client secret and the tokens are sent to these and to nothing else,
  whatever the metadata says later. `POST …/oauth-connections/discovery`
  shows them without making anything.
- **`provider.endpointHosts`**: every address of a generic provider's
  (authorization, token, revocation, userinfo, keys, issuer) is on one host,
  the issuer's or, with the endpoints given, the token endpoint's, unless the
  request names the others here. Otherwise it is refused (`endpoint-hosts`,
  with the hosts nobody named). The answer's `provider.endpointHosts` are all
  of them, and they are part of the [redirect URI](#connecting). A preset has
  fixed hosts.
- **`scopes`**: what to ask for. The presets add what they need to know the
  account and to get a refresh token.
- **`hosts`**: the destinations the access token may go to, written as a
  Capability's are. A Capability that names the connection may name only
  these, and an exercise for another is refused, also of a Capability issued
  before. Without hosts, whatever the Capability says.
- **`grant`**: `authorization_code` (the default), a person's consent, or
  `client_credentials`, the client's own access, nobody's account.

The client secret is stored encrypted, as every value is, and no operation
answers it. The rest is metadata: whoever may see that the item exists
(`config.metadata.read`) reads the endpoints, the client ID, the scopes, the
hosts, the account and the state. It is stored unencrypted, as item names
are.

The item is always a Secret. In the Contract it is an ordinary `string`
marked sensitive; make it optional, since no run delivers it. A value does
not replace a connection: delete the item first.

`client_credentials` needs a client secret; a public client (without one)
connects a person with PKCE alone. The device flow is not supported.

## Connecting

A person connects it, in their dashboard session, with `config.value.write`
in the environment: **Connect** on the item. Varlatch sends the browser to
the provider with a state, a nonce and a PKCE challenge (S256), and the
provider sends it back to the **redirect URI** shown with the connection,
which has to be registered there exactly:

```
https://{your Varlatch}/oauth/callback/{the token endpoint's host}
```

A generic provider on several hosts has them all in it, the token endpoint's
first and the others in order: `…/oauth/callback/login.example.com~api.example.com`.

Each provider has its own address, so a code one provider was asked for is
never sent to another. And each set of hosts has its own: a connection that
somebody made with one more host in it has a redirect URI that is not
registered with the client, so the provider sends nobody back to it and no
token, nor the client secret, ever goes there. Register the exact URI, never a
pattern or a prefix, and read the hosts: the dashboard shows them before the
client secret can be typed, on the item, and before a browser goes to a
generic provider.

The state is good for ten minutes, once, and only in
the session that began it; the code is exchanged by the server and is in no
log of Varlatch's. (A proxy in front of Varlatch may log the address the
browser came back to. The code in it is spent by then, and useless without
the PKCE verifier. That page is kept in no cache and sends no referrer.) This installation needs a public URL over HTTPS, or a
loopback one.

Where the provider gives an ID token, Varlatch verifies it (signature,
issuer, audience, nonce, times) and knows **whose account** it is; otherwise
its userinfo endpoint says, where there is one. Who connected it is recorded.

**Connecting again** needs the same account. Another one is refused and
nothing of it is kept, unless the person asked for it (**Another account**;
`confirmAccountChange`), and the change is in the audit log. This holds after
a disconnection too, and after a change of its provider or client ID. When the provider never said whose account it is,
Varlatch cannot tell.

## Getting a token

Issue a Capability that names the item, as for any Secret, and exercise it:

```http
POST …/environments/production/capabilities/{id}/exercises
{ "capabilitySecret": "{secret}", "destination": { "host": "gmail.googleapis.com", "port": 443 },
  "placements": [{ "item": "MAIL_TOKEN", "target": "header:authorization" }],
  "minValiditySeconds": 1800 }
```

```json
{ "items": [{ "name": "MAIL_TOKEN", "versionId": "ver_…", "kind": "oauth", "value": "ya29…",
    "expiresAt": "2026-11-24T11:00:00.000Z", "expiresInSeconds": 3291 }],
  "withheld": [], "targets": { "MAIL_TOKEN": ["header:authorization"] } }
```

Send `value` as a Bearer token. `expiresInSeconds` counts from the answer.
`expiresAt` and `expiresInSeconds` are absent when the provider does not say
how long its tokens last.

- The token is **refreshed first** when it has ended, ends within a minute
  (or the last quarter of a shorter life), or ends before
  `minValiditySeconds`. However many ask at once, the provider is asked once
  and all get the same new token.
- **`minValiditySeconds`** as long as the provider's tokens last, or longer, is
  refused: 422, reason `min-validity-too-long`, with `lifetimeSeconds`. For a
  longer validity alone the provider is asked once a minute at most (or once a
  quarter of a shorter life): within it, 429 `RATE_LIMITED`, reason
  `connection-unavailable`, cause `just-refreshed`, with `retryAfterSeconds`.
- **No token now** (the provider does not answer, or asks to wait): 429
  `RATE_LIMITED`, reason `connection-unavailable`, with `retryAfterSeconds`
  and `Retry-After`. An exercise waits 20 seconds at most. A token that
  still lasts long enough is given, refreshed or not.
- **A person has to act**: 403, reason `connection-needs-reconnect`,
  `connection-not-connected`, `connection-revoked` or `connection-paused`.
  Asking again does not help.

A refusal uses up nothing: not the single use of a single-use Capability. The
provider is asked only when everything else about the exercise is in order,
and the exercise is decided again after it: a grant removed meanwhile
refuses it. Capabilities
[issued for another broker](ci-and-machines.md#brokers-on-many-machines),
exercise-only credentials, `singleUse` and
[agent-safe runs](agent-safe-runs.md) work as for any Secret.

## States

| Status | What it means |
| --- | --- |
| `not_connected` | nobody connected it yet; a client's own connection gets its first token at its first use |
| `connected` | it has tokens |
| `refreshing` | a refresh is in progress |
| `failing` | the last refresh failed for now (`reason`). It is tried again when the token is asked for, after 5 seconds, doubling to 10 minutes; `retryAt` says when. Refreshing by hand, or a new client secret, tries at once |
| `needs_reconnect` | the provider refuses the refresh token (consent withdrawn, expired, used elsewhere), or gave none. A person connects it again |
| `revoked` | it was disconnected here |

`paused` (a person or a machine with `config.value.write`) stops use and
refreshes and keeps the tokens.

### When an answer is lost

A provider that replaces refresh tokens (rotation) may end the whole grant
when a replaced one is used again. Varlatch stores the new refresh token in
the same write as the access token, and gives the access token out only once
that is on disk. If the answer never arrives (a network failure, a crash, a
power cut), the refresh token that was used is still what is stored, and it
is used again, soon: after 5 seconds, or after 30 when the server itself
ended. Providers that keep a replaced token good for a short while, or do not
replace it (Google), carry on. One that does not says `invalid_grant`, and
the connection needs a person (`refresh-answer-lost`). Not asking again would
end there too.

### Connections nobody uses

Varlatch refreshes when a token is asked for, not to keep one warm. A refresh
token the provider drops when it is not used is the exception: where the
provider says when it ends, or the preset (or `refreshTokenIdleDays`) says
after how many days, Varlatch uses it after two thirds of that time, every ten
minutes at most. One whose announced end a use does not move is left to end.
A connection that cannot be refreshed, or whose provider is slow, holds up no
other Organization's.

Nothing is refreshed while the Organization is frozen or being deleted, the
environment expired or deleted, or the connection paused or disconnected.

## Changing one

`PATCH …/oauth-connections/MAIL_TOKEN`. A new **client secret** and new
**hosts** leave it connected; new **scopes** are asked for at the next
connection. The **provider** and the **client ID** stay while it holds
tokens: disconnect it first, and give the client secret again. Provider,
client ID, scopes and hosts are changed by a person; a machine may replace
the client secret or pause it. A connection a person has connected is also
deleted by a person (`person-required`), connected now or not; a machine that
may delete its whole environment still can.

With `expectedVersionId` a change, or the start of a connection
(`…/authorizations`), is of the version that was shown: send it with a client
secret.

## Disconnecting

**Disconnect** revokes the tokens at the provider where it has an endpoint
for that (RFC 7009) and forgets them here whatever it answers; the answer
says which (`atProvider`). The refresh token and the access token are each
asked for, whatever came of the other. It works while the Organization is
frozen, and in an environment that has expired. Many
providers, Google among them, end everything this client has for this
account, other connections to it included; with `revokeAtProvider: false`
they are left as they are. Tokens that were refused or replaced (another
account, a reconnection) are dropped without revoking them, for that reason.

Deleting the item, its environment, its Project or its Organization forgets
the tokens without asking the provider: disconnect it first to revoke them.

## Where the secrets go

| Path | What it does with a connection |
| --- | --- |
| Capability exercise | gives the access token, and nothing else of it |
| Effective configuration, `values list`, the dashboard, MCP | lists the item with `oauth` (preset, grant, status, account); no value |
| The connection's own operations | its parameters and state; no secret, no token |
| Disclosures of any kind, `secret.reveal` | leave it out; a named one is in `withheld`. There is no way to reveal one |
| `varlatch run` | leaves it out and says so |
| `varlatch run --strict`, strict retrieval | withheld, reason `oauth-connection`; a violation when the Contract requires it |
| Env files, exports, `varlatch scan` | leave it out |
| Integrations (sync targets), `varlatch sync` | never push it |
| A `${MAIL_TOKEN}` reference | stays literal when read, and refuses an exercise (cause `oauth-connection`) |
| Audit log, events, webhooks, logs, errors | neither a secret nor a token, nor text the provider wrote in an error |
| Backups | in the archive, encrypted as every value is |

After a **backup is restored**, its refresh token is one the provider may
have replaced since: the connection then needs a person. Two servers with one
database's copy end each other's grants the same way.

## Audit

| What | Event |
| --- | --- |
| Made, changed | `value.written`, with `oauth`, the server, `endpointHosts` (every host of the provider's), the client ID, the scopes and the hosts |
| Connected; connected again | `sync.connection_created`; `sync.connection_credential_replaced`, `outcome` `reconnected`. The person, the account, `accountChanged` and the previous one, `missingScopes` |
| Refused or failed to connect | `sync.connection_checked`, `outcome` `not-connected`, `reason` |
| Refreshed | `sync.connection_credential_replaced`, `outcome` `refreshed`, no actor (Varlatch's own), whether the refresh token was replaced |
| Failing; needs a person | `sync.connection_checked`, `outcome` `failing` (once an episode) or `needs-reconnect`, `reason` |
| Paused, resumed | `sync.connection_checked` |
| Disconnected | `sync.connection_revoked`, `atProvider` |
| A token given | `capability.exercised`, `oauthTokens`: the item, its version, which token of it, and when that one ends |
| A request the outbound policy refused | `outbound.refused`, purpose `oauth` |

The types are the ones connections to platforms have; `connection: oauth` in
the metadata, and the item in the resource, tell them apart. Each names the
`server` and the `endpointHosts`.

## Going back to an earlier release

An earlier release, and the TypeScript server after a reverse migration,
reads such an item as deleted: it has no value there, nothing refreshes it,
and an exercise that names it gives nothing (`withheld`). What it is stays.
On the same database its tokens stay too, and work when the newer release is
back, unless the provider dropped them; a reverse migration carries no
tokens, so after one and back it has to be connected again, and does not
know whose account it was.

Every request to a provider follows the installation's
[outbound policy](outbound-policy.md). The
[threat model](../THREAT-MODEL.md#6-agent-safety-the-credential-broker-shipped)
says what a stolen token, a broker's machine, a malicious provider or a
backup gives away.
