# Connecting another provider

For any OAuth 2 or OpenID Connect server. Read
[OAuth connections](oauth-connections.md) first.

## At the provider

Register a *confidential web application* (authorization code, with a client
secret), or a public client with PKCE. Register the redirect URI Varlatch
shows, exactly:

```
https://{your Varlatch}/oauth/callback/{the token endpoint's host}
```

with the port when it is not 443 (`…/oauth/callback/login.example.com:8443`),
and with every other host of the provider's
([below](#providers-on-several-hosts)). With an issuer, **Ask the provider**
(or `POST …/oauth-connections/discovery`) shows it before the connection is
made. The provider has to compare it exactly: where it lets you register a
pattern or only the start of an address, give the whole address all the same.

Allow refresh tokens, and find out which scope gives one (`offline_access`
at many). If the provider replaces refresh tokens, allow a short leeway for
the replaced one when it has such a setting (often called a grace period or
reuse interval): a minute carries a lost answer.

## In Varlatch

Preset **generic**, with either

- the **issuer**: its metadata (`/.well-known/openid-configuration`, or RFC
  8414's) names the endpoints. They are read once and pinned; or
- the **endpoints** from its documentation: `authorizationEndpoint`,
  `tokenEndpoint` and, where there are any, `revocationEndpoint` and
  `userinfoEndpoint`. The latter is asked once at each connection, with the
  access token, for a JSON object with `sub` or `id` (and `email`,
  `preferred_username`, `login` or `name`): without it or an ID token
  Varlatch does not know whose account it is, and cannot tell another one.

### Providers on several hosts

The addresses are all on one host: the issuer's or, with the endpoints given,
the token endpoint's. Many providers are not made like that: userinfo at
`api.example.com`, the sign-in page at `www.example.com`, or an issuer on
another host than its token endpoint. Such a provider is refused until the
other hosts are named, in the dashboard by confirming them, over the API in
`provider.endpointHosts`:

```json
{ "preset": "generic", "issuer": "https://login.example.com", "endpointHosts": ["api.example.com"] }
```

They are then in the redirect URI (`…/login.example.com~api.example.com`), so
register that one. Name a host only when it is the provider's: the access
token, and at a disconnection the refresh token and the client secret, go to
its userinfo and revocation endpoints. Hosts are compared whole, not by their
domain, since anybody may have a name under a domain that hosts for others. A
host that several parties have paths on is one host here.

Or leave an endpoint out: without userinfo the account is known only from an
ID token, without revocation a disconnection forgets the tokens here and the
consent is withdrawn at the provider.

A client's own connection (`client_credentials`) has no redirect URI to vouch
for its hosts: its addresses are all on one host, and none is named. Give the
token endpoint itself, and the revocation endpoint if it is on its host.

Every URL is `https`, and is one the installation's
[outbound policy](outbound-policy.md) allows: a server on a private network
needs the host operator's `outbound_allow`. Redirects are not followed.

More members of `provider`, over the API:

| Member | What for |
| --- | --- |
| `tokenEndpointAuthMethod` | `client_secret_basic` (the default, unless the metadata has only the other), `client_secret_post`, or `none` for a client without a secret |
| `authorizationParams` | more parameters of the authorization request, such as `audience` or `prompt`; none of the request's own |
| `accessTokenLifetimeSeconds` | how long an access token lasts when the provider does not say |
| `refreshTokenIdleDays` | after how many days without use the provider drops a refresh token: Varlatch uses it after two thirds of them |

## What the provider has to do

- The authorization code grant with PKCE `S256` (metadata that lists methods
  without it is refused), or `client_credentials`.
- JSON answers at the token endpoint with a `Bearer` token; `expires_in`
  where it can. DPoP and mutual TLS are not supported.
- With `openid` among the scopes and an issuer: an ID token signed with RS256
  or ES256.
- Metadata that says `authorization_response_iss_parameter_supported` (RFC
  9207) means an answer without `iss` is refused.

Client authentication with a signed assertion (`private_key_jwt`), the device
flow, and the implicit and password grants are not supported.
