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

with the port when it is not 443 (`…/oauth/callback/login.example.com:8443`).
With an issuer, **Ask the provider for it** (or `POST
…/oauth-connections/discovery`) shows it before the connection is made.

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
