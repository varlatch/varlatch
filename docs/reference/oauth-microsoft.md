# Connecting Microsoft

For Microsoft Graph and other APIs behind Microsoft Entra ID, with a person's
consent or as the application itself. Read
[OAuth connections](oauth-connections.md) first.

## The tenant

Varlatch needs your **tenant ID** (a UUID; Entra admin center, Overview:
*Directory (tenant) ID*). `common`, `organizations` and `consumers` are
refused: whoever has any Microsoft account could then be who connects, and
the tokens name another issuer than the one that was asked, so none could be
checked. For personal Microsoft accounts use their tenant's ID,
`9188040d-6c67-4c5b-b112-36a304b66dad`.

## At Microsoft

In the [Entra admin center](https://entra.microsoft.com/), **App
registrations**:

1. **New registration**. Supported account types: *this organizational
   directory only*.
2. Redirect URI: platform **Web**, exactly what Varlatch shows:

   ```
   https://{your Varlatch}/oauth/callback/login.microsoftonline.com
   ```

   (Not *Single-page application*: such a client has no secret and its
   refresh tokens last a day.)
3. **Certificates & secrets**, new client secret. Copy its *value*. It
   expires, within two years: set a reminder. When it has, the connection is
   `failing` with `invalid_client`, and a new secret
   (`PATCH …/oauth-connections/{item}`, or **Change** on the item) makes it
   work again without connecting anew.
4. **API permissions**: *delegated* ones for a person's account,
   *application* ones for the client's own access, and the administrator's
   consent where they need it.
5. Copy the *Application (client) ID*.

## In Varlatch

Preset **Microsoft**, the tenant ID, the client ID and secret.

- **A person's account**: scopes such as `https://graph.microsoft.com/Mail.Send`.
  Varlatch adds `openid`, `profile`, `email` and `offline_access`, without
  which there is no refresh token. Name the resource in each scope, and one
  resource only: a token is for one.
- **The client's own**: one scope, `https://graph.microsoft.com/.default`.

Hosts: `graph.microsoft.com`.

## Good to know

- Microsoft gives a new refresh token at each refresh and keeps the old one
  good, so a lost answer breaks nothing. One that was not used for 90 days
  ends (Varlatch uses it after 60). Conditional access, a changed password or
  an administrator can end it sooner.
- Access tokens last 60 to 90 minutes, not always the same: ask for
  `minValiditySeconds` of less than an hour.
- Microsoft has no endpoint that revokes a token: disconnecting forgets it
  here (`not-supported`), and the account ends it at
  <https://myaccount.microsoft.com/> or an administrator in Entra.
