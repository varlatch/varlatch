# Connecting Google

For Google's APIs with an account's consent. Read
[OAuth connections](oauth-connections.md) first.

## At Google

In the [Google Cloud console](https://console.cloud.google.com/), in the
project that owns the integration:

1. Enable the APIs you use (Gmail API, Google Drive API, …).
2. Set up the OAuth consent screen. **Internal** (Google Workspace) lets in
   your organization's accounts and needs no review. For an **External** app,
   publish it: while its status is *Testing*, Google ends refresh tokens
   after seven days, and the connection then needs a person every week.
   Restricted and sensitive scopes need Google's verification.
3. Create credentials: **OAuth client ID**, type **Web application**.
4. Under **Authorized redirect URIs**, add exactly what Varlatch shows:

   ```
   https://{your Varlatch}/oauth/callback/oauth2.googleapis.com
   ```

5. Copy the client ID and the client secret.

## In Varlatch

Preset **Google**, the client ID and secret, and the scopes of the APIs, such
as `https://www.googleapis.com/auth/gmail.send`. Varlatch adds `openid` and
`email`, to know the account, and asks for offline access with the consent
screen each time, since Google gives a refresh token only then.

Hosts: the API's, such as `gmail.googleapis.com` or `www.googleapis.com`.

## Good to know

- On the consent screen a person may untick scopes. Varlatch shows what was
  not granted (`missingScopes`), and records it.
- Google does not replace refresh tokens, so a lost answer breaks nothing. It
  drops one that was not used for six months (Varlatch uses it after four),
  when the account's password changes (for Gmail scopes), and the oldest ones
  beyond a hundred for one account and client.
- Disconnecting ends everything the client has for that account, in other
  environments too. Use a client of its own for each installation.
- Google Workspace service accounts (a signed assertion instead of a refresh
  token) are not supported; nor is `client_credentials`, which Google does
  not have.
