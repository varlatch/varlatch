# Integrations: pushing values to GitHub Actions, Coolify, and Convex

An integration pushes one environment's values to a platform that keeps
its own copy: the Actions secrets of a GitHub repository, the environment
variables of a Coolify application, or those of a Convex deployment. After
that, every change and rotation in the environment reaches the platform
without anyone re-entering it.

You set one up in two parts:

- A **connection** holds one credential for one platform account or
  instance. Create it once, under **Connections** or while adding an
  integration. Several integrations can share it.
- An **integration** pushes one environment to one destination through a
  connection. Add it on the environment's **Integrations** tab: pick the
  connection, the destination, the items, then review what will leave
  Varlatch.

Managing connections and integrations needs `config.sync.manage`. Adding an
integration also needs the authority to disclose what it pushes:
`secret.reveal` for Secrets and `config.value.read` for the other items
(both, on the whole environment, for "All items"). The installation must
allow outbound sync; see [`VARLATCH_SYNC`](../self-hosting/configuration.md#sync-targets).

## Varlatch checks the credential first

Before it saves anything, Varlatch asks the platform whether the credential
works: when you create a connection, when you replace its credential (once
for every integration that uses it), and on the review step of a new
integration, against the destination you chose. When the check fails, the
dialog says what is wrong and which part to fix. You can still go ahead
(**Save anyway**, **Create anyway**), for example for a GitHub environment
you have not created yet.

A platform cannot show whether a credential may write without a write, so
a passed check means Varlatch can reach the destination and read it; the
first push confirms the rest. If it fails, the integration says so, and
the connection shows **Credential rejected** with a **Replace credential**
button.

## GitHub Actions

A GitHub connection authenticates in one of two ways:

- **Through your organization's GitHub App** (below). Varlatch issues a
  token for each push, limited to one repository and valid for an hour.
  Nothing expires with a person, and nothing breaks when someone leaves.
- **With a personal access token**, which a person creates and which can
  expire. It is quicker to set up, and works where you may not register
  Apps.

### Through a GitHub App

Each Varlatch organization has at most one GitHub App, registered on the
GitHub account it pushes to. Varlatch keeps the App's private key,
encrypted, and stores no token: for each push, check, or listing, it asks
GitHub for a token limited to that use.

| Use | Repositories | Permissions |
| --- | --- | --- |
| Push | the destination | Secrets (or Environments) read and write, Metadata read |
| Check a destination | the destination | Secrets (or Environments) read, Metadata read |
| Check the connection, list repositories | the whole installation | Metadata read |

**Register the App.** Under **Connections**, **GitHub App**, **Register an
App**: choose the GitHub organization (or your personal account) and press
**Continue to GitHub**. GitHub shows its form to create the App, filled in
by Varlatch: secrets and environments (read and write) and metadata
(read), no webhook, private. Press **Create GitHub App**, and GitHub sends
you back to Varlatch.

- On an organization, only an owner, or a member allowed to manage its
  GitHub Apps, can register one. If GitHub says you don't have permission
  and offers to create the App for your own account, stop there: that App
  can only be installed on your account, not on the organization. If it
  happens anyway, Varlatch keeps nothing, says so, and links to where you
  delete the App on GitHub.
- Registering needs this installation's public address over HTTPS
  ([`VARLATCH_PUBLIC_URL`](../self-hosting/configuration.md#varlatch_public_url)), or a
  loopback address in local development: GitHub sends the browser back
  there.
- The link GitHub sends you back with works once, for an hour. Opening
  it again (a refresh, for example) says whether the registration
  finished and names the organization's App when there is one: keep
  that App. Only when the page says the registration did not finish,
  and the organization has no GitHub App in Varlatch, may GitHub still
  have created one: delete that App on GitHub under **Settings**,
  **Developer settings**, **GitHub Apps**, then start again.

**Or import one.** If an owner registered the App, **Import an App** takes
its App ID and a private key (the `.pem` file GitHub downloads under the
App's **Credentials**, **Key pairs**, **New key**). Varlatch checks the
pair with GitHub before keeping it. The App needs Secrets and
Environments (read and write) and Metadata (read). It may hold more, and
the audit log names the extra permissions, but the stored key keeps
everything the App holds: Varlatch limits each token it issues, not the
key. Give the App no more than it needs.

**Install it, then connect the installation.** On GitHub, install the App
on the account (**Install on GitHub** links there) and choose the
repositories Varlatch should push to. Back in Varlatch, **Connect an
installation** creates a connection for it. The connection's owner is the
installation's account, and its integrations can push only to the
repositories the installation includes. To push to another repository,
add it to the installation on GitHub; if you are not an owner there,
GitHub sends your change to an owner to approve, and the repository is
listed once it is reachable.

**Rotate the key.** Under **GitHub App**, **Rotate key**: on GitHub, open
the App's settings, **Credentials**, **Key pairs**, **New key**, then give
Varlatch the new `.pem`. Varlatch checks it with GitHub first, then
switches every integration on the App's connections to it at once,
paused and disabled ones included. That is a new disclosure for each of
them, so you need the authority to disclose what each pushes; if you
lack it for one, nothing changes. Once Varlatch confirms, delete the old
key on GitHub. An App connection has no credential of its own: its
**Rotate the App's key** button leads here. It never shows an expiry.

**Remove the App.** **Remove App** removes the App you confirmed (if
another one replaced it meanwhile, nothing changes) and revokes every
connection on it at once: their integrations are disabled and keep their destinations, and
Varlatch deletes the key. The App stays on GitHub; delete it there,
under the App's **Advanced** settings, if you no longer need it.

The audit log records the App's registration or import (and a refused
registration, with why), each listing of its installations, each key
rotation with the integrations it re-authorized, and its removal with
the connections it revoked; never the key. A token Varlatch issues is not
logged on its own: the push, check, or listing that used it is.

### With a personal access token

| Field | What to enter |
| --- | --- |
| Owner | The user or organization in `github.com/<owner>`. |
| Access token | A fine-grained personal access token, below. |
| Repository | On the integration: pick it from the repositories the token can see in the owner, or type its name, without the owner. |
| GitHub environment | Optional. Empty writes repository secrets; a name writes the secrets of that environment, which must already exist in the repository's settings. |

Create the token on GitHub under **Settings**, **Developer settings**,
**Personal access tokens**, **Fine-grained tokens**, **Generate new token**:

1. **Resource owner**: the owner you enter in Varlatch. An organization can
   require approving the token before it works.
2. **Repository access**: **Only select repositories**, and pick the ones
   you push to.
3. **Repository permissions**: **Secrets: Read and write** for repository
   secrets, **Environments: Read and write** for environment secrets.
   GitHub adds **Metadata: Read-only** itself.
4. **Expiration**: when the token expires, pushes stop with "Credential
   rejected" until you replace it under Connections. Varlatch shows the
   date GitHub reports: in the check while you create or replace the
   credential, and on the connection once it has used the token. From two
   weeks ahead it warns on the connection and on every integration that
   uses it, and a dialog asks before saving a token that expires within
   two weeks. A token without an expiry gets no date: GitHub reports none.

To push to another repository later, add it to the token's repository
access on GitHub; the token stays the same, so use **Check again** on the
review step instead of replacing it. A classic token with the `repo` scope
works too, but it reaches every repository you can.

GitHub never returns secret values, so Varlatch cannot read them back; its
periodic repair writes them again instead.

## Coolify

| Field | What to enter |
| --- | --- |
| Instance URL | The address of your Coolify instance, with `https://` and nothing after the host: `https://coolify.example.com`. |
| API token | A Coolify API token, below. |
| Application UUID | On the integration: pick the application from those of the token's team, or paste the last part of its address in Coolify (`…/application/<uuid>`). |
| Build time | On the integration: whether the variables exist during the build. Values compiled into a build (`VITE_*`, `NEXT_PUBLIC_*`) need it, and then end up in image layers. |

Then, in Coolify:

1. Turn on **API access** if it is off: **Settings**, **Advanced**, **API
   and MCP**. If **Allowed API IPs** is set, add the address Varlatch's
   server connects from.
2. Create the token under **Keys & Tokens**, **API Tokens**, logged in as an
   admin or owner of the team that holds the application. Coolify limits
   team members to read-only tokens.
3. Give it the **Read** and **Write** permissions, and **Deploy** when the
   integration redeploys after changes. Check the selected permissions
   before you create it: in some versions, ticking Deploy clears the
   others.

A Coolify token reaches every application of its team, so one connection
per instance is the honest unit. Create a token for Varlatch alone, so you
can revoke it on its own.

## Convex

| Field | What to enter |
| --- | --- |
| Deployment URL | `https://<name>.convex.cloud` for Convex Cloud, as shown in the deployment's settings, or the origin of a self-hosted backend. |
| Deploy or admin key | Convex Cloud: a deploy key for that deployment, generated in its settings in the Convex dashboard. Self-hosted: the backend's admin key. |

A key works for one deployment only, so each deployment is its own
connection, and the deployment is the destination: the integration has
nothing more to fill in. A production and a development deployment have
different keys. The key must be allowed to change environment variables; a
read-only key fails the check. A self-hosted backend from before March 2025
has no key check at all: the check then reports the deployment as not
found, so update the backend, or save anyway.

If the environment also holds the deployment's own key or URL
(`CONVEX_DEPLOY_KEY`, `CONVEX_URL`), keep them out of the push with **All
items** except `CONVEX_*`. Convex functions read new values at once; there
is no redeploy.

## When the check fails

| The dialog says | What to do |
| --- | --- |
| The credential was rejected | It is mistyped, expired, or revoked, or a Convex key belongs to another deployment. Paste it again or make a new one. |
| The credential is missing a permission | Give it the permissions listed above for its platform. On GitHub, also check that the organization approved the token; on Coolify, that API access is on and the allowed IPs include Varlatch's server. |
| Account or instance not found | Check the owner, instance URL, or deployment URL. |
| Destination not found | Check the repository, GitHub environment, or application UUID, and that the token can see it. |
| Could not check right now | Varlatch's server got no answer: the dialog says whether the address does not resolve, refuses the connection, redirects (a sign-in page in front of the API, for example), or has a certificate the server does not trust. A timeout, a rate limit, or a platform error clears with **Check again**. |
| The platform refused the check | Most often the address answers but is not the platform's API: check the instance or deployment URL. |
| GitHub refused the App's key | The key was deleted on GitHub, or belongs to another App: rotate the App's key. |
| This server's clock is ahead of, or behind, GitHub's | GitHub refuses the App's signed requests when the server's clock is minutes off. Set it right (NTP), then check again. |
| The App's installation cannot see the repository | Add the repository to the App's installation on GitHub, or check its name. |

## Picking the destination

On the Destination step, Varlatch lists what the connection can reach:
for GitHub, the repositories in its owner that the token can see, or that
the App's installation includes, archived ones left out in both cases;
for Coolify, the applications of the token's team. Pick one, or type it
when it is not listed: a repository you have not created yet, or one a
partial list leaves out (Varlatch stops reading at 1,000, or after 30
pages of GitHub repositories, and says so). If the list cannot load, the
step says why, as a failed check does, and **Try again** reloads it;
typing works meanwhile. After creating a repository or application on
the platform, reload the list from the same step. Choosing another
connection, or changing a new connection's owner or address, clears the
destination and loads the new list.

Seeing a destination is not permission to push to it: Review still checks
the one you picked or typed, and the first push confirms it.

## What a check sends

A check only reads. It sends the credential to the platform and nothing
else; a stored credential goes only to its connection's own address. It
reads nothing from the environment and stores nothing. An answer counts
only when it has the platform's own shape, so a sign-in page in front of
an instance, which answers too, does not pass.

| Platform | Requests |
| --- | --- |
| GitHub Actions | `GET /users/<owner>`; with a destination, the Actions secrets public key of the repository or environment (and the repository itself, to tell a missing environment from a repository the token cannot see) |
| GitHub Actions, through the App | First a token for this check, from `POST /app/installations/<id>/access_tokens` (signed with the App's key); then, for the connection alone, `GET /installation/repositories?per_page=1`, and with a destination, the same requests as with a token |
| Coolify | `GET /api/v1/version`; with a destination, `GET /api/v1/applications/<uuid>` |
| Convex | `GET /api/check_admin_key` |

Each check appears in the audit log as **Access checked**, with the
platform, the address or destination, and the outcome; never the
credential. Through the API, it is
`POST /v1/organizations/{org}/platform-connections/check`.

Listing destinations reads in the same way, with the same credential:

| Platform | Requests |
| --- | --- |
| GitHub Actions | `GET /users/<owner>`, then `GET /orgs/<owner>/repos` for an organization or `GET /user/repos` (filtered to the owner) for a user, 100 per page |
| GitHub Actions, through the App | A token for the listing, then `GET /installation/repositories`, 100 per page: exactly the installation's repositories |
| Coolify | `GET /api/v1/applications`; only each application's uuid, name, and first address are kept |

A listing appears in the audit log as **Destinations listed**, with how
many it found and never their names. Through the API, it is
`POST /v1/organizations/{org}/platform-connections/destinations`.
