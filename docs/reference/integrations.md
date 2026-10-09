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

## Picking the destination

On the Destination step, Varlatch lists what the connection's credential
can see: the GitHub repositories in its owner (archived ones left out),
or the applications of the Coolify token's team. Pick one, or type it
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
| Coolify | `GET /api/v1/applications`; only each application's uuid, name, and first address are kept |

A listing appears in the audit log as **Destinations listed**, with how
many it found and never their names. Through the API, it is
`POST /v1/organizations/{org}/platform-connections/destinations`.
