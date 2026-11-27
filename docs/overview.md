# How Varlatch works

Varlatch is a self-hosted platform for secrets and environment configuration.
Instead of passing `.env` files around Slack or leaving plaintext credentials on
every laptop, your team runs one small server (`varlatchd`) and delivers
configuration directly into your applications, CI jobs, and coding agents.

## Two roles, two paths

Most people arrive at Varlatch in one of two ways:

1. **You are setting up a server for yourself or your team.**
   One person installs `varlatchd` once on a Linux host (or in Docker / Coolify).
   It is a single binary with its own SQLite database, dashboard, HTTPS
   certificates, and encrypted backups: no Postgres or extra containers needed.
   Start at [Install Varlatch](self-hosting.md).
2. **Someone invited you to an existing server.**
   You open your one-time invitation link, create a passkey (there are no
   passwords), install the `varlatch` CLI, and run your app with
   `varlatch run -- npm run dev`.
   Start at [Join a team](join-a-team.md).

Already signed in and wiring up a new repository? Start at
[Connect a project](set-up-a-project.md).

## How configuration is organized

```text
Installation (your varlatchd server)
└── Organization (your company or team; strict isolation boundary)
    └── Project (typically one repo or service, with one Contract)
        └── Environment (development, staging, production, or personal/preview)
            └── Config Items (plain values and encrypted Secrets)
```

- **Organizations** isolate teams, grants, encryption keys, and audit logs.
- **Projects** hold a **Contract** declaring which keys the app needs, their
  types (`url`, `integer`, `boolean`, `enum`, etc.), and which ones are
  **Secrets**. You can keep the Contract in Git (`.env.schema`) or manage it in
  the dashboard.
- **Environments** hold the actual values. Every environment has a risk **Tier**
  (`development`, `staging`, or `production`). By default, members can edit
  `development`, read `staging`, and see only key names in `production`.
- **Encryption** uses envelope encryption: a Root KEK on the server wraps each
  organization's key, which wraps a fresh key per value version. A stolen
  database or backup yields no plaintext without the keys.
- **Passkeys & machine auth:** Humans sign in with passkeys (no passwords to
  store or leak). CI uses OIDC with zero stored secrets; servers use scoped,
  expiring credentials.

## How secrets reach apps and coding agents

| Mode | Command | What happens |
| --- | --- | --- |
| **Normal dev & deploys** | `varlatch run -- npm run dev` | Injects values directly into the process environment. No `.env` file lands on disk. Add `--strict` to validate against the Contract before starting. |
| **Coding agent helping you** | `varlatch --assisted run -- npm test` | Uses your sign-in, but masks every Secret in command output automatically and prevents accidental secret writes or deletes. See [Assisted mode](reference/assisted-mode.md). |
| **Untrusted AI agent** | `varlatch run --agent-safe ... -- my-agent` | Gives the agent random **Placeholders** instead of Secrets. A local Broker swaps in the real Secret only in HTTPS requests to hosts and headers/fields you allow. See [Agent-safe runs](reference/agent-safe-runs.md). |
| **External platforms** | Integrations tab / `varlatch sync` | Pushes an environment to GitHub Actions, Coolify, or Convex, audited on every push. See [Integrations](reference/integrations.md). |

## Next steps

- **Self-host a server:** [Install Varlatch](self-hosting.md) (or [Docker and Coolify](self-hosting/docker-and-coolify.md)).
- **Invited to a team:** [Join a team](join-a-team.md).
- **Connect a repository:** [Connect a project](set-up-a-project.md) or [Set up with a coding agent](set-up-with-an-agent.md).
- **Full terminology & security model:** [Glossary](../CONTEXT.md) and [Threat model](THREAT-MODEL.md).
