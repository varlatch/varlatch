# Members and access

People reach an organization as **members** or **admins**, by
invitation. Access is denied unless something allows it.

## Invite your team

Invite each person from the dashboard (Access, then Members), or from the
repository with the CLI:

```sh
varlatch invite "Ada Lovelace"                 # a member
varlatch invite "Grace Hopper" --role admin    # an organization admin
```

Each invitation is a one-time link: send it to that person. No email is
involved. Opening it creates their account and passkey. What they do
next is in [Join a team](../join-a-team.md).

## What members and admins can do

A **member** can read and change development environments, read staging
environments, and see only the names of production items. An **admin**
can do everything in the organization. For anything else, such as a
member who deploys to production, add a grant in the dashboard under
Access.

## When someone leaves

An admin removes them from the dashboard (Access, then Members, then the
person's menu), or with the CLI:

```sh
varlatch member remove "Ada Lovelace" --confirm "Ada Lovelace"
varlatch member role "Grace Hopper" member     # admin to member, or back with admin
varlatch member leave --confirm acme           # leave an organization yourself
```

From their next request they reach nothing in the organization: the
Grants given to them directly are revoked, and they leave every group and
team. Their sign-in itself is not affected. What they set up, such as
integrations, Connections, webhooks and machine credentials they were
shown, keeps working: removal lists it for you to review. The last admin
of an organization cannot be removed or leave.

When the organization turns on the `admin-step-up` security control,
removing someone, changing a role and inviting an admin each need your
approval with a trusted passkey: see
[Admin step-up](security-controls.md#admin-step-up). Leaving does not.

Then see what they received, from the dashboard (Former members, then
What they received) or the CLI:

```sh
varlatch member exposure "Ada Lovelace"        # --json for one record per line
```

The report lists each version of each value they received, how, and
whether Varlatch still serves it, with what they could reach when they were
removed and what they set up. Rotate what is still served, at the provider
too: a new value in Varlatch does not revoke the old one there. Then mark
each version as revoked at the provider; the report never does that on its
own. It needs permission to read the audit log, and never shows a value.
