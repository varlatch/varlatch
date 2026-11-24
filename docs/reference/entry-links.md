# Entry links

An application that needs a person's API key usually asks for it in a form of
its own and passes it on, so the key goes through a system that should only
ever use it. An **entry link** keeps it out of there: the application makes a
link, a person opens it and enters the value on Varlatch's own page, once, and
the application learns that it is there.

This needs the Go server (0.50.0 or later): `/v1/meta` lists
`values.entry-links`. The installation needs a public URL over HTTPS, or a
loopback one.

## What a link is

A link can write **one item of one environment, once**, and only while the
item is still what it was when the link was made. It reads nothing, and
nothing about it lets whoever made it read, reveal or overwrite anything.

- It lives 15 minutes, or as long as `ttlSeconds` says: 60 seconds to an hour.
- It is for an item that has **no value** there, an inherited one included. To
  replace a value the maker says `replace`, and needs `config.value.write`. If
  the value is another one when somebody enters theirs, nothing is written and
  the link ends.
- The item is a **Secret**: one the Contract marks sensitive. A maker without
  `config.value.write` asks for what the Contract names, when the project has
  one: an item nobody expects would reach every process that gets the
  environment, under a name such as `NODE_OPTIONS`.
- It takes a value, or, with `accepts: otpauth`, the seed of
  [one-time codes](one-time-codes.md). **An [OAuth connection](oauth-connections.md)
  is not entered**: connecting one decides whose account is used, so a person
  with `config.value.write` does it in their own session.

## Who may make one

| Who | Needs |
| --- | --- |
| A service, workload, ci or broker identity | `entry-link.create` in the environment; for a link open to anyone, `entry-link.create-open` instead |
| A person | `config.value.write` in the environment |
| Anyone of these, to replace a value | `config.value.write` too |
| An agent | not possible |

No built-in role holds the two actions, so an admin grants each on purpose, as
any grant. The right is decided again when the value is entered: remove the
grant or retire the identity, and its links no longer work.

## Who may enter the value

`restrictedTo` says it:

- **`member`** (the default): any member of the organization, signed in. They
  need no other right there.
- **`identity`**: the one member in `identityId`, signed in.
- **`anyone`**: whoever has the link, without signing in. It is a bearer
  secret that writes one value: whoever gets it first can enter a value *of
  theirs*, and the audit log cannot say who it was. Use it for people who have
  no account, and send it where only the right person reads it. Where the
  organization enforces the security control `passkey-verification`, such a
  link is refused, when made and when used. Under `report` it is counted when
  made.

A signed-in person is asked what a write of a value asks: under
`passkey-verification`, a verified passkey sign-in.

## The calls

```http
POST /v1/organizations/acme/projects/orders/environments/production/entry-links
{ "item": "PROVIDER_KEY",
  "description": "The API key of our account at the model provider.",
  "ttlSeconds": 900 }
```

```json
{ "link": { "id": "enl_…", "environmentId": "env_…", "item": "PROVIDER_KEY",
    "accepts": "value", "replace": false, "restrictedTo": "member",
    "description": "The API key of our account at the model provider.",
    "requestedByIdentityId": "idn_…", "status": "pending",
    "createdAt": "…", "expiresAt": "…", "endedAt": null },
  "url": "https://varlatch.example.com/entry#vlt_entry_…" }
```

The address is in this answer and nowhere else: Varlatch keeps a hash of what
follows the `#`. Give it to the person as it is.

| Call | What it does |
| --- | --- |
| `GET …/entry-links/{id}` | the link: `status` is `pending`, `entered`, `expired` or `cancelled` (with `reason` `cancelled` or `value-changed`) |
| `GET …/entry-links` | the environment's, newest first: a machine sees its own, a person with `config.value.write` all |
| `DELETE …/entry-links/{id}` | cancels it, also while the organization is frozen |

Nothing of the value is in any of them. Instead of asking, an application can
listen: the `value.written` event of a webhook has
`entryLinkId` in its metadata. Links are kept until a day after they expire.

Refusals at making: 409 `VERSION_CONFLICT`, reason `value-exists`; 409
`ROTATION_IN_PROGRESS`; 422 `VALIDATION_FAILED`, reason `not-sensitive`,
`not-in-contract`, `oauth-connection`, `one-time-code` or `no-public-url`; 429 `RATE_LIMITED`
beyond 100 pending links, or 300 an hour, of one identity.

From the command line: `varlatch values ask PROVIDER_KEY`, `values asked` and
`values ask-cancel`. In the dashboard: an item's panel, **Ask somebody…**.

## The page

`/entry` is Varlatch's own page, on your Varlatch's address. It shows the
organization, the project, the environment and the item, who asks, and the
caller's words in a box that says they are the caller's. For a link that is
not open to anyone it shows none of this before the person has signed in.

- **The caller's words** (`description`) are one line of plain text, 280
  characters at most. A link, a host name, an address, markup and invisible
  characters are refused, so the page shows no place to go but Varlatch's own.
  They are in the audit log. Tell people to check the address of the page and
  the name of the item, and not to believe the box.
- **The secret of the link** is after the `#`: a browser sends it to no server
  and no proxy. The page takes it out of the address at once and sends it in
  the body of a request. The page sends no referrer, loads nothing from
  anywhere else, cannot be framed and is not cached.
- **Looking at a link uses nothing up**, whoever looks: a mail scanner, a link
  preview, a browser that runs the page. Only a submitted value does.
- **The value** is masked, is sent once, and is in no answer, page or log
  afterwards. Several lines stay several lines. One that holds a
  reference (`${NAME}`) is refused: where it is used, another
  item's value would take its place.

An entered value is a value like any other. Its `value.written` event names
the person, or nobody for a link open to anyone, with `entryLinkId` and
`requestedByIdentityId`. Making and cancelling a link are `capability.issued`
and `capability.revoked` events whose resource has an `entryLinkId`, and a
refused entry is `capability.denied` with a reason (the first 20 of a link).

## Limits

- Reading the page open over somebody's shoulder, or a compromised browser or
  extension, gets what is typed there. Nothing on a page can help that.
- A link open to anyone goes to whoever has it. Mail, chat and their logs keep
  it: until it is used or ends, that is enough.
- Whoever may make links can ask any member for a value of a name they choose.
  They cannot read it, but a person may be talked into giving a value that
  belongs elsewhere. The name of the maker and of the item, and the warning on
  the page, are what there is against it.
- Making a link tells its maker whether the item has a value there.
- After a rollback to an earlier release, or a reverse migration, there are no
  links and no page. A restored backup brings links back as they were then: one
  that was used since can be used again until it expires, if its item has no
  value there either.
