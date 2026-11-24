# Pages, applications and pipes as destinations

A broker does not always send a value in a request. It may type a password
into a page of a browser or a field of a desktop application, or hand a value
to a process over a pipe. A Capability can name these as the places its values
may go, so such a use is held to the same rule as a request, and the audit log
says where the value went.

This needs the Go server (0.50.0 or later): `/v1/meta` lists
`capabilities.destination-kinds` and `capabilities.target-kinds`. Hosts and
the targets of a request are as they were, for every client.

> **What this is, and is not.** Varlatch compares what the broker *reports*.
> A broker that has exercised a Capability has the value, and nothing can stop
> a broker that lies from putting it somewhere else. This is a rule for a
> broker that is honest, or honest in the part that looks where it is typing,
> and a record of what it said. It is not containment. See
> [what a broker can still do](#what-a-broker-can-still-do).

## Destinations

| Written | Names |
| --- | --- |
| `api.example.com`, `api.example.com:8443`, `*.example.com` | a host, as ever |
| `web:https://portal.example.com/login` | pages of one host under a path |
| `web:https://*.example.com` | pages of subdomains, at any depth, never of `example.com` itself |
| `app:CRM Client@idn_…` | a desktop application on one machine |

A Capability's destinations are hosts, or pages and applications, **not both**
(`mixed-destinations`): a server that does not know pages reads the host alone
and would let a value for a field go there. Issue one for each.

### Pages

`web:` then `http` or `https`, `://`, a host, an optional port, and an optional
path. Compared with the page's address:

- **Scheme and port** exactly. No port is the scheme's own. `http:` is allowed
  when it is written out, and is a page **without encryption**: see the warning
  below.
- **Host** exactly, or `*.suffix`: subdomains only, never the suffix itself,
  never an IP address, and never all of a top-level domain. Letters, digits,
  `.`, `-` and `_` alone. Lower-cased,
  internationalized names in their ASCII form, one trailing dot dropped, so
  `Portal.Example.com.` is `portal.example.com`.
- **Path**: a prefix of whole segments, case-sensitive. `/login` names
  `/login`, `/login/` and `/login/step2`, and neither `/loginx` nor
  `/login;x`. No path, `/` and `/*` name every page of the host.
- **Query and fragment** are never compared and never recorded: they may hold
  what must not be in a log. A selector with one is refused.

An address that cannot be read, or could be read two ways, is none of any
selector: credentials (`user@host`), a backslash, a space, tab or control
character anywhere before the query, a dot segment (`..`, `%2e%2e`, `..;x`), an
encoded slash, backslash or control character, a percent sign encoded again
(`%252e`), an invalid percent-encoding, another scheme (`blob:`, `data:`,
`javascript:`, `about:`, `file:`).

> **Warning: an `http:` page is not encrypted.** Whoever is on the network
> between the machine and the page reads what is typed there, or shows another
> page in its place, and no destination can tell. Write `web:http://…` only for
> a page that has no HTTPS, on a network you trust for that value, with a
> Capability that names it alone. A Capability that names a page over `https:`
> never matches it over `http:`. The dashboard marks such a destination, and
> its uses in the audit log, "http: not encrypted". The API takes it as any
> other, without a warning in its answer.

**A frame**: report the frame's own address as `url` and the page's as
`topUrl`. Each has to be named by a destination of the Capability.

### Applications

`app:` then the application's name, `@`, and the **identity ID of the broker**
that exercises. The name is what your broker calls the application, compared
exactly (in Unicode's NFC): no case folding, no wildcard, 100 characters at
most, and no `@ * , ; = / \` or invisible characters.

The machine is not reported: it is the broker that authenticated. A selector
that names another machine than the Capability's broker is refused when the
Capability is issued (`app-machine`). Give each machine a broker identity of
its own for that to mean a machine; where machines share one, tie the
Capability to a run (`runId`).

## Targets

| Target | Where | Goes with |
| --- | --- | --- |
| `header:`, `query:`, `json:`, `form:` | in a request | hosts |
| `pipe:/token` | at that JSON pointer of a document handed to a process over a pipe | hosts (the process talks to one), applications (the process is one) |
| `field:Password` | typed into the field your broker knows by that name | pages, applications |

A field's name and a pipe's pointer are text that shows as it is, at most 256
characters and 512 bytes: without `;` and `=`, which separate the entries in the
audit log, without control, invisible and bidirectional characters, and a field
without a blank at either end. Names are compared as they are written. The
targets of a request take more; in the audit log such characters are
percent-encoded, so an entry is never read as two.

Until now a broker that uses a pipe borrowed `json:`. That still works;
`pipe:` says what it is. A target that none of the Capability's destinations
takes is refused at issuing (`target-without-destination`), and a placement
that the reported destination does not take, at exercise
(`placement-not-for-destination`).

## The calls

```http
POST /v1/organizations/acme/projects/orders/environments/production/capabilities
{ "brokerIdentityId": "{broker}", "agentIdentityId": "{agent}",
  "items": ["PORTAL_PASSWORD", "PORTAL_OTP"],
  "destinations": ["web:https://portal.example.com/login"],
  "targets": { "PORTAL_PASSWORD": ["field:Password"], "PORTAL_OTP": ["field:Code"] },
  "ttlSeconds": 900, "runId": "job-4711", "singleUse": true }
```

```http
POST …/capabilities/{id}/exercises
{ "capabilitySecret": "{secret}",
  "destination": { "url": "https://portal.example.com/login?lang=nl" },
  "placements": [{ "item": "PORTAL_PASSWORD", "target": "field:Password" },
                 { "item": "PORTAL_OTP", "target": "field:Code" }] }
```

`destination` is one of `{ "host", "port" }`, `{ "url", "topUrl"? }` and
`{ "app" }`; members of two are refused (422). A window's title is no part of
it: titles hold what people are looking at (a customer, a document, a message),
so Varlatch takes and records none. Do not put one in `app`.

Everything else about a Capability is as for a host: the agent's `secret.use`
decides at each exercise, [delegated](ci-and-machines.md#brokers-on-many-machines),
exercise-only, tied to a run and single-use Capabilities, and a granted
exercise is recorded before anything is decrypted. A
[one-time code](one-time-codes.md) can be placed in a field. An
[OAuth connection](oauth-connections.md)'s hosts bind a page as they bind a
host (the page around a frame too), and a connection that names hosts goes to
no application and to no page without TLS. A target goes with each of the
Capability's destinations: issue one Capability for each page when a field is
for one of them alone.

## How a broker should report

- Report **what is there**, not what should be: read the address from the
  browser and the application from the window system, at the moment of typing.
- Exercise **after** the page or window is in front, look again **after** the
  answer, and do not type if it changed.
- Report a frame's own address, from the frame that holds the field.
- Do not let whatever decides what to do on the screen (a model, a script of
  the page) give the report.
- Type only into a field that does not show what is typed, and forget the
  value.

## What the audit log says

`capability.exercised` has `destination` (`web:https://portal.example.com:443/login`
or `app:CRM Client@idn_…`), `destinationKind` (`web` or `app`), the `selector`
that named it, `topDestination` when reported, and `placements`. A refused one is
`capability.denied` with what was reported and its reason (`destination-mismatch`,
`placement-not-targeted`, `placement-not-for-destination`). Webhooks and exports
carry the same events. A host's are as they were.

**A page's path is recorded**, of a refused page too, shortened to 200
characters. A path can say something about a person (`/patients/4711`): report
the address all the same, and give the log to those who may read that.

Never recorded, in no event and no log of the server:

- the query and the fragment, also when their mark is encoded in the path
  (`%3F`, `%23`): the rest of the path goes with it (`/a…`);
- path parameters (`/a;jsessionid=…` is `/a;…`);
- credentials in an address: it is `web:unreadable`, as any address that
  could not be read, and nothing of it is kept;
- a window's title.

A refused application's name is recorded as it was reported.

## What a broker can still do

- **Lie about where it types.** It has the value once it is exercised.
  Short lives, single use, few items and, above all, values that are worth
  little elsewhere (a [one-time code](one-time-codes.md), an access token) are
  what limits that.
- **Report the truth and type it elsewhere**, or be made to: the page may
  change between the report and the typing, and an application of that name
  may not be the one you mean. The broker has to check; Varlatch cannot see a
  screen.
- **Not lie about its machine** for `app:`, nor exercise another broker's
  Capability: that is authenticated.
- What stays refused: a page, an application or a field the Capability does not
  name, *as reported*, so a bug, a phishing page or a screen that misleads
  whatever drives it does not get a value from a broker that reports what it
  sees, and the attempt is in the log.

## Older servers

A server without the capability refuses to issue for these selectors and
targets (422), and refuses an exercise that reports a page or an application
(422). A Capability issued here and exercised there, after a rollback or a
reverse migration, matches nothing (`destination-mismatch`).
