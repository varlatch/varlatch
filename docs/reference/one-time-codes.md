# One-time codes

A site that asks for a code from an authenticator app gives you a *seed*
once, usually as a QR code. Varlatch can hold that seed as an item of an
environment and make the codes (TOTP, RFC 6238), so an automation that signs
in there neither waits for a person nor holds the seed. Exercising a
[Capability](ci-and-machines.md#brokers-on-many-machines) that names the item
gives the code of the moment; nothing delivers the seed.

This needs the Go server (0.50.0 or later): `/v1/meta` lists `values.totp`.

## Storing a seed

Use what the QR code holds, an `otpauth://` URI:

- **In the dashboard:** an environment's page, **Add a one-time code**. Paste
  the URI, or choose an image of the QR code where the browser can read one
  itself (Chrome and Edge on most systems; the image is not sent anywhere).
- **With the CLI:**

  ```
  varlatch values set PORTAL_OTP --totp                   # a hidden prompt asks for the URI
  varlatch values set PORTAL_OTP --totp --stdin < seed.txt
  ```

  A seed is never taken from the command line.
- **Over the API:** `otpauth` where `value` would be.

  ```http
  PUT /v1/organizations/acme/projects/portal/environments/production/values/PORTAL_OTP
  { "otpauth": "otpauth://totp/Portal:alice?secret=…&issuer=Portal" }
  ```

  A server without one-time codes refuses that for want of a `value`: it
  never stores the URI as one. Change sets (`"op": "set"`) and rotations take
  it too.

When the site shows only a key, write the URI yourself:
`otpauth://totp/Name?secret=` followed by the key.

What is accepted: a base32 secret of 80 bits or more (16 characters), SHA-1
(the default), SHA-256 or SHA-512, 6 (the default) or 8 digits, a period of
30 (the default) or 60 seconds. Blanks, hyphens, padding and lower case in
the secret are fine. Counter-based codes (`otpauth://hotp`), a secret that is
shorter or one repeated byte, and an issuer or account that contains the
secret are refused. A refusal never repeats any of the URI.

The **issuer and the account** are metadata: whoever may see that the item
exists (`config.metadata.read`) reads them, with the number of digits, the
period and the algorithm. They are stored unencrypted, as item names are. The
seed is encrypted as every value is.

The item is always a Secret. In the Contract it is an ordinary `string`
marked sensitive; a seed for an item the Contract marks not sensitive is
refused. Make it optional: no run delivers it, so a strict run refuses to
start when the Contract requires it.

A value does not replace a seed by accident: setting one on such an item is
refused, in a change set or an import too. Give another seed, or delete the
item first.

## Getting a code

Issue a Capability that names the item, as for any Secret, and exercise it:

```http
POST …/environments/production/capabilities/{id}/exercises
{ "capabilitySecret": "{secret}", "destination": { "host": "portal.example.com", "port": 443 },
  "placements": [{ "item": "PORTAL_OTP", "target": "form:otp" }] }
```

```json
{ "items": [{ "name": "PORTAL_OTP", "versionId": "ver_…", "kind": "totp", "value": "492039",
    "expiresAt": "2026-11-24T10:00:30.000Z", "expiresInSeconds": 17 }],
  "withheld": [], "targets": { "PORTAL_OTP": ["form:otp"] } }
```

`expiresInSeconds` counts from the answer, so the machine's own clock does
not matter. Within one period every exercise gives the same code.

Two members of the request, for items that hold a seed (other items are not
affected):

- **`minValiditySeconds`**: how long the code must still be valid. When the
  current one ends sooner, the answer is the next one, with `notBefore` and
  `startsInSeconds`: wait that long before using it. The server does not
  wait. Asking for more than the period is refused
  (`min-validity-too-long`).
- **`fresh: true`**: a code of a later period than any this server has given.
  The first such exercise in a period gets the current code, and the next one
  gets the next code, with `notBefore`. Once a code of the next period (or a
  later one, when the clock moved back) was given, the exercise is refused:
  429 `RATE_LIMITED`, reason `no-fresh-code`, with `retryAfterSeconds` and
  `Retry-After`. That is so as well when `minValiditySeconds` skipped the
  current code: the server keeps only the newest period it gave a code of.

Use `fresh` for every sign-in when several run at once: most sites accept a
code once. Every code given counts, also one given without `fresh`, through
another Capability, or to another broker. What the server cannot know is a
code made elsewhere from the same seed (a phone that also has it, the same
seed stored under another item), and it forgets what it gave when the seed is
written again.

A refusal uses up nothing: neither a code nor the single use of a single-use
Capability. Beside Secrets in one exercise, the code is given last, after
their references resolved.
Capabilities [issued for another broker](ci-and-machines.md#brokers-on-many-machines),
exercise-only credentials and `singleUse` work as for any Secret. An
[agent-safe run](agent-safe-runs.md) works too: `--target
PORTAL_OTP=form:otp` puts the code of the moment in the agent's request.
Response scrubbing does not cover codes (it skips values under 8 bytes).

Codes follow the server's clock. Keep it synchronized (NTP): most sites
accept a code one period early or late, so a clock that is a minute off gives
codes they refuse. When the clock moves back, `fresh` refuses codes it gave
under the later time until the clock has caught up, rather than give one
twice; writing the seed again clears that.

## Where the seed goes

| Path | What it does with a seed |
| --- | --- |
| Capability exercise | gives the code |
| Effective configuration, `values list`, the dashboard, MCP | lists the item with `totp` (issuer, account, digits, period, algorithm); no value |
| `varlatch run` | leaves it out and says so |
| `varlatch run --strict`, strict retrieval | leaves it out: withheld, reason `one-time-code`; a violation when the Contract requires it |
| Agent-safe runs | the agent gets a placeholder; its broker gets the code |
| Disclosure of every Secret, of named Secrets, for a scan or an export | leaves it out; a named one is in `withheld` |
| A disclosure that names it and says `totpSeeds: true` | discloses it: see below |
| Env files, exports, `varlatch scan` | leave it out |
| Integrations (sync targets), `varlatch sync` | never push it; an item that becomes a seed leaves the destinations as a deleted one does |
| Validation | checks that it is there and that its Contract type is `string`; opens nothing |
| A `${PORTAL_OTP}` reference in another value | stays literal when read, and refuses an exercise (`unresolved-reference`, cause `one-time-code`) |
| Audit log, events, webhooks, logs, errors | neither the seed nor a code |
| Backups | in the archive, encrypted as every value is |

## Revealing a seed

Whoever may reveal Secrets in the environment (`secret.reveal`) may reveal a
seed, for example to enroll a phone as well:

```http
POST …/environments/production/disclosures
{ "items": ["PORTAL_OTP"], "totpSeeds": true }
```

In the dashboard that is **Reveal seed** on the item. It is recorded as
`secret.disclosed`, with `totpSeeds` in its metadata. Without `totpSeeds` a
seed is withheld, so a client that asks for every Secret by name never
receives one. It is refused together with a purpose (a scan, an export) or
with the all-authorized scope.

## Replacing a seed

When the account enrolls anew, rotate:

```
varlatch values rotate PORTAL_OTP --totp --grace 3600
```

Until the rotation ends, an exercise gives the new seed's code as `value` and
the old one's as `retiring`, so the new seed can be confirmed at the site
while the old one still works. `varlatch values rotate-complete PORTAL_OTP`
ends it. A seed rotates to a seed only.

## Audit

Each exercise that gives a code is a `capability.exercised` event like any
other use: the broker, the agent, the issuer when that is another identity,
the destination, the item and its version. Its `oneTimeCodes` says which
period's code was given (`PORTAL_OTP@ver_…=<start of the period>`), so two
uses of one code show. Beside Secrets in one exercise, the codes have an event
of their own with the same request id, after the Secrets'; a refusal in
between gave no code and has none. `fresh` and `minValiditySeconds` are
recorded when asked for. Refusals are `capability.denied`. Writing a seed is
`value.written` with `totp`. No event holds a code or a seed.

## Going back to an earlier release

An earlier release, and the TypeScript server after a reverse migration, has
no one-time codes and reads such an item as deleted: it has no value there,
in any path, an exercise that names it gives nothing (`withheld`), and
deleting the item there returns 404 (a seed cannot be deleted on an earlier
server). The seed stays in the database and returns live once a server that
knows it is back, unless a plain value was written under its name meanwhile.

The [threat model](../THREAT-MODEL.md#6-agent-safety-the-credential-broker-shipped)
says what a stolen code, a broker's machine or a backup gives away.
