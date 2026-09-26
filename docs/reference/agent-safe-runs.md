# Agent-safe runs

`varlatch run --agent-safe` starts a process you do not trust with plaintext,
such as an AI coding agent, with Placeholders instead of Secrets. The run
starts a local Broker. The Broker replaces a Placeholder with its Secret only
in requests it sends itself, over verified TLS, to destinations you allow,
and only at the places you name.

```sh
varlatch run --agent-safe --agent "coding agent" \
  --allow-host api.stripe.com \
  --target STRIPE_KEY=header:authorization \
  --omit DATABASE_URL \
  -- my-agent
```

Every agent-safe run needs a Varlatch 0.11.0 server or later, even one with
no Secrets to mediate: removing Secrets inherited from your shell relies on
the server's account of the active Contract. The CLI refuses an older server,
names the version it needs, and starts nothing.

## Substitution targets

Every Secret stored in the environment needs a `--target` or an `--omit`.
Otherwise the run does not start and nothing is issued:

```
varlatch: STRIPE_KEY has no substitution target: add --target STRIPE_KEY=header:authorization
          (or query:, json:, form:), or --omit STRIPE_KEY to leave it out of this run
```

`--target NAME=kind:location` names one place the Broker may put the
Secret. Repeat it for up to four places per Secret.

| Kind | Example | The location must hold | The Secret is written |
| --- | --- | --- | --- |
| `header:<name>` | `header:authorization` | the Placeholder once; other text is kept (`Bearer <placeholder>`) | as is |
| `query:<name>` | `query:api_key` | exactly the Placeholder | percent-encoded |
| `json:<pointer>` | `json:/auth/token` | a string that is exactly the Placeholder, in an `application/json` body | JSON-escaped |
| `form:<name>` | `form:client_secret` | exactly the Placeholder, in an `application/x-www-form-urlencoded` body | percent-encoded |

- JSON locations are JSON Pointers: `/a/0/b`, with `~1` for `/` and `~0`
  for `~` inside a key.
- Header names are case-insensitive. These headers are never targets,
  because the Broker sets them or they decide how a request is framed,
  routed, or parsed: `Host`, `Content-Length`, `Transfer-Encoding`,
  `Expect`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`,
  `Proxy-Authorization`, `Proxy-Authenticate`, `Proxy-Connection`, `Via`,
  `Forwarded`, `X-Forwarded-*`, `Content-Type`, `Content-Encoding`,
  `Accept-Encoding`, `Range`, and `If-Range`.
- The URL path, multipart and `text/*` bodies, and `Authorization: Basic`
  credentials are not targets.
- Each target is substituted at most once per request.

`--omit NAME` leaves a stored Secret out of the run: it is not on the
Capability, and its name is removed from the Agent's environment. In a
`--strict` run, omitting a Secret the Contract requires here is a violation.

Targets come only from your command line. varlatchd records them on the
Capability when it issues it, and the Broker enforces the targets varlatchd
returned. The Agent cannot add or change a target, and nothing in its
requests is read as policy. `--target` and `--omit` must name Secrets
stored in the environment: a name that is unknown, not stored there, or not
a Secret is a usage error, and so is a name given both a target and an
omit. Nothing starts.

## What the Broker does with a request

A request to an allowed destination has three surfaces: headers, query, and
body. A surface is targeted for a Secret when one of the Secret's targets is
in it.

- A Placeholder at one of its targets is substituted.
- A Placeholder in a surface that is not targeted for it is forwarded
  unchanged and reported, so an Agent that quotes its environment in, say, a
  log line still works.
- A request that contains Placeholders at none of their targets is
  forwarded unchanged.

Anything unclear in a targeted surface blocks the request:

- the Placeholder anywhere else in that surface, or a second copy at the
  target;
- the target header sent twice, in any case, or line-folded;
- the target query parameter or form field sent twice, compared after
  decoding (`api_key` and `api%5Fkey` are the same name);
- a `;` in a targeted query or form body;
- a Placeholder that is percent-encoded, `\uXXXX`-escaped, or otherwise
  visible only after decoding;
- a duplicate key anywhere in a targeted JSON body, or a body that does not
  parse;
- a targeted body whose `Content-Type` is missing, does not match the
  target, or declares a charset other than UTF-8, or that has a
  `Content-Encoding` other than `identity`.

A Secret's targets constrain every request that carries its Placeholder.
When the Secret has a `json:` or `form:` target, the request's body is a
targeted surface even if the Placeholder is only in a header: a body that
is not a valid body of that kind, as above, blocks the request, although
nothing in it would be substituted.

Only this run's Placeholders count: text that merely looks like one is left
alone. The Broker changes nothing else: every other header, the rest of the
query, and every body byte outside the substituted value are forwarded as
the Agent sent them, and a body is never re-serialized. It does own the
transport: `Host` comes from the allowed URL, hop-by-hop and proxy headers
are removed, and `Content-Length` is recomputed. A signature computed over a
Placeholder, or over the body or its length, does not match the substituted
request.

## When a request fails

The Broker connects to the destination only after the whole request has
been built, so a failed request sends it nothing.

- **Before the Secret is fetched:** a blocked request gets `403` (or `413`
  for a body over 2 MiB), and a substitution to a destination that is not
  `https://` gets `502`. varlatchd is not called and nothing is decrypted.
- **After the Secret is fetched:** a value that cannot be carried at its
  target (CR, LF, or NUL in a header), a substituted body over 2 MiB, or a
  response from varlatchd that does not match the request gets `502`. The
  audit trail shows the exercise; the Broker drops the value.

The Agent receives a plain-text reason naming the Secret, the rule, and the
location, never a value:

```
varlatch-broker: STRIPE_KEY: placeholder at query parameter "q", which is not a target
```

The run's output repeats each failure, names each stray Placeholder once,
and counts failures by rule when the run ends.

## The Agent's environment

- Each targeted Secret is a Placeholder.
- Stored Secrets and Contract Secrets are removed from the environment the
  Agent inherits from your shell. To know the Contract's Secrets the run
  reads the active Contract: when one is active, the run needs
  `contract.read` and does not start without it. The run names each
  inherited Secret it removed. A name Varlatch does not know to be secret
  still passes through.
- `HTTP_PROXY` and `HTTPS_PROXY` (and their lower-case forms) point at the
  Broker. `NODE_USE_ENV_PROXY=1` makes Node's built-in `fetch` use them.
- `NO_PROXY` and `no_proxy` each keep the entries inherited from your shell
  and gain exactly the Broker's own address, so a Node request addressed to
  the Broker is not proxied a second time. A spelling that was not set
  becomes the Broker's address alone. Clients disagree about which spelling
  wins when both are set (Node reads `no_proxy` first), so neither is copied
  into the other.
- No reusable Varlatch credential, unless you pass `--agent-metadata`.

## Sending requests through the Broker

Send plain HTTP requests with an absolute `https://` URL to the Broker, with
the per-run proxy credential from `HTTPS_PROXY`:

```js
import http from "node:http";

const proxy = new URL(process.env.HTTPS_PROXY);
const req = http.request({
  host: proxy.hostname,
  port: proxy.port,
  path: "https://api.stripe.com/v1/charges",
  method: "POST",
  headers: {
    "Proxy-Authorization":
      "Basic " + Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64"),
    Authorization: `Bearer ${process.env.STRIPE_KEY}`,
  },
});
req.end();
```

The Broker does not intercept TLS, so a client that tunnels HTTPS with
`CONNECT`, which includes Node's `fetch` and most HTTP libraries, gets a
`502` with an explanation for an allowed destination. Traffic to other
destinations passes through unchanged, Placeholders intact, unless you pass
`--agent-network strict`, which blocks it.

## Limits

- Enforcement is in the local Broker. A process running as your OS user can
  inspect the Broker's memory, credential file, and sockets.
- A correctly placed credential can call any endpoint and method on the
  destination that it permits. Destinations are host and port.
- A destination that logs or echoes the target header, or logs URLs with a
  query target, sees the value.
- Responses are relayed unchanged: a destination that returns the Secret, or
  data derived from it, returns it to the Agent.
- An exemption inherited in `NO_PROXY` or `no_proxy` still sends matching
  requests around the Broker, even with `--agent-network strict`, for every
  client that reads that spelling. Node, curl, and Python treat `*` as a
  wildcard only when it is the whole value, so the appended Broker address
  disables an inherited `*` for them; a client that honours `*` anywhere in
  the list still bypasses the Broker entirely. Start agent-safe runs without
  exemptions you do not need.
