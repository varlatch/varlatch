# Tailnet browser-read spikes (S1 to S8)

Browser reads through the tailnet listener (ADR-0046) rest on Tailscale and
browser behavior that was read in source but never run. These spikes run it
against a real tailnet before anything is built. They test assumptions, not
varlatchd: a small probe stands in for varlatchd, in the same topology.

| Spike | What it checks |
|---|---|
| S1 | The socket peer varlatchd sees on the tailnet listener, and WhoIs on it: with the port, with port 0, after the connection closed, and with 50 parallel connections from each of two nodes |
| S2 | A listener bound to 127.0.0.1 still gets tailnet traffic, and keeps Compose-network peers out; a Compose peer reaching a 0.0.0.0 listener gets no tailnet identity |
| S3 | The node certificate from the LocalAPI for varlatchd's uid: refused by default, given with `TS_PERMIT_CERT_UID`, and never with write access |
| S4 | Renewal through `min_validity`, and swapping the TLS context while requests are in flight |
| S5 | Chromium, Firefox and WebKit calling the endpoint cross-origin, from a public origin and a ts.net origin: preflights, Private Network Access, and how long an unreachable endpoint takes to fail |
| S6 | `tailscale serve` TCP forwarding, TLS-terminated and plain, carries no tailnet identity |
| S7 | A device from another tailnet, reaching the node through sharing, is refused by the tailnet pin |
| S8 | How a device the access rules deny `tcp:8688` fails, and how fast |

## What it does, and what it never does

- It joins two nodes to the tailnet with the auth key you give it: the spike
  node and a client node (both userspace, the image the Tailscale overlay
  pins). This machine is the third node and runs the browsers.
- It configures Serve on the spike node only (S6), from a file it writes.
- At the end both nodes log out and every container and volume is removed
  (`SPIKE_KEEP=1` keeps them for inspection).
- It never changes the tailnet's access rules, its settings, or any other
  device. S7 and S8 need changes only the owner makes (below); without
  them they report NOT RUN.
- The auth key is never printed or logged. It is read from a file
  (`SPIKE_TS_AUTHKEY_FILE`, preferred) or from `SPIKE_TS_AUTHKEY`, which the
  script removes from its environment before starting any process. A key
  from the environment is written to a private temporary file (mode 600)
  that is deleted as soon as both nodes have joined. From then on the
  Compose secret points at `/dev/null`.

## Running it

```sh
node scripts/spike-tailnet-browser/run.mjs preflight   # what this machine allows; joins nothing
node scripts/spike-tailnet-browser/run.mjs plan        # validates the Compose project; joins nothing
node scripts/spike-tailnet-browser/run.mjs selftest    # the probe against a fake LocalAPI; no tailnet
SPIKE_TS_AUTHKEY_FILE=~/.config/varlatch-spike/ts-authkey \
  node scripts/spike-tailnet-browser/run.mjs all       # or: s1 s2 s6
```

| Variable | Use |
|---|---|
| `SPIKE_TS_AUTHKEY_FILE` / `SPIKE_TS_AUTHKEY` | The auth key (see below) |
| `SPIKE_HOSTNAME` | The spike node's name (default `varlatch-browser-spike`; the client is `<name>-client`) |
| `SPIKE_PROBE_UID` | The probe's uid, varlatchd's user (default 999, `useradd -r` in the varlatchd image) |
| `SPIKE_S4_FORCE_RENEW=1` | Let S4 force one certificate renewal (one more Let's Encrypt issuance) |
| `SPIKE_HEADED=1` | S5 with visible browsers, to see permission prompts headless browsers never show |
| `SPIKE_S7_WAIT_SECONDS` | S7: how long to wait for the request from a shared-in device |
| `SPIKE_S8_RULE_APPLIED=1` | S8: the owner applied the deny rule below |
| `SPIKE_KEEP=1` | Keep the containers (the nodes stay joined until you log them out) |

Every result is one line, and one JSON line in a file under the temp
directory (the path is printed): PASS or FAIL for an expectation the design
makes, OBSERVED for a measurement, NOT RUN when a prerequisite is missing.
NOT RUN is not a pass. The exit code is 0 only when every selected spike ran
and passed; 1 when anything failed; 3 when anything did not run. S5 needs
Firefox and WebKit installed for Playwright (`npx playwright install
firefox webkit` in `apps/web`), or it reports them NOT RUN.

## What the test tailnet must allow

Prefer a test tailnet. The main tailnet works for S1 to S6 if its policy
already lets this machine reach the spike node (below); S7 and S8 belong on
a test tailnet.

**The auth key** (Settings, Keys, Generate auth key):

| Setting | Value | Why |
|---|---|---|
| Reusable | yes | Two nodes join with it |
| Ephemeral | yes | The nodes disappear once logged out or offline |
| Pre-approved | yes, if device approval is on | Otherwise the nodes wait for approval |
| Tags | none | A tag needs `tagOwners` in the policy, which is an access rule change. Untagged nodes belong to the key's creator, so WhoIs reports that user |
| Expiry | 1 day | Revoke it after the run |

**Tailnet settings**, checked by `preflight`, not changed by the script:

| Setting | Needed by | Note |
|---|---|---|
| MagicDNS | all | The spike node is reached by name |
| HTTPS certificates | S3, S4, S5, S6, S8 | Each spike node name gets a Let's Encrypt certificate. S4's forced renewal issues one more. Let's Encrypt allows 5 certificates for the same name per week: use another `SPIKE_HOSTNAME` for repeated runs |
| Funnel | none | Not used; leave it off |

**This machine** must be a device on the same tailnet: it is the first
client node and runs the browsers, as a real device. If the test tailnet is
not the one this machine is on, switching to it (`tailscale switch`) drops
this machine's connection to the main tailnet, including SSH to servers,
until you switch back.

**Connectivity.** This machine must reach the spike node on tcp 8687 to 8692,
and the client node must reach it on tcp 8687. Under the default policy
(every member reaches every device) nothing changes. If the policy is
narrower, the script stops at setup with "this machine cannot reach" and
changes nothing. The rule it would need is a proposal, to apply only with
the owner's approval, here for untagged nodes owned by the key's creator:

```jsonc
// Proposed, not applied. ACL form:
{ "action": "accept", "src": ["you@example.com"], "dst": ["you@example.com:8687-8692"] }
// Grants form:
{ "src": ["you@example.com"], "dst": ["you@example.com"], "ip": ["tcp:8687-8692"] }
```

**S7, a device from another tailnet.** Tailscale quarantines devices shared
into a tailnet: they answer connections but do not start them. So the
realistic case is the other way round: the Varlatch node shared out to
someone in another tailnet, whose devices then connect to it. The owner shares the spike node (machine menu, Share) with a user
of a second tailnet, then runs with `SPIKE_S7_WAIT_SECONDS=300`; from that
user's device, request the URL the script prints. The share is removed with
the node when it logs out.

**S8, a device denied `tcp:8688`.** Tailscale policies only allow, so denying
one port means narrowing an allow rule. On a test tailnet with the default
allow-all policy, the owner would replace it with (proposed, not applied):

```jsonc
// Everyone keeps every port except 8688; only <keeper> may use 8688.
{ "action": "accept", "src": ["*"], "dst": ["*:1-8687,8689-65535"] },
{ "action": "accept", "src": ["<a device or user that is not this machine>"], "dst": ["*:8688"] }
```

Then run `SPIKE_S8_RULE_APPLIED=1 node scripts/spike-tailnet-browser/run.mjs s8`
from this machine, the denied device, and restore the policy afterwards.
