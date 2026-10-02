# Agent-safe runs and `varlatch request`

## What an agent-safe run is

In an agent-safe run you never hold a Secret: each one is a Placeholder
(`vlch_ph_v1_...`), and a local Broker puts the real value into requests to
the destinations the human allowed, at the places they named. You can tell
you are in one: `VARLATCH_AGENT_RUN` is set.

## Launching one

Launching is the human's step: you cannot relaunch yourself. Give them the
command with the Secrets, destinations, and targets the task needs, and
wait. For example:

```text
varlatch run --agent-safe --agent <agent identity> \
  --allow-host api.stripe.com \
  --target STRIPE_KEY=header:authorization \
  -- <your coding agent's command>
```

- Every stored Secret needs a `--target` (a header, query parameter, JSON
  pointer, or form field) or an `--omit`.
- The Broker needs its credential: `--broker-credential-file <path>` or
  `VARLATCH_BROKER_CREDENTIAL`. The agent identity and the Broker are set up
  in the dashboard.
- `--agent-metadata` lets you read configuration metadata inside the run.

## Calling an API inside the run

Use `varlatch request`, a curl-like client. The shell expands the variable to
its Placeholder, and the Broker substitutes the Secret at its target. Use
double quotes: in single quotes the shell passes the literal text
`$STRIPE_KEY`, which carries no Placeholder, so nothing is substituted and the
API sees no valid key. A tool that runs commands without a shell must pass
the Placeholder itself (`varlatch --assisted context --json` lists the names;
the variable holds the Placeholder):

```sh
varlatch --assisted request -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com/v1/balance
varlatch --assisted request -X POST -H "Authorization: Bearer $STRIPE_KEY" --json '{"amount": 500}' https://api.stripe.com/v1/charges
varlatch --assisted request -i -o response.json https://api.example.com/v1/items
```

- It takes `-X`, `-H`, `-d`, `--json`, `-o`, and `-i`; `@file` and `@-` send
  a file or standard input as the body.
- Responses arrive scrubbed: a Secret echoed back shows as its Placeholder.
- curl, fetch, and most SDKs open a tunnel the Broker refuses (502).
- Exit 0 when the destination answered, whatever the HTTP status; 1 when the
  Broker refused (its reason is on stderr) or the response was cut off; 77
  when the Broker did not accept the run's proxy credential.
- A Placeholder in a header that is not a target is refused. Never try to
  work around a refusal: report it to the human.

## Other commands inside the run

- `varlatch --assisted run -- <command>` starts the command with the run's
  environment, Placeholders included, and masks the run's own credentials in
  its output. Inherited variables that are not Placeholders pass as they
  are: show only the names `varlatch --assisted context --json` lists under
  `agentRun.placeholders`.
- Commands that read from the server work only with `--agent-metadata`, and
  only for reading.
