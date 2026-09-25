# Strict startup: `varlatch run --strict`

`varlatch run --strict` works out the exact environment your command would
receive, checks it against the active Contract, and starts the command only
if nothing is wrong. On any problem it starts nothing, prints every problem
at once, and exits with status 78.

```
varlatch run --strict [--allow-inherited NAME]... -- <command> [args...]
```

A default `varlatch run` is unchanged: it never injects defaults and never
fails because of the Contract.

## What it checks

Strict startup makes one request to the server, which returns every value
this identity may receive, the active Contract, and what was captured, all
from one consistent snapshot of the server's state. It needs:

- a server running Varlatch 0.11.0 or later. On an older server it fails and
  never falls back to a default run;
- an active Contract;
- `contract.read` on the project, so the Contract can be checked;
- a Contract semantics version this CLI implements.

If the request fails on the server, strict startup retries once and then
fails.

## Where each Contract item's value comes from

For each Contract item, the first rule that applies decides:

| What the server did | Your shell | Result |
| --- | --- | --- |
| Delivered the value, references expanded | anything | The delivered value, replacing any value in your shell |
| Delivered a value with a `${NAME}` reference left literal | anything | Violation: *unresolved-reference* |
| Withheld the value from this identity | sets it, and `--allow-inherited NAME` names it | Your shell's value |
| Withheld the value | sets it, not allowed | Violation: *withheld* |
| Withheld the value | does not set it | Violation *withheld* if the item is required in this environment; otherwise absent |
| Has no stored value | sets it, and `--allow-inherited NAME` names it | Your shell's value |
| Has no stored value | sets it, not allowed | Violation: *inherited* |
| Has no stored value | does not set it, and the Contract has a default | The Contract default |
| Has no stored value | does not set it, no default | Violation *missing* if required in this environment; otherwise absent |

- **Every value the command will receive is validated exactly as it will
  receive it**, whether it was delivered, inherited, or a default, using the
  Contract's semantics version. An invalid value is a violation.
- **A Contract default never replaces a withheld value.** The real value
  exists; a default could silently change behaviour.
- **`--allow-inherited NAME`** lets one named Contract item take its value
  from your shell when Varlatch delivered none (not stored, or withheld). It
  never overrides a delivered value. It takes exact names, can be repeated,
  and a name that is not in the Contract is an error.
- **Items outside the Contract** that Varlatch delivers are passed to the
  command as usual and counted. Other variables in your shell (`PATH`,
  `HOME`, and so on) pass through unchanged.

## Output

Violations name the item, the kind, and the reason. They never print a
value.

```
varlatch: strict startup found 3 violation(s); the command was not started:
  HOST: inherited: not stored in Varlatch and set only in the parent environment; accept it with --allow-inherited HOST
  LEVEL: invalid: the delivered value must be one of: debug, info
  NEEDED: missing: required in this environment and not stored
```

## The run context

A strict run gives the command one extra variable, `VARLATCH_RUN_CONTEXT`.
It is JSON that records, for each Contract item, what the server did and how
the item reached the command. It holds names and identifiers only, never
values:

```json
{"v":1,"mode":"strict","contractRevisionId":"rev_…","contractHash":"sha256:…",
 "semanticsVersion":2,"environment":{"rootId":"env_…","tier":"production"},
 "items":{"API_KEY":{"server":"withheld","delivery":"inherited"},
          "PORT":{"server":"notStored","delivery":"default"},
          "DATABASE_URL":{"server":"delivered","delivery":"varlatch"}}}
```

- `server` is `delivered`, `withheld`, or `notStored`.
- `delivery` is `varlatch`, `inherited`, `default`, or `absent`.

The name is reserved: no Contract item or stored value may use it, and every
`varlatch run`, strict or not, removes a `VARLATCH_RUN_CONTEXT` inherited
from an outer run, so it never describes the wrong Environment.

## Agent-safe strict startup

With `--agent-safe`, the Agent never receives Secret plaintext: each stored
Secret reaches it as a Placeholder that the local Broker substitutes on the
way out. `--strict --agent-safe` adds the strict checks without the operator
ever seeing a Secret either:

1. **The operator's preflight.** One request returns the non-sensitive
   values and, when the operator holds `secret.reveal`, a verdict for each
   Secret, never its value. The server decrypts each Secret only to
   validate it, after an audit event that records the attempt and its
   purpose.
2. **The Broker's issuance.** The Capability is issued against the state
   the preflight saw. If the configuration changed in between, issuance
   refuses and names only what kind of thing changed (the Environment, the
   Contract, item versions, or a rotation window); both requests are
   retried once. On a match, issuance reports for each Secret whether it is
   stored and whether the Agent holds `secret.use` here. It decrypts
   nothing.

The Agent starts only if nothing is wrong. In addition to the ordinary
strict checks, these are violations:

- the operator lacks `secret.reveal`, so the Secrets cannot be validated
  (`not-evaluated`);
- a Secret's stored value is invalid, or one of its references stays literal
  for the operator;
- the Agent lacks `secret.use`, or a Requirement on it is not met
  (`agent-unauthorized`);
- a Contract Secret is set only in your shell: it would reach the Agent as
  plaintext.

`--allow-inherited` may not name a Secret in an agent-safe run.

**What this does not show.** Matching state means the same configuration,
not the same permissions: the operator and the Agent may hold different
Grants. A Secret whose references the operator can expand may reference
something the Agent may not read. Every request the Agent makes through the
Broker is authorized again, and resolves every reference or is denied.

## Limits

Strict startup checks what the command receives when it starts. Values the
command reads later, or changes itself, are outside it. It is a correctness
check, not a confidentiality control: once a value is in the command's
environment, the command can do anything with it. In an agent-safe run,
rotation, revocation, and Grant changes still apply at every exercise, and a
later exercise may use a newer version than the one the preflight checked.
