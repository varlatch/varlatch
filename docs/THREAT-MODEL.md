# Varlatch Threat Model

Consolidated from Varlatch's design decisions and readable on its own. Honesty is the design
principle: every strong claim below either maps to an automated test, an
integration/E2E check, or a deployment invariant, or it explicitly states why
the property cannot be enforced. Claims carry one of three statuses:

- **SHIPPED GUARANTEE**: implemented and verified by tests/E2E/deployment invariants.
- **DESIGNED INVARIANT**: an architectural rule the implementation follows and enforces where it applies today.
- **DESIGNED / NOT SHIPPED, NOT CURRENTLY GUARANTEED**: planned architecture; no protection exists yet.

## 1. Assets

Plaintext configuration Values and Secrets; the Root KEK; Organization KEKs
and per-version DEKs; Varlatch credentials (service/CLI/browser bearers,
setup/invite grants, Better Auth sessions and passkeys); authorization state
(identities, memberships, Grants, Requirements, Contracts);
the Security Audit history; the JWT signing key.

## 2. Principals and trust zones

| Zone | Members | Trust |
|---|---|---|
| **Infrastructure Operator** | Anyone with host/container exec, volume/env access, Secret Plane DB credentials, the running image, or the KEK (includes Coolify terminal access and the Convex admin key holder) | **Above the application's enforcement.** Varlatch makes operator actions explicit and audited; it never claims to prevent them. |
| **Secret Plane** (`varlatchd`) | The daemon, its DB schema, the KEK in memory | Trusted. Its compromise may expose all secrets. |
| **Application Plane** (Convex, `varlatch-web` static assets) | Mirrors, product metadata, dashboard serving | Untrusted for authority: can break UI, never authorization. |
| **Authenticated Identities** | Humans (installation-level), machine identities (org-scoped) | Only what Grants + roles allow, per request. |
| **Network peers** | Public internet, tailnet peers | Nothing by presence. Tailnet identity is an *additional* constraint or an explicitly enrolled authentication method, never ambient authority. |
| **AI agents / untrusted subprocesses** | Anything `varlatch run` spawns | Untrusted. In agent-safe mode (§6) an Agent Run holds only placeholders and no Varlatch credential; plain `varlatch run` still injects plaintext (§5). |
| **Local Broker** | The loopback proxy `varlatch run --agent-safe` starts in the trusted parent | Trusted for mediation only: it holds the broker credential and sees plaintext at the substitution boundary, but `secret.use` authority belongs to the Agent Identity and is evaluated by `varlatchd` per exercise. |

## 3. Trust boundaries

1. **Application Plane ↔ Secret Plane.** Convex holds no plaintext, no key material, no authorization state: only one-way Mirrors. Convex cannot mint anything `varlatchd` accepts; `varlatchd` never trusts Convex's word about a caller.
2. **Database roles.** `varlatchd_runtime` (no DDL; INSERT/SELECT-only on audit), `varlatchd_migrate` (elevated, one-shot job only), `convex` (own database, zero access to `varlatch`). Superuser = Infrastructure Operator. **On Coolify this separation does not currently hold:** Coolify passes every stack environment variable to every service, so runtime `varlatchd` also receives the migrate and superuser passwords (#28).
3. **Bearer-only `/v1`.** Cookies authenticate only the `/auth` ceremony surface; the browser exchanges its httpOnly session for a short-lived in-memory bearer.
4. **Ordinary listener vs tailnet listener.** Trusted Tailnet Context can only be constructed on the dedicated tailnet listener from the true socket peer via WhoIs; headers, forwarded IPs, and CGNAT-range sources never create it. The tailnet listener is never reverse-proxied.
5. **HumanAuth module boundary.** Better Auth answers "who is this human?"; its user IDs never leave the module (`auth_user_links` maps to Varlatch Identities). It holds no authorization authority.

## 4. Shipped guarantees

Each maps to its verification. Unit/integration tests run on every push;
"clean-room E2E" = `scripts/ci-e2e.sh` in CI (fresh stack, virtual
authenticator).

| Claim | Status | Verified by |
|---|---|---|
| Secret Plane DB/backup/disk theft without the KEK yields ciphertext only: per-version DEKs wrapped by per-org KEKs wrapped by the Root KEK; the unwrapped Root KEK is never stored in any database | **SHIPPED GUARANTEE** | `test/crypto.test.ts` round-trip/wrong-key; deployment invariant: KEK is a mounted file only |
| Ciphertext cannot be transplanted across org/secret/version rows or reused across purposes (AAD binding + purpose discriminators) | **SHIPPED GUARANTEE** | `test/crypto.test.ts` transplant/purpose cases |
| A wrong KEK is refused at startup and by `/readyz` (canary verification), and `admin kek verify` proves backup possession without exposing key material | **SHIPPED GUARANTEE** | `test/bootstrap-auth.test.ts`, `test/http.test.ts` readyz; live smoke |
| Root-KEK rewrapping primitive preserves value ciphertext; an operator rotation command with canary/file transition is not implemented | **TESTED PRIMITIVE, WORKFLOW PLANNED** | `test/crypto.test.ts` rotation case |
| Authorization is default-deny; Grants union additively; the fixed Member bundle denies production value access; Requirements restrict and never grant; admins do not bypass Requirements | **SHIPPED GUARANTEE** | `test/authz.test.ts` (14 evaluator cases) |
| Org scope derives from authenticated identity + memberships; outsiders get not-found-equivalent responses; machine identities act only inside their own org | **SHIPPED GUARANTEE** | `test/http.test.ts` authorization cases |
| Tailnet-constrained retrieval fails closed: no Tailnet Context, wrong tag, or foreign/shared tailnet ⇒ deny with a diagnosable code; the ordinary listener can never satisfy a Tailnet Requirement; a stolen credential used off-tailnet is useless for constrained resources | **SHIPPED GUARANTEE** | `test/tailnet.test.ts` end-to-end; whois client tailnet-pinning tests; live smoke |
| Application Plane JWTs (ES256, 10-min, audience-scoped) are never accepted back as Secret Plane credentials; Convex verifies via JWKS and cannot mint authority | **SHIPPED GUARANTEE** | `test/jwt.test.ts` one-way-trust case |
| Convex mirror writes require varlatchd's dedicated mirror identity; mirror reads are scoped by verified token claims | **SHIPPED GUARANTEE** | Live verification of mirror auth (foreign-org/anonymous ⇒ empty) |
| The Convex admin key (and the instance secret it derives from) exists only in deploy-only custody, never in runtime varlatchd | **SHIPPED on plain Compose; on Coolify only with file-based secrets** (#28) | Compose per-service `environment:` scoping and per-service secret files (`test-backup-compose.mjs` pins each service's secrets; `test-prod-shape.mjs` checks a Coolify-shaped installation with file secrets holds none of the other services' secrets in runtime varlatchd). Coolify passes every variable to every service, so installations still setting secrets as Coolify variables, including `CONVEX_ADMIN_KEY`/`CONVEX_INSTANCE_SECRET`, do **not** hold this until moved to files |
| Security Audit Events commit transactionally with mutations and before disclosure; the runtime DB role cannot UPDATE/DELETE audit rows | **SHIPPED GUARANTEE** | Domain tests; migration 0003 grants; proven live against PostgreSQL (`UPDATE/DELETE audit_events` ⇒ permission denied) |
| Each retrieval (Effective Configuration, disclosure, validation, Capability exercise) reads everything from one read-only database snapshot: a value write, a parent write, a Contract activation, a rotation, or a Grant change that commits during the request is invisible to it, never half-applied | **SHIPPED GUARANTEE** | `test/retrieval-consistency.test.ts` (real PostgreSQL, writes injected between a request's reads), `test/retrieval-audit-order.test.ts` |
| Every retrieval decryption is preceded by a committed audit event naming its exact version, including values decrypted only to expand references (audited one reference level at a time); a failed audit commit stops the request before that decryption, and a failed decryption leaves the audit event as the record of the attempt | **SHIPPED GUARANTEE** | `test/retrieval-audit-order.test.ts` (traced connection: no read after the snapshot, injected commit and decryption failures) |
| The state manifest and `stateDigest` contain identifiers only (environment, contract revision and semantics version, item sources and version IDs), never plaintext or anything derived from it; the digest is identical for callers with different Grants on the same state, and changes with any captured version, source, rotation window, or contract. A strict retrieval returns values, manifest, and verdicts from one snapshot, or an error with no values | **SHIPPED GUARANTEE** | `test/strict-retrieval.test.ts`, `test/retrieval-consistency.test.ts` (real PostgreSQL) |
| Strict startup (`varlatch run --strict`) starts the command only if the environment it would receive satisfies the snapshot's active Contract at a semantics version the CLI implements: no missing, withheld, parent-only, invalid, or unresolved-reference item, an active Contract, and `contract.read`; otherwise it starts nothing and exits 78. Defaults fill only items with no stored value, never withheld ones; parent values are used only for names allowed with `--allow-inherited`, and are validated | **SHIPPED GUARANTEE** | `apps/cli/test/strictRun.test.ts`; clean-room `e2e-strict-run.mjs` (bundled CLI against a live server) |
| Agent-safe strict startup (`varlatch run --strict --agent-safe`): Secret verdicts are computed only in the operator's preflight retrieval and only when the operator holds `secret.reveal` (never on `secret.use` alone, never for the Broker), after an audit event recording the attempt and purpose with no verdicts; the Broker's issuance decrypts nothing, is bound to the preflight's state by a digest that confers no authority, and names only the categories that changed on a mismatch; a Contract Secret present only in the parent environment is a violation, and `--allow-inherited` cannot name a Secret | **SHIPPED GUARANTEE** | `test/agent-safe-preflight.test.ts`, `apps/cli/test/strictRun.test.ts`; clean-room `e2e-strict-run.mjs` |
| Audit events contain identifiers only: no plaintext, key/credential material, or value-derived hashes; value changes are expressed as version-ID transitions | **DESIGNED INVARIANT** | Enforced by the `recordAuditEvent` input shape; reviewed, not schema-proven |
| Human authentication is passkey-only: no password database, no SMTP; setup/invite grants are high-entropy, single-use, expiring; replay is rejected; sign-in without an authenticator fails | **SHIPPED GUARANTEE** | Clean-room E2E (7 passkey checks incl. replay rejection), invite tests |
| Break-glass is narrow: recovery targets a named Installation Admin; disabled admins need explicit `--enable`; `--new-admin` only when zero enabled admins exist; every issuance/consumption is audited | **SHIPPED GUARANTEE** | `test/bootstrap-auth.test.ts` |
| Opaque credentials are hashed at rest, shown once, individually revocable with immediate effect; expiry and disabled-identity checks apply on every request | **SHIPPED GUARANTEE** | `test/bootstrap-auth.test.ts` credentials cases |
| Expired preview environments fail closed for retrieval and mutation, synchronously, with no dependence on a cleanup worker | **SHIPPED GUARANTEE** | `test/domain.test.ts` expiry case |
| Contract authority is server-side: revisions are content-hashed server-side (client hashes untrusted), activation is a separate audited action with a semantic diff; unknown environment names in a schema file's `env(...)` fail loudly before anything is pushed | **SHIPPED GUARANTEE** | `test/domain.test.ts`, `test/http.test.ts`, `test/env-schema-conditions.test.ts`, `packages/env-schema` tests |
| `secret.use` is distinct from `secret.reveal`, never in the Member bundle, arrives only via explicit Grants, and is tailnet-constrained | **SHIPPED GUARANTEE** | `test/authz.test.ts` secret.use cases |
| Capability issuance never expands authority: exercise re-evaluates the Agent's `secret.use` (incl. Tailnet Requirements against the exercise request) against current state; Grant revocation, Capability revocation, and expiry all deny the very next exercise; rotation resolves at exercise (Model B) | **SHIPPED GUARANTEE** | `test/capabilities.test.ts`; clean-room `e2e-broker.mjs` |
| Capabilities are unforgeable handles: exercise needs the ID, the hash-at-rest capability secret, and the bound Broker's bearer, all agreeing; mismatches are existence-hidden | **SHIPPED GUARANTEE** | `test/capabilities.test.ts` |
| Reference expansion at exercise is strict and capability-bound: referenced Secrets must be named in the Capability, non-sensitive pull-ins require the Agent's `config.value.read` and are audited before use, and any unresolvable reference denies the exercise rather than sending literal `${NAME}` upstream | **SHIPPED GUARANTEE** | `test/capabilities.test.ts` reference-expansion cases |
| Destination constraints are canonical host+port; wildcards never match the apex; every hop is independently checked and successful exercise is audited (host+port + `item@versionId`) before decryption | **SHIPPED GUARANTEE** | `test/destination.test.ts`, `test/capabilities.test.ts` |
| In agent-safe runs the Agent Run's environment holds opaque placeholders and no reusable Varlatch credential; substitution happens only in broker-originated, TLS-verified requests to allowlisted destinations; redirects are relayed, never followed with substituted material; CONNECT to secret-using destinations is refused (no MITM) | **SHIPPED GUARANTEE** | `apps/cli/test/broker.test.ts`; clean-room `e2e-broker.mjs` (real TLS upstream, redirect/decoy targets, log scan) |
| Sync Targets are opt-in standing disclosures: creation/widening passes a write-time gate (`secret.reveal`/`config.value.read`, decision-time provenance recorded); every push commits `sync.push_attempted` before material leaves; a destination has exactly one writer; Platform Adapters are a closed allowlist (no generic push-to-URL); Platform Credentials rest KEK-wrapped and are never redisplayed; credential replacement re-authorizes every referencing Target atomically | **SHIPPED GUARANTEE** | `test/sync.test.ts` (gate denial, exclusivity, audit-before-wire, atomic replacement refusal, ciphertext-at-rest); `packages/sync` adapter tests (sealed-box encryption, https/origin pinning) |
| Sync ledger content identity is a keyed fingerprint (HKDF from the Org KEK, per Target), never a bare hash; fingerprints appear in no audit event or log | **DESIGNED INVARIANT** | Enforced by `syncFingerprintKey` + audit input shape; reviewed, not schema-proven |
| Validation verdicts are value-derived, so `POST …/validate` evaluates an item only if the caller may read what the verdict describes: presence needs `config.metadata.read`, non-sensitive verdicts `config.value.read`, Secret verdicts `secret.reveal` including its Requirements (`secret.use` alone is not enough). Everything else is reported as not evaluated, with an authorization-derived reason only, and a partial evaluation is never valid. Validation decryption is audited before it happens (`secret.validated`/`value.validated`, `item@versionId`, no verdicts). Residual: a `secret.reveal` holder who can also change the Contract can probe by repeated activation, but can already read the value, and each probe is audited | **SHIPPED GUARANTEE** | `test/validation-access.test.ts` (permission, Tailnet Requirement, audit failure, enum-probe cases); `apps/cli/test/validation.test.ts`; `apps/web/test/validationSummary.test.ts` |

## 5. Explicit assumptions and non-guarantees

These are the boundaries of the model. None of them is a bug.

- **The Infrastructure Operator is outside enforcement.** Host/exec/volume/DB-superuser/KEK access defeats everything, including audit: append-only holds against runtime authority, **not** against an operator who can rewrite the database, restore old state, or replace the binary. Operator-resistant audit evidence would require an external trust anchor and does not exist yet.
- **`varlatchd` compromise may expose all plaintext** the process can decrypt, plus the KEK in memory. The Secret Plane is the trusted computing base.
- **KEK loss is permanent data loss.** Database backup + matching KEK = recoverable; either alone is not. The *raw* KEK stored with the backup weakens theft protection to nothing. `admin kek export` produces a passphrase-wrapped escrow blob (scrypt + AES-256-GCM, KDF parameters AAD-bound) that IS safe to store with backups; loss then reduces to passphrase loss. `admin kek split`/`combine` provide k-of-n Shamir sharing for multi-custodian setups; fewer than k shares reveal nothing. Both recovery paths verify against the installation canary before writing a key file.
- **Organization isolation is tenant isolation, not protection from the operator** of the installation.
- **Installation Admins have a real escalation path**: recovery mediation can take over any human identity, including Organization Admins. It is allowed, single-admin, and loud (high-severity audit), not prevented.
- **Tailscale limitations**: revocation is bounded by local netmap freshness (a removed node may retain access until the netmap syncs); tag enrollment delegates identity issuance to whoever assigns that tag in the tailnet; a compromised machine that legitimately satisfies identity and policy can exercise whatever that machine is allowed. Tailnet identity is a constraint layer, never the sole credential.
- **Convex compromise** does not directly expose plaintext or grant Secret Plane authority, but yields metadata, mirror contents (names, structures, audit summaries), and dashboard disruption.
- **JavaScript memory cannot be reliably zeroized.** Node/GC gives no precise-erasure guarantee for plaintext or key material that has passed through the process.
- **Environment injection is disclosure.** Anything `varlatch run` places in a child's environment is fully readable by that process and everything it spawns. Varlatch cannot control what an arbitrary process does with plaintext it was handed.
- **Strict startup is a startup check, not a confidentiality control.** It validates what the command receives when it starts; values the command reads later, or changes itself, are outside it.
- **The agent-safe preflight does not establish the Agent's reference resolvability.** A matching state digest shows the same configuration, not the same permissions. Every exercise evaluates the Agent's authorization and resolves every reference or denies, and a later exercise may use a version the preflight never checked.
- **`varlatch run` does not redact.** It is a plain injector and cannot stop a process from leaking what it was given. Agent-safe mode (§6) is the protection for untrusted processes.
- **Authorization is effective at the snapshot boundary.** A retrieval is authorized by the Grants, Roles, Groups, Requirements, and Capability state in its database snapshot, and by nothing later. A revocation that commits after a request's snapshot began does not affect that request: it may still complete and return what the snapshot authorized. The next request sees the revocation. The window is one request, with no network call inside it. The audit event records the decision the snapshot produced, so it can follow the revocation's own event in audit order.
- **Denial-of-service and side channels** (timing, traffic analysis) are out of scope for the MVP model.
- **Outbound sync is a deliberate egress class.** With a Sync Target configured, `varlatchd` initiates TLS connections carrying plaintext Values to allowlisted third-party APIs, authenticated by stored Platform Credentials. The mitigations (the closed adapter allowlist, KEK-wrapped org-level credentials scoped as narrowly as each platform honestly allows, audit-before-disclosure, the write-time disclosure gate, and the installation switch, `VARLATCH_SYNC=off`) bound the egress; they are not a claim that it is riskless. Sync delivery is a server-side convergence loop, not a caller's retrieval: it decrypts values to detect what changed, and its audit event precedes the push, not the decryption. A stored Platform Credential can confer authority beyond reading Varlatch's secrets.
- **The platform-facing copy is outside Varlatch's authority.** Once pushed, a Value's protection is the destination platform's: revocation and crypto-shredding do not extend there, an abandoned destination (after a destination change or Target revocation) is not cleaned up, and Varlatch never claims a pushed value was *adopted* by running workloads. Rotation completion stays a human decision informed by per-target sync status.

## 6. Agent safety: the credential broker (SHIPPED)

`varlatch run --agent-safe` spawns the untrusted Agent with opaque per-run
placeholders instead of Secrets and **no reusable Varlatch credential**
(the explicit `--agent-metadata` mode substitutes exactly one:
a ≤1h, revocable, HTTP-layer-read-only agent-run bearer whose authority is
still the Agent's Grants, so sensitive plaintext stays unreachable); a
trusted local Broker substitutes real material only in requests it
originates itself over verified TLS to Capability-allowlisted destinations;
`varlatchd` remains the `secret.use` authorization/Capability/audit
authority, re-evaluated on every exercise. Its guarantees are in the §4
table with their test mappings. The governing invariant:

> `secret.use` authorizes mediated use of secret material for an explicitly
> constrained destination. It does not imply `secret.reveal`.

And the honest limits, stated with the same discipline:

- **Same-user process escape is outside the boundary.** A process running as
  the same OS user may inspect the parent/Broker's memory, credential file,
  environment, or sockets. The Broker is not an OS sandbox.
- **Mediation, not a network sandbox.** Non-allowlisted traffic passes
  through unchanged by default (placeholders intact, useless);
  `--agent-network=strict` blocks it. An agent can still make arbitrary
  outbound requests unless separately sandboxed.
- **Opaque CONNECT tunnels cannot carry substitution** without MITM, which
  Varlatch deliberately does not do (no local CA). Clients must send
  inspectable absolute-URI HTTP requests to the Broker; CONNECT to a
  secret-using destination is refused with a precise diagnostic. This is
  narrower than generic `HTTPS_PROXY` compatibility.
- **No response guarantee.** Varlatch prevents direct delivery of stored
  Secret plaintext to the Agent during credential injection. It does not
  guarantee that an authorized destination will never return secret-derived
  or plaintext data to the Agent.
- **Destination granularity is host+port**, not path or method.
- **Body substitution is bounded and textual** (JSON/form/`text/*`); the
  Broker cannot repair application signatures computed over
  placeholder-bearing payloads.
- **Substitution is not tied to a location.** A placeholder is replaced
  wherever it appears in the headers or textual body of a request to an
  allowlisted destination, including fields that destination stores or
  publishes. An agent that may call an API host can therefore have the
  Broker write a Secret into content on that host. Keep allowlists narrow
  and upstream credentials narrowly scoped.
- **The Agent inherits the operator's environment.** The agent-safe child
  receives a copy of the parent's environment, minus Varlatch's own
  credentials, with placeholders and non-sensitive values overlaid. Any
  plaintext secret already in the operator's shell, including a contract
  Secret that has no value stored in Varlatch, reaches the Agent. Start
  agent-safe runs from a clean environment.
- **Plain `varlatch run` (without `--agent-safe`) still injects plaintext**
  into the child environment (§5); agent safety is opt-in per run.

## 7. Reviewing a claim

The rule this document lives by: **a strong security claim must map to an
automated test, an integration/E2E check, or a deployment invariant, or
explicitly say that the property cannot be enforced (usually: against the
Infrastructure Operator) and why.** If you find a claim here without one of
those, that is a documentation bug; file it as such.

## September 2026 hardening limits

Audit insertion now uses a transactional counter to order worker delivery by commit. This serializes audit writers and should be load-tested for large installations. Delivery remains at least once: a crash after a remote receiver accepts a batch but before cursor persistence can replay it. Consumers must deduplicate event IDs.

Request bodies are capped at 1 MiB on ordinary and tailnet listeners. A bounded process-local limiter permits 600 requests per minute per socket peer, excluding health checks. Proxy deployments share the proxy peer's allowance; forwarding headers are not trusted. This is a basic abuse bound, not a distributed denial-of-service guarantee. Reference expansion is capped at 1 MiB, 10,000 substitutions, and eight reference levels.

Dashboard Convex reads expose only invalidation signals; authoritative resource and audit reads go through the Secret Plane. Human recovery codes and an operator root-KEK rotation workflow remain planned.
