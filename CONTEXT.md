# Varlatch

An open-source, self-host-first secrets and environment configuration platform without artificial limits, designed from the beginning for safe use with AI coding agents.

## Language

### Planes and components

**Secret Plane**:
The security authority of Varlatch: authentication, identities, credentials, organization memberships, policies, grants, authorization decisions, secret material, key material, and authoritative security audit. Compromise of the Secret Plane may expose secrets; it is explicitly inside the trust boundary.
_Avoid_: vault, crypto service, control plane

**Application Plane**:
The non-authoritative part of Varlatch: the reactive dashboard backend and the Mirrors it serves. Anything that feeds an authorization decision, including Contracts, tiers, and the Organization/Project/Environment skeleton, is authoritative in the Secret Plane and only mirrored here. Nothing in the Application Plane can independently grant, change, or forge access to secrets; corrupting it may break the UI, never authorization. Everything it holds can be rebuilt; non-authoritative never means disposable (see Installation Archive).
_Avoid_: control plane (implies authority it must not have), backend, app server

**varlatchd**:
The daemon that implements the Secret Plane. The sole credential authority (alongside explicitly trusted external identity providers), the only component that can decrypt secret material, and the component that participates directly in a tailnet for tailnet-bound retrieval. Every principal authenticates to it end-to-end; it never accepts another component's word about who a caller is.
_Avoid_: latchd, broker (a Broker is a different component)

**Mirror**:
A one-way, read-only copy of Secret Plane state published into the Application Plane for reactive display. Authority flows only Secret Plane → Application Plane; a stale or corrupted Mirror produces incorrect UI, never incorrect authorization.
_Avoid_: sync, replica (both suggest bidirectionality)

**Installation**:
One deployed instance of Varlatch. An Installation may contain many Organizations.
_Avoid_: deployment (reserved for deploying user applications), instance

### Tenancy and people

**Organization**:
The tenant and authorization boundary inside an Installation. Every project, secret, identity, policy, and audit event belongs to exactly one Organization; nothing crosses Organizations. An Organization boundary is tenant isolation, not protection from the operator of the Installation.
_Avoid_: workspace, team, tenant

**Installation Admin**:
An Identity with application-level authority over the Installation itself: user lifecycle, recovery mediation, installation settings, organization lifecycle. Confers no organization membership, no secret access, and no Organization Admin authority; access to an organization's contents requires ordinary membership.
_Avoid_: superadmin, root user

**Organization Admin**:
An Identity with application-level administrative authority inside one Organization. Confers nothing outside that Organization, and cannot reset another user's global authentication root.

**Infrastructure Operator**:
A threat-model authority, not an application role: whoever controls the deployment itself: host, containers, exec/terminal access, volumes, environment, Secret Plane database credentials, running image/process, or KEK. Application policy cannot constrain an Infrastructure Operator; Varlatch makes their interventions explicit and audited, never claims to prevent them.
_Avoid_: hidden super admin, root role

**Identity**:
Any authenticatable actor: human user, service account, workload, CI job, device, agent, or Broker. All are first-class; none are "just an API token." Every Identity has a stable Varlatch-owned identifier that outlives any authentication provider.
_Avoid_: account, user, principal, token (a credential is not an identity)

**Authentication Method**:
A linked mechanism by which an Identity proves who it is: a passkey, an external OIDC subject, a tailnet enrollment, a service credential. Authentication Methods establish *who*; they never carry *what the Identity may do*. An Identity may have several; they are replaceable without changing the Identity.
_Avoid_: login method, auth provider (the provider is the external system, not the link)

**Credential**:
A revocable bearer artifact by which an Identity exercises an Authentication Method for a bounded time: it has a kind (`browser`, `cli`, OIDC-exchanged, agent-metadata), an expiry, and an individual server-side record that can be listed and revoked. A Credential proves *who is calling right now*; it is never the Identity itself, never carries authority beyond the Identity's Grants, and expiry is a feature, not an inconvenience.
_Avoid_: token (overloaded: proxy tokens and Placeholders are not Credentials), API key (implies non-expiring)

### Configuration and secrets

**Project**:
One deployable application/service/unit, with exactly one effective Configuration Contract and its own Environments. A monorepo commonly maps to several Projects; repository structure never distorts the hierarchy.
_Avoid_: app, service, repo

**Environment**:
A named value set within a Project, and the single value-set concept (there is no separate "config" object). May derive from exactly one root Environment, one level deep; resolution is child override, then parent value. Its *kind* (shared, personal, preview) describes lifecycle/ownership; its Tier describes risk. Names are free-form.
_Avoid_: config, branch config, stage

**Tier**:
The normalized risk/deployment class of a root Environment: `development | staging | production`. A derived Environment inherits its parent's Tier and cannot weaken it. A policy selector, not authorization by itself, and never confused with kind (preview is not a tier).
_Avoid_: stage, level

**Config Item**:
A named configuration slot within a Project (`PORT`, `DATABASE_URL`, `STRIPE_SECRET_KEY`).
_Avoid_: variable, key (ambiguous with cryptographic keys), env var

**Value**:
The Environment-specific content of a Config Item. All Values, sensitive or not, live authoritatively in the Secret Plane; sensitivity affects policy and handling, never storage location.

**Secret**:
A Config Item whose effective Contract metadata marks it sensitive. `secret.reveal`/`secret.use` policy language applies to Secrets; non-sensitive Config Items stay boring.
_Avoid_: calling every configuration value a secret

**Value Reference**:
A `${NAME}` token inside a Value that reuses another Config Item's Value from the same Effective Configuration. Expanded strictly server-side and never authority-expanding: read paths leave what the caller may not read literal, while capability exercise resolves every reference or denies. `$${NAME}` escapes to literal text.
_Avoid_: interpolation, templating (suggests a general expression language; it is name substitution only)

**Effective Configuration**:
The fully resolved set of Values for an Environment after applying its allowed inheritance (child overrides over parent values). Contract validation evaluates the Effective Configuration, not a child's overrides alone.
_Avoid_: merged config, resolved env

**Delivered Configuration**:
What a command started by `varlatch run` actually receives: the Values Varlatch delivered to this caller (after authorization and reference expansion) and any variables inherited from the parent environment, plus, under strict startup, applied Contract defaults. It can differ from the Effective Configuration: withheld Secrets are absent, inherited variables fill gaps, and references to values the caller may not read stay literal.
_Avoid_: runtime env (ambiguous about which of these layers is meant)

**Strict Startup**:
`varlatch run --strict`: validate the Delivered Configuration against the active Contract Revision of one strict retrieval before starting the command, and refuse to start it on any violation (exit 78). Contract defaults fill only items with no stored value, never withheld ones, and inherited values are used only for names allowed with `--allow-inherited`. A default run never blocks on the Contract. With `--agent-safe`, the operator's preflight validates Secrets without returning them (it needs `secret.reveal`), and the Broker's Capability is issued against the state the preflight saw; the Agent still receives only Placeholders.

**Output Redaction**:
`varlatch run --redact`: the command's stdout and stderr become pipes, and each complete occurrence of a Secret delivered to the command in this run (as written, or in a stated encoding) is replaced with `[REDACTED:<name>]` before the output is written on. Nothing is fetched to build the filter. Non-terminal output only, and refused with `--agent-safe`, whose Agent receives Placeholders. It protects where output is written (logs, files), not the command's own view, and guards against accidents, not deliberate leaks.
_Avoid_: masking (suggests the value is hidden from the command too)

**Run Context**:
The one reserved variable, `VARLATCH_RUN_CONTEXT`, that a strict run gives the command: JSON naming the Contract Revision, content hash, semantics version, and Environment, and recording for each Contract item the server's status (`delivered`, `withheld`, `notStored`) and how it was delivered (`varlatch`, `inherited`, `default`, `absent`). Names and identifiers only. Every run removes an inherited one.

**Retrieval Snapshot**:
The one read-only database snapshot a retrieval (Effective Configuration, disclosure, validation, Capability exercise) reads everything from: scope rows, authorization inputs, the Contract Revision, values, and the ciphertext it may decrypt. Each decryption then follows an audit commit naming its version. Authorization is effective at the snapshot boundary: a revocation that commits after a request's snapshot began does not affect that request.

**State Manifest**:
The caller-independent record of what a Retrieval Snapshot captured: the Environment (with its root, parent, Tier, and expiry), the active Contract Revision and its semantics version, and every resolved item's source and version IDs. Identifiers only, never values. Its SHA-256 digest (`stateDigest`) is equal for any two retrievals of the same state, whoever makes them.

**Configuration Contract**:
Varlatch's internal model of what an application's configuration must look like: which Config Items exist, which are required (possibly per Environment Selector), which are sensitive, their types, defaults, and validation rules. Authoritative in the Secret Plane, and populated either from a schema file or through the dashboard and API. Each Project declares exactly one authority mode: `git`, where the repository's `.env.schema` file is the human-authored source and the dashboard is read-only, or `managed`, where the dashboard and API are the authoring surface. There is never a sync or merge between the two.
_Avoid_: schema (overloaded with schema files and database schemas)

**Contract Revision**:
An immutable, content-hashed, normalized snapshot of a Contract with provenance metadata. A Project points at one active revision; activation is an audited security-relevant operation.

**Contract Semantics**:
How a Contract applies to a Value: whether an item is required in an Environment, when an absent item counts as missing, and whether a Value is valid for the item's type. Defined once in the shared contract package so the server and clients apply the same rules. The rules are versioned, and a released version never changes. Every Contract Revision currently uses version 1, which validates Values but does not convert them to typed values.

**Contract Drift**:
The state where a repository's local `.env.schema` no longer matches the active Contract Revision. Warns by default; strictness is opt-in. The server's active revision remains authoritative until another revision is explicitly accepted.

**Environment Selector**:
The small internal construct a Contract condition resolves against: specific root Environment identities or a Tier. Deliberately not an expression language. In a schema file, `env(...)` names root Environments, which are resolved to their identities when the Contract is pushed (an unknown name fails loudly), and `tier(...)` names a Tier.

**Secret Metadata**:
Everything about a secret except its material: name, contract linkage, sensitivity, version history, policy references. Any metadata field whose modification could change who may access, reveal, use, decrypt, enroll for, or administer a secret is authoritative in the Secret Plane; purely descriptive fields are non-authoritative, yet user-authored ones must still survive restore.

**Secret Material**:
The value of a secret (plaintext or ciphertext) and the key material protecting it. Lives only in the Secret Plane.
_Avoid_: secret value (ambiguous about whether keys are included)

**Dual-phase Rotation**:
A bounded overlap where a Value's previous version stays retrievable (the _retiring_ value) alongside the new _primary_ for a grace window, so running consumers migrate without an outage before the old upstream credential is revoked. Reads resolve the primary; the retiring value is exposed only through explicit disclosure and capability exercise. Ends on explicit completion, deadline expiry, or any plain write.
_Avoid_: versioning (every write is already versioned; rotation is the deliberate two-live-versions overlap)

### Authorization

**Grant**:
The fundamental permission object: binds one subject (an Identity or a Group) to a resource scope (Organization, Project, Project + Environment Selector, or a Team's projects) and either a fixed set of actions or a Custom Role. Authorization is default-deny; applicable Grants combine by union with no precedence. Grants permit; they never restrict. A Grant's declaration is immutable: "editing" one is an atomic replacement by a successor Grant, so a Grant identifier always denotes exactly one declaration.
_Avoid_: permission, ACL entry, policy (too vague), deny rule (unsupported)

**Requirement**:
A restrictive object (e.g., a Tailnet Constraint; future dual-control) evaluated after Grants. A Requirement may only reduce the set of successful operations; it can never create permission.
_Avoid_: condition, constraint policy

**Organization Role**:
A built-in Grant bundle for humans. There are exactly two: Organization Admin and Organization Member. Evaluated directly from org membership, never through Grants; distinct from a Custom Role. Machine identities have no Organization Role and start with zero Grants.
_Avoid_: role (ambiguous with Custom Role)

**Custom Role**:
A named, reusable bundle of actions an org defines; a Grant may cite a Role instead of listing actions, and editing the Role re-points every Grant that uses it. Org-scoped, expanded to actions at evaluation (a revoked or missing Role contributes nothing). Never carries Organization-Role semantics.
_Avoid_: permission set, policy

**Group**:
A named set of Identities usable as a Grant's subject; every member inherits the Group's Grants (additive fan-out: a Group only ever grants). Managing membership changes access without editing Grants.
_Avoid_: team (a Team is the project-owning specialization), cohort

**Team**:
A Group that also owns Projects. Beyond acting as a subject like any Group, a Team is a Grant scope target: a `team` scope resolves to every Project the Team owns, so one Grant expresses "this Group may do this Role across this Team's Projects."
_Avoid_: project group, squad

### Actions on secrets

**Reveal**:
Return plaintext secret material to the caller. `secret.reveal` is its own authorizable action.
_Avoid_: read, get, fetch (ambiguous between metadata and material)

**Use**:
Exercise a credential on the caller's behalf without disclosing the plaintext to the caller. `secret.use` is a distinct authorizable action from `secret.reveal`, and being allowed one never implies the other.
_Avoid_: access (ambiguous between use and reveal)

### Cryptography

**Root KEK**:
The installation-level key that wraps Organization KEKs. Supplied by the Infrastructure Operator (canonically a mounted file), never stored in any database. Its loss makes all encrypted secret material permanently unrecoverable.

**Organization KEK**:
A per-Organization wrapping key, stored only in wrapped form, that wraps the organization's DEKs. Gives the tenant boundary a cryptographic edge: per-org rotation and crypto-shredding.

**DEK**:
A fresh random key encrypting exactly one secret version's payload, stored only wrapped by the Organization KEK. Never reused across versions.
_Avoid_: data key (ambiguous about granularity)

**Crypto-Shredding**:
Destroying all recoverable copies of a wrapping key so the remaining ciphertext cannot be decrypted through the normal key hierarchy. Not deletion from historical backups, snapshots, or exports. Never claim otherwise.
_Avoid_: cryptographic deletion, guaranteed erasure

### Installation operations

**Installation Configuration**:
The small set of operator-chosen inputs an Installation is built from: its public URL, ingress mode, and optional integrations. Every other setting is generated or derived from it, never set independently.
_Avoid_: env, settings (ambiguous with Installation settings in the dashboard)

**Installation Health**:
Whether the whole Installation is operating as intended: release and Application Plane consistency, Mirror lag, realtime reachability, configuration consistency, backups, and custody. Distinct from Secret Plane readiness; degraded Installation Health never withholds secret retrieval.
_Avoid_: readiness (reserved for Secret Plane serviceability)

**Installation Archive**:
A sealed, point-in-time copy of every durable source users expect to recover (today, the Secret Plane); everything else is rebuilt on restore. Recovery also takes its separately held encryption key and Root KEK, the release artifacts, and the Installation Configuration: an archive never contains the Root KEK and never suffices alone.
_Avoid_: backup (the activity, not the artifact), snapshot, dump

**Custody Attestation**:
An Infrastructure Operator's dated statement that a separately held recovery copy of a key exists. Varlatch can verify that key material works, never that a copy exists elsewhere, so an attestation is always presented as a claim, not a check.
_Avoid_: backup verified, escrow confirmed

### Audit

**Security Audit Event**:
The authoritative Secret Plane record of the exercise, attempted exercise, or change of security authority. Committed transactionally with the operation it records; append-only under normal runtime authority (not operator-proof); never contains plaintext Values, key/credential/recovery material, or value-derived hashes.
_Avoid_: log line, activity, event log (ambiguous with Product Activity)

**Product Activity**:
Non-authoritative history for UX (renames, description edits) that carries no security claims. Not rebuildable from the Secret Plane, so it needs an explicit retention and recovery policy before it exists.
_Avoid_: audit (reserved for Security Audit Events)

### Outbound sync

**Sync Target**:
A configured, standing disclosure of one Environment's mapped Values to one external platform destination (a repository's CI secrets, a Coolify application, a hosting project), pushed by varlatchd itself. Its *disclosure set*, the items it may ever push including future items for a wildcard mapping, is fixed by an audited write-time gate; pushes converge the destination to the current Effective Configuration, best-effort and audited before material leaves. Surfaced in the UI as an *integration*, always opt-in: no Sync Target exists until an authorized user creates one. Explicitly not a Mirror: a Mirror projects state into Varlatch's own Application Plane and never carries Secret Material; a Sync Target deliberately sends Secret Material outside Varlatch's authority.
_Avoid_: mirror, export, plugin (implies installable third-party code); "integration" is the UI label, not the model term

**Platform Adapter**:
The code module that knows how to push Values to one platform type: its API, authentication, and encoding. Adapters form a closed allowlist; there is no generic push-to-URL adapter.
_Avoid_: connector (ambiguous with future inbound integrations), plugin

**Platform Connection**:
The org-level object authenticating one external platform account or instance, entered once: platform type, base identity (instance URL, account owner), and the Platform Credential. Many Sync Targets reference one Connection, and reuse is organization-wide by design; a Connection alone discloses nothing; disclosure authority lives on the Targets that use it. Its base identity is immutable: a different instance or account is a new Connection. Replacing its credential re-authorizes every referencing Target atomically; revoking it disables them all.
_Avoid_: integration account, workspace link

**Platform Credential**:
A third-party token a Platform Connection holds so Sync Targets can write to their destination platform, scoped as narrowly as the platform honestly allows. Supplied by the user, stored only encrypted under the Organization KEK, never redisplayed. It is the platform's credential, not a Varlatch credential, and it confers nothing inside Varlatch.
_Avoid_: API key (ambiguous with Varlatch credentials)

### Network and agent concepts

**Tailnet Context**:
Trusted request-scoped information (node, tags, user, pinned tailnet) derived only from a connection through Varlatch's dedicated Tailscale ingress and verified via the supported Tailscale identity mechanism. Never constructed from headers, forwarded IPs, or CGNAT-range source addresses on the ordinary listener.
_Avoid_: tailscale headers, source-IP identity

**Tailnet Selector**:
A Varlatch-owned predicate identifying acceptable Tailscale node/user/tag identities within the pinned expected tailnet. Explicit and boring; not a Tailscale-policy expression language.

**Tailnet Constraint**:
An authorization requirement that an action may proceed only if trusted Tailnet Context satisfies a Tailnet Selector, always *in addition to* ordinary Varlatch authorization, never instead of it. Fails closed when Tailnet Context cannot be verified.
_Avoid_: IP allowlisting, VPN-gating, tailnet-bound retrieval (the flagship *use* of a constraint, not a separate mechanism)

**Tailnet Authentication Method**:
An explicitly enrolled mapping from a Tailscale node or tag to a Varlatch Identity, establishing the principal before ordinary authorization. Tag enrollment is a documented, audited delegation to whoever can assign that tag in the tailnet.

**Capability**:
A short-lived, constrained authorization artifact issued *and verified* by the Secret Plane, binding one Broker, one Agent, one Environment, explicit Config Items, canonical Destination Selectors, and an expiry. Represented as a server-side record redeemed with a high-entropy capability secret (hash-at-rest); it *narrows* potential future use and never expands the Agent's Grants: every exercise re-evaluates the Agent's `secret.use` against current state.
_Avoid_: scoped token, macaroon, biscuit (all presume a self-certifying representation this is not)

**Broker**:
A trusted local process that exercises credentials on behalf of a less-trusted process (typically an AI agent), substituting real secret material only at the TLS-verified network boundary so the agent handles Placeholders. The Broker authenticates *mediation*; `secret.use` authority always belongs to the Agent Identity.
_Avoid_: proxy (describes its mechanism, not its role), agent (the Broker is trusted; the Agent is not)

**Agent**:
An AI coding agent acting as a distinct, less-trusted Identity, never as the human it works for. A persistent logical principal that owns Grants; individual executions are Agent Runs.

**Agent Run**:
One ephemeral execution of an Agent: a spawned child process correlated by a run identifier, holding Placeholders, proxy configuration, and a per-run proxy token, but no reusable Varlatch credential (unless the explicit metadata-credential mode adds an Agent Metadata Credential). Capabilities are scoped to a run and die with it (revoke-on-exit best-effort, TTL as fail-safe).
_Avoid_: session (overloaded with Better Auth sessions)

**Agent Metadata Credential**:
A short-lived (≤1h), read-only bearer a Broker mints for an Agent Identity so one Agent Run can read configuration metadata directly. Explicit opt-in, never the default; identity only (authority stays with the Agent's Grants), and refused for every non-read operation regardless of Grants.
_Avoid_: agent token (ambiguous with the per-run proxy token)

**Placeholder**:
A per-run, cryptographically random opaque token (`vlch_ph_v1_<random>`) injected into an Agent Run's environment in place of a Secret's plaintext. Carries no Config Item name or other metadata; the Broker alone maps Placeholders to Config Items and substitutes by exact-token match only, and only at the Secret's Substitution Targets.

**Substitution Target**:
A declared location in an outbound request where the Broker may substitute a given Secret's Placeholder: a named header, query parameter, JSON pointer, or form field, never a transport-owned header. At most once per target per request. Every Secret an agent-safe run carries has at least one, with no default; the operator gives them on the command line (`--target`), varlatchd records them on the Capability, and the Broker enforces the recorded ones. A Placeholder is never substituted outside its targets.
_Avoid_: injection point, slot

**Destination Selector**:
A Capability's constraint on where secret-bearing traffic may go: canonical lowercase host (exact, or `*.suffix` wildcard matching subdomains but never the apex) plus port. Every outbound hop, including each redirect, is independently checked against it.
