// SPDX-License-Identifier: Apache-2.0
/**
 * The suites of a run, in order. Each entry names a suite in
 * inventory.json (which holds its script and the capabilities it needs) and
 * builds the suite's arguments from the run's context:
 *
 *   ctx.origin           the dashboard origin the suites use
 *   ctx.token            the admin identity's CLI credential
 *   ctx.grant()          a fresh recovery enrollment URL for the admin identity
 *   ctx.cliCredential()  a fresh CLI credential for the admin identity
 *   ctx.seededSecret     the Secret value the runner seeded
 *
 * `setup` entries are the runner's own steps (run.mjs): the first
 * enrollment, and the seed data every later suite uses. `around` names a
 * condition the runner holds while the suite runs, on targets that can.
 * `always` marks a suite whose work later steps need, so a run limited with
 * --suite still runs it (its checks are judged only when it is chosen): the
 * reconcile suite deploys the Convex functions the seed step's mirror sync
 * calls, and the passkey suite enrolls the identity everything after it uses.
 */

/**
 * The suites that write audit events in bulk: realtime-events floods
 * Organization changes (tens of thousands of audit events) until its slow
 * client is cut off. The converge engine's trigger scan reads 500 audit
 * events a pass on the TypeScript targets (TypeScript defect 10;
 * feature-parity.md, go/server/syncs/CONVERGE.md), so after them a value
 * change would reach the engine only after one 30-second pass per 500
 * events. The sync suite runs before every one of them (test/plan.test.mjs
 * fails otherwise); the Go server drains the scan each pass.
 */
export const BULK_AUDIT_SUITES = ["realtime-events"];

export const PLAN = [
  { suite: "reconcile", args: () => [], always: true },
  { setup: "bootstrap" },
  { suite: "passkey", args: (ctx) => [ctx.bootstrapUrl], always: true },
  { setup: "seed" },
  // The CLI's compatibility core that no other suite reports on its own:
  // token sign-in, whoami and env list, before anything changes the seed.
  { suite: "cli-core", args: (ctx) => [ctx.origin, ctx.token, ctx.seededSecret] },
  // The hand-over between the Go CLI and the TypeScript CLI (go-client
  // checks): each signs in with a credential of its own, issued for it, so
  // its logout never touches the token later suites use.
  { suite: "cli-handover", args: async (ctx) => [ctx.origin, await ctx.cliCredential(), await ctx.cliCredential(), await ctx.grant()] },
  { suite: "dashboard", args: async (ctx) => [await ctx.grant()] },
  // The enroll page's next steps against a stub server (ADR-0058 Decision 4).
  { suite: "enroll-steps", args: () => [] },
  { suite: "values", args: async (ctx) => [await ctx.grant(), ctx.token] },
  { suite: "access", args: async (ctx) => [await ctx.grant()] },
  // A disposable same-identity credential the suite revokes live, to assert
  // the identity signal refreshes /credentials without a reload. Its audit
  // timeline checks filter for the identity.created events the access suite
  // just wrote, so a sharded run keeps it in access's shard (shardWith,
  // shard.mjs).
  { suite: "p4", args: async (ctx) => [await ctx.grant(), ctx.token, await ctx.cliCredential()], shardWith: "access" },
  { suite: "onboarding", args: async (ctx) => [await ctx.grant(), ctx.token] },
  { suite: "realtime", args: async (ctx) => [await ctx.grant(), ctx.token] },
  // Degraded live updates on any server: the connection cut in the page;
  // three disposable credentials of the same identity to revoke from
  // outside it (while live, while down, and in a short drop).
  {
    suite: "realtime-degraded",
    args: async (ctx) => [await ctx.grant(), await ctx.cliCredential(), await ctx.cliCredential(), await ctx.cliCredential()],
  },
  // Sync Targets against fake platforms, before the suites that write audit
  // events in bulk (BULK_AUDIT_SUITES: TypeScript defect 10).
  { suite: "sync", args: (ctx) => [ctx.origin, ctx.token] },
  // G11 on the Go server's server-sent events (go-server checks). It writes
  // audit events in bulk (BULK_AUDIT_SUITES).
  { suite: "realtime-events", args: (ctx) => [ctx.origin] },
  // The credential broker (ADR-0022). It ran inside the realtime suite, with
  // Convex down; on the TypeScript stack the runner still stops Convex
  // around it (broker.convex-down-throughout).
  { suite: "broker", args: (ctx) => [ctx.origin, ctx.token], around: "convex-down" },
  { suite: "maintenance", args: async (ctx) => [await ctx.grant(), ctx.token] },
  { suite: "server-logs", args: (ctx) => [ctx.seededSecret] },
  { suite: "cli-login", args: async (ctx) => [await ctx.grant()] },
  { suite: "device", args: async (ctx) => [await ctx.grant()] },
  { suite: "proxy-probe", args: (ctx) => [ctx.origin] },
  { suite: "client-runtime", args: (ctx) => [ctx.origin, ctx.token] },
  { suite: "strict-run", args: (ctx) => [ctx.origin, ctx.token] },
  // `varlatch mcp` over stdio, and packages/sdk from the same source as the
  // CLI under test (this checkout, or the pinned release's commit).
  { suite: "mcp", args: (ctx) => [ctx.origin, ctx.token, ctx.seededSecret] },
  { suite: "sdk", args: (ctx) => [ctx.origin, ctx.token, ctx.seededSecret] },
  // Security Controls over the API, in an Organization of its own.
  { suite: "security", args: (ctx) => [ctx.origin, ctx.token] },
  // Organization administration with the CLI under test, one smoke check
  // per command, in an Organization of its own (internal
  // docs/design/go-cli.md, slice 5.7a).
  { suite: "admin-cli", args: (ctx) => [ctx.origin, ctx.token] },
  { suite: "security-cli", args: (ctx) => [ctx.origin, ctx.token] },
  // Deletion over the API: a Project's deletion, its approval at enforce.
  { suite: "deletion", args: (ctx) => [ctx.origin, ctx.token] },
  // Audit webhook delivery against the target's local receiver.
  { suite: "webhooks", args: (ctx) => [ctx.origin, ctx.token] },
  // The audit export to object storage, against the target's local S3 server.
  { suite: "audit-export", args: (ctx) => [ctx.origin, ctx.token] },
  // OIDC workload identity, against the target's local issuer.
  { suite: "oidc", args: (ctx) => [ctx.origin, ctx.token] },
  { suite: "doctor", args: () => [] },
  // The Go installation's doctor (go-server checks), on its own host.
  { suite: "go-doctor", args: () => [] },
  { suite: "convex-down", args: (ctx) => [ctx.origin, ctx.token] },
  { suite: "cli-download-off", args: (ctx) => [ctx.origin] },
  { suite: "cli-download-on", args: (ctx) => [ctx.origin] },
  // The runner's own check on the target's request log, after every suite.
  { suite: "request-budget", runner: true },
];
