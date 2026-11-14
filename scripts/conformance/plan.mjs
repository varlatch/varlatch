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
 */
export const PLAN = [
  { suite: "reconcile", args: () => [] },
  { setup: "bootstrap" },
  { suite: "passkey", args: (ctx) => [ctx.bootstrapUrl] },
  { setup: "seed" },
  { suite: "dashboard", args: async (ctx) => [await ctx.grant()] },
  // The enroll page's next steps against a stub server (ADR-0058 Decision 4).
  { suite: "enroll-steps", args: () => [] },
  { suite: "values", args: async (ctx) => [await ctx.grant(), ctx.token] },
  { suite: "access", args: async (ctx) => [await ctx.grant()] },
  // A disposable same-identity credential the suite revokes live, to assert
  // the identity signal refreshes /credentials without a reload.
  { suite: "p4", args: async (ctx) => [await ctx.grant(), ctx.token, await ctx.cliCredential()] },
  { suite: "onboarding", args: async (ctx) => [await ctx.grant(), ctx.token] },
  { suite: "realtime", args: async (ctx) => [await ctx.grant(), ctx.token] },
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
  { suite: "doctor", args: () => [] },
  { suite: "convex-down", args: (ctx) => [ctx.origin, ctx.token] },
  { suite: "cli-download-off", args: (ctx) => [ctx.origin] },
  { suite: "cli-download-on", args: (ctx) => [ctx.origin] },
  // The runner's own check on the target's request log, after every suite.
  { suite: "request-budget", runner: true },
];
