// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * The dashboard runs under a strict Content-Security-Policy (ADR-0046,
 * rollout step 4). Every browser suite collects what Chromium reports as a
 * violation, in every page of its context, and fails on any: a policy that
 * blocks something the dashboard needs never passes quietly.
 */
export function watchCsp(context) {
  const violations = [];
  const watch = (page) =>
    page.on("console", (m) => {
      if (/Content Security Policy/i.test(m.text())) violations.push(m.text().slice(0, 240));
    });
  for (const page of context.pages()) watch(page);
  context.on("page", watch);
  return violations;
}
