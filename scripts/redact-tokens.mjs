// SPDX-License-Identifier: Apache-2.0
/**
 * CI logs are public. End-to-end scripts print page status lines and
 * command output that can carry the disposable stack's credentials: a
 * browser bearer after a passkey ceremony, the token in a setup link.
 * Importing this module masks every Varlatch token shape in console
 * output. The stack is thrown away after the run, but its logs are not.
 * Values a script reads from the page or a command are unaffected.
 */
const TOKEN = /\bvlt_([a-z]+)_[A-Za-z0-9_-]{8,}/g;

export const redactTokens = (text) => String(text).replace(TOKEN, (_match, kind) => `vlt_${kind}_…`);

for (const name of ["log", "error", "warn", "info"]) {
  const write = console[name].bind(console);
  console[name] = (...args) => write(...args.map((arg) => (typeof arg === "string" ? redactTokens(arg) : arg)));
}
