// SPDX-License-Identifier: Apache-2.0
/**
 * CI logs are public. End-to-end scripts print page status lines and
 * command output that can carry the disposable stack's credentials: a
 * browser bearer after a passkey ceremony, the token in a setup link.
 *
 * Importing this module masks every Varlatch token shape in what this
 * process writes to stdout and stderr: console output of every kind
 * (strings, objects, errors) and direct stream writes. It does not reach
 * child processes that inherit the terminal, and a token split across two
 * writes stays as it is; in CI, scripts/ci-shell.sh therefore also passes
 * each suite's whole output through redact-output.mjs. Values a script
 * reads from a page or a command are unaffected.
 */
const TOKEN = /\bvlt_([a-z]+)_[A-Za-z0-9_-]{8,}/g;
const MARK = Buffer.from("vlt_");

export const redactTokens = (text) => String(text).replace(TOKEN, (_match, kind) => `vlt_${kind}_…`);

for (const stream of [process.stdout, process.stderr]) {
  const write = stream.write.bind(stream);
  stream.write = (chunk, ...rest) => {
    if (typeof chunk === "string") return write(redactTokens(chunk), ...rest);
    if (chunk instanceof Uint8Array) {
      const bytes = Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
      // Only text that may hold a token is decoded, so other bytes pass unchanged.
      if (bytes.includes(MARK)) return write(Buffer.from(redactTokens(bytes.toString("utf8"))), ...rest);
    }
    return write(chunk, ...rest);
  };
}
