// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { VarlatchClient, maskServer, maskUserinfo, maskUserinfoInText } from "../src/index.js";

/**
 * Diagnostics never print credential values: a header value fetch refuses
 * (the credential) is never quoted, and a URL's user name and password are
 * shown as [redacted].
 */

describe("maskUserinfo", () => {
  it("masks what could be a user name and password, and leaves every other text as it is", () => {
    const cases: Record<string, string> = {
      "not a url": "not a url",
      "https://a.example/team": "https://a.example/team",
      "http://127.0.0.1:3000": "http://127.0.0.1:3000",
      "http://u:p@h:1/x@y": "http://[redacted]@h:1/x@y",
      "u:p@h": "[redacted]@h",
      "http://a@b@c?d@e": "http://[redacted]@c?d@e",
      "http://h/path@x": "http://h/path@x",
      "@h": "@h",
      "https://:secret@[::1/v1/me": "https://[redacted]@[::1/v1/me",
      "http:/user:hunter2pass@[::1": "http:/[redacted]@[::1",
      "http:\\\\user:hunter2pass@h/x": "http:\\\\[redacted]@h/x",
      "https:\\user:hunter2pass@h": "https:\\[redacted]@h",
      "http:user:hunter2pass@h": "http:[redacted]@h",
      "http:///user:hunter2pass@h/p@q": "http:///[redacted]@h/p@q",
      "https:/\\/user:hunter2pass@h?x@y": "https:/\\/[redacted]@h?x@y",
      "HTTPS:user:hunter2pass@h": "HTTPS:[redacted]@h",
      "ws:/user:hunter2pass@h": "ws:/[redacted]@h",
      "file:user:hunter2pass@h": "file:[redacted]@h",
      "ht\ttp:/user:hunter2pass@h": "ht\ttp:/[redacted]@h",
      "http:/\n/user:hunter2pass@h": "http:/\n/[redacted]@h",
      "  http:user:hunter2pass@h": "  http:[redacted]@h",
      "http://h\\user:hunter2pass@x/y": "http://[redacted]@x/y",
      "mailto:user:hunter2pass@h": "[redacted]@h",
      "foo:/\n/user:hunter2pass@h": "foo:/\n/[redacted]@h",
      "https://h.example/a@b": "https://h.example/a@b",
    };
    for (const [input, want] of Object.entries(cases)) expect(maskUserinfo(input), JSON.stringify(input)).toBe(want);
  });

  it("leaves no user name or password wherever WHATWG URL parsing finds one", () => {
    const schemes = ["http", "HTTPS", "ws", "wss", "ftp", "file", "foo", " http", "h\ttp"];
    const separators = ["", "/", "//", "///", "\\", "\\\\", "/\\", "\\/", "/\n/", "\t//"];
    const authorities = ["usr:pw9secret@h", "usr:pw9secret@h:8080", ":pw9secret@[::1]", "usr9secret@h", "a@b:pw9secret@h", "usr:pw9secret@[::1"];
    const tails = ["", "/x", "/x@y", "?q@r", "#f@g", "\\p"];
    let checked = 0;
    for (const s of schemes) {
      for (const sep of separators) {
        for (const a of authorities) {
          for (const tail of tails) {
            const text = `${s}:${sep}${a}${tail}`;
            let u: URL;
            try {
              u = new URL(text);
            } catch {
              continue;
            }
            if (u.username === "" && u.password === "") continue;
            checked++;
            const masked = maskUserinfo(text);
            for (const part of [decodeURIComponent(u.username), decodeURIComponent(u.password)]) {
              if (part !== "") expect(masked, JSON.stringify(text)).not.toContain(part);
            }
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(100);
  });

  it("maskUserinfoInText masks every URL in longer text, and nothing else", () => {
    const input = '3:  server = "https://u:p@a@h.example/x@y" # and http://k@h2 or http:/u:p@h3, http:\\\\u:p@h4, HTTP:u:p@h5\n';
    const want = '3:  server = "https://[redacted]@h.example/x@y" # and http://[redacted]@h2 or http:/[redacted]@h3, http:\\\\[redacted]@h4, HTTP:[redacted]@h5\n';
    expect(maskUserinfoInText(input)).toBe(want);
    const plain = 'server = "https://h.example" # mail@example.com';
    expect(maskUserinfoInText(plain)).toBe(plain);
  });

  it("maskServer masks every string in a JSON value", () => {
    expect(maskServer({ a: ["http://u:p@h", 1, null], b: "https://h" })).toEqual({ a: ["http://[redacted]@h", 1, null], b: "https://h" });
  });
});

describe("refused requests never show the credential", () => {
  const secret = "vlt_cli_abcdefghijklmnop";

  async function refusal(client: VarlatchClient): Promise<TypeError> {
    try {
      await client.meta();
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      return err as TypeError;
    }
    throw new Error("the request was not refused");
  }

  it("a token with a line break or a NUL inside, or a character above U+00FF, is refused without quoting it", async () => {
    for (const token of [`${secret}\r\nmore`, `${secret}\nmore`, `${secret}\0more`, `${secret}Ā`]) {
      const err = await refusal(new VarlatchClient({ server: "http://127.0.0.1:9", token }));
      expect(err.message).toBe("the credential contains a character that is not allowed in an HTTP header");
      expect(`${err.message}\n${err.stack ?? ""}`).not.toContain(secret);
    }
  });

  it("another header names itself, without its value", async () => {
    const err = await refusal(new VarlatchClient({ server: "http://127.0.0.1:9", userAgent: `agent\n${secret}` }));
    expect(err.message).toBe("the User-Agent header contains a character that is not allowed in an HTTP header");
  });

  it("a server URL with a user name and password is refused with them masked", async () => {
    const err = await refusal(new VarlatchClient({ server: `http://user:${secret}@127.0.0.1:9`, token: "vlt_cli_x" }));
    expect(err.message).toBe("Request cannot be constructed from a URL that includes credentials: http://[redacted]@127.0.0.1:9/v1/meta");
    expect(`${err.message}\n${err.stack ?? ""}`).not.toContain(secret);
  });

  it("a server URL that does not parse is quoted with its user name and password masked", async () => {
    const err = await refusal(new VarlatchClient({ server: `http://user:${secret}@[::1`, token: "vlt_cli_x" }));
    expect(err.message).toBe("Failed to parse URL from http://[redacted]@[::1/v1/meta");
    expect(`${err.message}\n${err.stack ?? ""}`).not.toContain(secret);
  });

  it("a token with leading or trailing whitespace is still sent, trimmed by fetch as before", async () => {
    let sent: Record<string, string> | undefined;
    const client = new VarlatchClient({
      server: "https://v.example",
      token: " vlt_cli_x \n",
      fetch: async (_input, init) => {
        sent = init?.headers as Record<string, string>;
        return new Response(JSON.stringify({ serverVersion: "1" }));
      },
    });
    await client.meta();
    expect(sent?.Authorization).toBe("Bearer  vlt_cli_x \n");
  });
});
