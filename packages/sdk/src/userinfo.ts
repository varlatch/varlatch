// SPDX-License-Identifier: Apache-2.0

/**
 * Diagnostics never print credential values: a URL's user name and password
 * are shown as [redacted], in human output, --json documents and messages
 * alike. A URL without them is shown exactly as it is.
 */

const SPECIAL_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp", "file"]);

const isAlpha = (c: string): boolean => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");

/** Where maskUserinfo looks for a user name and password. */
function authorityStart(text: string): number {
  let i = 0;
  // WHATWG URL parsing trims leading C0 controls and spaces.
  while (i < text.length && text.charCodeAt(i) <= 0x20) i++;
  let j = i;
  if (j < text.length && isAlpha(text[j] as string)) {
    for (j++; j < text.length; j++) {
      const c = text[j] as string;
      if (!(isAlpha(c) || (c >= "0" && c <= "9") || "+.-\t\n\r".includes(c))) break;
    }
    if (text[j] === ":") {
      const scheme = text.slice(i, j).replace(/[\t\n\r]/g, "").toLowerCase();
      if (SPECIAL_SCHEMES.has(scheme)) {
        let k = j + 1;
        while (k < text.length && "/\\\t\n\r".includes(text[k] as string)) k++;
        return k;
      }
    }
  }
  // The first "//", tabs and newlines between the two slashes included.
  for (let k = 0; k < text.length; k++) {
    if (text[k] !== "/") continue;
    let m = k + 1;
    while (m < text.length && "\t\n\r".includes(text[m] as string)) m++;
    if (text[m] === "/") return m + 1;
  }
  return 0;
}

/**
 * Text that may be a URL, with what could be its user name and password
 * replaced by [redacted]. The text may not parse, so this errs towards
 * masking more, following WHATWG URL parsing:
 *
 * - for a special scheme (http, https, ws, wss, ftp, file, in any case),
 *   the authority starts after any run of "/" and "\" (and the tabs and
 *   newlines WHATWG parsing drops) that follows the scheme, none included:
 *   "http:/u:p@h", "http:\\u:p@h", "http:u:p@h" and "http:///u:p@h" all
 *   have u:p as user name and password;
 * - otherwise it starts after the first "//" (tabs and newlines between its
 *   slashes allowed), or at the start of the text.
 *
 * Everything from there to the last "@" before the first "/", "?" or "#" is
 * masked; a backslash does not end it, so a URL that does not parse is
 * masked through it rather than shown.
 */
export function maskUserinfo(text: string): string {
  const start = authorityStart(text);
  const rest = text.slice(start);
  const stop = rest.search(/[/?#]/);
  const authority = stop < 0 ? rest : rest.slice(0, stop);
  const at = authority.lastIndexOf("@");
  if (at <= 0) return text;
  return `${text.slice(0, start)}[redacted]${text.slice(start + at)}`;
}

/** A server value as the CLI shows it: a string through maskUserinfo, and any other JSON value with every string in it masked the same way. */
export function maskServer<T>(value: T): T {
  if (typeof value === "string") return maskUserinfo(value) as T;
  if (Array.isArray(value)) return value.map((v) => maskServer(v)) as T;
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, maskServer(v)])) as T;
  }
  return value;
}

/** A URL's scheme and authority up to its last "@", inside longer text: a special scheme followed by any run of "/" and "\", or any scheme followed by "//". */
const URL_IN_TEXT = /(\b(?:https?|wss?|ftp|file):[/\\\t]*|[A-Za-z][A-Za-z0-9+.-]*:\/\t*\/)[^/?#\s"']*@/gi;

/** Every URL's user name and password masked, in text that holds URLs among other words (a quoted line of varlatch.toml). */
export function maskUserinfoInText(text: string): string {
  return text.replace(URL_IN_TEXT, "$1[redacted]@");
}

/**
 * The refusal of a header value fetch would refuse (it must be a ByteString
 * with no NUL, CR or LF once its leading and trailing HTTP whitespace is
 * removed), naming the header but never showing its value; null when fetch
 * takes it.
 */
export function refusedHeader(name: string, value: string): TypeError | null {
  let ok = true;
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0xff) {
      ok = false;
      break;
    }
  }
  if (ok && /[\0\r\n]/.test(value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, ""))) ok = false;
  if (ok) return null;
  return new TypeError(
    name.toLowerCase() === "authorization"
      ? "the credential contains a character that is not allowed in an HTTP header"
      : `the ${name} header contains a character that is not allowed in an HTTP header`,
  );
}

/**
 * fetch's own refusals of a URL, before it connects, with the URL shown
 * without its user name and password; null when fetch takes it.
 */
export function refusedUrl(url: string): TypeError | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return new TypeError(`Failed to parse URL from ${maskUserinfo(url)}`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    parsed.username = "";
    parsed.password = "";
    const shown = parsed.href.replace(/^([^:]+:\/\/)/, "$1[redacted]@");
    return new TypeError(`Request cannot be constructed from a URL that includes credentials: ${shown}`);
  }
  return null;
}
