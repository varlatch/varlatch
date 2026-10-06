// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from "node:child_process";
import { type Dirent, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, normalize, resolve, sep } from "node:path";
import { credentialsPath } from "@varlatch/context";

/**
 * `varlatch agents hook --format <agent>` (ADR-0043 Decision 8): the one
 * handler every guardrail hook calls. It reads a coding agent's pre-tool-use
 * event and denies three kinds of tool call:
 *
 * - reading a `.env*` file other than `.env.example` and `.env.schema`;
 * - reading the Varlatch credential store;
 * - dumping the environment of a `varlatch run`.
 *
 * This is accident prevention, never a boundary: it reads commands the way a
 * careful person would, not the way a shell runs them, so a determined agent
 * gets around it (a script file, an unusual reader, a pipe through xargs),
 * and the hook fails open when the CLI is missing or the event is not
 * understood. Every protection Varlatch claims is in the CLI and the server.
 */

export const HOOK_FORMATS = ["claude", "codex"] as const;
export type HookFormat = (typeof HOOK_FORMATS)[number];

export interface HookContext {
  /** The directory the tool call runs in. */
  cwd: string;
  env: NodeJS.ProcessEnv;
  home: string;
}

/** A denial: what was refused and what to do instead, for the coding agent. */
export type Denial = string;

const ENV_TEMPLATES = new Set([".env.example", ".env.schema"]);
/** Names a glob is tried against: a glob that can match one of them reads a .env file. */
const ENV_NAMES = [".env", ".envrc", ".env.local", ".env.production", ".env.development.local", ".env.bak"];

function nameOf(path: string): string {
  return path.replace(/[/\\]+$/, "").split(/[/\\]/).pop() ?? "";
}

function isGlob(name: string): boolean {
  return /[*?[]/.test(name);
}

/** A shell glob as a regular expression for one name. A leading dot is matched only by a dot, as the shell does. */
function globRegex(glob: string): RegExp | null {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") out += ".*";
    else if (c === "?") out += ".";
    else if (c === "[") {
      const close = glob.indexOf("]", i + 2);
      if (close < 0) return null;
      const body = glob.slice(i + 1, close);
      out += `[${body.startsWith("!") ? `^${body.slice(1)}` : body}]`;
      i = close;
    } else out += c.replace(/[\\^$.|+(){}]/g, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

function globMatches(glob: string, name: string): boolean {
  if (name.startsWith(".") && !glob.startsWith(".")) return false;
  return globRegex(glob)?.test(name) ?? false;
}

/**
 * Whether a name is a .env file by its name alone: `.env`, `.envrc`, or
 * `.env.<anything>`, other than the two templates; or a glob that matches
 * one (`.env*`, `.e*`, `.*`). Other names that start with `.env`
 * (`.env-old`, `.environment`) count only as existing files: see
 * isProtectedEnvPath.
 */
export function isProtectedEnvFile(path: string): boolean {
  const name = nameOf(path);
  if (ENV_TEMPLATES.has(name)) return false;
  if (isGlob(name)) return ENV_NAMES.some((n) => globMatches(name, n));
  return name === ".env" || name === ".envrc" || /^\.env\..+/.test(name);
}

function statOf(path: string) {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

/** An existing file other than a template whose name starts with `.env`. */
function isEnvLikeFile(path: string): boolean {
  const name = nameOf(path);
  return name.startsWith(".env") && !ENV_TEMPLATES.has(name) && statOf(path)?.isFile() === true;
}

/**
 * Whether a path the command reads is a .env file. A .env name is one
 * unless it is an existing directory (a Python virtualenv is often called
 * .env); a glob is one when it can match a .env name, or matches an
 * existing .env* file in its directory; another name starting with `.env`
 * is one only as an existing file, so a jq filter `.environment` or a
 * pattern `.env|app` is not.
 */
function isProtectedEnvPath(path: string, ctx: HookContext): boolean {
  const full = resolve(ctx.cwd, expandPath(path, ctx));
  const name = nameOf(path);
  if (ENV_TEMPLATES.has(name)) return false;
  if (isGlob(name)) {
    if (isProtectedEnvFile(name)) return true;
    return entriesOf(dirname(full)).some((entry) => globMatches(name, entry) && isEnvLikeFile(resolve(dirname(full), entry)));
  }
  if (isProtectedEnvFile(name)) return statOf(full)?.isDirectory() !== true;
  return isEnvLikeFile(full);
}

function entriesOf(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/** The credential-store directories: the one this environment uses, and the default one. */
function storeDirs(ctx: HookContext): string[] {
  const dirs = new Set<string>([
    dirname(credentialsPath(ctx.env)),
    dirname(credentialsPath({ ...ctx.env, VARLATCH_CONFIG_DIR: undefined })),
    resolve(ctx.home, ".config", "varlatch"),
  ]);
  return [...dirs].map((d) => normalize(d));
}

function expandPath(word: string, ctx: HookContext): string {
  const vars: Record<string, string | undefined> = {
    HOME: ctx.home,
    XDG_CONFIG_HOME: ctx.env.XDG_CONFIG_HOME,
    VARLATCH_CONFIG_DIR: ctx.env.VARLATCH_CONFIG_DIR,
  };
  let out = word.replace(/^~(?=$|[/\\])/, ctx.home);
  out = out.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, a: string | undefined, b: string | undefined) => vars[(a ?? b) as string] ?? m);
  return out;
}

/** Whether a path is in the credential store. */
export function isInStore(path: string, ctx: HookContext): boolean {
  if (/\/\.config\/varlatch(\/|$)/.test(path.replaceAll("\\", "/"))) return true;
  const expanded = expandPath(path, ctx);
  if (expanded.includes("$")) return false;
  const abs = normalize(isAbsolute(expanded) ? expanded : resolve(ctx.cwd, expanded));
  return storeDirs(ctx).some((dir) => abs === dir || abs.startsWith(dir.endsWith(sep) ? dir : dir + sep));
}

const DENY_ENV_FILE =
  "Varlatch guardrail: .env files are off limits to coding agents, because their values would enter your context. " +
  "To see the names a .env file sets, run `varlatch --assisted import --dry-run <file>`; to store its values, " +
  "`varlatch --assisted import <file>`. .env.example and .env.schema stay readable.";
const DENY_STORE =
  "Varlatch guardrail: the Varlatch credential store is off limits: it holds the human's credential. " +
  "Use `varlatch --assisted status --json` to see who is signed in.";
const DENY_ENV_DUMP =
  "Varlatch guardrail: printing the environment of a `varlatch run` would print Secrets. " +
  "Run the command you need instead, and list names with `varlatch --assisted values list --json`.";

// ---- A small shell reader ---------------------------------------------------

interface Segment {
  words: string[];
  /** Files read through `<`. */
  inputs: string[];
  /** Files written through `>` and `>>`. */
  outputs: string[];
}

interface Lexed {
  segments: Segment[];
  /** Commands inside $(...), backticks, and <(...), read on their own. */
  nested: string[];
}

/** From `open` (just after the opening parenthesis) to its closing one, skipping quoted text. */
function balanced(text: string, open: number): { inner: string; end: number } {
  let depth = 1;
  let i = open;
  while (i < text.length) {
    const c = text[i];
    if (c === "\\") i += 2;
    else if (c === "'") i = text.indexOf("'", i + 1) < 0 ? text.length : text.indexOf("'", i + 1) + 1;
    else if (c === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === "\\" ? 2 : 1;
      i++;
    } else {
      if (c === "(") depth++;
      if (c === ")" && --depth === 0) return { inner: text.slice(open, i), end: i + 1 };
      i++;
    }
  }
  return { inner: text.slice(open), end: text.length };
}

/**
 * Splits a command line into simple commands (at ; & && | || newlines and
 * parentheses), their words with quotes removed, their `<` inputs, and the
 * nested commands inside substitutions. Heredoc bodies are skipped, since
 * they are text, not commands.
 */
export function lexShell(text: string): Lexed {
  const segments: Segment[] = [];
  const nested: string[] = [];
  let seg: Segment = { words: [], inputs: [], outputs: [] };
  let word: string | null = null;
  let redirect: "in" | "out" | "herestring" | null = null;
  const heredocs: { delimiter: string; strip: boolean }[] = [];
  let pendingHeredoc: boolean | null = null;

  const endWord = () => {
    if (word === null) return;
    if (pendingHeredoc !== null) {
      heredocs.push({ delimiter: word, strip: pendingHeredoc });
      pendingHeredoc = null;
    } else if (redirect === "in") seg.inputs.push(word);
    else if (redirect === "out") seg.outputs.push(word);
    else if (redirect === null) seg.words.push(word);
    redirect = null;
    word = null;
  };
  const endSegment = () => {
    endWord();
    if (seg.words.length > 0 || seg.inputs.length > 0 || seg.outputs.length > 0) segments.push(seg);
    seg = { words: [], inputs: [], outputs: [] };
  };

  let i = 0;
  while (i < text.length) {
    const c = text[i] as string;
    const next = text[i + 1];
    if (c === "\\") {
      if (next === "\n") i += 2;
      else {
        word = (word ?? "") + (next ?? "");
        i += 2;
      }
      continue;
    }
    if (c === "'") {
      const close = text.indexOf("'", i + 1);
      word = (word ?? "") + text.slice(i + 1, close < 0 ? text.length : close);
      i = close < 0 ? text.length : close + 1;
      continue;
    }
    if (c === '"') {
      i++;
      let part = "";
      while (i < text.length && text[i] !== '"') {
        if (text[i] === "\\" && i + 1 < text.length) {
          // In double quotes a backslash escapes only $ ` " \ and a newline: `"\.env"` keeps it.
          const escaped = text[i + 1] as string;
          if (escaped !== "\n") part += "$`\"\\".includes(escaped) ? escaped : `\\${escaped}`;
          i += 2;
        } else if (text[i] === "$" && text[i + 1] === "(") {
          const { inner, end } = balanced(text, i + 2);
          nested.push(inner);
          i = end;
        } else if (text[i] === "`") {
          const close = text.indexOf("`", i + 1);
          nested.push(text.slice(i + 1, close < 0 ? text.length : close));
          i = close < 0 ? text.length : close + 1;
        } else {
          part += text[i];
          i++;
        }
      }
      word = (word ?? "") + part;
      i++;
      continue;
    }
    if (c === "$" && next === "(") {
      const { inner, end } = balanced(text, i + 2);
      nested.push(inner);
      word = (word ?? "") + "$SUBST";
      i = end;
      continue;
    }
    if (c === "`") {
      const close = text.indexOf("`", i + 1);
      nested.push(text.slice(i + 1, close < 0 ? text.length : close));
      word = (word ?? "") + "$SUBST";
      i = close < 0 ? text.length : close + 1;
      continue;
    }
    if ((c === "<" || c === ">") && next === "(") {
      endWord();
      const { inner, end } = balanced(text, i + 2);
      nested.push(inner);
      i = end;
      continue;
    }
    if (c === "#" && word === null) {
      const eol = text.indexOf("\n", i);
      i = eol < 0 ? text.length : eol;
      continue;
    }
    if (c === " " || c === "\t") {
      endWord();
      i++;
      continue;
    }
    if (c === "\n") {
      endSegment();
      i++;
      // A heredoc's body runs from the next line to its delimiter line.
      for (const doc of heredocs.splice(0)) {
        while (i < text.length) {
          const eol = text.indexOf("\n", i);
          const line = text.slice(i, eol < 0 ? text.length : eol);
          i = eol < 0 ? text.length : eol + 1;
          if ((doc.strip ? line.replace(/^\t+/, "") : line) === doc.delimiter) break;
        }
      }
      continue;
    }
    if (c === ";" || c === "&" || c === "|" || c === "(" || c === ")") {
      // A file descriptor duplication (2>&1, >&2) is not a separator.
      if (c === "&" && (text[i - 1] === ">" || text[i - 1] === "<")) {
        i++;
        while (i < text.length && /[0-9-]/.test(text[i] as string)) i++;
        redirect = null;
        continue;
      }
      endSegment();
      i++;
      continue;
    }
    if (c === "<" || c === ">") {
      // A number right before a redirection is a file descriptor, not a word.
      if (word !== null && /^\d+$/.test(word)) word = null;
      endWord();
      if (c === "<" && next === "<") {
        if (text[i + 2] === "<") {
          redirect = "herestring";
          i += 3;
        } else {
          pendingHeredoc = text[i + 2] === "-";
          i += pendingHeredoc ? 3 : 2;
        }
        continue;
      }
      redirect = c === "<" ? "in" : "out";
      i++;
      while (text[i] === ">" || text[i] === "|") i++;
      continue;
    }
    word = (word ?? "") + c;
    i++;
  }
  endSegment();
  return { segments, nested };
}

// ---- Reading commands ---------------------------------------------------------

const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "ash"]);
/** Commands that do not print a file's content, so naming a .env file with them is fine. */
const NON_READING = new Set([
  "ls", "echo", "printf", "touch", "rm", "rmdir", "mkdir", "test", "[", "[[", "stat", "wc", "du", "file",
  "chmod", "chown", "realpath", "basename", "dirname", "true", "false", "cd", "pushd", "popd", "type", "which",
]);
/** git subcommands that print file content. */
const GIT_READING = new Set(["show", "diff", "log", "blame", "annotate", "cat-file", "grep", "archive", "stash", "format-patch", "whatchanged", "difftool"]);
/** Interpreters and the options that take inline code. */
const INLINE_CODE: Record<string, string[]> = {
  node: ["-e", "--eval", "-p", "--print"],
  nodejs: ["-e", "--eval", "-p", "--print"],
  bun: ["-e", "--eval", "-p", "--print"],
  deno: ["eval"],
  python: ["-c"],
  python3: ["-c"],
  ruby: ["-e"],
  perl: ["-e", "-E"],
  php: ["-r"],
};
const ENV_ACCESS = /process\.env|os\.environ|getenv|\bENV\b|\$_ENV|Deno\.env|environ/;

function base(word: string): string {
  return word.split(/[/\\]/).pop() ?? word;
}

/** Leading assignments and wrappers (sudo, env with assignments, nice, timeout, ...) taken off. */
function unwrap(words: string[]): { words: string[]; bareEnv: boolean } {
  let rest = [...words];
  for (;;) {
    while (rest.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[0] as string)) rest.shift();
    const name = rest[0] === undefined ? "" : base(rest[0]);
    if (name === "env") {
      rest.shift();
      while (rest.length > 0 && (/^-/.test(rest[0] as string) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[0] as string))) {
        const opt = rest.shift() as string;
        if ((opt === "-u" || opt === "-C" || opt === "--unset" || opt === "--chdir") && rest.length > 0) rest.shift();
      }
      if (rest.length === 0) return { words: [], bareEnv: true };
      continue;
    }
    if (["sudo", "doas", "command", "builtin", "exec", "nohup", "time", "nice", "stdbuf", "timeout", "xargs"].includes(name)) {
      rest.shift();
      while (rest.length > 0 && /^-/.test(rest[0] as string)) {
        const opt = rest.shift() as string;
        if ((name === "sudo" && (opt === "-u" || opt === "-g")) || (name === "nice" && opt === "-n")) rest.shift();
      }
      if (name === "timeout" && rest.length > 0 && /^\d/.test(rest[0] as string)) rest.shift();
      continue;
    }
    return { words: rest, bareEnv: false };
  }
}

/** The inline code an interpreter runs, or null. */
function inlineCode(name: string, words: string[]): string | null {
  const options = INLINE_CODE[name] ?? INLINE_CODE[name.replace(/[\d.]+$/, "")];
  if (!options) return null;
  for (let i = 1; i < words.length; i++) {
    const w = words[i] as string;
    if (options.includes(w) && words[i + 1] !== undefined) return words[i + 1] as string;
    const joined = options.find((o) => o.startsWith("--") && w.startsWith(`${o}=`));
    if (joined) return w.slice(joined.length + 1);
  }
  return null;
}

/** Whether a piece of code names a protected .env file. */
function codeNamesEnvFile(code: string): boolean {
  for (const m of code.matchAll(/(?:^|[^\w.-])(\.env[\w.-]*)/g)) if (isProtectedEnvFile(m[1] as string)) return true;
  return false;
}

/** Shell variables that hold no Secret: printing one inside `varlatch run` prints none. */
const SHELL_VARS = new Set([
  "HOME", "PWD", "OLDPWD", "PATH", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "HOSTNAME", "TMPDIR",
  "UID", "EUID", "PPID", "SHLVL", "RANDOM", "SECONDS", "LINENO", "IFS", "COLUMNS", "LINES", "TZ",
]);
const PRINTERS = new Set(["echo", "printf", "print"]);

/** The variables a word expands (`$NAME`, `${NAME}`, `${NAME:-x}`), without the lexer's marker for a substitution. */
function expandedNames(word: string): string[] {
  return [...word.matchAll(/\$(?:\{([A-Za-z_]\w*)|([A-Za-z_]\w*))/g)].map((m) => (m[1] ?? m[2]) as string).filter((n) => n !== "SUBST");
}

/**
 * Why a simple command dumps the environment, when it is the command of a
 * `varlatch run`. Printing one variable is printing the environment too,
 * however it is printed (`printenv NAME`, `echo "$NAME"`, `printf`), unless
 * it is a shell variable such as HOME: the hook cannot tell a Secret from
 * configuration.
 */
function dumpsEnvironment(name: string, words: string[], bareEnv: boolean): boolean {
  if (bareEnv) return true;
  const args = words.slice(1);
  if (name === "printenv") {
    const names = args.filter((a) => !a.startsWith("-"));
    return names.length === 0 || names.some((n) => !SHELL_VARS.has(n));
  }
  if (PRINTERS.has(name)) return args.some((a) => expandedNames(a).some((n) => !SHELL_VARS.has(n)));
  if (name === "set") return args.length === 0;
  if (name === "export" || name === "declare" || name === "typeset") return args.length === 0 || args.every((a) => /^-[a-zA-Z]*[px]/.test(a));
  return words.some((w) => /^\/proc\/[^/]+\/environ$/.test(w));
}

function varlatchArgs(words: string[]): string[] | null {
  const name = base(words[0] ?? "");
  if (name === "varlatch") return words.slice(1);
  if (["npx", "pnpx", "bunx"].includes(name) && base(words[1] ?? "") === "varlatch") return words.slice(2);
  if (["pnpm", "npm", "yarn"].includes(name) && words[1] === "exec" && base(words[2] ?? "") === "varlatch") return words.slice(3);
  return null;
}

// ---- Searches -------------------------------------------------------------------

/** What a search command reads: the files and directories it searches, and the files it reads patterns or filters from. */
interface Search {
  roots: string[];
  /** Files read whole, for patterns (`grep -f`) or a filter (`jq -f`). */
  read: string[];
  /** Whether a directory among the roots is searched, with what is under it. */
  recursive: boolean;
  /** Whether matching lines are printed, not only names or counts. */
  printsContent: boolean;
  /** Which files under a directory: every one, those git does not ignore, or those git tracks. */
  scope: "all" | "unignored" | "tracked";
  /** Whether hidden files (every .env file) are searched under a directory. */
  hidden: boolean;
  include: string[];
  exclude: string[];
  excludeDir: string[];
  /** A file-type filter (`rg -t`, the Grep tool's `type`): no .env file is of a type. */
  typed: boolean;
}

/** Options and operands, with each option's value: `--opt=v`, and `--opt v` or `-o v` for the options in `valued`; short flags run together (`-rn`, `-m5`). */
function parseArgs(args: string[], valued: Set<string>): { options: [string, string | undefined][]; operands: string[] } {
  const options: [string, string | undefined][] = [];
  const operands: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const w = args[i] as string;
    if (w === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      if (eq > 0) options.push([w.slice(0, eq), w.slice(eq + 1)]);
      else options.push([w, valued.has(w) ? args[++i] : undefined]);
    } else if (w.startsWith("-") && w.length > 1) {
      for (let j = 1; j < w.length; j++) {
        const opt = `-${w[j]}`;
        if (valued.has(opt)) {
          options.push([opt, j + 1 < w.length ? w.slice(j + 1) : args[++i]]);
          break;
        }
        options.push([opt, undefined]);
      }
    } else operands.push(w);
  }
  return { options, operands };
}

const GREP_VALUED = new Set([
  "-e", "-f", "-m", "-A", "-B", "-C", "-d", "-D", "--regexp", "--file", "--max-count", "--after-context", "--before-context",
  "--context", "--directories", "--devices", "--include", "--exclude", "--exclude-dir", "--exclude-from", "--label", "--group-separator",
]);
const RG_VALUED = new Set([
  "-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-j", "-M", "-d", "-E", "-r", "--regexp", "--file", "--glob", "--iglob",
  "--type", "--type-not", "--max-count", "--after-context", "--before-context", "--context", "--threads", "--max-columns",
  "--max-depth", "--encoding", "--replace", "--sort", "--sortr", "--type-add", "--type-clear", "--pre", "--pre-glob",
  "--ignore-file", "--max-filesize", "--path-separator", "--context-separator", "--colors", "--color", "--engine",
]);
const AG_VALUED = new Set([
  "-A", "-B", "-C", "-G", "-g", "-m", "-p", "-W", "--ignore", "--ignore-dir", "--file-search-regex", "--path-to-ignore",
  "--depth", "--context", "--after", "--before", "--max-count", "--pager", "--width",
]);
const GIT_GREP_VALUED = new Set(["-e", "-f", "-A", "-B", "-C", "-m", "--max-depth", "--threads", "--max-count", "--after-context", "--before-context", "--context"]);
const JQ_VALUED = new Set(["-f", "--from-file", "-L", "--indent"]);
const GREPS = new Set(["grep", "egrep", "fgrep", "rgrep", "zgrep"]);

/** What a search command (grep and its kin, rg, ag, git grep) or jq reads, or null for another command. */
function searchOf(name: string, args: string[]): Search | null {
  const parse = (valued: Set<string>) => {
    const { options, operands } = parseArgs(args, valued);
    const has = (...names: string[]) => options.some(([k]) => names.includes(k));
    const values = (...names: string[]) => options.filter(([k]) => names.includes(k)).map(([, v]) => v).filter((v): v is string => v !== undefined);
    return { options, operands, has, values };
  };
  const base: Omit<Search, "roots"> = { read: [], recursive: false, printsContent: true, scope: "all", hidden: true, include: [], exclude: [], excludeDir: [], typed: false };
  if (GREPS.has(name)) {
    const { operands, has, values } = parse(GREP_VALUED);
    const files = has("-e", "--regexp", "-f", "--file") ? operands : operands.slice(1);
    const recursive = name === "rgrep" || has("-r", "-R", "--recursive", "--dereference-recursive") || values("-d", "--directories").includes("recurse");
    return {
      ...base,
      roots: files.length > 0 ? files : recursive ? ["."] : [],
      read: values("-f", "--file"),
      recursive,
      printsContent: !has("-l", "-L", "-c", "-q", "--files-with-matches", "--files-without-match", "--count", "--quiet", "--silent"),
      include: values("--include"),
      exclude: values("--exclude"),
      excludeDir: values("--exclude-dir"),
    };
  }
  if (name === "rg") {
    const { options, operands, has, values } = parse(RG_VALUED);
    const listing = has("--files", "--type-list");
    const files = listing || has("-e", "--regexp", "-f", "--file") ? operands : operands.slice(1);
    const unrestricted = options.filter(([k]) => k === "-u").length;
    const globs = values("-g", "--glob", "--iglob");
    return {
      ...base,
      roots: files.length > 0 ? files : ["."],
      read: values("-f", "--file"),
      recursive: true,
      printsContent: !listing && !has("-l", "-c", "-q", "--files-with-matches", "--files-without-match", "--count", "--count-matches", "--quiet"),
      scope: has("--no-ignore", "--no-ignore-vcs") || unrestricted >= 1 ? "all" : "unignored",
      hidden: has("--hidden", "-.") || unrestricted >= 2,
      include: globs.filter((g) => !g.startsWith("!")),
      exclude: globs.filter((g) => g.startsWith("!")).map((g) => g.slice(1)),
      typed: has("-t", "--type"),
    };
  }
  if (name === "ag") {
    const { operands, has } = parse(AG_VALUED);
    return {
      ...base,
      roots: operands.length > 1 ? operands.slice(1) : ["."],
      recursive: true,
      printsContent: !has("-l", "-L", "-c", "-g", "--files-with-matches", "--files-without-matches", "--count"),
      scope: has("-u", "--unrestricted", "-U", "--skip-vcs-ignores") ? "all" : "unignored",
      hidden: has("--hidden", "-u", "--unrestricted"),
    };
  }
  if (name === "git-grep") {
    const { operands, has, values } = parse(GIT_GREP_VALUED);
    const files = has("-e", "-f") ? operands : operands.slice(1);
    return {
      ...base,
      roots: files.length > 0 ? files : ["."],
      read: values("-f"),
      recursive: true,
      printsContent: !has("-l", "-L", "-c", "-q", "--name-only", "--files-with-matches", "--files-without-match", "--count", "--quiet"),
      scope: has("--no-index") ? (has("--exclude-standard") ? "unignored" : "all") : has("--untracked") ? "unignored" : "tracked",
    };
  }
  if (name === "jq") {
    // --arg, --argjson, --slurpfile and --rawfile take two words; the last two read a file.
    const rest: string[] = [];
    const read: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const w = args[i] as string;
      if (["--arg", "--argjson", "--slurpfile", "--rawfile"].includes(w)) {
        if (w === "--slurpfile" || w === "--rawfile") read.push(args[i + 2] ?? "");
        i += 2;
      } else rest.push(w);
    }
    const { options, operands } = parseArgs(rest, JQ_VALUED);
    const filterFile = options.filter(([k]) => k === "-f" || k === "--from-file").map(([, v]) => v).filter((v): v is string => v !== undefined);
    // The first operand is the filter, unless it comes from a file.
    return { ...base, roots: filterFile.length > 0 ? operands : operands.slice(1), read: [...read, ...filterFile] };
  }
  return null;
}

/** Whether a file-name glob (grep's --include, rg's --glob) matches a file found under a search root. */
function patternMatches(glob: string, name: string, relative: string): boolean {
  const re = globRegex(glob.startsWith("**/") ? glob.slice(3) : glob);
  return re !== null && (re.test(name) || re.test(relative));
}

function git(args: string[], cwd: string): number | null {
  const r = spawnSync("git", args, { cwd, stdio: "ignore", timeout: 5_000 });
  return r.error ? null : r.status;
}

/** Whether a search reads this .env file: its scope, its hidden-file rule, and its filters. */
function searchReads(search: Search, path: string, relative: string): boolean {
  const name = nameOf(path);
  if (search.typed || !search.hidden) return false;
  if (search.include.length > 0 && !search.include.some((g) => patternMatches(g, name, relative))) return false;
  if (search.exclude.some((g) => patternMatches(g, name, relative))) return false;
  if (search.scope === "unignored") return git(["check-ignore", "-q", "--", path], dirname(path)) !== 0;
  if (search.scope === "tracked") return git(["ls-files", "--error-unmatch", "--", path], dirname(path)) === 0;
  return true;
}

const WALK_SKIP = new Set(["node_modules", ".git", ".hg", ".svn"]);
const WALK_LIMIT = 20_000;
const WALK_DEPTH = 8;

/**
 * Whether a recursive search of a directory would print a .env file under
 * it. The walk is bounded (depth and entries) and skips dependency and VCS
 * directories; past the bound it gives no denial, as the hook fails open.
 */
function searchReadsEnvUnder(root: string, search: Search): boolean {
  const queue: [string, number][] = [[root, 0]];
  let seen = 0;
  while (queue.length > 0) {
    const [dir, level] = queue.shift() as [string, number];
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (++seen > WALK_LIMIT) return false;
      const path = resolve(dir, entry.name);
      if (entry.isDirectory()) {
        if (level < WALK_DEPTH && !WALK_SKIP.has(entry.name) && !search.excludeDir.some((g) => globRegex(g)?.test(entry.name))) queue.push([path, level + 1]);
      } else if (entry.isFile() && entry.name.startsWith(".env") && !ENV_TEMPLATES.has(entry.name)) {
        if (searchReads(search, path, path.slice(root.length + 1))) return true;
      }
    }
  }
  return false;
}

const DENY_ENV_SEARCH =
  "Varlatch guardrail: this search would print lines of .env files, so their values would enter your context. " +
  "Leave them out (`grep -r --exclude='.env*'`, `rg --glob '!.env*'`, the Grep tool's glob `!.env*`) or search only the files you need. " +
  "To see the names a .env file sets, run `varlatch --assisted import --dry-run <file>`.";

/** The denial for a search: a .env file it names, or one a recursive search would print. */
function checkSearch(search: Search, ctx: HookContext): Denial | null {
  for (const path of [...search.roots, ...search.read]) if (isProtectedEnvPath(path, ctx)) return DENY_ENV_FILE;
  if (!search.recursive || !search.printsContent) return null;
  for (const root of search.roots) {
    const dir = resolve(ctx.cwd, expandPath(root, ctx));
    if (statOf(dir)?.isDirectory() && searchReadsEnvUnder(dir, search)) return DENY_ENV_SEARCH;
  }
  return null;
}

function checkSegment(seg: Segment, ctx: HookContext, underRun: boolean, depth: number): Denial | null {
  for (const input of seg.inputs) {
    if (isProtectedEnvPath(input, ctx)) return DENY_ENV_FILE;
    if (isInStore(input, ctx)) return DENY_STORE;
  }
  for (const output of seg.outputs) if (isInStore(output, ctx)) return DENY_STORE;
  const { words, bareEnv } = unwrap(seg.words);
  if (bareEnv) return underRun ? DENY_ENV_DUMP : null;
  if (words.length === 0) return null;

  // The CLI reads files itself and prints no values; the command a
  // `varlatch run` starts is checked as a command of its own.
  const varlatch = varlatchArgs(words);
  if (varlatch) {
    const own = varlatch.includes("--") ? varlatch.slice(0, varlatch.indexOf("--")) : varlatch;
    const sub = own.find((w) => !w.startsWith("-"));
    if (sub === "run" && varlatch.includes("--")) {
      return checkSegment({ words: varlatch.slice(varlatch.indexOf("--") + 1), inputs: [], outputs: [] }, ctx, true, depth + 1);
    }
    return null;
  }

  const name = base(words[0] as string);
  if (SHELLS.has(name)) {
    const flag = words.findIndex((w, i) => i > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(w));
    if (flag > 0 && words[flag + 1] !== undefined) return checkCommand(words[flag + 1] as string, ctx, underRun, depth + 1);
  }
  if (name === "eval") return checkCommand(words.slice(1).join(" "), ctx, underRun, depth + 1);
  if (underRun && dumpsEnvironment(name, words, false)) return DENY_ENV_DUMP;

  const code = inlineCode(name, words);
  if (code !== null) {
    if (underRun && ENV_ACCESS.test(code)) return DENY_ENV_DUMP;
    if (codeNamesEnvFile(code)) return DENY_ENV_FILE;
    if (code.includes(".config/varlatch")) return DENY_STORE;
  }

  let reads = !NON_READING.has(name);
  let args = words.slice(1);
  const gitSub = name === "git" ? args.findIndex((w, i, rest) => !w.startsWith("-") && !["-C", "-c"].includes(rest[i - 1] ?? "")) : -1;
  if (name === "git") reads = gitSub >= 0 && GIT_READING.has(args[gitSub] as string);
  // A search reads the files it searches, not its pattern; jq reads its files, not its filter.
  const search = name === "git" ? (args[gitSub] === "grep" ? searchOf("git-grep", args.slice(gitSub + 1)) : null) : searchOf(name, args);
  if (search) {
    const denial = checkSearch(search, ctx);
    if (denial) return denial;
    reads = false;
  }
  // find lists names unless it runs a command on what it finds.
  if (name === "find") reads = args.some((w) => ["-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf"].includes(w));
  // cp and mv read their sources; the destination (the last operand) is written.
  if (name === "cp" || name === "mv") {
    const last = args.map((w, i) => (w.startsWith("-") ? -1 : i)).filter((i) => i >= 0).pop();
    if (last !== undefined) args = args.filter((_w, i) => i !== last);
  }
  for (const w of words.slice(1)) {
    // --env-file=.env, and git's rev:path form (HEAD:.env).
    const candidates = [w, w.slice(w.lastIndexOf("=") + 1), w.slice(w.lastIndexOf(":") + 1)];
    for (const candidate of candidates) {
      if (reads && args.includes(w) && isProtectedEnvPath(candidate, ctx)) return DENY_ENV_FILE;
      if (isInStore(candidate, ctx)) return DENY_STORE;
    }
  }
  return null;
}

/** The first denial for a shell command line, or null. */
export function checkCommand(command: string, ctx: HookContext, underRun = false, depth = 0): Denial | null {
  if (depth > 8) return null;
  const { segments, nested } = lexShell(command);
  for (const inner of nested) {
    const denial = checkCommand(inner, ctx, underRun, depth + 1);
    if (denial) return denial;
  }
  for (const seg of segments) {
    const denial = checkSegment(seg, ctx, underRun, depth);
    if (denial) return denial;
  }
  return null;
}

// ---- Tool calls -----------------------------------------------------------------

const PATH_KEYS = /^(file_?path|file_?paths|path|paths|notebook_?path|glob|filename|file|files)$/i;
/** Tools that list names without reading content. */
const LISTING_TOOLS = new Set(["Glob", "LS"]);

function pathsIn(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (!PATH_KEYS.test(key)) continue;
    if (typeof value === "string") out.push(value);
    else if (Array.isArray(value)) for (const v of value) if (typeof v === "string") out.push(v);
  }
  return out;
}

/** The files an apply_patch body adds, updates, deletes, or moves. */
function patchPaths(patch: string): string[] {
  return [...patch.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm)].map((m) => (m[1] ?? m[2] ?? "").trim());
}

/** The denial for a tool call, or null. */
export function checkToolCall(toolName: string, toolInput: unknown, ctx: HookContext): Denial | null {
  if (typeof toolInput !== "object" || toolInput === null) return null;
  const input = toolInput as Record<string, unknown>;
  const command = input.command;
  let paths: string[];
  if (toolName === "apply_patch" && typeof command === "string") paths = patchPaths(command);
  else if (typeof command === "string") return checkCommand(command, ctx);
  else if (Array.isArray(command) && command.every((w) => typeof w === "string")) {
    return checkSegment({ words: command as string[], inputs: [], outputs: [] }, ctx, false, 0);
  } else if (LISTING_TOOLS.has(toolName)) return null;
  else paths = pathsIn(input);
  for (const path of paths) {
    if (isProtectedEnvPath(path, ctx)) return DENY_ENV_FILE;
    if (isInStore(path, ctx)) return DENY_STORE;
  }
  if (toolName === "Grep") return checkSearch(grepToolSearch(input), ctx);
  return null;
}

/**
 * Claude Code's Grep tool searches its path (the directory by default) the
 * way rg does with hidden files on: a .env file git does not ignore is
 * searched. It prints lines only with `output_mode: "content"`; its `glob`
 * and `type` narrow the files.
 */
function grepToolSearch(input: Record<string, unknown>): Search {
  const glob = typeof input.glob === "string" ? input.glob : null;
  return {
    roots: [typeof input.path === "string" ? input.path : "."],
    read: [],
    recursive: true,
    printsContent: input.output_mode === "content",
    scope: "unignored",
    hidden: true,
    include: glob !== null && !glob.startsWith("!") ? [glob] : [],
    exclude: glob !== null && glob.startsWith("!") ? [glob.slice(1)] : [],
    excludeDir: [],
    typed: typeof input.type === "string",
  };
}

/**
 * Runs the handler on one event. Claude Code and Codex send the same
 * PreToolUse shape and read the same answer: a JSON decision on stdout with
 * status 0, or nothing for no decision. An event the handler does not
 * understand gets no decision.
 */
export function runHook(format: HookFormat, stdin: string, env: NodeJS.ProcessEnv, processCwd: string): string {
  let event: Record<string, unknown>;
  try {
    event = JSON.parse(stdin) as Record<string, unknown>;
  } catch {
    return "";
  }
  if (typeof event !== "object" || event === null || typeof event.tool_name !== "string") return "";
  if (event.hook_event_name !== undefined && event.hook_event_name !== "PreToolUse") return "";
  const ctx: HookContext = { cwd: typeof event.cwd === "string" ? event.cwd : processCwd, env, home: env.HOME || homedir() };
  const denial = checkToolCall(event.tool_name, event.tool_input, ctx);
  if (denial === null) return "";
  switch (format) {
    case "claude":
    case "codex":
      return `${JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: denial } })}\n`;
  }
}
