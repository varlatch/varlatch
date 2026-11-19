// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch agents hook --format <agent>` (ADR-0043 Decision 8), ported
// from apps/cli/src/agents/hook.ts in this tree (v0.22.0's, with the home
// directory from @varlatch/context since 091f1c08; the hook vectors are
// recorded from this tree's hook.ts, not a release): the one handler every
// guardrail hook calls. It reads a coding agent's pre-tool-use event and
// denies three kinds of tool call:
//
//   - reading a `.env*` file other than `.env.example` and `.env.schema`;
//   - reading the Varlatch credential store;
//   - dumping the environment of a `varlatch run`.
//
// This is accident prevention, never a boundary: it reads commands the way
// a careful person would, not the way a shell runs them, so a determined
// agent gets around it, and the hook fails open when the event is not
// understood. Every protection Varlatch claims is in the CLI and the
// server.

// HookFormats are the coding agents whose hook format the handler answers.
var HookFormats = []string{"claude", "codex"}

// hookContext is the tool call's world: its directory, the environment and
// the home directory.
type hookContext struct {
	cwd  string
	env  clientctx.Env
	home string
}

// envTemplates are the dotenv templates that hold no values.
var envTemplates = map[string]bool{".env.example": true, ".env.schema": true}

// envNames are the names a glob is tried against: a glob that can match
// one of them reads a .env file.
var envNames = []string{".env", ".envrc", ".env.local", ".env.production", ".env.development.local", ".env.bak"}

// nameOf is a path's last name, trailing separators dropped.
func nameOf(path string) string {
	trimmed := strings.TrimRight(path, `/\`)
	if i := strings.LastIndexAny(trimmed, `/\`); i >= 0 {
		return trimmed[i+1:]
	}
	return trimmed
}

func isGlob(name string) bool { return strings.ContainsAny(name, "*?[") }

// globCache holds the globs compiled in this run: a search tries its
// filters on every entry it walks, and compiling a long glob each time
// would be slow where V8, which caches compiled regular expressions, is
// not.
var globCache = struct {
	sync.Mutex
	m map[string]*regexp.Regexp
}{m: map[string]*regexp.Regexp{}}

// globRegex is a shell glob as a regular expression for one name, or nil
// for a glob with an unclosed class (or one that is no regular expression).
// The regular expression is RE2's (Go's regexp), not JavaScript's.
func globRegex(glob string) *regexp.Regexp {
	globCache.Lock()
	defer globCache.Unlock()
	if re, ok := globCache.m[glob]; ok {
		return re
	}
	if len(globCache.m) >= 256 {
		clear(globCache.m)
	}
	re := compileGlob(glob)
	globCache.m[glob] = re
	return re
}

func compileGlob(glob string) *regexp.Regexp {
	var out strings.Builder
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		switch c {
		case '*':
			// A run of stars matches what one does.
			for i+1 < len(glob) && glob[i+1] == '*' {
				i++
			}
			out.WriteString(".*")
		case '?':
			out.WriteString(".")
		case '[':
			close := -1
			if i+2 <= len(glob) {
				if j := strings.IndexByte(glob[min(i+2, len(glob)):], ']'); j >= 0 {
					close = i + 2 + j
				}
			}
			if close < 0 {
				return nil
			}
			body := glob[i+1 : close]
			if strings.HasPrefix(body, "!") {
				body = "^" + body[1:]
			}
			out.WriteString("[" + body + "]")
			i = close
		default:
			if strings.IndexByte(`\^$.|+(){}`, c) >= 0 {
				out.WriteByte('\\')
			}
			out.WriteByte(c)
		}
	}
	re, err := regexp.Compile("^(?:" + out.String() + ")$")
	if err != nil {
		return nil
	}
	return re
}

func globMatches(glob, name string) bool {
	if strings.HasPrefix(name, ".") && !strings.HasPrefix(glob, ".") {
		return false
	}
	re := globRegex(glob)
	return re != nil && re.MatchString(name)
}

var envDotted = regexp.MustCompile(`^\.env\..+`)

// IsProtectedEnvFile is whether a name is a .env file by its name alone:
// `.env`, `.envrc`, or `.env.<anything>`, other than the two templates; or
// a glob that matches one.
func IsProtectedEnvFile(path string) bool {
	name := nameOf(path)
	if envTemplates[name] {
		return false
	}
	if isGlob(name) {
		return slices.ContainsFunc(envNames, func(n string) bool { return globMatches(name, n) })
	}
	return name == ".env" || name == ".envrc" || envDotted.MatchString(name)
}

func statOf(path string) os.FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return info
}

// isEnvLikeFile is an existing file, other than a template, whose name
// starts with `.env`.
func isEnvLikeFile(path string) bool {
	name := nameOf(path)
	info := statOf(path)
	return strings.HasPrefix(name, ".env") && !envTemplates[name] && info != nil && info.Mode().IsRegular()
}

// resolvePath is Node.js's path.resolve(cwd, path) on POSIX.
func resolvePath(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	if !filepath.IsAbs(cwd) {
		if wd, err := os.Getwd(); err == nil {
			cwd = filepath.Join(wd, cwd)
		}
	}
	return filepath.Join(cwd, path)
}

// isProtectedEnvPath is whether a path the command reads is a .env file.
func isProtectedEnvPath(path string, ctx hookContext) bool {
	full := resolvePath(ctx.cwd, expandPath(path, ctx))
	name := nameOf(path)
	if envTemplates[name] {
		return false
	}
	if isGlob(name) {
		if IsProtectedEnvFile(name) {
			return true
		}
		dir := filepath.Dir(full)
		for _, entry := range entriesOf(dir) {
			if globMatches(name, entry) && isEnvLikeFile(resolvePath(dir, entry)) {
				return true
			}
		}
		return false
	}
	if IsProtectedEnvFile(name) {
		info := statOf(full)
		return info == nil || !info.IsDir()
	}
	return isEnvLikeFile(full)
}

func entriesOf(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Name()
	}
	return out
}

// withoutConfigDir is an environment without VARLATCH_CONFIG_DIR.
type withoutConfigDir struct{ clientctx.Env }

func (e withoutConfigDir) LookupEnv(key string) (string, bool) {
	if key == "VARLATCH_CONFIG_DIR" {
		return "", false
	}
	return e.Env.LookupEnv(key)
}

// storeDirs are the credential-store directories: the one this environment
// uses, and the default one.
func storeDirs(ctx hookContext) ([]string, error) {
	configured, err := clientctx.CredentialsPath(ctx.env)
	if err != nil {
		return nil, err
	}
	fallback, err := clientctx.CredentialsPath(withoutConfigDir{ctx.env})
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, d := range []string{filepath.Dir(configured), filepath.Dir(fallback), resolvePath(ctx.home, filepath.Join(".config", "varlatch"))} {
		if d = filepath.Clean(d); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	return dirs, nil
}

var shellVariable = regexp.MustCompile(`\$\{(\w+)\}|\$(\w+)`)

// expandPath expands ~ and $HOME, $XDG_CONFIG_HOME and $VARLATCH_CONFIG_DIR
// in a word; any other variable stays as written.
func expandPath(word string, ctx hookContext) string {
	vars := map[string]*string{"HOME": &ctx.home}
	for _, k := range []string{"XDG_CONFIG_HOME", "VARLATCH_CONFIG_DIR"} {
		if v, ok := ctx.env.LookupEnv(k); ok {
			v := v
			vars[k] = &v
		}
	}
	out := word
	if out == "~" || strings.HasPrefix(out, "~/") || strings.HasPrefix(out, `~\`) {
		out = ctx.home + out[1:]
	}
	return shellVariable.ReplaceAllStringFunc(out, func(m string) string {
		sub := shellVariable.FindStringSubmatch(m)
		name := sub[1]
		if name == "" {
			name = sub[2]
		}
		if v := vars[name]; v != nil {
			return *v
		}
		return m
	})
}

var configVarlatch = regexp.MustCompile(`/\.config/varlatch(/|$)`)

// isInStore is whether a path is in the credential store.
func isInStore(path string, ctx hookContext) (bool, error) {
	if configVarlatch.MatchString(strings.ReplaceAll(path, `\`, "/")) {
		return true, nil
	}
	expanded := expandPath(path, ctx)
	if strings.Contains(expanded, "$") {
		return false, nil
	}
	abs := filepath.Clean(resolvePath(ctx.cwd, expanded))
	dirs, err := storeDirs(ctx)
	if err != nil {
		return false, err
	}
	for _, dir := range dirs {
		prefix := dir
		if !strings.HasSuffix(prefix, string(filepath.Separator)) {
			prefix += string(filepath.Separator)
		}
		if abs == dir || strings.HasPrefix(abs, prefix) {
			return true, nil
		}
	}
	return false, nil
}

// The denials, as hook.ts words them.
const (
	denyEnvFile = "Varlatch guardrail: .env files are off limits to coding agents, because their values would enter your context. " +
		"To see the names a .env file sets, run `varlatch --assisted import --dry-run <file>`; to store its values, " +
		"`varlatch --assisted import <file>`. .env.example and .env.schema stay readable."
	denyStore = "Varlatch guardrail: the Varlatch credential store is off limits: it holds the human's credential. " +
		"Use `varlatch --assisted status --json` to see who is signed in."
	denyEnvDump = "Varlatch guardrail: printing the environment of a `varlatch run` would print Secrets. " +
		"Run the command you need instead, and list names with `varlatch --assisted values list --json`."
	denyEnvSearch = "Varlatch guardrail: this search would print lines of .env files, so their values would enter your context. " +
		"Leave them out (`grep -r --exclude='.env*'`, `rg --glob '!.env*'`, the Grep tool's glob `!.env*`) or search only the files you need. " +
		"To see the names a .env file sets, run `varlatch --assisted import --dry-run <file>`."
)

// ---- A small shell reader ----------------------------------------------------

// segment is one simple command: its words, the files it reads through `<`
// and writes through `>` and `>>`.
type segment struct {
	words, inputs, outputs []string
}

// lexed is a command line read: its simple commands, and the commands
// inside $(...), backticks and <(...), read on their own.
type lexed struct {
	segments []segment
	nested   []string
}

// balanced is text from open (just after the opening parenthesis) to its
// closing one, skipping quoted text.
func balanced(text string, open int) (string, int) {
	depth := 1
	i := open
	for i < len(text) {
		c := text[i]
		switch {
		case c == '\\':
			i += 2
		case c == '\'':
			if j := strings.IndexByte(text[i+1:], '\''); j < 0 {
				i = len(text)
			} else {
				i = i + 1 + j + 1
			}
		case c == '"':
			i++
			for i < len(text) && text[i] != '"' {
				if text[i] == '\\' {
					i += 2
				} else {
					i++
				}
			}
			i++
		default:
			if c == '(' {
				depth++
			}
			if c == ')' {
				depth--
				if depth == 0 {
					return text[open:i], i + 1
				}
			}
			i++
		}
	}
	if open > len(text) {
		return "", len(text)
	}
	return text[open:], len(text)
}

// indexFrom is text.indexOf(c, from), -1 for none.
func indexFrom(text string, c byte, from int) int {
	if from > len(text) {
		return -1
	}
	if j := strings.IndexByte(text[from:], c); j >= 0 {
		return from + j
	}
	return -1
}

var allDigits = regexp.MustCompile(`^\d+$`)

// lexShell splits a command line into simple commands (at ; & && | ||
// newlines and parentheses), their words with quotes removed, their `<`
// inputs, and the nested commands inside substitutions. Heredoc bodies are
// skipped, since they are text, not commands.
func lexShell(text string) lexed {
	var out lexed
	seg := segment{}
	// The word being read. Its bytes are appended whole, so a UTF-8 name
	// stays as written, and a long word takes linear time.
	var word strings.Builder
	inWord := false
	redirect := ""
	type heredoc struct {
		delimiter string
		strip     bool
	}
	var heredocs []heredoc
	pending := -1 // -1 none; 0 a plain heredoc; 1 one with <<-
	add := func(s string) {
		inWord = true
		word.WriteString(s)
	}
	addByte := func(b byte) {
		inWord = true
		word.WriteByte(b)
	}
	endWord := func() {
		if !inWord {
			return
		}
		w := word.String()
		switch {
		case pending >= 0:
			heredocs = append(heredocs, heredoc{w, pending == 1})
			pending = -1
		case redirect == "in":
			seg.inputs = append(seg.inputs, w)
		case redirect == "out":
			seg.outputs = append(seg.outputs, w)
		case redirect == "":
			seg.words = append(seg.words, w)
		}
		redirect = ""
		word = strings.Builder{}
		inWord = false
	}
	endSegment := func() {
		endWord()
		if len(seg.words) > 0 || len(seg.inputs) > 0 || len(seg.outputs) > 0 {
			out.segments = append(out.segments, seg)
		}
		seg = segment{}
	}
	at := func(i int) byte {
		if i >= 0 && i < len(text) {
			return text[i]
		}
		return 0
	}
	i := 0
	for i < len(text) {
		c := text[i]
		next := at(i + 1)
		switch {
		case c == '\\':
			if next == '\n' {
				i += 2
			} else {
				if i+1 < len(text) {
					addByte(next)
				} else {
					add("")
				}
				i += 2
			}
			continue
		case c == '\'':
			close := indexFrom(text, '\'', i+1)
			if close < 0 {
				add(text[i+1:])
				i = len(text)
			} else {
				add(text[i+1 : close])
				i = close + 1
			}
			continue
		case c == '"':
			i++
			inWord = true // "" is a word
			for i < len(text) && text[i] != '"' {
				switch {
				case text[i] == '\\' && i+1 < len(text):
					// In double quotes a backslash escapes only $ ` " \ and a newline.
					escaped := text[i+1]
					if escaped != '\n' {
						if strings.IndexByte("$`\"\\", escaped) >= 0 {
							addByte(escaped)
						} else {
							addByte('\\')
							addByte(escaped)
						}
					}
					i += 2
				case text[i] == '$' && at(i+1) == '(':
					inner, end := balanced(text, i+2)
					out.nested = append(out.nested, inner)
					i = end
				case text[i] == '`':
					close := indexFrom(text, '`', i+1)
					if close < 0 {
						out.nested = append(out.nested, text[i+1:])
						i = len(text)
					} else {
						out.nested = append(out.nested, text[i+1:close])
						i = close + 1
					}
				default:
					addByte(text[i])
					i++
				}
			}
			i++
			continue
		case c == '$' && next == '(':
			inner, end := balanced(text, i+2)
			out.nested = append(out.nested, inner)
			add("$SUBST")
			i = end
			continue
		case c == '`':
			close := indexFrom(text, '`', i+1)
			if close < 0 {
				out.nested = append(out.nested, text[i+1:])
				i = len(text)
			} else {
				out.nested = append(out.nested, text[i+1:close])
				i = close + 1
			}
			add("$SUBST")
			continue
		case (c == '<' || c == '>') && next == '(':
			endWord()
			inner, end := balanced(text, i+2)
			out.nested = append(out.nested, inner)
			i = end
			continue
		case c == '#' && !inWord:
			if eol := indexFrom(text, '\n', i); eol < 0 {
				i = len(text)
			} else {
				i = eol
			}
			continue
		case c == ' ' || c == '\t':
			endWord()
			i++
			continue
		case c == '\n':
			endSegment()
			i++
			// A heredoc's body runs from the next line to its delimiter line.
			docs := heredocs
			heredocs = nil
			for _, doc := range docs {
				for i < len(text) {
					eol := indexFrom(text, '\n', i)
					var line string
					if eol < 0 {
						line = text[i:]
						i = len(text)
					} else {
						line = text[i:eol]
						i = eol + 1
					}
					if doc.strip {
						line = strings.TrimLeft(line, "\t")
					}
					if line == doc.delimiter {
						break
					}
				}
			}
			continue
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			// A file descriptor duplication (2>&1, >&2) is not a separator.
			if c == '&' && (at(i-1) == '>' || at(i-1) == '<') {
				i++
				for i < len(text) && (text[i] >= '0' && text[i] <= '9' || text[i] == '-') {
					i++
				}
				redirect = ""
				continue
			}
			endSegment()
			i++
			continue
		case c == '<' || c == '>':
			// A number right before a redirection is a file descriptor, not a word.
			if inWord && allDigits.MatchString(word.String()) {
				word = strings.Builder{}
				inWord = false
			}
			endWord()
			if c == '<' && next == '<' {
				if at(i+2) == '<' {
					redirect = "herestring"
					i += 3
				} else {
					if at(i+2) == '-' {
						pending = 1
						i += 3
					} else {
						pending = 0
						i += 2
					}
				}
				continue
			}
			if c == '<' {
				redirect = "in"
			} else {
				redirect = "out"
			}
			i++
			for at(i) == '>' || at(i) == '|' {
				i++
			}
			continue
		}
		addByte(c)
		i++
	}
	endSegment()
	return out
}

// ---- Reading commands -----------------------------------------------------------

var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "fish": true, "ash": true}

// nonReading are commands that do not print a file's content.
var nonReading = setOf("ls", "echo", "printf", "touch", "rm", "rmdir", "mkdir", "test", "[", "[[", "stat", "wc", "du", "file",
	"chmod", "chown", "realpath", "basename", "dirname", "true", "false", "cd", "pushd", "popd", "type", "which")

// gitReading are the git subcommands that print file content.
var gitReading = setOf("show", "diff", "log", "blame", "annotate", "cat-file", "grep", "archive", "stash", "format-patch", "whatchanged", "difftool")

// inlineCodeOptions are interpreters and the options that take inline code.
var inlineCodeOptions = map[string][]string{
	"node":    {"-e", "--eval", "-p", "--print"},
	"nodejs":  {"-e", "--eval", "-p", "--print"},
	"bun":     {"-e", "--eval", "-p", "--print"},
	"deno":    {"eval"},
	"python":  {"-c"},
	"python3": {"-c"},
	"ruby":    {"-e"},
	"perl":    {"-e", "-E"},
	"php":     {"-r"},
}

var envAccess = regexp.MustCompile(`process\.env|os\.environ|getenv|\bENV\b|\$_ENV|Deno\.env|environ`)

func setOf(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// base is a word's last path element.
func base(word string) string {
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		return word[i+1:]
	}
	return word
}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

var wrappers = setOf("sudo", "doas", "command", "builtin", "exec", "nohup", "time", "nice", "stdbuf", "timeout", "xargs")

// unwrap takes leading assignments and wrappers (sudo, env with
// assignments, nice, timeout, ...) off a command.
func unwrap(words []string) ([]string, bool) {
	rest := slices.Clone(words)
	for {
		for len(rest) > 0 && assignment.MatchString(rest[0]) {
			rest = rest[1:]
		}
		name := ""
		if len(rest) > 0 {
			name = base(rest[0])
		}
		if name == "env" {
			rest = rest[1:]
			for len(rest) > 0 && (strings.HasPrefix(rest[0], "-") || assignment.MatchString(rest[0])) {
				opt := rest[0]
				rest = rest[1:]
				if (opt == "-u" || opt == "-C" || opt == "--unset" || opt == "--chdir") && len(rest) > 0 {
					rest = rest[1:]
				}
			}
			if len(rest) == 0 {
				return nil, true
			}
			continue
		}
		if wrappers[name] {
			rest = rest[1:]
			for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
				opt := rest[0]
				rest = rest[1:]
				if (name == "sudo" && (opt == "-u" || opt == "-g") || name == "nice" && opt == "-n") && len(rest) > 0 {
					rest = rest[1:]
				}
			}
			if name == "timeout" && len(rest) > 0 && rest[0] != "" && rest[0][0] >= '0' && rest[0][0] <= '9' {
				rest = rest[1:]
			}
			continue
		}
		return rest, false
	}
}

var trailingVersion = regexp.MustCompile(`[\d.]+$`)

// inlineCode is the inline code an interpreter runs, if any.
func inlineCode(name string, words []string) (string, bool) {
	options, ok := inlineCodeOptions[name]
	if !ok {
		options, ok = inlineCodeOptions[trailingVersion.ReplaceAllString(name, "")]
	}
	if !ok {
		return "", false
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		if slices.Contains(options, w) && i+1 < len(words) {
			return words[i+1], true
		}
		for _, o := range options {
			if strings.HasPrefix(o, "--") && strings.HasPrefix(w, o+"=") {
				return w[len(o)+1:], true
			}
		}
	}
	return "", false
}

var envFileInCode = regexp.MustCompile(`(?:^|[^\w.-])(\.env[\w.-]*)`)

// codeNamesEnvFile is whether a piece of code names a protected .env file.
func codeNamesEnvFile(code string) bool {
	for _, m := range envFileInCode.FindAllStringSubmatch(code, -1) {
		if IsProtectedEnvFile(m[1]) {
			return true
		}
	}
	return false
}

// shellVars are shell variables that hold no Secret.
var shellVars = setOf("HOME", "PWD", "OLDPWD", "PATH", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "HOSTNAME", "TMPDIR",
	"UID", "EUID", "PPID", "SHLVL", "RANDOM", "SECONDS", "LINENO", "IFS", "COLUMNS", "LINES", "TZ")

var printers = setOf("echo", "printf", "print")

var expandedName = regexp.MustCompile(`\$(?:\{([A-Za-z_]\w*)|([A-Za-z_]\w*))`)

// expandedNames are the variables a word expands, without the lexer's
// marker for a substitution.
func expandedNames(word string) []string {
	var out []string
	for _, m := range expandedName.FindAllStringSubmatch(word, -1) {
		n := m[1]
		if n == "" {
			n = m[2]
		}
		if n != "SUBST" {
			out = append(out, n)
		}
	}
	return out
}

var exportFlags = regexp.MustCompile(`^-[a-zA-Z]*[px]`)
var procEnviron = regexp.MustCompile(`^/proc/[^/]+/environ$`)

// dumpsEnvironment is whether a simple command dumps the environment, when
// it is the command of a `varlatch run`.
func dumpsEnvironment(name string, words []string, bareEnv bool) bool {
	if bareEnv {
		return true
	}
	args := words[1:]
	switch {
	case name == "printenv":
		var names []string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				names = append(names, a)
			}
		}
		return len(names) == 0 || slices.ContainsFunc(names, func(n string) bool { return !shellVars[n] })
	case printers[name]:
		return slices.ContainsFunc(args, func(a string) bool {
			return slices.ContainsFunc(expandedNames(a), func(n string) bool { return !shellVars[n] })
		})
	case name == "set":
		return len(args) == 0
	case name == "export" || name == "declare" || name == "typeset":
		return len(args) == 0 || !slices.ContainsFunc(args, func(a string) bool { return !exportFlags.MatchString(a) })
	}
	return slices.ContainsFunc(words, procEnviron.MatchString)
}

func varlatchArgs(words []string) ([]string, bool) {
	at := func(i int) string {
		if i < len(words) {
			return words[i]
		}
		return ""
	}
	name := base(at(0))
	switch {
	case name == "varlatch":
		return words[1:], true
	case (name == "npx" || name == "pnpx" || name == "bunx") && base(at(1)) == "varlatch":
		return words[2:], true
	case (name == "pnpm" || name == "npm" || name == "yarn") && at(1) == "exec" && base(at(2)) == "varlatch":
		return words[3:], true
	}
	return nil, false
}

// ---- Searches ---------------------------------------------------------------------

// search is what a search command reads.
type search struct {
	roots, read                []string
	recursive, printsContent   bool
	scope                      string // all, unignored, tracked
	hidden                     bool
	include, exclude, excludeD []string
	typed                      bool
}

type option struct {
	name  string
	value *string
}

// parseArgs is hook.ts's parseArgs: options and operands, with each
// option's value.
func parseArgs(args []string, valued map[string]bool) ([]option, []string) {
	var options []option
	var operands []string
	value := func(i *int) *string {
		*i++
		if *i < len(args) {
			v := args[*i]
			return &v
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		w := args[i]
		if w == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if strings.HasPrefix(w, "--") {
			if eq := strings.IndexByte(w, '='); eq > 0 {
				v := w[eq+1:]
				options = append(options, option{w[:eq], &v})
			} else if valued[w] {
				options = append(options, option{w, value(&i)})
			} else {
				options = append(options, option{w, nil})
			}
		} else if strings.HasPrefix(w, "-") && len(w) > 1 {
			for j := 1; j < len(w); {
				// One option per character, its UTF-8 bytes kept whole.
				_, size := utf8.DecodeRuneInString(w[j:])
				opt := "-" + w[j:j+size]
				j += size
				if valued[opt] {
					if j < len(w) {
						v := w[j:]
						options = append(options, option{opt, &v})
					} else {
						options = append(options, option{opt, value(&i)})
					}
					break
				}
				options = append(options, option{opt, nil})
			}
		} else {
			operands = append(operands, w)
		}
	}
	return options, operands
}

var (
	grepValued = setOf("-e", "-f", "-m", "-A", "-B", "-C", "-d", "-D", "--regexp", "--file", "--max-count", "--after-context", "--before-context",
		"--context", "--directories", "--devices", "--include", "--exclude", "--exclude-dir", "--exclude-from", "--label", "--group-separator")
	rgValued = setOf("-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-j", "-M", "-d", "-E", "-r", "--regexp", "--file", "--glob", "--iglob",
		"--type", "--type-not", "--max-count", "--after-context", "--before-context", "--context", "--threads", "--max-columns",
		"--max-depth", "--encoding", "--replace", "--sort", "--sortr", "--type-add", "--type-clear", "--pre", "--pre-glob",
		"--ignore-file", "--max-filesize", "--path-separator", "--context-separator", "--colors", "--color", "--engine")
	agValued = setOf("-A", "-B", "-C", "-G", "-g", "-m", "-p", "-W", "--ignore", "--ignore-dir", "--file-search-regex", "--path-to-ignore",
		"--depth", "--context", "--after", "--before", "--max-count", "--pager", "--width")
	gitGrepValued = setOf("-e", "-f", "-A", "-B", "-C", "-m", "--max-depth", "--threads", "--max-count", "--after-context", "--before-context", "--context")
	jqValued      = setOf("-f", "--from-file", "-L", "--indent")
	greps         = setOf("grep", "egrep", "fgrep", "rgrep", "zgrep")
)

type parsed struct {
	options  []option
	operands []string
}

func (p parsed) has(names ...string) bool {
	return slices.ContainsFunc(p.options, func(o option) bool { return slices.Contains(names, o.name) })
}

func (p parsed) values(names ...string) []string {
	var out []string
	for _, o := range p.options {
		if slices.Contains(names, o.name) && o.value != nil {
			out = append(out, *o.value)
		}
	}
	return out
}

func (p parsed) count(name string) int {
	n := 0
	for _, o := range p.options {
		if o.name == name {
			n++
		}
	}
	return n
}

func tail(list []string, from int) []string {
	if from >= len(list) {
		return nil
	}
	return list[from:]
}

// searchOf is what a search command (grep and its kin, rg, ag, git grep) or
// jq reads, or nil for another command.
func searchOf(name string, args []string) *search {
	parse := func(valued map[string]bool) parsed {
		o, operands := parseArgs(args, valued)
		return parsed{o, operands}
	}
	s := &search{printsContent: true, scope: "all", hidden: true}
	switch {
	case greps[name]:
		p := parse(grepValued)
		files := tail(p.operands, 1)
		if p.has("-e", "--regexp", "-f", "--file") {
			files = p.operands
		}
		s.recursive = name == "rgrep" || p.has("-r", "-R", "--recursive", "--dereference-recursive") || slices.Contains(p.values("-d", "--directories"), "recurse")
		s.roots = files
		if len(files) == 0 && s.recursive {
			s.roots = []string{"."}
		}
		s.read = p.values("-f", "--file")
		s.printsContent = !p.has("-l", "-L", "-c", "-q", "--files-with-matches", "--files-without-match", "--count", "--quiet", "--silent")
		s.include, s.exclude, s.excludeD = p.values("--include"), p.values("--exclude"), p.values("--exclude-dir")
		return s
	case name == "rg":
		p := parse(rgValued)
		listing := p.has("--files", "--type-list")
		files := tail(p.operands, 1)
		if listing || p.has("-e", "--regexp", "-f", "--file") {
			files = p.operands
		}
		unrestricted := p.count("-u")
		globs := p.values("-g", "--glob", "--iglob")
		s.roots = files
		if len(files) == 0 {
			s.roots = []string{"."}
		}
		s.read = p.values("-f", "--file")
		s.recursive = true
		s.printsContent = !listing && !p.has("-l", "-c", "-q", "--files-with-matches", "--files-without-match", "--count", "--count-matches", "--quiet")
		s.scope = "unignored"
		if p.has("--no-ignore", "--no-ignore-vcs") || unrestricted >= 1 {
			s.scope = "all"
		}
		s.hidden = p.has("--hidden", "-.") || unrestricted >= 2
		for _, g := range globs {
			if strings.HasPrefix(g, "!") {
				s.exclude = append(s.exclude, g[1:])
			} else {
				s.include = append(s.include, g)
			}
		}
		s.typed = p.has("-t", "--type")
		return s
	case name == "ag":
		p := parse(agValued)
		s.roots = []string{"."}
		if len(p.operands) > 1 {
			s.roots = p.operands[1:]
		}
		s.recursive = true
		s.printsContent = !p.has("-l", "-L", "-c", "-g", "--files-with-matches", "--files-without-matches", "--count")
		s.scope = "unignored"
		if p.has("-u", "--unrestricted", "-U", "--skip-vcs-ignores") {
			s.scope = "all"
		}
		s.hidden = p.has("--hidden", "-u", "--unrestricted")
		return s
	case name == "git-grep":
		p := parse(gitGrepValued)
		files := tail(p.operands, 1)
		if p.has("-e", "-f") {
			files = p.operands
		}
		s.roots = files
		if len(files) == 0 {
			s.roots = []string{"."}
		}
		s.read = p.values("-f")
		s.recursive = true
		s.printsContent = !p.has("-l", "-L", "-c", "-q", "--name-only", "--files-with-matches", "--files-without-match", "--count", "--quiet")
		switch {
		case p.has("--no-index") && p.has("--exclude-standard"):
			s.scope = "unignored"
		case p.has("--no-index"):
			s.scope = "all"
		case p.has("--untracked"):
			s.scope = "unignored"
		default:
			s.scope = "tracked"
		}
		return s
	case name == "jq":
		// --arg, --argjson, --slurpfile and --rawfile take two words; the
		// last two read a file.
		var rest, read []string
		for i := 0; i < len(args); i++ {
			w := args[i]
			if w == "--arg" || w == "--argjson" || w == "--slurpfile" || w == "--rawfile" {
				if w == "--slurpfile" || w == "--rawfile" {
					f := ""
					if i+2 < len(args) {
						f = args[i+2]
					}
					read = append(read, f)
				}
				i += 2
			} else {
				rest = append(rest, w)
			}
		}
		options, operands := parseArgs(rest, jqValued)
		var filterFile []string
		for _, o := range options {
			if (o.name == "-f" || o.name == "--from-file") && o.value != nil {
				filterFile = append(filterFile, *o.value)
			}
		}
		// The first operand is the filter, unless it comes from a file.
		s.roots = tail(operands, 1)
		if len(filterFile) > 0 {
			s.roots = operands
		}
		s.read = append(read, filterFile...)
		return s
	}
	return nil
}

// patternMatches is whether a file-name glob (grep's --include, rg's
// --glob) matches a file found under a search root.
func patternMatches(glob, name, relative string) bool {
	re := globRegex(strings.TrimPrefix(glob, "**/"))
	return re != nil && (re.MatchString(name) || re.MatchString(relative))
}

// git runs git quietly in cwd: its status, or -1 when it could not run.
func git(args []string, cwd string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = cwd
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok && ctx.Err() == nil {
		return exit.ExitCode()
	}
	return -1
}

// searchReads is whether a search reads this .env file: its scope, its
// hidden-file rule and its filters.
func searchReads(s *search, path, relative string) bool {
	name := nameOf(path)
	if s.typed || !s.hidden {
		return false
	}
	if len(s.include) > 0 && !slices.ContainsFunc(s.include, func(g string) bool { return patternMatches(g, name, relative) }) {
		return false
	}
	if slices.ContainsFunc(s.exclude, func(g string) bool { return patternMatches(g, name, relative) }) {
		return false
	}
	switch s.scope {
	case "unignored":
		return git([]string{"check-ignore", "-q", "--", path}, filepath.Dir(path)) != 0
	case "tracked":
		return git([]string{"ls-files", "--error-unmatch", "--", path}, filepath.Dir(path)) == 0
	}
	return true
}

var walkSkip = setOf("node_modules", ".git", ".hg", ".svn")

const (
	walkLimit = 20_000
	walkDepth = 8
)

// searchReadsEnvUnder is whether a recursive search of a directory would
// print a .env file under it: a bounded walk (depth and entries) that skips
// dependency and VCS directories; past the bound it gives no denial, as the
// hook fails open.
func searchReadsEnvUnder(root string, s *search) bool {
	type item struct {
		dir   string
		level int
	}
	queue := []item{{root, 0}}
	seen := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		entries, err := os.ReadDir(cur.dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			seen++
			if seen > walkLimit {
				return false
			}
			path := filepath.Join(cur.dir, entry.Name())
			// The entry's own type, never a symbolic link's target, as a Dirent's.
			mode := entry.Type()
			switch {
			case mode.IsDir():
				if cur.level < walkDepth && !walkSkip[entry.Name()] && !slices.ContainsFunc(s.excludeD, func(g string) bool {
					re := globRegex(g)
					return re != nil && re.MatchString(entry.Name())
				}) {
					queue = append(queue, item{path, cur.level + 1})
				}
			case mode.IsRegular() && strings.HasPrefix(entry.Name(), ".env") && !envTemplates[entry.Name()]:
				if searchReads(s, path, path[len(root)+1:]) {
					return true
				}
			}
		}
	}
	return false
}

// checkSearch is the denial for a search: a .env file it names, or one a
// recursive search would print.
func checkSearch(s *search, ctx hookContext) string {
	for _, path := range append(slices.Clone(s.roots), s.read...) {
		if isProtectedEnvPath(path, ctx) {
			return denyEnvFile
		}
	}
	if !s.recursive || !s.printsContent {
		return ""
	}
	for _, root := range s.roots {
		dir := resolvePath(ctx.cwd, expandPath(root, ctx))
		if info := statOf(dir); info != nil && info.IsDir() && searchReadsEnvUnder(dir, s) {
			return denyEnvSearch
		}
	}
	return ""
}

var shellCodeFlag = regexp.MustCompile(`^-[a-zA-Z]*c[a-zA-Z]*$`)

var findRuns = []string{"-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf"}

func (h *hook) checkSegment(seg segment, ctx hookContext, underRun bool, depth int) (string, error) {
	for _, input := range seg.inputs {
		if isProtectedEnvPath(input, ctx) {
			return denyEnvFile, nil
		}
		if in, err := isInStore(input, ctx); err != nil || in {
			return denyIf(in, denyStore), err
		}
	}
	for _, output := range seg.outputs {
		if in, err := isInStore(output, ctx); err != nil || in {
			return denyIf(in, denyStore), err
		}
	}
	words, bareEnv := unwrap(seg.words)
	if bareEnv {
		return denyIf(underRun, denyEnvDump), nil
	}
	if len(words) == 0 {
		return "", nil
	}

	// The CLI reads files itself and prints no values; the command a
	// `varlatch run` starts is checked as a command of its own.
	if varlatch, ok := varlatchArgs(words); ok {
		separator := slices.Index(varlatch, "--")
		own := varlatch
		if separator >= 0 {
			own = varlatch[:separator]
		}
		sub := ""
		for _, w := range own {
			if !strings.HasPrefix(w, "-") {
				sub = w
				break
			}
		}
		if sub == "run" && separator >= 0 {
			return h.checkSegment(segment{words: varlatch[separator+1:]}, ctx, true, depth+1)
		}
		return "", nil
	}

	name := base(words[0])
	if shells[name] {
		flag := -1
		for i, w := range words {
			if i > 0 && shellCodeFlag.MatchString(w) {
				flag = i
				break
			}
		}
		if flag > 0 && flag+1 < len(words) {
			return h.checkCommand(words[flag+1], ctx, underRun, depth+1)
		}
	}
	if name == "eval" {
		return h.checkCommand(strings.Join(words[1:], " "), ctx, underRun, depth+1)
	}
	if underRun && dumpsEnvironment(name, words, false) {
		return denyEnvDump, nil
	}

	if code, ok := inlineCode(name, words); ok {
		if underRun && envAccess.MatchString(code) {
			return denyEnvDump, nil
		}
		if codeNamesEnvFile(code) {
			return denyEnvFile, nil
		}
		if strings.Contains(code, ".config/varlatch") {
			return denyStore, nil
		}
	}

	reads := !nonReading[name]
	args := words[1:]
	gitSub := -1
	if name == "git" {
		for i, w := range args {
			previous := ""
			if i > 0 {
				previous = args[i-1]
			}
			if !strings.HasPrefix(w, "-") && previous != "-C" && previous != "-c" {
				gitSub = i
				break
			}
		}
		reads = gitSub >= 0 && gitReading[args[gitSub]]
	}
	// A search reads the files it searches, not its pattern; jq reads its
	// files, not its filter.
	var s *search
	if name == "git" {
		if gitSub >= 0 && args[gitSub] == "grep" {
			s = searchOf("git-grep", args[gitSub+1:])
		}
	} else {
		s = searchOf(name, args)
	}
	if s != nil {
		if denial := checkSearch(s, ctx); denial != "" {
			return denial, nil
		}
		reads = false
	}
	// find lists names unless it runs a command on what it finds.
	if name == "find" {
		reads = slices.ContainsFunc(args, func(w string) bool { return slices.Contains(findRuns, w) })
	}
	// cp and mv read their sources; the destination (the last operand) is written.
	if name == "cp" || name == "mv" {
		last := -1
		for i, w := range args {
			if !strings.HasPrefix(w, "-") {
				last = i
			}
		}
		if last >= 0 {
			args = append(slices.Clone(args[:last]), args[last+1:]...)
		}
	}
	for _, w := range words[1:] {
		// --env-file=.env, and git's rev:path form (HEAD:.env).
		for _, candidate := range []string{w, w[strings.LastIndexByte(w, '=')+1:], w[strings.LastIndexByte(w, ':')+1:]} {
			if reads && slices.Contains(args, w) && isProtectedEnvPath(candidate, ctx) {
				return denyEnvFile, nil
			}
			if in, err := isInStore(candidate, ctx); err != nil || in {
				return denyIf(in, denyStore), err
			}
		}
	}
	return "", nil
}

func denyIf(cond bool, denial string) string {
	if cond {
		return denial
	}
	return ""
}

// hook is one run of the handler.
type hook struct{}

// checkCommand is the first denial for a shell command line, or "".
func (h *hook) checkCommand(command string, ctx hookContext, underRun bool, depth int) (string, error) {
	if depth > 8 {
		return "", nil
	}
	l := lexShell(command)
	for _, inner := range l.nested {
		if denial, err := h.checkCommand(inner, ctx, underRun, depth+1); denial != "" || err != nil {
			return denial, err
		}
	}
	for _, seg := range l.segments {
		if denial, err := h.checkSegment(seg, ctx, underRun, depth); denial != "" || err != nil {
			return denial, err
		}
	}
	return "", nil
}

// ---- Tool calls -----------------------------------------------------------------------

var pathKeys = regexp.MustCompile(`(?i)^(file_?path|file_?paths|path|paths|notebook_?path|glob|filename|file|files)$`)

// listingTools list names without reading content.
var listingTools = setOf("Glob", "LS")

func pathsIn(input jsjson.Object) []string {
	var out []string
	for _, m := range input {
		if !pathKeys.MatchString(m.Key) {
			continue
		}
		switch v := m.Value.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

var patchFile = regexp.MustCompile(`(?m)^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$`)

// patchPaths are the files an apply_patch body adds, updates, deletes or
// moves.
func patchPaths(patch string) []string {
	var out []string
	for _, m := range patchFile.FindAllStringSubmatch(patch, -1) {
		p := m[1]
		if p == "" {
			p = m[2]
		}
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// checkToolCall is the denial for a tool call, or "".
func (h *hook) checkToolCall(toolName string, toolInput any, ctx hookContext) (string, error) {
	input, ok := toolInput.(jsjson.Object)
	if _, isArray := toolInput.([]any); isArray {
		// An array is an object to JavaScript, with no key a tool reads.
		input, ok = jsjson.Object{}, true
	}
	if !ok {
		return "", nil
	}
	command, _ := input.Get("command")
	var paths []string
	switch c := command.(type) {
	case string:
		if toolName != "apply_patch" {
			return h.checkCommand(c, ctx, false, 0)
		}
		paths = patchPaths(c)
	case []any:
		words := make([]string, 0, len(c))
		allStrings := true
		for _, w := range c {
			s, isString := w.(string)
			if !isString {
				allStrings = false
				break
			}
			words = append(words, s)
		}
		if allStrings {
			return h.checkSegment(segment{words: words}, ctx, false, 0)
		}
		if listingTools[toolName] {
			return "", nil
		}
		paths = pathsIn(input)
	default:
		if listingTools[toolName] {
			return "", nil
		}
		paths = pathsIn(input)
	}
	for _, path := range paths {
		if isProtectedEnvPath(path, ctx) {
			return denyEnvFile, nil
		}
		if in, err := isInStore(path, ctx); err != nil || in {
			return denyIf(in, denyStore), err
		}
	}
	if toolName == "Grep" {
		return checkSearch(grepToolSearch(input), ctx), nil
	}
	return "", nil
}

// grepToolSearch is Claude Code's Grep tool as a search: its path (the
// directory by default), the way rg searches with hidden files on; lines
// printed only with output_mode "content"; its glob and type narrow the
// files.
func grepToolSearch(input jsjson.Object) *search {
	root := "."
	if p, ok := input.Value("path").(string); ok {
		root = p
	}
	s := &search{roots: []string{root}, recursive: true, scope: "unignored", hidden: true}
	s.printsContent = input.Value("output_mode") == "content"
	if glob, ok := input.Value("glob").(string); ok {
		if strings.HasPrefix(glob, "!") {
			s.exclude = []string{glob[1:]}
		} else {
			s.include = []string{glob}
		}
	}
	_, s.typed = input.Value("type").(string)
	return s
}

// RunHook runs the handler on one event. Claude Code and Codex send the
// same PreToolUse shape and read the same answer: a JSON decision on
// stdout, or nothing for no decision. An event the handler does not
// understand gets no decision. An error is one the handler could not get
// past (no home directory to find the credential store in): no decision.
func RunHook(format, stdin string, env clientctx.Env, processCwd string) (string, error) {
	// JSON.parse refuses a byte order mark, which lib/jsjson skips.
	if strings.HasPrefix(stdin, "\uFEFF") {
		return "", nil
	}
	// JSON.parse has no nesting limit short of memory, so neither does this:
	// a deeply nested event still gets its decision.
	parsed, err := jsjson.ParseDeep([]byte(stdin))
	if err != nil {
		return "", nil
	}
	event, ok := parsed.(jsjson.Object)
	if !ok {
		return "", nil
	}
	toolName, ok := event.Value("tool_name").(string)
	if !ok {
		return "", nil
	}
	if name, present := event.Get("hook_event_name"); present && name != "PreToolUse" {
		return "", nil
	}
	ctx := hookContext{cwd: processCwd, env: env}
	if cwd, ok := event.Value("cwd").(string); ok {
		ctx.cwd = cwd
	}
	if home, _ := env.LookupEnv("HOME"); home != "" {
		ctx.home = home
	} else if ctx.home, err = clientctx.HomeDir(env); err != nil {
		return "", err
	}
	toolInput, _ := event.Get("tool_input")
	denial, err := (&hook{}).checkToolCall(toolName, toolInput, ctx)
	if err != nil || denial == "" {
		return "", err
	}
	_ = format // both formats answer alike
	return string(jsjson.Stringify(jsjson.Object{{Key: "hookSpecificOutput", Value: jsjson.Object{
		{Key: "hookEventName", Value: "PreToolUse"},
		{Key: "permissionDecision", Value: "deny"},
		{Key: "permissionDecisionReason", Value: denial},
	}}})) + "\n", nil
}
