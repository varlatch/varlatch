// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// envEntry is one variable of an installation's .env, with the bytes of
// the whole lines it stands on.
type envEntry struct {
	name, value string
	// expands: the value holds a $ that Compose expands, which migrate does
	// not.
	expands    bool
	start, end int
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// parseComposeEnv reads a .env as Compose does (measured with Compose
// 5.6.1): NAME=value or NAME: value, an export prefix, blank and # lines;
// an unquoted value ends at " #" and is trimmed; a quoted one may span
// lines, and what follows its closing quote on the line is not part of it;
// \n, \r, \t and escaped quotes in double quotes. It is migrate's only
// reader and writer of .env. A line of any length is read whole. The error
// names a line, never its text.
func parseComposeEnv(b []byte) ([]envEntry, error) {
	var out []envEntry
	for pos := 0; pos < len(b); {
		start := pos
		eol := lineEnd(b, pos)
		line := strings.TrimSpace(string(b[pos:eol]))
		next := min(eol+1, len(b))
		if line == "" || line[0] == '#' {
			pos = next
			continue
		}
		at := pos
		if i := bytes.IndexAny(b[pos:eol], "=:"); i >= 0 {
			at = pos + i
		} else {
			pos = next // a name alone takes the shell's value
			continue
		}
		name := strings.TrimSpace(string(b[pos:at]))
		if rest, ok := strings.CutPrefix(name, "export"); ok && rest != "" && strings.ContainsAny(rest[:1], " \t") {
			name = strings.TrimSpace(rest)
		}
		if !envName.MatchString(name) {
			pos = next
			continue
		}
		v := at + 1
		for v < eol && (b[v] == ' ' || b[v] == '\t') {
			v++
		}
		e := envEntry{name: name, start: start}
		if v < eol && (b[v] == '"' || b[v] == '\'') {
			q, end := b[v], -1
			for i := v + 1; i < len(b); i++ {
				if b[i] == '\\' {
					i++
					continue
				}
				if b[i] == q {
					end = i
					break
				}
			}
			if end < 0 {
				return nil, fmt.Errorf("line %d: a quoted value is not closed", 1+bytes.Count(b[:start], []byte("\n")))
			}
			e.value = string(b[v+1 : end])
			if q == '"' {
				e.expands = strings.Contains(e.value, "$")
				e.value = strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t", `\"`, `"`, `\\`, `\`).Replace(e.value)
			} else {
				e.value = strings.ReplaceAll(e.value, `\'`, `'`)
			}
			next = min(lineEnd(b, end)+1, len(b))
		} else {
			text, _, _ := strings.Cut(string(b[v:eol]), " #")
			e.value = strings.TrimSpace(text)
			if strings.HasPrefix(e.value, "#") && v > at+1 {
				e.value = "" // NAME= # a comment
			}
			e.expands = strings.Contains(e.value, "$")
		}
		e.end = next
		out = append(out, e)
		pos = next
	}
	return out, nil
}

// lineEnd is where the line at pos ends (its newline, or the end).
func lineEnd(b []byte, pos int) int {
	if i := bytes.IndexByte(b[pos:], '\n'); i >= 0 {
		return pos + i
	}
	return len(b)
}

func (c *Compose) envPath() string { return filepath.Join(c.Directory, ".env") }

func (c *Compose) envEntries() ([]envEntry, []byte, error) {
	b, err := os.ReadFile(c.envPath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	entries, err := parseComposeEnv(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", c.envPath(), err)
	}
	return entries, b, nil
}

// envFile is the installation's .env: the last of a name wins.
func (c *Compose) envFile() (map[string]string, error) {
	entries, _, err := c.envEntries()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		out[e.name] = e.value
	}
	return out, nil
}

// envValue is one of .env's values, and whether it is set. One of Compose's
// own variables that is expanded from others is refused: what it names is
// not read here.
func (c *Compose) envValue(name string) (string, bool, error) {
	entries, _, err := c.envEntries()
	if err != nil {
		return "", false, err
	}
	value, set, expands := "", false, false
	for _, e := range entries {
		if e.name == name {
			value, set, expands = e.value, true, e.expands
		}
	}
	if expands && strings.HasPrefix(name, "COMPOSE_") {
		return "", false, fmt.Errorf("%s sets %s from another variable: write its value there, so that migrate reads the one Compose does", c.envPath(), name)
	}
	return value, set, nil
}

// envRaw is the lines of .env that set name, as they are ("" for none).
func (c *Compose) envRaw(name string) (string, error) {
	entries, b, err := c.envEntries()
	if err != nil {
		return "", err
	}
	raw := ""
	for _, e := range entries {
		if e.name == name {
			raw += string(b[e.start:e.end])
		}
	}
	return raw, nil
}

// plainEnv are the values an unquoted .env value holds as they are.
var plainEnv = regexp.MustCompile(`^[A-Za-z0-9_./:;,@%+=~-]*$`)

// envQuote is value as .env holds it.
func envQuote(value string) (string, error) {
	if plainEnv.MatchString(value) {
		return value, nil
	}
	if strings.ContainsAny(value, "'\\\n\r") {
		return "", errors.New("the value has a quote, a backslash or a line end, which is not written there")
	}
	return "'" + value + "'", nil
}

// setEnv writes .env with name set to value (nil: its lines removed), every
// other byte as it was. raw, when not empty, is written instead (envRaw's
// lines, to put them back as they were). A .env that is a symbolic link is
// written at its target, which is replaced through a temporary name beside
// it; the link stays. A link whose target is not there is refused, never
// replaced by a file. Its mode is kept.
func (c *Compose) setEnv(name string, value *string, raw string) error {
	path := c.envPath()
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if st, lerr := os.Lstat(path); lerr == nil && st.Mode()&fs.ModeSymlink != 0 {
		link, _ := os.Readlink(path)
		return fmt.Errorf("%s is a symbolic link to %s, which is not there: the installation's .env is not replaced by a file; restore its target, then run varlatch migrate again", path, link)
	}
	entries, b, err := c.envEntries()
	if err != nil {
		return err
	}
	mode := fs.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	text := raw
	if text == "" && value != nil {
		quoted, err := envQuote(*value)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", path, name, err)
		}
		text = name + "=" + quoted + "\n"
	}
	var out bytes.Buffer
	from, done := 0, false
	for _, e := range entries {
		if e.name != name {
			continue
		}
		out.Write(b[from:e.start])
		if !done {
			out.WriteString(text)
			if text != "" && !strings.HasSuffix(text, "\n") && e.end < len(b) {
				out.WriteByte('\n')
			}
			done = true
		}
		from = e.end
	}
	out.Write(b[from:])
	if !done && text != "" {
		if out.Len() > 0 && !bytes.HasSuffix(out.Bytes(), []byte("\n")) {
			out.WriteByte('\n')
		}
		out.WriteString(text)
	}
	return writeFileDurably(path, out.Bytes(), mode)
}
