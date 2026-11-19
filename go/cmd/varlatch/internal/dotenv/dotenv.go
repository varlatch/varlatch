// SPDX-License-Identifier: Apache-2.0

// Package dotenv is the dotenv parser behind `varlatch import` (ADR-0043
// Decision 2), a port of apps/cli/src/dotenv.ts. It reads the common
// dotenv format:
//
//	# comment
//	NAME=value                 unquoted: trimmed; whitespace then `#` starts a comment
//	export NAME=value          an `export ` prefix is ignored
//	NAME = value               spaces or tabs around `=` are allowed
//	NAME='literal'             single quotes and backticks: taken as written,
//	NAME=`literal`             and may span lines
//	NAME="text\n"              double quotes: \n \r \t \" \\ are escapes, and
//	                           may span lines
//	NAME=                      an empty value
//
// Nothing is expanded: `$OTHER` and `${OTHER}` stay as written. Errors
// carry a line number and a reason, never the line's text or any part of a
// value, since the file holds secrets.
//
// The text is UTF-8 (import decodes it strictly first); every character
// the grammar looks at is ASCII, so it is read byte by byte.
package dotenv

import (
	"regexp"
	"strconv"
	"strings"
)

// Entry is one NAME=value, with the 1-based line it starts on.
type Entry struct {
	Name  string
	Value string
	Line  int
}

// ParseError is DotenvParseError: "line <n>: <reason>".
type ParseError struct {
	Line   int
	Reason string
}

func (e *ParseError) Error() string { return "line " + strconv.Itoa(e.Line) + ": " + e.Reason }

var (
	name        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*`)
	exportWord  = regexp.MustCompile(`^export[ \t]+`)
	lineBreak   = regexp.MustCompile(`\r?\n`)
	commentMark = regexp.MustCompile(`[ \t]#`)
)

func trimLeft(s string) string  { return strings.TrimLeft(s, " \t") }
func trimRight(s string) string { return strings.TrimRight(s, " \t") }

// Parse is parseDotenv.
func Parse(source string) ([]Entry, error) {
	text := strings.TrimPrefix(source, "\uFEFF")
	lines := lineBreak.Split(text, -1)
	var entries []Entry
	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		rest := trimLeft(lines[i])
		if rest == "" || strings.HasPrefix(rest, "#") {
			continue
		}
		if m := exportWord.FindString(rest); m != "" {
			rest = rest[len(m):]
		}
		n := name.FindString(rest)
		if n == "" {
			return nil, &ParseError{lineNo, "expected NAME=value"}
		}
		rest = trimLeft(rest[len(n):])
		if !strings.HasPrefix(rest, "=") {
			return nil, &ParseError{lineNo, "expected NAME=value"}
		}
		rest = trimLeft(rest[1:])

		if rest != "" && (rest[0] == '\'' || rest[0] == '`' || rest[0] == '"') {
			quote := rest[0]
			// A quoted value may continue on the following lines.
			body := rest[1:]
			var value strings.Builder
			end := -1
			for {
				end = closingQuote(body, quote)
				if end >= 0 {
					value.WriteString(body[:end])
					break
				}
				value.WriteString(body)
				value.WriteByte('\n')
				i++
				if i >= len(lines) {
					return nil, &ParseError{lineNo, "a quoted value is not closed"}
				}
				body = lines[i]
			}
			after := trimLeft(body[end+1:])
			if after != "" && !strings.HasPrefix(after, "#") {
				return nil, &ParseError{i + 1, "unexpected text after a closing quote"}
			}
			v := value.String()
			if quote == '"' {
				var err error
				if v, err = unescape(v, lineNo); err != nil {
					return nil, err
				}
			}
			entries = append(entries, Entry{Name: n, Value: v, Line: lineNo})
			continue
		}
		// Unquoted: up to a comment (whitespace, then #), trimmed.
		if loc := commentMark.FindStringIndex(rest); loc != nil {
			rest = rest[:loc[0]]
		}
		entries = append(entries, Entry{Name: n, Value: trimRight(rest), Line: lineNo})
	}
	return entries, nil
}

// closingQuote is the index of the quote that closes a value, or -1; in
// double quotes a backslash escapes the next character.
func closingQuote(body string, quote byte) int {
	for j := 0; j < len(body); j++ {
		if quote == '"' && body[j] == '\\' {
			j++
			continue
		}
		if body[j] == quote {
			return j
		}
	}
	return -1
}

var escapes = map[byte]string{'n': "\n", 'r': "\r", 't': "\t", '"': `"`, '\\': `\`}

func unescape(value string, line int) (string, error) {
	var out strings.Builder
	for j := 0; j < len(value); j++ {
		if value[j] != '\\' {
			out.WriteByte(value[j])
			continue
		}
		if j+1 >= len(value) {
			return "", &ParseError{line, "a double-quoted value ends in a backslash"}
		}
		next := value[j+1]
		if e, ok := escapes[next]; ok {
			out.WriteString(e)
		} else {
			// An unknown escape keeps its backslash, as common dotenv parsers do.
			out.WriteByte('\\')
			out.WriteByte(next)
		}
		j++
	}
	return out.String(), nil
}
