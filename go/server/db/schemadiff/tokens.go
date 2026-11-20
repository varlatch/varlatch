// SPDX-License-Identifier: AGPL-3.0-or-later

package schemadiff

import (
	"fmt"
	"strings"
)

// tokenize splits SQL into tokens, without comments or spacing: string
// literals as written, quoted identifiers unquoted when they need no quotes,
// everything else lower-cased (SQLite's keywords and identifiers are
// case-insensitive). ( ) , ; are tokens of their own; so is each run of word
// characters and each run of other punctuation.
func tokenize(src string) ([]string, error) {
	var out []string
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, fmt.Errorf("an unterminated comment")
			}
			i += end + 4
		case c == '\'':
			j, err := closing(src, i, '\'')
			if err != nil {
				return nil, err
			}
			out = append(out, src[i:j+1])
			i = j + 1
		case c == '"' || c == '`' || c == '[':
			end := c
			if c == '[' {
				end = ']'
			}
			j, err := closing(src, i, end)
			if err != nil {
				return nil, err
			}
			out = append(out, identifier(src[i:j+1]))
			i = j + 1
		case c == '(' || c == ')' || c == ',' || c == ';':
			out = append(out, string(c))
			i++
		case word(c):
			j := i
			for j < len(src) && word(src[j]) {
				j++
			}
			out = append(out, strings.ToLower(src[i:j]))
			i = j
		default:
			j := i
			for j < len(src) && !word(src[j]) && !strings.ContainsRune(" \t\n\r\f\v()',;\"`[", rune(src[j])) &&
				!(src[j] == '-' && j+1 < len(src) && src[j+1] == '-') && !(src[j] == '/' && j+1 < len(src) && src[j+1] == '*') {
				j++
			}
			if j == i {
				j = i + 1
			}
			out = append(out, src[i:j])
			i = j
		}
	}
	return out, nil
}

// closing returns the index of the quote that ends the quoted text starting
// at src[start]; a doubled quote inside it is part of the text.
func closing(src string, start int, quote byte) (int, error) {
	for j := start + 1; j < len(src); j++ {
		if src[j] != quote {
			continue
		}
		if quote != ']' && j+1 < len(src) && src[j+1] == quote {
			j++
			continue
		}
		return j, nil
	}
	return 0, fmt.Errorf("an unterminated quote")
}

func word(c byte) bool {
	return c == '_' || c == '$' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// identifier is a quoted identifier as a token: bare and lower-cased when it
// is a plain word, quoted with " otherwise.
func identifier(q string) string {
	name := unquote(q)
	plain := name != ""
	for i := 0; i < len(name); i++ {
		if !word(name[i]) {
			plain = false
		}
	}
	if plain {
		return strings.ToLower(name)
	}
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// unquote removes an identifier's quotes.
func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	switch s[0] {
	case '"', '`':
		if s[len(s)-1] == s[0] {
			return strings.ReplaceAll(s[1:len(s)-1], string(s[0])+string(s[0]), string(s[0]))
		}
	case '[':
		if s[len(s)-1] == ']' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func join(toks []string) string { return strings.Join(toks, " ") }
