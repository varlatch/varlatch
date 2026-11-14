// SPDX-License-Identifier: AGPL-3.0-or-later

package db

// A small parser for the SQL expressions of CHECK constraints and index
// predicates, so that mapping_test.go compares PostgreSQL's and SQLite's
// by structure: grouping and literal contents count, while the spellings
// that differ only by dialect do not. It parses into a tree with SQLite's
// operator precedence (PostgreSQL's deparser parenthesizes every operation,
// so its text parses the same either way) and prints the tree in one
// canonical form:
//
//   - redundant parentheses vanish, since the tree holds the grouping;
//   - identifiers and keywords are case-insensitive, quotes around
//     identifiers are dropped; string literals are kept exactly;
//   - PostgreSQL's casts (x::text) are dropped; x = ANY (ARRAY[...]) is
//     x IN (...), x <> ALL (ARRAY[...]) is x NOT IN (...); IS DISTINCT FROM
//     is IS NOT, NOT (a IS DISTINCT FROM b) is a IS b; char_length is length;
//   - SQLite's a BETWEEN b AND c is a >= b AND a <= c, as PostgreSQL prints
//     it; == is =, != is <>;
//   - a chain of ANDs (or of ORs) is one list, whatever its grouping, since
//     the operators are associative.

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokKeyword
	tokString
	tokNumber
	tokOp
)

type token struct {
	kind tokKind
	text string // keywords upper-case, identifiers lower-case, strings unquoted
}

var keywords = map[string]bool{
	"AND": true, "OR": true, "NOT": true, "IS": true, "NULL": true, "IN": true, "LIKE": true, "GLOB": true,
	"BETWEEN": true, "DISTINCT": true, "FROM": true, "ARRAY": true, "ANY": true, "ALL": true, "TRUE": true, "FALSE": true,
}

func tokenize(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'':
			var b strings.Builder
			i++
			for {
				if i >= len(s) {
					return nil, fmt.Errorf("unterminated string in %q", s)
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(s[i])
				i++
			}
			out = append(out, token{tokString, b.String()})
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				return nil, fmt.Errorf("unterminated identifier in %q", s)
			}
			out = append(out, token{tokIdent, strings.ToLower(s[i+1 : i+1+j])})
			i += j + 2
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, token{tokNumber, s[i:j]})
			i = j
		case c == '_' || unicode.IsLetter(rune(c)):
			j := i
			for j < len(s) && (s[j] == '_' || unicode.IsLetter(rune(s[j])) || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			w := s[i:j]
			if keywords[strings.ToUpper(w)] {
				out = append(out, token{tokKeyword, strings.ToUpper(w)})
			} else {
				out = append(out, token{tokIdent, strings.ToLower(w)})
			}
			i = j
		default:
			op := ""
			for _, o := range []string{"->>", "::", "<>", "!=", ">=", "<=", "==", "||", "->"} {
				if strings.HasPrefix(s[i:], o) {
					op = o
					break
				}
			}
			if op == "" {
				if !strings.ContainsRune("()[],=<>+-*/%.", rune(c)) {
					return nil, fmt.Errorf("unexpected %q in %q", c, s)
				}
				op = string(c)
			}
			out = append(out, token{tokOp, op})
			i += len(op)
		}
	}
	return append(out, token{kind: tokEOF}), nil
}

// node is a parsed expression; its canonical text is the comparison key.
type node struct {
	op   string // "id", "str", "num", "null", "bool", "call", "not", "neg", "and", "or", "in", "notin", "isnull", "notnull", "array", or a binary operator
	text string
	args []*node
}

func (n *node) String() string {
	switch n.op {
	case "id", "num", "null", "bool":
		return n.text
	case "str":
		return "'" + strings.ReplaceAll(n.text, "'", "''") + "'"
	}
	parts := make([]string, len(n.args))
	for i, a := range n.args {
		parts[i] = a.String()
	}
	name := n.op
	if n.op == "call" {
		name = "call " + n.text
	}
	return "(" + name + " " + strings.Join(parts, " ") + ")"
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }
func (p *parser) is(kind tokKind, text string) bool {
	t := p.peek()
	return t.kind == kind && t.text == text
}
func (p *parser) expect(kind tokKind, text string) error {
	if !p.is(kind, text) {
		return fmt.Errorf("expected %q at %q", text, p.peek().text)
	}
	p.pos++
	return nil
}

// Binding powers, SQLite's order from loosest to tightest.
const (
	bpOr    = 1
	bpAnd   = 2
	bpNot   = 3
	bpEq    = 4 // = <> IS IN LIKE GLOB BETWEEN
	bpRel   = 5 // < > <= >=
	bpAdd   = 7
	bpMul   = 8
	bpCat   = 9 // || -> ->>
	bpUnary = 10
	bpCast  = 11
)

func parseExpr(s string) (*node, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.expr(0)
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q after the expression in %q", p.peek().text, s)
	}
	return canonical(n), nil
}

func (p *parser) list(end string) ([]*node, error) {
	var out []*node
	for !p.is(tokOp, end) {
		e, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		if !p.is(tokOp, ",") {
			break
		}
		p.pos++
	}
	return out, p.expect(tokOp, end)
}

func (p *parser) primary() (*node, error) {
	t := p.next()
	switch {
	case t.kind == tokString:
		return &node{op: "str", text: t.text}, nil
	case t.kind == tokNumber:
		return &node{op: "num", text: t.text}, nil
	case t.kind == tokKeyword && t.text == "NULL":
		return &node{op: "null", text: "NULL"}, nil
	case t.kind == tokKeyword && (t.text == "TRUE" || t.text == "FALSE"):
		return &node{op: "bool", text: t.text}, nil
	case t.kind == tokKeyword && t.text == "NOT":
		e, err := p.expr(bpNot)
		return &node{op: "not", args: []*node{e}}, err
	case t.kind == tokOp && (t.text == "-" || t.text == "+"):
		e, err := p.expr(bpUnary)
		if t.text == "+" {
			return e, err
		}
		return &node{op: "neg", args: []*node{e}}, err
	case t.kind == tokOp && t.text == "(":
		e, err := p.expr(0)
		if err != nil {
			return nil, err
		}
		return e, p.expect(tokOp, ")")
	case t.kind == tokKeyword && t.text == "ARRAY":
		if err := p.expect(tokOp, "["); err != nil {
			return nil, err
		}
		items, err := p.list("]")
		return &node{op: "array", args: items}, err
	case t.kind == tokIdent:
		if p.is(tokOp, "(") {
			p.pos++
			args, err := p.list(")")
			return &node{op: "call", text: t.text, args: args}, err
		}
		return &node{op: "id", text: t.text}, nil
	}
	return nil, fmt.Errorf("unexpected %q", t.text)
}

func bin(op string, l, r *node) *node { return &node{op: op, args: []*node{l, r}} }

func (p *parser) expr(min int) (*node, error) {
	left, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		var op string
		var bp int
		switch {
		case t.kind == tokOp && t.text == "::":
			if bpCast < min {
				return left, nil
			}
			p.pos++
			if p.next().kind != tokIdent { // the type name, dropped
				return nil, fmt.Errorf("expected a type after ::")
			}
			if p.is(tokOp, "[") {
				p.pos++
				if err := p.expect(tokOp, "]"); err != nil {
					return nil, err
				}
			}
			continue
		case t.kind == tokKeyword && (t.text == "OR" || t.text == "AND"):
			op, bp = strings.ToLower(t.text), map[string]int{"OR": bpOr, "AND": bpAnd}[t.text]
		case t.kind == tokKeyword && (t.text == "IS" || t.text == "IN" || t.text == "LIKE" || t.text == "GLOB" || t.text == "BETWEEN" || t.text == "NOT"):
			op, bp = t.text, bpEq
		case t.kind == tokOp && (t.text == "=" || t.text == "==" || t.text == "<>" || t.text == "!="):
			op, bp = t.text, bpEq
		case t.kind == tokOp && (t.text == "<" || t.text == ">" || t.text == "<=" || t.text == ">="):
			op, bp = t.text, bpRel
		case t.kind == tokOp && (t.text == "+" || t.text == "-"):
			op, bp = t.text, bpAdd
		case t.kind == tokOp && (t.text == "*" || t.text == "/" || t.text == "%"):
			op, bp = t.text, bpMul
		case t.kind == tokOp && (t.text == "||" || t.text == "->" || t.text == "->>"):
			op, bp = t.text, bpCat
		default:
			return left, nil
		}
		if bp < min {
			return left, nil
		}
		p.pos++
		right := func() (*node, error) { return p.expr(bp + 1) }
		switch op {
		case "IS":
			not := false
			if p.is(tokKeyword, "NOT") {
				p.pos++
				not = true
			}
			if p.is(tokKeyword, "NULL") {
				p.pos++
				left = &node{op: map[bool]string{false: "isnull", true: "notnull"}[not], args: []*node{left}}
				continue
			}
			if p.is(tokKeyword, "DISTINCT") {
				p.pos++
				if err := p.expect(tokKeyword, "FROM"); err != nil {
					return nil, err
				}
				not = !not // IS DISTINCT FROM is IS NOT
			}
			r, err := right()
			if err != nil {
				return nil, err
			}
			left = bin(map[bool]string{false: "is", true: "isnot"}[not], left, r)
		case "NOT":
			// NOT IN, NOT LIKE, NOT GLOB, NOT BETWEEN
			inner := p.next()
			if inner.kind != tokKeyword {
				return nil, fmt.Errorf("unexpected NOT %q", inner.text)
			}
			e, err := p.infixKeyword(inner.text, left, bp)
			if err != nil {
				return nil, err
			}
			left = &node{op: "not", args: []*node{e}}
		case "IN", "LIKE", "GLOB", "BETWEEN":
			if left, err = p.infixKeyword(op, left, bp); err != nil {
				return nil, err
			}
		case "=", "==", "<>", "!=":
			eq := op == "=" || op == "=="
			if p.is(tokKeyword, "ANY") || p.is(tokKeyword, "ALL") {
				p.pos++
				if err := p.expect(tokOp, "("); err != nil {
					return nil, err
				}
				arr, err := p.expr(0)
				if err != nil {
					return nil, err
				}
				if err := p.expect(tokOp, ")"); err != nil {
					return nil, err
				}
				if arr.op != "array" {
					return nil, fmt.Errorf("ANY/ALL over something other than ARRAY[...]")
				}
				left = &node{op: "in", args: append([]*node{left}, arr.args...)}
				if !eq {
					left = &node{op: "not", args: []*node{left}}
				}
				continue
			}
			r, err := right()
			if err != nil {
				return nil, err
			}
			left = bin(map[bool]string{true: "=", false: "<>"}[eq], left, r)
		default:
			r, err := right()
			if err != nil {
				return nil, err
			}
			left = bin(op, left, r)
		}
	}
}

func (p *parser) infixKeyword(op string, left *node, bp int) (*node, error) {
	switch op {
	case "IN":
		if err := p.expect(tokOp, "("); err != nil {
			return nil, err
		}
		items, err := p.list(")")
		return &node{op: "in", args: append([]*node{left}, items...)}, err
	case "LIKE", "GLOB":
		r, err := p.expr(bp + 1)
		return bin(strings.ToLower(op), left, r), err
	case "BETWEEN":
		lo, err := p.expr(bpRel)
		if err != nil {
			return nil, err
		}
		if err := p.expect(tokKeyword, "AND"); err != nil {
			return nil, err
		}
		hi, err := p.expr(bpRel)
		if err != nil {
			return nil, err
		}
		return &node{op: "and", args: []*node{bin(">=", left, lo), bin("<=", left, hi)}}, nil
	}
	return nil, fmt.Errorf("unexpected %s", op)
}

// canonical applies the rewrites that make two spellings of one expression
// equal.
func canonical(n *node) *node {
	for i, a := range n.args {
		n.args[i] = canonical(a)
	}
	switch n.op {
	case "call":
		if n.text == "char_length" {
			n.text = "length"
		}
	case "not":
		a := n.args[0]
		switch a.op {
		case "isnot": // NOT (a IS DISTINCT FROM b)
			return bin("is", a.args[0], a.args[1])
		case "in":
			return &node{op: "notin", args: a.args}
		case "like", "glob":
			return &node{op: "not" + a.op, args: a.args}
		}
	case "and", "or":
		var flat []*node
		for _, a := range n.args {
			if a.op == n.op {
				flat = append(flat, a.args...)
			} else {
				flat = append(flat, a)
			}
		}
		n.args = flat
	}
	return n
}

func canonicalExpr(t *testing.T, where, e string) string {
	t.Helper()
	n, err := parseExpr(strings.TrimPrefix(strings.TrimSpace(e), "CHECK "))
	if err != nil {
		t.Errorf("%s: %v", where, err)
		return "unparsable: " + e
	}
	return n.String()
}

func TestExpressionComparison(t *testing.T) {
	same := [][2]string{
		{`CHECK (((origin = 'dashboard'::text) = (auth_session_id IS NOT NULL)))`, `(origin = 'dashboard') = (auth_session_id IS NOT NULL)`},
		{`CHECK ((kind = ANY (ARRAY['service'::text, 'cli'::text])))`, `kind IN ('service', 'cli')`},
		{`CHECK (((operation <> ALL (ARRAY['a'::text, 'b'::text])) OR (organization_id IS NOT NULL)))`, `operation NOT IN ('a', 'b') OR organization_id IS NOT NULL`},
		{`CHECK (((client IS NULL) OR ((char_length(client) >= 1) AND (char_length(client) <= 64))))`, `client IS NULL OR length(client) BETWEEN 1 AND 64`},
		{`CHECK (((NOT (trusted_via IS DISTINCT FROM 'setup-grant'::text)) = (setup_grant_kind IS NOT NULL)))`, `(trusted_via IS 'setup-grant') = (setup_grant_kind IS NOT NULL)`},
		{`CHECK (((lift_method IS DISTINCT FROM 'approval'::text) OR (lifted_by IS NOT NULL)))`, `lift_method IS NOT 'approval' OR lifted_by IS NOT NULL`},
		{`CHECK ((((a IS NULL) AND (b = 'x'::text)) OR ((a IS NOT NULL) AND (b = ANY (ARRAY['y'::text, 'z'::text])))))`, `(a IS NULL AND b = 'x') OR (a IS NOT NULL AND b IN ('y', 'z'))`},
		{`((consumed_at IS NULL) AND (closed_at IS NULL))`, `consumed_at IS NULL AND closed_at IS NULL`},
		{`CHECK (("Counter" > 0))`, `counter > 0`},
		{`CHECK ((a AND b AND c))`, `a AND (b AND c)`},
	}
	for _, c := range same {
		if a, b := canonicalExpr(t, "postgres", c[0]), canonicalExpr(t, "sqlite", c[1]); a != b {
			t.Errorf("should compare equal:\n  %s -> %s\n  %s -> %s", c[0], a, c[1], b)
		}
	}
	different := [][2]string{
		// Grouping counts: SQLite reads this as ((origin = 'dashboard') = auth_session_id) IS NOT NULL.
		{`CHECK (((origin = 'dashboard'::text) = (auth_session_id IS NOT NULL)))`, `origin = 'dashboard' = auth_session_id IS NOT NULL`},
		// A literal's contents count, case included.
		{`CHECK ((mode = ANY (ARRAY['off'::text, 'report'::text, 'enforce'::text])))`, `mode IN ('off', 'report', 'ENFORCE')`},
		{`CHECK ((mode = 'a b'::text))`, `mode = 'ab'`},
		{`CHECK (((a IS NULL) OR (b AND c)))`, `(a IS NULL OR b) AND c`},
		{`CHECK ((x > 0))`, `x >= 0`},
		{`CHECK ((kind = ANY (ARRAY['a'::text, 'b'::text])))`, `kind NOT IN ('a', 'b')`},
		{`CHECK ((n <= 5))`, `n BETWEEN 1 AND 5`},
	}
	for _, c := range different {
		if a, b := canonicalExpr(t, "postgres", c[0]), canonicalExpr(t, "sqlite", c[1]); a == b {
			t.Errorf("should compare different, both are %s:\n  %s\n  %s", a, c[0], c[1])
		}
	}
}
