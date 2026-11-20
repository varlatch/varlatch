// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The two sections after the tables (BUNDLE.md, "The check sections"):
// the writer's keyed digest of every encrypted item (decision 7) and its
// evaluator's decisions (decision 8), which the migration's checks hold the
// target against.

// Digest is one encrypted item's keyed digest: HMAC-SHA256 under the
// migration's run key over canonical.DigestInput(Class, IDs, plaintext).
type Digest struct {
	Class string
	IDs   map[string]string
	// HMAC is 64 lowercase hex digits.
	HMAC string
}

// IDsText is the digest's ids as a bundle writes them: canonical JSON,
// members in jsonb's order. Digests are written in (class, IDsText) order.
func (d Digest) IDsText() string {
	o := jsvalue.Object{}
	for k, v := range d.IDs {
		o = append(o, jsvalue.Member{Key: k, Value: v})
	}
	return string(jsvalue.Stringify(jsvalue.Jsonb(o)))
}

// CompareDigests is the digests' order: by class, then by IDsText's bytes.
func CompareDigests(a, b Digest) int {
	if c := bytes.Compare([]byte(a.Class), []byte(b.Class)); c != 0 {
		return c
	}
	return bytes.Compare([]byte(a.IDsText()), []byte(b.IDsText()))
}

func (d Digest) line() []byte {
	return []byte(`{"class":` + string(jsvalue.Stringify(d.Class)) + `,"ids":` + d.IDsText() + `,"hmac":` + string(jsvalue.Stringify(d.HMAC)) + `}`)
}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (d Digest) check() error {
	switch {
	case d.Class == "":
		return errors.New("bundle: a digest without its class")
	case len(d.IDs) == 0:
		return fmt.Errorf("bundle: a %s digest without its ids", d.Class)
	case !hexDigest.MatchString(d.HMAC):
		return fmt.Errorf("bundle: a %s digest that is not 64 lowercase hex digits", d.Class)
	}
	return nil
}

// Credential states a decision is evaluated in (decision 8).
const (
	Active  = "active"
	Expired = "expired"
	Revoked = "revoked"
)

// Tailnet is the Tailnet Context a decision is evaluated with.
type Tailnet struct {
	Tailnet   string
	NodeID    string
	Tags      []string
	UserLogin *string
}

// Decision is one row of the writer's decision table: the credential, in
// the given state, asking for the action on the resource (Project and
// Environment "" for none), with the Tailnet Context (nil for none), and
// the evaluator's answer: allowed, or the error code it denied with.
type Decision struct {
	Credential   string
	State        string
	Organization string
	Project      string
	Environment  string
	Action       string
	Tailnet      *Tailnet
	Allowed      bool
	Code         string
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (d Decision) line() []byte {
	var tn any
	if d.Tailnet != nil {
		tags := make([]any, len(d.Tailnet.Tags))
		for i, s := range d.Tailnet.Tags {
			tags[i] = s
		}
		var login any
		if d.Tailnet.UserLogin != nil {
			login = *d.Tailnet.UserLogin
		}
		tn = jsvalue.Object{{Key: "tailnet", Value: d.Tailnet.Tailnet}, {Key: "nodeId", Value: d.Tailnet.NodeID},
			{Key: "tags", Value: tags}, {Key: "userLogin", Value: login}}
	}
	return jsvalue.Stringify(jsvalue.Object{
		{Key: "credential", Value: d.Credential}, {Key: "state", Value: d.State},
		{Key: "organization", Value: d.Organization}, {Key: "project", Value: orNull(d.Project)},
		{Key: "environment", Value: orNull(d.Environment)}, {Key: "action", Value: d.Action},
		{Key: "tailnet", Value: tn}, {Key: "allowed", Value: d.Allowed}, {Key: "code", Value: orNull(d.Code)},
	})
}

func (d Decision) check() error {
	switch {
	case d.Credential == "" || d.Organization == "" || d.Action == "":
		return errors.New("bundle: a decision without its credential, organization or action")
	case !slices.Contains([]string{Active, Expired, Revoked}, d.State):
		return fmt.Errorf("bundle: a decision in state %q, not active, expired or revoked", d.State)
	case d.Environment != "" && d.Project == "":
		return errors.New("bundle: a decision on an environment outside a Project")
	case d.Allowed == (d.Code != ""):
		return errors.New("bundle: a decision allowed with an error code, or denied without one")
	case d.Tailnet != nil && (d.Tailnet.Tailnet == "" || d.Tailnet.NodeID == ""):
		return errors.New("bundle: a decision's Tailnet Context without its tailnet or node")
	}
	return nil
}

// Digests starts the digest section, after the last table, with its count.
func (w *Writer) Digests(n int) error {
	if w.err != nil {
		return w.err
	}
	if w.left != 0 || w.next != len(w.tables) || w.section != 0 {
		return errors.New("bundle: the digests follow the last table's rows")
	}
	if n < 0 {
		return errors.New("bundle: a negative digest count")
	}
	w.section, w.left = 1, n
	w.nDigests = n
	w.line(jsvalue.Stringify(jsvalue.Object{{Key: "digests", Value: n}}))
	return w.err
}

// Digest writes the next digest; they come in CompareDigests order, each
// once.
func (w *Writer) Digest(d Digest) error {
	if w.err != nil {
		return w.err
	}
	if w.section != 1 || w.left <= 0 {
		return errors.New("bundle: a digest beyond the section's count")
	}
	if err := d.check(); err != nil {
		return err
	}
	if w.lastDigest != nil && CompareDigests(*w.lastDigest, d) >= 0 {
		return fmt.Errorf("bundle: a %s digest out of order, or written twice", d.Class)
	}
	w.lastDigest = &d
	w.left--
	w.line(d.line())
	return w.err
}

// Decisions starts the decision section, after the digests, with its count
// and the moment the decisions were evaluated at (Unix microseconds).
func (w *Writer) Decisions(n int, at int64) error {
	if w.err != nil {
		return w.err
	}
	if w.section != 1 || w.left != 0 {
		return errors.New("bundle: the decisions follow the last digest")
	}
	if n < 0 {
		return errors.New("bundle: a negative decision count")
	}
	w.section, w.left = 2, n
	w.nDecisions = n
	w.line(jsvalue.Stringify(jsvalue.Object{{Key: "decisions", Value: n}, {Key: "at", Value: at}}))
	return w.err
}

// Decision writes the next decision.
func (w *Writer) Decision(d Decision) error {
	if w.err != nil {
		return w.err
	}
	if w.section != 2 || w.left <= 0 {
		return errors.New("bundle: a decision beyond the section's count")
	}
	if err := d.check(); err != nil {
		return err
	}
	w.left--
	w.line(d.line())
	return w.err
}

// Digests reads the digest section's line, after the last table: its count.
func (r *Reader) Digests() (int, error) {
	if r.left != 0 || r.next != len(r.tables) || r.section != 0 {
		return 0, errors.New("bundle: the digests follow the last table's rows")
	}
	line, err := r.line()
	if err != nil {
		return 0, err
	}
	var s struct {
		Digests *int `json:"digests"`
	}
	if err := strict(line, &s); err != nil || s.Digests == nil || *s.Digests < 0 {
		return 0, fmt.Errorf("bundle: the digest section's line was due: %s", shortLine(line))
	}
	r.section, r.left, r.nDigests = 1, *s.Digests, *s.Digests
	return *s.Digests, nil
}

// Digest reads the next digest, in its canonical form and order.
func (r *Reader) Digest() (Digest, error) {
	if r.section != 1 || r.left <= 0 {
		return Digest{}, errors.New("bundle: no digest is due")
	}
	line, err := r.line()
	if err != nil {
		return Digest{}, err
	}
	var raw struct {
		Class *string            `json:"class"`
		IDs   *map[string]string `json:"ids"`
		HMAC  *string            `json:"hmac"`
	}
	if err := strict(line, &raw); err != nil || raw.Class == nil || raw.IDs == nil || raw.HMAC == nil {
		return Digest{}, fmt.Errorf("bundle: a digest line was due: %s", shortLine(line))
	}
	d := Digest{Class: *raw.Class, IDs: *raw.IDs, HMAC: *raw.HMAC}
	if err := d.check(); err != nil {
		return Digest{}, err
	}
	if !bytes.Equal(d.line(), line) {
		return Digest{}, fmt.Errorf("bundle: a %s digest not in canonical form", d.Class)
	}
	if r.lastDigest != nil && CompareDigests(*r.lastDigest, d) >= 0 {
		return Digest{}, fmt.Errorf("bundle: a %s digest out of order, or written twice", d.Class)
	}
	r.lastDigest = &d
	r.left--
	return d, nil
}

// Decisions reads the decision section's line, after the last digest: its
// count and the moment of evaluation.
func (r *Reader) Decisions() (n int, at int64, err error) {
	if r.section != 1 || r.left != 0 {
		return 0, 0, errors.New("bundle: the decisions follow the last digest")
	}
	line, err := r.line()
	if err != nil {
		return 0, 0, err
	}
	var s struct {
		Decisions *int   `json:"decisions"`
		At        *int64 `json:"at"`
	}
	if err := strict(line, &s); err != nil || s.Decisions == nil || s.At == nil || *s.Decisions < 0 {
		return 0, 0, fmt.Errorf("bundle: the decision section's line was due: %s", shortLine(line))
	}
	r.section, r.left, r.nDecisions = 2, *s.Decisions, *s.Decisions
	return *s.Decisions, *s.At, nil
}

// Decision reads the next decision, in its canonical form.
func (r *Reader) Decision() (Decision, error) {
	if r.section != 2 || r.left <= 0 {
		return Decision{}, errors.New("bundle: no decision is due")
	}
	line, err := r.line()
	if err != nil {
		return Decision{}, err
	}
	var raw struct {
		Credential   *string `json:"credential"`
		State        *string `json:"state"`
		Organization *string `json:"organization"`
		Project      *string `json:"project"`
		Environment  *string `json:"environment"`
		Action       *string `json:"action"`
		Tailnet      *struct {
			Tailnet   *string   `json:"tailnet"`
			NodeID    *string   `json:"nodeId"`
			Tags      *[]string `json:"tags"`
			UserLogin *string   `json:"userLogin"`
		} `json:"tailnet"`
		Allowed *bool   `json:"allowed"`
		Code    *string `json:"code"`
	}
	if err := strict(line, &raw); err != nil || raw.Credential == nil || raw.State == nil || raw.Organization == nil ||
		raw.Action == nil || raw.Allowed == nil {
		return Decision{}, fmt.Errorf("bundle: a decision line was due: %s", shortLine(line))
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	d := Decision{Credential: *raw.Credential, State: *raw.State, Organization: *raw.Organization, Project: str(raw.Project),
		Environment: str(raw.Environment), Action: *raw.Action, Allowed: *raw.Allowed, Code: str(raw.Code)}
	if raw.Tailnet != nil {
		if raw.Tailnet.Tailnet == nil || raw.Tailnet.NodeID == nil || raw.Tailnet.Tags == nil {
			return Decision{}, errors.New("bundle: a decision's Tailnet Context lacks a member")
		}
		d.Tailnet = &Tailnet{Tailnet: *raw.Tailnet.Tailnet, NodeID: *raw.Tailnet.NodeID, Tags: *raw.Tailnet.Tags, UserLogin: raw.Tailnet.UserLogin}
	}
	if err := d.check(); err != nil {
		return Decision{}, err
	}
	if !bytes.Equal(d.line(), line) {
		return Decision{}, errors.New("bundle: a decision not in canonical form")
	}
	r.left--
	return d, nil
}

// SkipSections reads the digest and decision sections without keeping
// them, each line checked: what an import does, which holds nothing
// against them.
func (r *Reader) SkipSections() error {
	n, err := r.Digests()
	if err != nil {
		return err
	}
	for range n {
		if _, err := r.Digest(); err != nil {
			return err
		}
	}
	if n, _, err = r.Decisions(); err != nil {
		return err
	}
	for range n {
		if _, err := r.Decision(); err != nil {
			return err
		}
	}
	return nil
}
