// SPDX-License-Identifier: AGPL-3.0-or-later

package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/migration/canonical"
	"github.com/varlatch/varlatch/go/server/migration/manifest"
)

// writeVectors regenerates testdata/small.jsonl and testdata/refused.json:
//
//	VARLATCH_WRITE_BUNDLE_VECTORS=1 go test ./server/migration/bundle/
var writeVectors = os.Getenv("VARLATCH_WRITE_BUNDLE_VECTORS") == "1"

func load(t *testing.T) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// small is the shared valid bundle: every table, two of them with a row.
func small(t *testing.T, m *manifest.Manifest) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, m, Header{Manifest: m.Version, Encoding: m.Encoding, Direction: Forward, Release: m.Source.Release,
		FrozenPoint: FrozenPoint{AuditPosition: 1, Snapshot: "00000003-0000001B-1"}})
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string][]any{
		"installation": {"inst_vectors", `{"nonce":"n","authTag":"t","algorithm":"aes-256-gcm","ciphertext":"c","formatVersion":1}`,
			int64(1795000000000000), int64(1795000000000000), int64(1), "idle", nil},
		"audit_events": {"evt_vectors", int64(1), "installation.initialized", int64(1795000000000001), nil, nil, nil, nil, nil,
			`{"installationId":"inst_vectors"}`, "info", nil, nil, nil, nil, `{"é":"z","a":[1,2]}`, int64(1), nil},
	}
	for _, tb := range Tables(m) {
		v, ok := rows[tb.Source]
		n := 0
		if ok {
			n = 1
		}
		if err := w.Table(tb.Source, n); err != nil {
			t.Fatal(err)
		}
		if ok {
			row, err := canonical.AppendRow(nil, tb.Types(), v)
			if err != nil {
				t.Fatalf("%s: %v", tb.Source, err)
			}
			if err := w.Row(row); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Digests(len(smallDigests)); err != nil {
		t.Fatal(err)
	}
	for _, d := range smallDigests {
		if err := w.Digest(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Decisions(len(smallDecisions), 1795000000000002); err != nil {
		t.Fatal(err)
	}
	for _, d := range smallDecisions {
		if err := w.Decision(d); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The small bundle's sections: digests in their order (a class, then ids
// in jsonb's order: the shorter key first), and two decisions, one with a
// Tailnet Context.
var (
	smallDigests = []Digest{
		{Class: "kek-canary", IDs: map[string]string{"installationId": "inst_vectors"}, HMAC: strings.Repeat("0a", 32)},
		{Class: "value", IDs: map[string]string{"secretId": "val_vectors", "versionId": "ver_vectors", "organizationId": "org_vectors"}, HMAC: strings.Repeat("1b", 32)},
	}
	login          = "vectors@example.test"
	smallDecisions = []Decision{
		{Credential: "crd_vectors", State: Active, Organization: "org_vectors", Project: "prj_vectors", Environment: "env_vectors",
			Action: "secret.reveal", Allowed: true},
		{Credential: "crd_vectors", State: Revoked, Organization: "org_vectors", Action: "organization.read",
			Tailnet: &Tailnet{Tailnet: "example.ts.net", NodeID: "nVectors", Tags: []string{"tag:ci"}, UserLogin: &login}, Code: "UNAUTHENTICATED"},
	}
)

// readAll reads a bundle whole, as an import does.
func readAll(m *manifest.Manifest, b []byte) (map[string][][]byte, error) {
	r, err := NewReader(bytes.NewReader(b), m)
	if err != nil {
		return nil, err
	}
	out := map[string][][]byte{}
	for range Tables(m) {
		tb, n, err := r.NextTable()
		if err != nil {
			return nil, err
		}
		for range n {
			row, err := r.Row()
			if err != nil {
				return nil, err
			}
			if _, err := Decode(tb, row); err != nil {
				return nil, err
			}
			out[tb.Source] = append(out[tb.Source], row)
		}
	}
	n, err := r.Digests()
	if err != nil {
		return nil, err
	}
	for range n {
		d, err := r.Digest()
		if err != nil {
			return nil, err
		}
		out["(digests)"] = append(out["(digests)"], d.line())
	}
	n, _, err = r.Decisions()
	if err != nil {
		return nil, err
	}
	for range n {
		d, err := r.Decision()
		if err != nil {
			return nil, err
		}
		out["(decisions)"] = append(out["(decisions)"], d.line())
	}
	return out, r.End()
}

type refusal struct {
	Name   string `json:"name"`
	Bundle string `json:"bundle"`
	Why    string `json:"why"`
}

// refusals are small.jsonl damaged, each in one way, with the reason a
// reader gives.
func refusals(good []byte) []refusal {
	lines := strings.SplitAfter(string(good), "\n")
	lines = lines[:len(lines)-1] // the empty string after the last \n
	join := func(ls []string) string { return strings.Join(ls, "") }
	with := func(i int, line string) string {
		ls := append([]string{}, lines...)
		ls[i] = line
		return join(ls)
	}
	last := len(lines) - 1
	var instRow, digests, decisions int
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, `{"table":"installation"`):
			instRow = i + 1
		case strings.HasPrefix(l, `{"digests":`):
			digests = i
		case strings.HasPrefix(l, `{"decisions":`):
			decisions = i
		}
	}
	endWith := func(old, repl string) string { return reseal(with(last, strings.Replace(lines[last], old, repl, 1))) }
	header := lines[0]
	return []refusal{
		{"cut short: no end line", join(lines[:last]), "cut short"},
		{"cut short mid-table", join(lines[:instRow]), "cut short"},
		{"a changed row byte", with(instRow, strings.Replace(lines[instRow], "idle", "idlf", 1)), "damaged"},
		{"text after the end line", join(lines) + "\n", "after the end line"},
		{"a sequence listed", with(0, strings.Replace(header, `"sequences":[]`, `"sequences":["s"]`, 1)), "sequences"},
		{"another manifest version", with(0, strings.Replace(header, `"manifest":1`, `"manifest":2`, 1)), "manifest 2"},
		{"another encoding", with(0, strings.Replace(header, `canonical-v1`, `canonical-v2`, 1)), "canonical-v2"},
		{"an unknown header member", with(0, strings.Replace(header, `"sequences":[]`, `"sequences":[],"extra":1`, 1)), "the header"},
		{"a forward bundle without its snapshot", with(0, strings.Replace(header, `,"snapshot":"00000003-0000001B-1"`, "", 1)), "snapshot"},
		{"another direction", with(0, strings.Replace(header, `"forward"`, `"sideways"`, 1)), "neither forward nor reverse"},
		{"another source release", with(0, strings.Replace(header, `"release":"0.23.1"`, `"release":"0.22.9"`, 1)), "the manifest's source"},
		{"tables out of order", with(1, lines[3]), "the manifest's order"},
		{"a row more than counted", with(instRow-1, strings.Replace(lines[instRow-1], `"rows":1`, `"rows":0`, 1)), "a table line was due"},
		{"a blank line", join(lines[:1]) + "\n" + join(lines[1:]), "blank line"},
		{"CRLF", with(0, strings.TrimSuffix(header, "\n")+"\r\n"), "blank line, or a line ending"},
		{"a session token carried", reseal(withSession(lines, `["ses_vectors",1795000000000000,"a token",1795000000000000,1795000000000000,null,null,"usr_vectors"]`)), "session.token holds a value"},
		{"a row that is not canonical", reseal(with(instRow, strings.Replace(lines[instRow], `"inst_vectors",`, `"inst_vectors", `, 1))), "not in canonical form"},
		{"no digest section", reseal(join(append(append([]string{}, lines[:digests]...), lines[digests+3:]...))), "the digest section's line was due"},
		{"digests out of order", reseal(join(append(append(append([]string{}, lines[:digests+1]...), lines[digests+2], lines[digests+1]), lines[digests+3:]...))), "out of order"},
		{"a digest written twice", reseal(with(digests+2, lines[digests+1])), "out of order, or written twice"},
		{"a digest's ids not in jsonb order", reseal(with(digests+2, strings.Replace(lines[digests+2], `{"secretId":"val_vectors","versionId":"ver_vectors","organizationId":"org_vectors"}`,
			`{"organizationId":"org_vectors","secretId":"val_vectors","versionId":"ver_vectors"}`, 1))), "not in canonical form"},
		{"a digest's hmac in upper case", reseal(with(digests+1, strings.Replace(lines[digests+1], "0a0a", "0A0A", 1))), "64 lowercase hex"},
		{"a digest that is not a line of its own", reseal(with(digests+1, strings.TrimSuffix(lines[digests+1], "\n")+lines[digests+2])), "a digest line was due"},
		{"a decision allowed with a code", reseal(with(decisions+1, strings.Replace(lines[decisions+1], `"code":null`, `"code":"PERMISSION_DENIED"`, 1))), "allowed with an error code"},
		{"a decision in another state", reseal(with(decisions+1, strings.Replace(lines[decisions+1], `"active"`, `"suspended"`, 1))), "not active, expired or revoked"},
		{"a decision with an empty project", reseal(with(decisions+2, strings.Replace(lines[decisions+2], `"project":null`, `"project":""`, 1))), "not in canonical form"},
		{"a decision with an unknown member", reseal(with(decisions+1, strings.Replace(lines[decisions+1], `"code":null`, `"code":null,"why":1`, 1))), "a decision line was due"},
		{"an end line counting another digest", endWith(`"digests":2`, `"digests":3`), "3 digests"},
		{"an end line counting another decision", endWith(`"decisions":2,"sha256"`, `"decisions":1,"sha256"`), "1 decisions"},
		{"a negative decision moment", reseal(with(decisions, strings.Replace(lines[decisions], `"at":1795000000000002`, `"at":-1`, 1))), "before 1970"},
		{"an end line without its section counts", endWith(`"digests":2,"decisions":2,`, ""), "the end line was due"},
	}
}

// The shared valid bundle: written the same, byte for byte, and read back.
func TestTheSmallBundle(t *testing.T) {
	m := load(t)
	got := small(t, m)
	path := filepath.Join("testdata", "small.jsonl")
	if writeVectors {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the writer's bundle differs from %s", path)
	}
	rows, err := readAll(m, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows["installation"]) != 1 || len(rows["audit_events"]) != 1 || len(rows["(digests)"]) != 2 || len(rows["(decisions)"]) != 2 || len(rows) != 4 {
		t.Fatalf("rows %v", rows)
	}
}

// Every shared refusal is refused, with its reason.
func TestRefusedBundles(t *testing.T) {
	m := load(t)
	path := filepath.Join("testdata", "refused.json")
	if writeVectors {
		b, err := json.MarshalIndent(refusals(small(t, m)), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases []refusal
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 30 {
		t.Fatalf("%d cases", len(cases))
	}
	for _, c := range cases {
		if _, err := readAll(m, []byte(c.Bundle)); err == nil || !strings.Contains(err.Error(), c.Why) {
			t.Errorf("%s: %v, want %q", c.Name, err, c.Why)
		}
		// Verify refuses it too, but for a row's form: it checks the
		// stream, not the rows.
		rowFault := c.Name == "a row that is not canonical" || c.Name == "a session token carried"
		if _, err := Verify(bytes.NewReader([]byte(c.Bundle)), m); (err == nil) != rowFault {
			t.Errorf("Verify, %s: %v", c.Name, err)
		}
	}
	if _, err := Verify(bytes.NewReader(small(t, m)), m); err != nil {
		t.Errorf("Verify, the small bundle: %v", err)
	}
}

// The writer refuses what would make an invalid bundle.
func TestTheWriterKeepsTheFormat(t *testing.T) {
	m := load(t)
	h := Header{Manifest: m.Version, Encoding: m.Encoding, Direction: Reverse, Release: "0.50.0", FrozenPoint: FrozenPoint{AuditPosition: 3}}
	w, err := NewWriter(io.Discard, m, h)
	if err != nil {
		t.Fatal(err)
	}
	tables := Tables(m)
	if err := w.Table(tables[1].Source, 0); err == nil {
		t.Error("a table out of order")
	}
	if err := w.Table(tables[0].Source, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.Row([]byte("[\n]")); err == nil {
		t.Error("a row with a line break")
	}
	if err := w.Close(); err == nil {
		t.Error("closed with a row due")
	}
	if err := w.Digests(0); err == nil {
		t.Error("digests with a row due")
	}
	full, err := NewWriter(io.Discard, m, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range tables {
		if err := full.Table(tb.Source, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := full.Close(); err == nil {
		t.Error("closed without the sections")
	}
	if err := full.Digests(2); err != nil {
		t.Fatal(err)
	}
	if err := full.Row([]byte("[]")); err == nil {
		t.Error("a row in the digest section")
	}
	if err := full.Digest(smallDigests[1]); err != nil {
		t.Fatal(err)
	}
	if err := full.Digest(smallDigests[0]); err == nil {
		t.Error("digests out of order")
	}
	bad2 := smallDigests[0]
	bad2.HMAC = "x"
	if err := full.Digest(bad2); err == nil {
		t.Error("a digest that is not hex")
	}
	if err := full.Decisions(0, 1); err == nil {
		t.Error("decisions with a digest due")
	}
	bad := h
	bad.FrozenPoint.Snapshot = "x"
	if _, err := NewWriter(io.Discard, m, bad); err == nil {
		t.Error("a reverse bundle with a snapshot")
	}
	for _, tb := range tables {
		if tb.Action == manifest.LeftOut {
			t.Errorf("%s: a left-out table among the bundle's", tb.Source)
		}
	}
}

// withSession is the bundle with one session row in place of none.
func withSession(lines []string, row string) string {
	var out []string
	for _, l := range lines {
		if l == `{"table":"session","rows":0}`+"\n" {
			out = append(out, `{"table":"session","rows":1}`+"\n", row+"\n")
			continue
		}
		if strings.HasPrefix(l, `{"end":`) {
			// One row more in the end line's count.
			i := strings.Index(l, `"rows":`) + len(`"rows":`)
			j := i + strings.IndexByte(l[i:], ',')
			n, _ := strconv.Atoi(l[i:j])
			l = l[:i] + strconv.Itoa(n+1) + l[j:]
		}
		out = append(out, l)
	}
	return strings.Join(out, "")
}

// reseal writes a bundle's end line again for its changed bytes, so the
// only fault left is the one made.
func reseal(b string) string {
	body := b[:strings.LastIndex(b[:len(b)-1], "\n")+1]
	end := b[len(body):]
	sum := sha256.Sum256([]byte(body))
	i := strings.Index(end, `"sha256":"`) + len(`"sha256":"`)
	return body + end[:i] + hex.EncodeToString(sum[:]) + end[i+64:]
}
