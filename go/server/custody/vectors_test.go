// SPDX-License-Identifier: AGPL-3.0-or-later

package custody

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"strings"
	"testing"
)

// Escrow and Shamir both ways (services/varlatchd/test/go-backup-vectors.test.ts):
// blobs and splits the TypeScript server made restore and combine here,
// and its refusals have the same messages; TestGoVectors writes blobs,
// splits and refusals made here for the TypeScript server to check.

var writeGoVectors = flag.String("write-go-vectors", "", "write escrows and splits made by this code to this file")

type escrowVector struct {
	Name       string `json:"name"`
	Passphrase string `json:"passphrase"`
	KEK        string `json:"kek"`
	Blob       Blob   `json:"blob"`
}

type refusal struct {
	Name       string          `json:"name"`
	Passphrase string          `json:"passphrase,omitempty"`
	Blob       json.RawMessage `json:"blob,omitzero"`
	Shares     []string        `json:"shares,omitzero"`
	Message    string          `json:"message"`
}

type splitVector struct {
	Name        string   `json:"name"`
	KEK         string   `json:"kek"`
	Shares      int      `json:"shares"`
	Threshold   int      `json:"threshold"`
	Split       []string `json:"split"`
	Fingerprint string   `json:"fingerprint"`
}

type vectors struct {
	Comment         string         `json:"comment"`
	Escrow          []escrowVector `json:"escrow"`
	EscrowRefusals  []refusal      `json:"escrowRefusals"`
	Shamir          []splitVector  `json:"shamir"`
	CombineRefusals []refusal      `json:"combineRefusals"`
}

func messageOf(err error) string {
	if err == nil {
		return "(no error)"
	}
	return err.Error()
}

func restoreMessage(raw json.RawMessage, passphrase string) string {
	b, err := ParseBlob(raw)
	if err != nil {
		return messageOf(err)
	}
	_, err = Restore(b, passphrase)
	return messageOf(err)
}

func check(t *testing.T, v vectors) {
	t.Helper()
	if len(v.Escrow) < 2 || len(v.EscrowRefusals) < 8 || len(v.Shamir) < 6 || len(v.CombineRefusals) < 10 {
		t.Fatalf("incomplete vectors")
	}
	for _, e := range v.Escrow {
		kek, err := Restore(e.Blob, e.Passphrase)
		if err != nil || hex.EncodeToString(kek) != e.KEK {
			t.Errorf("%s: %v", e.Name, err)
		}
	}
	for _, r := range v.EscrowRefusals {
		if got := restoreMessage(r.Blob, r.Passphrase); got != r.Message {
			t.Errorf("%s: %q, want %q", r.Name, got, r.Message)
		}
	}
	for _, s := range v.Shamir {
		if len(s.Split) != s.Shares {
			t.Errorf("%s: %d shares", s.Name, len(s.Split))
		}
		reversed := slices.Clone(s.Split[len(s.Split)-s.Threshold:])
		slices.Reverse(reversed)
		for _, set := range [][]string{s.Split[:s.Threshold], reversed} {
			kek, err := Combine(set)
			if err != nil || hex.EncodeToString(kek) != s.KEK {
				t.Errorf("%s: %v", s.Name, err)
			}
		}
		for _, share := range s.Split {
			if !strings.HasSuffix(share, "."+s.Fingerprint) {
				t.Errorf("%s: %s", s.Name, share)
			}
		}
	}
	for _, r := range v.CombineRefusals {
		_, err := Combine(r.Shares)
		if got := messageOf(err); got != r.Message {
			t.Errorf("%s: %q, want %q", r.Name, got, r.Message)
		}
	}
}

func TestTSVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	check(t, v)
}

// TestGoVectors makes the same kinds of vectors with this code, checks
// them here, and writes them for the TypeScript server with the flag.
func TestGoVectors(t *testing.T) {
	var ts vectors
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &ts); err != nil {
		t.Fatal(err)
	}
	out := vectors{Comment: "Written by go/server/custody TestGoVectors with the Go code; do not edit."}
	for _, e := range ts.Escrow {
		kek := randomKey(t)
		blob, err := Export(kek, e.Passphrase)
		if err != nil {
			t.Fatal(err)
		}
		out.Escrow = append(out.Escrow, escrowVector{Name: e.Name, Passphrase: e.Passphrase, KEK: hex.EncodeToString(kek), Blob: blob})
	}
	// The same refusals, on a Go blob: each blob changed as the TypeScript
	// vectors change theirs, with this code's message.
	goBlob, _ := json.Marshal(out.Escrow[0].Blob)
	for _, r := range ts.EscrowRefusals {
		var tsBlob, base map[string]any
		_ = json.Unmarshal(r.Blob, &tsBlob)
		_ = json.Unmarshal(goBlob, &base)
		tsOrig := map[string]any{}
		_ = json.Unmarshal(mustJSON(ts.Escrow[0].Blob), &tsOrig)
		changed := mergeChanges(base, tsOrig, tsBlob)
		raw, _ := json.Marshal(changed)
		passphrase := r.Passphrase
		if passphrase == ts.Escrow[0].Passphrase {
			passphrase = out.Escrow[0].Passphrase
		}
		out.EscrowRefusals = append(out.EscrowRefusals, refusal{Name: r.Name, Passphrase: passphrase, Blob: raw, Message: restoreMessage(raw, passphrase)})
	}
	for _, s := range ts.Shamir {
		kek := randomKey(t)
		split, fp, err := Split(kek, s.Shares, s.Threshold)
		if err != nil {
			t.Fatal(err)
		}
		out.Shamir = append(out.Shamir, splitVector{Name: s.Name, KEK: hex.EncodeToString(kek), Shares: s.Shares, Threshold: s.Threshold, Split: split, Fingerprint: fp})
	}
	sp, other := out.Shamir[2].Split, out.Shamir[1].Split
	tweak := func(share string) string {
		p := strings.Split(share, ".")
		c := []byte(p[3])
		if c[0] == 'A' {
			c[0] = 'B'
		} else {
			c[0] = 'A'
		}
		p[3] = string(c)
		return strings.Join(p, ".")
	}
	huge := func(share string) string {
		p := strings.Split(share, ".")
		p[2] = "1e300"
		return strings.Join(p, ".")
	}
	upper := func(share string) string {
		i := strings.LastIndex(share, ".")
		return share[:i] + strings.ToUpper(share[i:])
	}
	for _, r := range []struct {
		name   string
		shares []string
	}{
		{"none", nil},
		{"too few", sp[:2]},
		{"a share twice", []string{sp[0], sp[0], sp[1]}},
		{"mixed splits", []string{sp[0], sp[1], other[0]}},
		{"a changed share", []string{tweak(sp[0]), sp[1], sp[2]}},
		{"a malformed share", []string{"vlks1.1.3.abc", sp[1], sp[2]}},
		{"another prefix", []string{strings.Replace(sp[0], "vlks1", "vlks2", 1), sp[1], sp[2]}},
		{"x 0", []string{strings.Replace(sp[0], "vlks1.1.", "vlks1.0.", 1), sp[1], sp[2]}},
		{"threshold 1", []string{strings.Replace(sp[0], "vlks1.1.3.", "vlks1.1.1.", 1)}},
		{"an upper-case fingerprint", []string{upper(sp[0]), sp[1], sp[2]}},
		{"a huge threshold", []string{huge(sp[0]), huge(sp[1]), huge(sp[2])}},
	} {
		_, err := Combine(r.shares)
		shares := r.shares
		if shares == nil {
			shares = []string{}
		}
		out.CombineRefusals = append(out.CombineRefusals, refusal{Name: r.name, Shares: shares, Message: messageOf(err)})
	}
	// The messages match the TypeScript refusals of the same name.
	for i, r := range out.CombineRefusals {
		if want := ts.CombineRefusals[i]; want.Name != r.Name || want.Message != r.Message {
			t.Errorf("%s: %q, the TypeScript one %q", r.Name, r.Message, want.Message)
		}
	}
	for i, r := range out.EscrowRefusals {
		if want := ts.EscrowRefusals[i]; want.Message != r.Message {
			t.Errorf("%s: %q, the TypeScript one %q", r.Name, r.Message, want.Message)
		}
	}
	check(t, out)
	if *writeGoVectors != "" {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(*writeGoVectors, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := randRead(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// mergeChanges applies to base what changed from orig to changed, member
// by member (one level into kdf).
func mergeChanges(base, orig, changed map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range changed {
		o, ok := orig[k]
		if ok && string(mustJSON(o)) == string(mustJSON(v)) {
			continue
		}
		if sub, isMap := v.(map[string]any); isMap {
			if origSub, ok := o.(map[string]any); ok {
				if baseSub, ok := base[k].(map[string]any); ok {
					out[k] = mergeChanges(baseSub, origSub, sub)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}
