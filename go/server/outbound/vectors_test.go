// SPDX-License-Identifier: AGPL-3.0-or-later

package outbound

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// testdata/ts-vectors.json is the TypeScript server's outbound policy on a
// fixed set of inputs (services/varlatchd/test/go-outbound-vectors.test.ts,
// which also checks the committed file is still its own): every class, the
// allow list parser's entries, refusals and warnings, 705 decisions, and
// the refusal sentences. The Go policy gives the same answers.
type vectors struct {
	Classes []struct {
		Address string  `json:"address"`
		Class   *string `json:"class"`
	} `json:"classes"`
	Allow []struct {
		Spec     string           `json:"spec"`
		Entries  []map[string]any `json:"entries"`
		Warnings []string         `json:"warnings"`
		Error    *string          `json:"error"`
	} `json:"allow"`
	Decisions []struct {
		Allow       string      `json:"allow"`
		URL         string      `json:"url"`
		Destination Destination `json:"destination"`
		Addresses   []string    `json:"addresses"`
		Verdict     struct {
			Allowed bool     `json:"allowed"`
			Via     string   `json:"via"`
			Entries []string `json:"entries"`
			Reason  Reason   `json:"reason"`
		} `json:"verdict"`
	} `json:"decisions"`
	Messages []struct {
		Reason   Reason `json:"reason"`
		Sentence string `json:"sentence"`
		Label    string `json:"label"`
		Message  string `json:"message"`
	} `json:"messages"`
	Generic  string `json:"generic"`
	HostNote string `json:"hostNote"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func entryVector(e Entry) map[string]any {
	port := func(p Port) any {
		switch {
		case p.Any:
			return "*"
		case p == None:
			return nil
		}
		return float64(p.N)
	}
	if e.Kind == "name" {
		return map[string]any{"kind": "name", "text": e.Text, "name": e.Name, "wildcard": e.Wildcard, "port": port(e.Port)}
	}
	base, family, prefix := e.RangeBase()
	return map[string]any{"kind": "cidr", "text": e.Text, "base": base, "family": float64(family), "prefix": float64(prefix), "port": port(e.Port), "hostOnly": e.HostOnly}
}

func TestTSVectors(t *testing.T) {
	v := readVectors(t)
	if len(v.Classes) < 100 || len(v.Allow) < 60 || len(v.Decisions) < 700 {
		t.Fatalf("incomplete vectors: %d classes, %d allow lists, %d decisions", len(v.Classes), len(v.Allow), len(v.Decisions))
	}
	for _, c := range v.Classes {
		got, ok := ClassOf(c.Address)
		if (c.Class == nil) == ok || ok && string(got) != *c.Class {
			t.Errorf("class of %q: %q %v, TypeScript %v", c.Address, got, ok, c.Class)
		}
	}
	for _, a := range v.Allow {
		entries, err := ParseAllow(a.Spec)
		if a.Error != nil {
			if err == nil || err.Error() != *a.Error {
				t.Errorf("%q: %v, TypeScript %q", a.Spec, err, *a.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", a.Spec, err)
			continue
		}
		got := []map[string]any{}
		for _, e := range entries {
			got = append(got, entryVector(e))
		}
		if a.Entries == nil {
			a.Entries = []map[string]any{}
		}
		if !reflect.DeepEqual(got, a.Entries) {
			t.Errorf("%q: %v, TypeScript %v", a.Spec, got, a.Entries)
		}
		if w := Warnings(entries); !reflect.DeepEqual(w, a.Warnings) {
			t.Errorf("%q warnings: %q, TypeScript %q", a.Spec, w, a.Warnings)
		}
	}
	for _, d := range v.Decisions {
		u, ok := whatwg.ParseURL(d.URL)
		dest, ok2 := DestinationOf(u)
		if !ok || !ok2 || dest != d.Destination {
			t.Errorf("%s: destination %+v, TypeScript %+v", d.URL, dest, d.Destination)
			continue
		}
		entries, err := ParseAllow(d.Allow)
		if err != nil {
			t.Fatal(err)
		}
		got := Decide(entries, dest, d.Addresses)
		want := Verdict{Allowed: d.Verdict.Allowed, Via: d.Verdict.Via, Entries: d.Verdict.Entries, Reason: d.Verdict.Reason}
		if !d.Verdict.Allowed {
			want.Entries = nil
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("allow %q, %s %v: %+v, TypeScript %+v", d.Allow, d.URL, d.Addresses, got, want)
		}
	}
	if len(v.Messages) != len(Reasons) {
		t.Fatalf("%d messages", len(v.Messages))
	}
	for i, m := range v.Messages {
		if m.Reason != Reasons[i] || Sentences[m.Reason] != m.Sentence || Labels[m.Reason] != m.Label || Message(m.Reason) != m.Message {
			t.Errorf("%s: the wording differs", m.Reason)
		}
	}
	if v.Generic != RefusedGeneric || v.HostNote != HostNote {
		t.Error("the generic sentence or the host note differs")
	}
}
