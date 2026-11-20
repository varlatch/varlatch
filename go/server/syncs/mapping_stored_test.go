// SPDX-License-Identifier: AGPL-3.0-or-later

package syncs_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/syncs"
)

// A stored mapping this server cannot read (imported or migrated data can
// hold one: a TypeScript test fixture's `{}`) is an error, never a panic.
func TestParseMappingRefusesWhatItCannotRead(t *testing.T) {
	for _, text := range []string{
		`{}`, `[]`, `null`, `"explicit"`, `not json`, ``,
		`{"kind":"explicit"}`, `{"kind":"explicit","items":[]}`, `{"items":{}}`,
		`{"kind":"explicit","items":[1]}`, `{"kind":"explicit","items":[{}]}`, `{"kind":"explicit","items":[{"name":""}]}`,
		`{"kind":"explicit","items":[{"name":7}]}`, `{"kind":"explicit","items":[{"name":"A","rename":5}]}`,
		`{"kind":"wildcard","exclude":"A"}`, `{"kind":"wildcard","exclude":[1]}`, `{"kind":"other","items":[{"name":"A"}]}`,
	} {
		if _, err := syncs.ParseMapping(text); !errors.Is(err, syncs.ErrStoredMapping) {
			t.Errorf("%q: %v", text, err)
		}
	}
	for _, text := range []string{
		`{"kind":"wildcard"}`, `{"kind":"wildcard","exclude":["A","B*"]}`,
		`{"kind":"explicit","items":[{"name":"PORT","rename":"HTTP_PORT","secretAffirmed":false},{"name":"API_KEY","secretAffirmed":true}]}`,
		`{"kind":"explicit","items":[{"name":"PORT","rename":null}]}`,
	} {
		if _, err := syncs.ParseMapping(text); err != nil {
			t.Errorf("%q: %v", text, err)
		}
	}
}

// Whatever the column holds, ParseMapping answers without panicking, and
// a mapping it reads writes back as one it reads the same.
func FuzzParseMapping(f *testing.F) {
	for _, seed := range []string{`{}`, `{"kind":"wildcard","exclude":["A*"]}`, `{"kind":"explicit","items":[{"name":"A","rename":"B","secretAffirmed":true}]}`,
		`{"kind":"explicit","items":[{"name":"A"},null]}`, `[{"name":"A"}]`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		m, err := syncs.ParseMapping(text)
		if err != nil {
			return
		}
		again, err := syncs.ParseMapping(string(jsvalue.Stringify(m.JS())))
		if err != nil {
			t.Fatalf("%q read, but its own form %s is not: %v", text, jsvalue.Stringify(m.JS()), err)
		}
		if string(jsvalue.Stringify(again.JS())) != string(jsvalue.Stringify(m.JS())) {
			t.Fatalf("%q: %s, then %s", text, jsvalue.Stringify(m.JS()), jsvalue.Stringify(again.JS()))
		}
	})
}

// A Target whose stored mapping cannot be read fails its own run, named in
// its last result and counted as a failure, and the others converge: the
// loop, and the daemon, go on.
func TestUnreadableMappingFailsOnlyItsTarget(t *testing.T) {
	w := newEngineWorld(t)
	w.exec(`UPDATE sync_targets SET mapping = '{}' WHERE canonical_destination = ?`, ghAPI)
	w.exec(`UPDATE sync_targets SET mapping = ? WHERE canonical_destination = ?`, `{"kind":"explicit","items":[{"rename":5}]}`, appOne)
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
	rows := w.targets()
	failed := 0
	for _, r := range rows {
		dest, _ := r["canonical_destination"].(string)
		result, _ := r["last_result"].(string)
		if dest == ghAPI || dest == appOne {
			failed++
			if !strings.Contains(result, "stored mapping is not one this server reads") || r["failure_count"] != int64(1) {
				t.Errorf("%s: %v", dest, r)
			}
			continue
		}
		if strings.Contains(result, "stored mapping") || r["failure_count"] != int64(0) {
			t.Errorf("another Target was failed: %v", r)
		}
	}
	if failed != 2 || len(rows) < 3 {
		t.Fatalf("%v", rows)
	}
	// And again: still no panic, still only those two.
	w.later()
	w.engine.RunOnce(context.Background(), syncs.RunOptions{})
}
