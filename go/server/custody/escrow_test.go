// SPDX-License-Identifier: AGPL-3.0-or-later

package custody

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A blob's N, r and p are JavaScript numbers: 131072.0 is 131072, as
// JSON.parse reads it.
func TestRestoreReadsNumbersAsJavaScript(t *testing.T) {
	kek := randomKey(t)
	blob, err := Export(kek, "a long passphrase here")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(blob)
	raw = bytes.Replace(raw, []byte(`"N":131072`), []byte(`"N":131072.0`), 1)
	if !strings.Contains(string(raw), `"N":131072.0`) {
		t.Fatal("no N to respell")
	}
	b, err := ParseBlob(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Restore(b, "a long passphrase here")
	if err != nil || !bytes.Equal(got, kek) {
		t.Fatalf("%v", err)
	}
}

func TestSeparated(t *testing.T) {
	for in, want := range map[string]string{"1099511627776": "1_099_511_627_776", "-9007199254740992": "-9_007_199_254_740_992", "123": "123", "1234": "1_234"} {
		if got := separated(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}
