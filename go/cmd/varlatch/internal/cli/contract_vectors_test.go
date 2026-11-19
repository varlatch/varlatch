// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// TestContractPushSendsTheSameRevision: for every valid Contract of
// lib/contract's normalization vectors, what `contract push --file` sends
// (ContractFileBody) normalizes, as the server normalizes it, to the
// canonical bytes and hash the TypeScript CLI's push gives
// (testdata/vectors/envschema.json, "push").
func TestContractPushSendsTheSameRevision(t *testing.T) {
	data, err := os.ReadFile("../../testdata/vectors/envschema.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Push []struct {
			Name             string
			Input            string
			VersionUndecided bool
			Canonical, Hash  string
		}
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Push) < 20 {
		t.Fatalf("only %d push vectors", len(f.Push))
	}
	for _, v := range f.Push {
		body, err := ContractFileBody([]byte(v.Input))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		sent, err := contract.ParseJSON(jsjson.Stringify(body))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		c, err := contract.Normalize(sent, contract.Options{VersionUndecided: v.VersionUndecided})
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(c.Bytes()) != v.Canonical || c.Hash() != v.Hash {
			t.Errorf("%s: got %s %s, want %s %s", v.Name, c.Bytes(), c.Hash(), v.Canonical, v.Hash)
		}
	}
}
