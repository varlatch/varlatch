// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"strings"
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

const contractPath = "/v1/organizations/acme/projects/web/contract"

// TestContractNeverShowsASecret: a sensitive item's default is a value in
// flight, so a server echoing it in an error never shows it; contract show
// prints such a default as [redacted], and the bearer a server echoes in
// the document is masked; activate repeats only an id of the server's
// shape.
func TestContractNeverShowsASecret(t *testing.T) {
	const secretDefault = "q7" // short: held whatever its length
	file := `{"schemaVersion": 1, "items": [{"name": "API_KEY", "required": {"kind": "never"}, "sensitive": true, "type": "string", "defaultValue": "` + secretDefault + `"},
		{"name": "PORT", "required": {"kind": "never"}, "sensitive": false, "type": "string", "defaultValue": "8080"}]}`
	t.Run("push echoed", func(t *testing.T) {
		s := newValuesServer(t)
		s.answer("POST", contractPath+"/revisions", 400, `{"error": {"code": "VALIDATION_FAILED", "message": "bad default `+secretDefault+`"}}`)
		code, stdout, stderr := runIn(t, s, "", map[string]string{"c.json": file}, nil, "contract", "push", "--file", "c.json")
		noneShown(t, stdout, stderr, secretDefault)
		if code != 1 {
			t.Errorf("status %d", code)
		}
	})
	t.Run("show", func(t *testing.T) {
		s := newValuesServer(t)
		s.answer("GET", contractPath, 200, `{"id": "rev_x", "echo": "vlt_cli_secretTestAAAA and a`+canary+`", "contract": {"schemaVersion": 1, "items": [
			{"name": "API_KEY", "required": {"kind": "never"}, "sensitive": true, "type": "string", "defaultValue": "`+canary+`"},
			{"name": "MISSING_FLAG", "required": {"kind": "never"}, "type": "string", "defaultValue": "`+canary+`"},
			{"name": "PORT", "required": {"kind": "never"}, "sensitive": false, "type": "string", "defaultValue": "8080"}]}}`)
		code, stdout, stderr := runIn(t, s, "", nil, nil, "contract", "show")
		noneShown(t, stdout, stderr, canary, "vlt_cli_secretTestAAAA")
		if code != 0 || !strings.Contains(stdout, `"defaultValue": "8080"`) || strings.Count(stdout, `"defaultValue": "[redacted]"`) != 2 {
			t.Errorf("status %d, %q", code, stdout)
		}
	})
	t.Run("activate", func(t *testing.T) {
		s := newValuesServer(t)
		s.answer("POST", contractPath+"/revisions/"+canary+"/activate", 200, `{}`)
		code, stdout, stderr := runIn(t, s, "", nil, nil, "contract", "activate", canary)
		noneShown(t, stdout, stderr, canary)
		if code != 0 || stdout != "Activated the revision.\n" {
			t.Errorf("status %d, %q", code, stdout)
		}
	})
}

// TestContractPushReadsTheProtocolsTypes: a push answer's active only as a
// boolean (an object is not "active"), its id only of the server's shape,
// and an environment list only with string ids and names.
func TestContractPushReadsTheProtocolsTypes(t *testing.T) {
	s := newValuesServer(t)
	s.answer("POST", contractPath+"/revisions", 201, `{"active": {"yes": true}, "contentHash": "x", "semanticsVersion": "3"}`)
	code, stdout, _ := runIn(t, s, "", map[string]string{"c.json": `{"schemaVersion": 1, "items": []}`}, nil, "contract", "push", "--file", "c.json")
	if code != 0 || strings.Contains(stdout, "[active]") || !strings.Contains(stdout, "Revision "+UnrecognizedID+" ("+UnrecognizedHash+")") ||
		!strings.Contains(stdout, "Contract Semantics version "+UnrecognizedVersion) || !strings.Contains(stdout, "Activate with:") {
		t.Errorf("status %d, %q", code, stdout)
	}
	s = newValuesServer(t)
	s.answer("GET", "/v1/organizations/acme/projects/web/environments", 200, `{"items": [{"name": "staging", "parentEnvironmentId": null}]}`)
	code, stdout, stderr := runIn(t, s, "", map[string]string{".env.schema": "# @required=env(staging)\nKEY=\n"}, nil, "contract", "push", "--schema", ".env.schema")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "unexpected shape (items[0])") || strings.Contains(stderr, "undefined") {
		t.Errorf("status %d, %q %q", code, stdout, stderr)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) != 0 {
		t.Errorf("sent %q", s.sent)
	}
}
