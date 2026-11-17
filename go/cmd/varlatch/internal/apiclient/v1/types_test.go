// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"
	"testing"
)

// The generated types read what the server answers: the answers status
// --probe reads, as recorded in testdata/transcripts/5.1c-api-client.json.
func TestTypesReadAnswers(t *testing.T) {
	var meta Meta
	if err := json.Unmarshal([]byte(`{"serverVersion":"0.22.0","apiMajor":1,"capabilities":["identity.whoami"]}`), &meta); err != nil || len(meta.Capabilities) != 1 || meta.Capabilities[0] != "identity.whoami" {
		t.Errorf("Meta: %+v %v", meta, err)
	}
	var credential OwnCredential
	if err := json.Unmarshal([]byte(`{"id":"cred_a","current":true,"kind":"cli","name":"laptop","createdAt":"2026-11-01T10:00:00.000Z","expiresAt":null}`), &credential); err != nil || credential.Id != "cred_a" || !credential.Current {
		t.Errorf("OwnCredential: %+v %v", credential, err)
	}
	var apiError ApiError
	if err := json.Unmarshal([]byte(`{"error":{"code":"MAINTENANCE","message":"m","requestId":"req_1"}}`), &apiError); err != nil || apiError.Error.Code != "MAINTENANCE" {
		t.Errorf("ApiError: %+v %v", apiError, err)
	}
}
