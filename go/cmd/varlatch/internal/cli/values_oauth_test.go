// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What reads an environment with an OAuth connection in it (ADR-0062): the
// listing names it, and a run says it is not delivered.
func TestAConnectionIsListedAndNotDelivered(t *testing.T) {
	const listed = `{"items":[{"name":"API_KEY","sensitive":true,"source":"self","versionId":"ver_1","value":null},
		{"name":"MAIL_TOKEN","sensitive":true,"source":"self","versionId":"ver_2","value":null,"oauth":{"preset":"google","grant":"authorization_code","status":"needs_reconnect","paused":false,"account":"al\u001b[31mice"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/disclosures") {
			_, _ = io.WriteString(w, `{"items":[{"name":"API_KEY","versionId":"ver_1","value":"`+canary+`"}],"withheld":["MAIL_TOKEN"]}`)
			return
		}
		_, _ = io.WriteString(w, listed)
	}))
	t.Cleanup(srv.Close)
	s := &valuesServer{Server: srv}
	code, stdout, stderr := runIn(t, s, "", nil, nil, "values", "list")
	if code != 0 || !strings.Contains(stdout, "MAIL_TOKEN  (OAuth connection, needs reconnect, al") || strings.Contains(stdout, "\x1b") || !strings.Contains(stdout, "API_KEY  (secret, self)") {
		t.Errorf("list: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runIn(t, s, "", nil, nil, "values", "list", "--json")
	if code != 0 || !strings.Contains(stdout, `"preset": "google"`) {
		t.Errorf("list --json: %d %q %q", code, stdout, stderr)
	}
	code, stdout, stderr = runIn(t, s, "", nil, nil, "run", "--", "env")
	if code != 0 || !strings.Contains(stderr, "1 OAuth connection(s) not delivered") || strings.Contains(stderr, "withheld by policy") || strings.Contains(stdout, "MAIL_TOKEN") {
		t.Errorf("run: %d %q %q", code, stdout, stderr)
	}
}
