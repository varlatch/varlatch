// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
	"github.com/varlatch/varlatch/go/server/upgraderequests"
	"github.com/varlatch/varlatch/go/server/write"
)

// The web upgrade's routes (ADR-0065 phase 2): not there without the
// service (the image); with it, /v1/meta lists installation.upgrade, an
// Installation Admin reads the state (no-store), only a dashboard session
// files a request, which always asks for a step-up approval first, and a
// cancel names the last request.
func TestUpgradeRequestRoutes(t *testing.T) {
	bare, _, _, _, tb := newTestServerAuth(t, nil)
	if w := do(bare, "GET", "/v1/installation/upgrade-request", "", map[string]string{"Authorization": "Bearer " + tb.tokens["valid"]}); w.Code != 404 {
		t.Fatalf("without the service: %d %s", w.Code, w.Body.String())
	}
	if caps := metaCapabilities(t, bare); slices.Contains(caps, "installation.upgrade") {
		t.Fatal("installation.upgrade listed without the service")
	}

	svc := &upgraderequests.Service{DataDir: t.TempDir(), ConfigDir: t.TempDir(), Version: "0.51.0",
		Installation: func(context.Context) (string, error) { return "inst_test", nil },
		Preflight: func(context.Context) upgradecheck.Report {
			return upgradecheck.Report{Target: &release.Target{Version: "0.52.0", Verified: &release.VerifiedTarget{}},
				Lines: []upgradecheck.Line{{ID: upgradecheck.LineHelper, Status: upgradecheck.Pass}}}
		}}
	s, _, _, _, ta := newTestServerAuth(t, func(o *Options) { o.UpgradeRequests = svc })
	svc.Writer, svc.Approvals = &write.Writer{Store: ta.store, Gates: write.NewGates()}, ta.svc
	if caps := metaCapabilities(t, s); !slices.Contains(caps, "installation.upgrade") {
		t.Fatalf("installation.upgrade not listed: %v", caps)
	}
	cli := map[string]string{"Authorization": "Bearer " + ta.tokens["valid"], "Content-Type": "application/json"}
	w := do(s, "GET", "/v1/installation/upgrade-request", "", cli)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), `"state":"none"`) {
		t.Fatalf("GET: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	body := `{"version":"0.52.0","requestId":"upr_` + strings.Repeat("a", 26) + `"}`
	if w := do(s, "POST", "/v1/installation/upgrade-request", body, cli); w.Code != 403 || !strings.Contains(w.Body.String(), "PERMISSION_DENIED") {
		t.Fatalf("from the CLI: %d %s", w.Code, w.Body.String())
	}
	browser := map[string]string{"Authorization": "Bearer " + ta.tokens["browser"], "Content-Type": "application/json"}
	w = do(s, "POST", "/v1/installation/upgrade-request", body, browser)
	var e envelope
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != 403 || e.Error.Code != "STEP_UP_REQUIRED" || !strings.Contains(w.Body.String(), `"operation":"installation.upgrade"`) {
		t.Fatalf("the step-up: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "POST", "/v1/installation/upgrade-request", `{"version":"0.52.0","requestId":"upr_x"}`, browser); w.Code != 422 {
		t.Fatalf("a bad request id: %d %s", w.Code, w.Body.String())
	}
	if w := do(s, "POST", "/v1/installation/upgrade-request/upr_"+strings.Repeat("a", 26)+"/cancel", "", cli); w.Code != 404 {
		t.Fatalf("cancel of no request: %d %s", w.Code, w.Body.String())
	}
}
