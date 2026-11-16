// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/api/openapicheck"
	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/daemon"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/paritytest"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

var writeGoSealed = flag.String("write-go-sealed", "", "write the audit export fixture with every Organization KEK and export credential sealed again by Go to this path")

// The fixture's tables, public URL, allow list and fixed endpoint
// (go-audit-export-fixture.test.ts).
var tables = []string{"installation", "identities", "credentials", "organizations", "org_memberships", "approval_intents",
	"organization_freezes", "organization_deletions", "audit_exports", "audit_export_plans"}

const (
	publicURL = "http://127.0.0.1:8686"
	allow     = "s3.fixture.test,127.0.0.1/32:*"
	fixtureIP = "10.9.9.9"
)

// extra is what the fixture holds beyond the kit's members.
type extra struct {
	Credentials map[string]struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
	} `json:"credentials"`
	Exchanges map[string][]string `json:"exchanges"`
}

func read(t *testing.T) (paritytest.Fixture, extra) {
	t.Helper()
	path := paritytest.Path("audit-export-v0.22.0.json")
	f, err := paritytest.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var x extra
	if err := json.Unmarshal(b, &x); err != nil {
		t.Fatal(err)
	}
	if len(f.Requests) < 50 || len(x.Exchanges) < 8 || len(x.Credentials) < 3 {
		t.Fatalf("%d requests, %d exchanges, %d credentials: the fixture is incomplete", len(f.Requests), len(x.Exchanges), len(x.Credentials))
	}
	return f, x
}

// replay runs the table against varlatchd on the file's rows, its
// destination the Go fake under the fixture's fixed endpoint, and
// compares each request's exchange with it.
func replay(t *testing.T, f paritytest.Fixture, x extra) {
	fake := s3fake.New()
	t.Cleanup(fake.Close)
	path := filepath.Join(t.TempDir(), "varlatch.db")
	if err := paritytest.Prepare(path, f.Rows, tables); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), storage.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := outbound.ParseAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(entries, outbound.Options{
		Log: log,
		Resolve: func(_ context.Context, name string) ([]outbound.Answer, error) {
			if name == "s3.fixture.test" {
				return []outbound.Answer{{Address: fixtureIP, Family: 4}}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		},
		// The fixture's name, once the policy allowed it, connects to the fake.
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if host, _, _ := net.SplitHostPort(address); host == fixtureIP {
				address = fake.Listener.Addr().String()
			}
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	})
	t.Cleanup(policy.Close)
	public, _ := url.Parse(publicURL)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	now := paritytest.HourClock()
	approvals := auth.New(store, auth.Options{Log: log, RootKEK: rootKEK, PublicURL: public, PersonGate: w.Gates.PersonGate, Now: now})
	vs := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: w.Gates, Now: now})
	h, err := httpserver.New(httpserver.Options{
		Version: f.Version(), Backend: daemon.NewBackend(store, rootKEK), Log: log, PublicURL: public,
		Auth: approvals, Values: vs, Writer: w, RootKEK: rootKEK, Now: now, Outbound: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vs.Settled()
		_ = store.Close()
	})
	acme := ""
	for _, o := range f.Rows["organizations"] {
		if o["slug"] == "acme" {
			acme = o["id"].(string)
		}
	}
	seen := 0
	got := map[string][]string{}
	paritytest.Replay(t, paritytest.Target{
		Handler: h, Store: store, Settled: vs.Settled, Path: strings.NewReplacer("{acmeId}", acme).Replace, Now: now,
		Check: func(t testing.TB, req *http.Request, body []byte, rec *httptest.ResponseRecorder) {
			openapicheck.Recorder{T: t}.Exchange(req, body, rec)
		},
		Inspect: func(_ testing.TB, c paritytest.Recorded, _ paritytest.Raw) {
			reqs := fake.Requests()
			for _, r := range reqs[seen:] {
				line := r.Method
				if r.Retention {
					line += " retention"
				}
				got[c.ID] = append(got[c.ID], fmt.Sprintf("%s %s %d", line, r.AccessKey, r.Status))
			}
			seen = len(reqs)
		},
	}, f)
	if !reflect.DeepEqual(got, x.Exchanges) {
		t.Errorf("exchanges with the destination:\n got %v\nwant %v", got, x.Exchanges)
	}
}

// The audit export fixture gives the TypeScript server's answers (step
// 4.11a): getAuditExport, createAuditExport (every zod issue, the
// validation, the outbound policy's refusal and its record, the probe's
// findings, frozen and deleting), checkAuditExport (a supplied key, the
// stored one, the stored one elsewhere), changeAuditExport (tightening,
// loosening and another destination under their approvals, its probe),
// replaceAuditExportCredential and removeAuditExport, with their audit
// events and side rows; and each request's exchange with the destination,
// the same. A check and a change with the stored key send the key the
// TypeScript code sealed: G3 at the database level, ts-to-go.
func TestTypeScriptFixture(t *testing.T) {
	f, x := read(t)
	replay(t, f, x)
}

func envelopeValue(t *testing.T, e envelope.Envelope) map[string]any {
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// goSealed is the fixture with the Root KEK canary, every Organization KEK
// and every export credential sealed again by Go, and the recorded side
// rows naming them.
func goSealed(t *testing.T) (paritytest.Fixture, extra, map[string]map[string]any) {
	f, x := read(t)
	rootKEK, err := hex.DecodeString(f.RootKEK)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range f.Rows["installation"] {
		canary, err := envelope.NewCanary(rootKEK, inst["id"].(string))
		if err != nil {
			t.Fatal(err)
		}
		inst["kek_canary"] = envelopeValue(t, canary)
	}
	kekOf := map[string][]byte{}
	for _, o := range f.Rows["organizations"] {
		id := o["id"].(string)
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
		if err != nil {
			t.Fatal(err)
		}
		kekOf[id] = kek
		o["wrapped_org_kek"] = envelopeValue(t, wrapped)
	}
	sealedOf := map[string]map[string]any{}
	for _, e := range f.Rows["audit_exports"] {
		if e["credential_envelope"] == nil {
			continue
		}
		id, org := e["id"].(string), e["organization_id"].(string)
		c, ok := x.Credentials[id]
		if !ok {
			t.Fatalf("no credential for %s", id)
		}
		plain := jsvalue.Stringify(jsvalue.Object{{Key: "accessKeyId", Value: c.AccessKeyID}, {Key: "secretAccessKey", Value: c.SecretAccessKey}})
		sealed, err := envelope.Seal(kekOf[org], plain, envelope.AuditExportCredentialContext(org, id))
		if err != nil {
			t.Fatal(err)
		}
		sealedOf[id] = envelopeValue(t, sealed)
		e["credential_envelope"] = sealedOf[id]
	}
	for _, r := range f.Requests {
		for _, rows := range r.Side["audit_exports"] {
			resealSide(rows, sealedOf)
		}
	}
	f.Comment = "Written by the Go tests (go test ./server/auditexport -run TestGoSealedFixture -args -write-go-sealed=<file>): the audit export fixture with the Root KEK canary, every Organization KEK and every export credential sealed again by Go; services/varlatchd/test/go-audit-export-fixture.test.ts opens it with the TypeScript server."
	f.Ref = "go"
	return f, x, sealedOf
}

// resealSide puts the envelope Go sealed into side rows of the exports it
// sealed one for (a row whose envelope a request kept).
func resealSide(rows []paritytest.Row, sealedOf map[string]map[string]any) {
	for _, row := range rows {
		if id, ok := row["id"].(string); ok && sealedOf[id] != nil {
			if _, isObject := row["credential_envelope"].(map[string]any); isObject {
				row["credential_envelope"] = sealedOf[id]
			}
		}
	}
}

// TestGoSealedFixture: export credentials Go sealed go out from varlatchd
// with the TypeScript server's answers and exchanges; with
// -write-go-sealed, the file for the TypeScript side (G3, go-to-ts).
func TestGoSealedFixture(t *testing.T) {
	f, x, sealedOf := goSealed(t)
	replay(t, f, x)
	if *writeGoSealed == "" {
		return
	}
	var raw map[string]json.RawMessage
	b, err := os.ReadFile(paritytest.Path("audit-export-v0.22.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var requests []map[string]any
	if err := json.Unmarshal(raw["requests"], &requests); err != nil {
		t.Fatal(err)
	}
	for _, r := range requests {
		side, _ := r["side"].(map[string]any)
		changes, _ := side["audit_exports"].(map[string]any)
		for _, rows := range changes {
			for _, row := range rows.([]any) {
				resealSide([]paritytest.Row{row.(map[string]any)}, sealedOf)
			}
		}
	}
	for k, v := range map[string]any{"comment": f.Comment, "ref": f.Ref, "rows": f.Rows, "requests": requests} {
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw[k] = enc
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*writeGoSealed, append(out, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
