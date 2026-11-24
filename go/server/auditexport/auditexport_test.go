// SPDX-License-Identifier: AGPL-3.0-or-later

package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/authz"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/orgs"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/write"
)

type world struct {
	t     *testing.T
	store *storage.DB
	s     *Service
	org   authz.Organization
	fake  *s3fake.Server
	key   []byte
}

func newWorld(t *testing.T) *world {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := db.Init(ctx, store, "test"); err != nil {
		t.Fatal(err)
	}
	wd := &world{t: t, store: store, fake: s3fake.New()}
	t.Cleanup(wd.fake.Close)
	wd.exec(`INSERT INTO identities (id, kind, name) VALUES ('idn_a', 'human', 'Alice')`)
	wd.exec(`INSERT INTO credentials (id, identity_id, kind, token_hash) VALUES ('crd_a', 'idn_a', 'cli', 'h_a')`)
	w := &write.Writer{Store: store, Gates: write.NewGates()}
	wd.key = envelope.GenerateKey()
	org, err := orgs.Create(ctx, w, wd.key, "idn_a", "acme", "Acme")
	if err != nil {
		t.Fatal(err)
	}
	wd.org = authz.Organization{ID: org.ID, Slug: "acme", Name: "Acme"}
	entries, _ := outbound.ParseAllow("127.0.0.1/32:*")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := outbound.New(entries, outbound.Options{Log: log})
	t.Cleanup(policy.Close)
	public, _ := url.Parse("http://127.0.0.1:8686")
	approvals := auth.New(store, auth.Options{PublicURL: public, RootKEK: wd.key, PersonGate: w.Gates.PersonGate})
	wd.s = &Service{Writer: w, Approvals: approvals, RootKEK: wd.key, Policy: policy, Enabled: true}
	return wd
}

func (wd *world) exec(q string, args ...any) {
	wd.t.Helper()
	if err := wd.store.Write(context.Background(), func(tx *storage.Tx) error { _, err := tx.ExecContext(context.Background(), q, args...); return err }); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) count(q string, args ...any) int {
	wd.t.Helper()
	var n int
	if err := wd.store.Reader().QueryRow(q, args...).Scan(&n); err != nil {
		wd.t.Fatal(err)
	}
	return n
}

func alice() Request {
	return Request{Principal: &auth.Principal{Identity: auth.Identity{ID: "idn_a", Kind: "human"}, Credential: auth.Credential{ID: "crd_a", Kind: auth.KindCLI}}, RequestID: "req_test"}
}

func (wd *world) dest(bucket string) Destination {
	return Destination{Endpoint: wd.fake.URL, Region: "us-east-1", Bucket: bucket, PathStyle: true}
}

func good() Credential {
	return Credential{AccessKeyID: s3fake.KeyGood, SecretAccessKey: "fixture-secret"}
}

func code(err error) (string, jsvalue.Object) {
	var de *domainerr.Error
	if errors.As(err, &de) {
		return de.Code, de.Details
	}
	return "", nil
}

func (wd *world) create(in CreateInput) {
	wd.t.Helper()
	if _, err := wd.s.Create(context.Background(), alice(), wd.org, in); err != nil {
		wd.t.Fatal(err)
	}
}

// Creating probes the destination (a conditional write, its refusal, a
// HEAD, the retention read back) with the key, then writes the export, its
// first stream's manifest plan and two audit events; the key rests sealed.
func TestCreate(t *testing.T) {
	wd := newWorld(t)
	wd.create(CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: good(), Retention: &Retention{Mode: "compliance", Days: 7}, From: "beginning"})
	var got []string
	for _, r := range wd.fake.Requests() {
		got = append(got, r.Method+" "+map[bool]string{true: "retention ", false: ""}[r.Retention]+r.AccessKey)
	}
	if strings.Join(got, ", ") != "PUT AKIAFIXTUREGOOD, PUT AKIAFIXTUREGOOD, HEAD AKIAFIXTUREGOOD, GET retention AKIAFIXTUREGOOD" {
		t.Errorf("probe requests: %v", got)
	}
	if st := wd.fake.Requests()[1].Status; st != 412 {
		t.Errorf("second write %d", st)
	}
	var lock, keyRead, retRead int
	var cursor int64
	var sealed string
	if err := wd.store.Reader().QueryRow(`SELECT lock_verified, key_can_read, retention_readable, cursor_order, credential_envelope FROM audit_exports`).
		Scan(&lock, &keyRead, &retRead, &cursor, &sealed); err != nil {
		t.Fatal(err)
	}
	if lock != 1 || keyRead != 1 || retRead != 1 || cursor != 0 || strings.Contains(sealed, "fixture-secret") {
		t.Errorf("row: lock %d read %d retention %d cursor %d", lock, keyRead, retRead, cursor)
	}
	var name, sum, md5sum string
	var body []byte
	var planned, until int64
	if err := wd.store.Reader().QueryRow(`SELECT object_name, body, sha256, md5, planned_at, retain_until FROM audit_export_plans`).
		Scan(&name, &body, &sum, &md5sum, &planned, &until); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(body, &manifest); err != nil || !strings.HasSuffix(string(body), "\n") {
		t.Fatalf("manifest %q", body)
	}
	if !strings.HasPrefix(name, "varlatch-audit/"+wd.org.ID+"/aes_") || !strings.HasSuffix(name, "/stream.json") || sum != sha256Hex(body) || md5sum != md5Hex(body) ||
		manifest["kind"] != "stream" || manifest["startOrder"] != "0" || manifest["reason"] != "created" || manifest["previousStreamId"] != nil ||
		until-planned != 7*24*int64(time.Hour/time.Microsecond) || planned%1000 != 0 {
		t.Errorf("plan %s %v", name, manifest)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type IN ('audit_export.created', 'audit_export.stream_started') AND request_id = 'req_test'`); n != 2 {
		t.Errorf("%d events", n)
	}
	// A second creation finds the live export, before anything is sent.
	before := len(wd.fake.Requests())
	_, err := wd.s.Create(context.Background(), alice(), wd.org, CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: good(), From: "now"})
	if c, d := code(err); c != "VALIDATION_FAILED" || !strings.Contains(string(jsvalue.Stringify(d)), "export-exists") || len(wd.fake.Requests()) != before {
		t.Errorf("second creation: %v", err)
	}
}

// What the probe finds, as Check answers it, for every case the fake has.
func TestProbeFindings(t *testing.T) {
	wd := newWorld(t)
	compliance := &Retention{Mode: "compliance", Days: 1}
	check := func(bucket string, cred Credential, r *Retention) ProbeResult {
		t.Helper()
		res, _, err := wd.s.Check(context.Background(), alice(), wd.org, CheckInput{Destination: wd.dest(bucket), Credential: &cred, Retention: r})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	str := func(r ProbeResult) string { return string(jsvalue.Stringify(r.JS())) }
	cases := []struct {
		name   string
		got    ProbeResult
		expect string
	}{
		{"locked, no retention", check(s3fake.BucketLocked, good(), nil),
			`{"ok":true,"message":null,"conditionalCreation":true,"objectLock":"not-set","keyCanRead":true,"retentionReadable":null}`},
		{"locked, compliance", check(s3fake.BucketLocked, good(), compliance),
			`{"ok":true,"message":null,"conditionalCreation":true,"objectLock":"verified","keyCanRead":true,"retentionReadable":true}`},
		{"overwrites", check(s3fake.BucketOverwrite, good(), nil),
			`{"ok":false,"message":"` + ProbeWords.Overwrote + `","conditionalCreation":false,"objectLock":null,"keyCanRead":null,"retentionReadable":null}`},
		{"drops the metadata", check(s3fake.BucketNoMetadata, good(), nil),
			`{"ok":false,"message":"` + ProbeWords.NoMetadata + `","conditionalCreation":true,"objectLock":null,"keyCanRead":null,"retentionReadable":null}`},
		{"keeps no retention", check(s3fake.BucketNoLock, good(), compliance),
			`{"ok":false,"message":"` + ProbeWords.NoRetention + `","conditionalCreation":true,"objectLock":null,"keyCanRead":true,"retentionReadable":true}`},
		{"keeps a weaker retention", check(s3fake.BucketWeak, good(), compliance),
			`{"ok":false,"message":"` + ProbeWords.WeakerRetention + `","conditionalCreation":true,"objectLock":null,"keyCanRead":true,"retentionReadable":true}`},
		{"governance asked, compliance kept is not weaker", check(s3fake.BucketWeak, good(), &Retention{Mode: "governance", Days: 1}),
			`{"ok":true,"message":null,"conditionalCreation":true,"objectLock":"verified","keyCanRead":true,"retentionReadable":true}`},
		{"a key that cannot read", check(s3fake.BucketLocked, Credential{AccessKeyID: s3fake.KeyNoRead, SecretAccessKey: "x"}, compliance),
			`{"ok":true,"message":null,"conditionalCreation":true,"objectLock":"accepted","keyCanRead":false,"retentionReadable":false}`},
		{"a key that cannot read retention", check(s3fake.BucketLocked, Credential{AccessKeyID: s3fake.KeyNoRetentionRead, SecretAccessKey: "x"}, compliance),
			`{"ok":true,"message":null,"conditionalCreation":true,"objectLock":"accepted","keyCanRead":true,"retentionReadable":false}`},
		{"a wrong key", check(s3fake.BucketLocked, Credential{AccessKeyID: "AKIAWRONG", SecretAccessKey: "x"}, nil),
			`{"ok":false,"message":"The test write failed (S3 error InvalidAccessKeyId, HTTP 403): the destination rejected the key; check its ID and secret, and that it is not deleted or expired","conditionalCreation":null,"objectLock":null,"keyCanRead":null,"retentionReadable":null}`},
		{"no such bucket", check("missing-bucket", good(), nil),
			`{"ok":false,"message":"The test write failed (S3 error NoSuchBucket, HTTP 404): the bucket does not exist at the destination","conditionalCreation":null,"objectLock":null,"keyCanRead":null,"retentionReadable":null}`},
	}
	for _, c := range cases {
		if got := str(c.got); got != c.expect {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.expect)
		}
	}
	// A verified provider (Decision 7) is verified without the read-back.
	wd.s.VerifiedProvider = func(string) bool { return true }
	if got := check(s3fake.BucketLocked, Credential{AccessKeyID: s3fake.KeyNoRead, SecretAccessKey: "x"}, compliance); *got.ObjectLock != "verified" {
		t.Errorf("verified provider: %s", str(got))
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type LIKE 'audit_export.%'`); n != 0 {
		t.Errorf("a check recorded %d events", n)
	}
}

// Refusals before anything is sent: the switch, a refused endpoint (its
// refusal recorded although the request failed), the validation, a
// machine credential.
func TestCreateRefusals(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	in := CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: good(), From: "beginning"}
	wd.s.Enabled = false
	if _, err := wd.s.Create(ctx, alice(), wd.org, in); !strings.Contains(err.Error(), "audit_export = off in varlatchd.conf") {
		t.Errorf("switch off: %v", err)
	}
	wd.s.Enabled = true
	refused := in
	refused.Destination = Destination{Endpoint: "https://10.0.0.7", Region: "us-east-1", Bucket: "export-bucket"}
	_, err := wd.s.Create(ctx, alice(), wd.org, refused)
	if c, d := code(err); c != "VALIDATION_FAILED" || !strings.Contains(string(jsvalue.Stringify(d)), "private_address") || strings.Contains(err.Error(), "10.0.0.7") {
		t.Errorf("refused endpoint: %v %v", err, d)
	}
	if n := wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'outbound.refused' AND json_extract(metadata, '$.purpose') = 'audit_export'`); n != 1 {
		t.Errorf("%d refusals recorded", n)
	}
	for name, bad := range map[string]Destination{
		"endpoint: not a URL":                {Endpoint: "nope", Region: "r", Bucket: "export-bucket"},
		"endpoint: must be https":            {Endpoint: "ftp://x", Region: "r", Bucket: "export-bucket"},
		"endpoint: must not carry user info": {Endpoint: "https://u@x", Region: "r", Bucket: "export-bucket"},
		"endpoint: must be a scheme, host and optional port, without a path or query": {Endpoint: "https://x/p", Region: "r", Bucket: "export-bucket"},
		"bucket: 3 to 63":          {Endpoint: "https://x", Region: "r", Bucket: "Bad_Bucket"},
		"region: lowercase":        {Endpoint: "https://x", Region: "Bad", Bucket: "export-bucket"},
		"prefix: no leading slash": {Endpoint: "https://x", Region: "r", Bucket: "export-bucket", Prefix: "/x"},
	} {
		c := in
		c.Destination = bad
		if _, err := wd.s.Create(ctx, alice(), wd.org, c); !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	machine := alice()
	machine.Principal.Identity.Kind = "service"
	if _, err := wd.s.Create(ctx, machine, wd.org, in); !strings.Contains(err.Error(), "never a machine credential") {
		t.Errorf("machine: %v", err)
	}
	if n := wd.count(`SELECT count(*) FROM audit_exports`); n != 0 {
		t.Errorf("%d exports", n)
	}
	if len(wd.fake.Requests()) != 0 {
		t.Errorf("%d requests sent", len(wd.fake.Requests()))
	}
}

// Tightening the retention needs no approval; loosening, another
// destination, a new key and removal always ask for one, before any key
// is sent; a stale version is refused first.
func TestChangesAndApprovals(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	wd.create(CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: good(), Retention: &Retention{Mode: "governance", Days: 7}, From: "beginning"})
	id, _ := LiveID(ctx, wd.store.Reader(), wd.org.ID)
	out, _, err := wd.s.Change(ctx, alice(), wd.org, id, ChangeInput{SetRetention: true, Retention: &Retention{Mode: "compliance", Days: 30}, ExpectedVersion: 1})
	if err != nil || !out.Changed || out.Loosened {
		t.Fatalf("tighten: %+v %v", out, err)
	}
	out, _, err = wd.s.Change(ctx, alice(), wd.org, id, ChangeInput{SetRetention: true, Retention: &Retention{Mode: "compliance", Days: 30}, ExpectedVersion: 2})
	if err != nil || out.Changed {
		t.Errorf("unchanged: %+v %v", out, err)
	}
	need := func(err error) bool { var n *auth.ApprovalNeeded; return errors.As(err, &n) }
	if _, _, err := wd.s.Change(ctx, alice(), wd.org, id, ChangeInput{SetRetention: true, ExpectedVersion: 2}); !need(err) {
		t.Errorf("remove retention: %v", err)
	}
	sent := len(wd.fake.Requests())
	other := "other/"
	if _, _, err := wd.s.Change(ctx, alice(), wd.org, id, ChangeInput{Destination: DestinationPatch{Prefix: &other}, ExpectedVersion: 2}); !need(err) || len(wd.fake.Requests()) != sent {
		t.Errorf("another destination: %v, %d requests", err, len(wd.fake.Requests())-sent)
	}
	if _, _, err := wd.s.Change(ctx, alice(), wd.org, id, ChangeInput{SetRetention: true, ExpectedVersion: 1}); func() string { c, _ := code(err); return c }() != "VERSION_CONFLICT" {
		t.Errorf("stale: %v", err)
	}
	if _, err := wd.s.ReplaceCredential(ctx, alice(), wd.org, id, good(), 2); !need(err) {
		t.Errorf("new key: %v", err)
	}
	if _, _, err := wd.s.Remove(ctx, alice(), wd.org, id, 2); !need(err) {
		t.Errorf("remove: %v", err)
	}
	wd.s.Enabled = false
	if _, _, err := wd.s.Remove(ctx, alice(), wd.org, id, 2); !need(err) {
		t.Errorf("remove with the switch off still asks for the approval: %v", err)
	}
	if _, _, err := wd.s.Remove(ctx, alice(), wd.org, "aex_none", 2); func() string { c, _ := code(err); return c }() != "RESOURCE_NOT_FOUND" {
		t.Errorf("no export: %v", err)
	}
}

// approve inserts an approved intent of alice's CLI credential for b.
func (wd *world) approve(id string, b auth.Binding) {
	wd.t.Helper()
	summary := jsvalue.Stringify(b.Summary.JS())
	now := time.Now().UnixMicro()
	wd.exec(`INSERT INTO approval_intents (id, credential_id, identity_id, organization_id, operation, target, body_hash, query_hash, expected_version,
		summary, origin, created_at, expires_at, poll_interval, approved_at, approved_with_passkey_id, approval_user_verified)
		VALUES (?, 'crd_a', 'idn_a', ?, ?, ?, ?, ?, ?, ?, 'cli', ?, ?, 5, ?, 'PasskeyConf001', 1)`,
		id, *b.OrganizationID, b.Operation, auth.CanonicalJSON(b.Target), auth.ApprovalHash(wd.key, "body", b.Body),
		auth.ApprovalHash(wd.key, "query", b.Query), *b.ExpectedVersion, string(summary), now-1, now+3_600_000_000, now)
}

// Decision 4: a destination change holds the export's gate across its
// probe. A credential replacement asked meanwhile waits for it, then
// finds the version the change made.
func TestChangeHoldsTheExportAcrossItsProbe(t *testing.T) {
	wd := newWorld(t)
	ctx := context.Background()
	wd.create(CreateInput{Destination: wd.dest(s3fake.BucketLocked), Credential: good(), From: "beginning"})
	id, _ := LiveID(ctx, wd.store.Reader(), wd.org.ID)
	row, err := activeExport(ctx, wd.store.Reader(), wd.org.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	other := "moved/"
	in := ChangeInput{Destination: DestinationPatch{Prefix: &other}, ExpectedVersion: 1}
	d, r, _ := in.next(*row)
	c := classify(destinationOf(*row), retentionOf(*row), d, r)
	approval := "apr_changeaaaaaaaaaaaaaaaaaaaa"
	wd.approve(approval, changeBinding(wd.org, id, d, r, 1, c))
	req := alice()
	req.Approval = &approval

	wd.fake.Hold, wd.fake.Held = make(chan struct{}), make(chan struct{}, 8)
	changed := make(chan error, 1)
	go func() { _, _, err := wd.s.Change(ctx, req, wd.org, id, in); changed <- err }()
	<-wd.fake.Held
	replaced := make(chan error, 1)
	go func() { _, err := wd.s.ReplaceCredential(ctx, alice(), wd.org, id, good(), 1); replaced <- err }()
	select {
	case err := <-replaced:
		t.Fatalf("the replacement did not wait for the probe: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(wd.fake.Hold)
	if err := <-changed; err != nil {
		t.Fatalf("change: %v", err)
	}
	if err := <-replaced; func() string { c, _ := code(err); return c }() != "VERSION_CONFLICT" {
		t.Errorf("replacement after the change: %v", err)
	}
	var prefix string
	var version int64
	_ = wd.store.Reader().QueryRow(`SELECT prefix, version FROM audit_exports WHERE id = ?`, id).Scan(&prefix, &version)
	if prefix != "moved/" || version != 2 || wd.count(`SELECT count(*) FROM audit_events WHERE event_type = 'audit_export.stream_started'`) != 2 {
		t.Errorf("after the change: %s v%d", prefix, version)
	}
}
