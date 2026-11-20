// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g5 && linux

package g5_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/auditexport/s3fake"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/auth/authtest"
)

// The kinds of change G5's reverse half makes on Go before a reverse
// migration (internal docs/design/go-step7.md §7.6): one of each, through
// Go's own code paths (its HTTP API, and `varlatchd admin` where that is
// the only route), on a fresh Go installation:
//
//  1. a new value (PUT .../values/{item});
//  2. a rotation (POST .../values/{item}/rotations);
//  3. a new passkey (the WebAuthn registration ceremony over HTTP, a
//     software authenticator answering it, from a recovery link of
//     `varlatchd admin recover --identity`); its browser session and the
//     browser credential minted from it are kept, for the reverse to end;
//  4. a revoked credential (a service identity's first credential,
//     revoked through the API);
//  5. a grant change (a Grant to that service identity);
//  6. a Sync Target run (a Convex Connection and Target against a local
//     fake deployment, over https with a certificate made here);
//  7. a webhook delivery (a webhook to a local receiver, which the other
//     changes' events reach, its cursor moved);
//  8. an audit export batch (an audit export to a local S3 stand-in,
//     server/auditexport/s3fake, its cursor moved).
//
// Nothing leaves this machine: every destination is a 127.0.0.1 test
// server, which outbound_allow lets through, and the fake deployment's
// certificate, made at run time, is the only root varlatchd trusts
// (SSL_CERT_FILE). No key, token or certificate is written in this file,
// and none is printed.

// kindsWorld is the local stand-ins the kinds of change reach.
type kindsWorld struct {
	// webhook receives the deliveries; platform is a Convex deployment
	// (https), bucket an S3 bucket with Object Lock.
	webhook  *httptest.Server
	platform *httptest.Server
	bucket   *s3fake.Server
	// caFile holds the platform's certificate, the root varlatchd trusts.
	caFile string
	// bucketSecret is the bucket credential's secret half, made here.
	bucketSecret string

	mu         sync.Mutex
	deliveries []delivery
	convex     map[string]string
}

// delivery is one request the webhook receiver answered.
type delivery struct {
	Method, Path, Signature string
	Body                    []byte
}

// newKindsWorld starts the stand-ins; the test's cleanup stops them.
func newKindsWorld(t *testing.T) *kindsWorld {
	t.Helper()
	w := &kindsWorld{convex: map[string]string{}, bucketSecret: hex.EncodeToString(randomBytes(20))}
	w.webhook = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.mu.Lock()
		w.deliveries = append(w.deliveries, delivery{Method: r.Method, Path: r.URL.Path, Signature: r.Header.Get("X-Varlatch-Signature"), Body: body})
		w.mu.Unlock()
		rw.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(w.webhook.Close)

	cert, pemBytes := selfSigned(t)
	w.caFile = filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(w.caFile, pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	w.platform = httptest.NewUnstartedServer(http.HandlerFunc(w.serveConvex))
	w.platform.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	w.platform.StartTLS()
	t.Cleanup(w.platform.Close)

	w.bucket = s3fake.New()
	t.Cleanup(w.bucket.Close)
	return w
}

// selfSigned is a certificate for 127.0.0.1, its own issuer, with a key
// made now: the certificate the fake deployment serves and the one root
// varlatchd trusts.
func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "g5 fake platform"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// serveConvex answers as a Convex deployment's admin API does what the
// Convex adapter asks (lib/sync/convex.go): the key check, the variable
// list and the batch update, keeping the variables.
func (w *kindsWorld) serveConvex(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	answer := func(status int, v any) {
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		_ = json.NewEncoder(rw).Encode(v)
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Convex ") {
		answer(http.StatusUnauthorized, map[string]any{})
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case r.Method == "POST" && r.URL.Path == "/api/check_admin_key":
		answer(http.StatusOK, map[string]any{"success": true})
	case r.Method == "POST" && r.URL.Path == "/api/query":
		list := []map[string]string{}
		for k, v := range w.convex {
			list = append(list, map[string]string{"name": k, "value": v})
		}
		answer(http.StatusOK, map[string]any{"status": "success", "value": list})
	case r.Method == "POST" && r.URL.Path == "/api/update_environment_variables":
		var in struct {
			Changes []struct {
				Name  string  `json:"name"`
				Value *string `json:"value"`
			} `json:"changes"`
		}
		if json.Unmarshal(body, &in) != nil {
			answer(http.StatusUnprocessableEntity, map[string]any{})
			return
		}
		for _, c := range in.Changes {
			if c.Value == nil {
				delete(w.convex, c.Name)
			} else {
				w.convex[c.Name] = *c.Value
			}
		}
		answer(http.StatusOK, map[string]any{})
	default:
		answer(http.StatusNotFound, map[string]any{})
	}
}

// config is the varlatchd.conf lines the kinds need: the converge engine
// on, narrowed to the Convex adapter; the audit export on; loopback let
// through the outbound policy (plain http for the receiver and the bucket,
// https for the deployment).
func (w *kindsWorld) config() string {
	return "sync = on\nsync_adapters = convex\naudit_export = on\noutbound_allow = 127.0.0.1/32:*\n"
}

// env is the environment varlatchd runs with: the fake deployment's
// certificate its only root.
func (w *kindsWorld) env() []string {
	return append(os.Environ(), "SSL_CERT_FILE="+w.caFile, "SSL_CERT_DIR="+filepath.Dir(w.caFile))
}

// received is the webhook deliveries so far.
func (w *kindsWorld) received() []delivery {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]delivery(nil), w.deliveries...)
}

// convexValues is the fake deployment's variables.
func (w *kindsWorld) convexValues() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]string{}
	for k, v := range w.convex {
		out[k] = v
	}
	return out
}

// kindsInstall is a fresh Go installation: its configuration, data
// directory and database, its URL, and an Installation Admin's CLI
// credential (bootstrapped offline) and identity.
type kindsInstall struct {
	Conf, Data, DB string
	// Base is the address it serves at (http://127.0.0.1:<port>); Public
	// its public URL (http://localhost:<port>), the browser's origin.
	Base, Public string
	Admin        string
	AdminID      string
}

// bootstrapped is `varlatchd admin bootstrap --cli-credential`'s answer.
var bootstrapped = regexp.MustCompile(`^Installation bootstrapped\.\nInstallation Admin identity: (idn_[a-z2-7]+)\nOne-time CLI credential \(store it now; it is not retrievable\):\n(vlt_\S+)\n$`)

// freshInstall is a new Go installation for the kinds: its Root KEK made
// now, its listener on a free loopback port, the world's configuration,
// bootstrapped offline with an Installation Admin's CLI credential.
func freshInstall(t *testing.T, bin string, w *kindsWorld) kindsInstall {
	t.Helper()
	dir := t.TempDir()
	port := strings.TrimPrefix(freePort(t), "127.0.0.1:")
	in := kindsInstall{Conf: filepath.Join(dir, "varlatchd.conf"), Data: filepath.Join(dir, "data"),
		Base: "http://127.0.0.1:" + port, Public: "http://localhost:" + port}
	in.DB = filepath.Join(in.Data, "varlatch.db")
	if err := os.Mkdir(in.Data, 0o700); err != nil {
		t.Fatal(err)
	}
	kek := filepath.Join(dir, "root-kek")
	if err := os.WriteFile(kek, []byte(hex.EncodeToString(randomBytes(32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf("listen = 127.0.0.1:%s\npublic_url = %s\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\nbackup_interval = off\n",
		port, in.Public, in.Data, kek, filepath.Join(dir, "access.log")) + w.config()
	if err := os.WriteFile(in.Conf, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "admin", "bootstrap", "--cli-credential", "--config", in.Conf)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("bootstrap: %v: %s", err, stderr.String())
	}
	m := bootstrapped.FindStringSubmatch(stdout.String())
	if m == nil {
		t.Fatal("bootstrap did not answer with an identity and a CLI credential")
	}
	in.AdminID, in.Admin = m[1], m[2]
	return in
}

// kindsService is a running `varlatchd serve`.
type kindsService struct {
	cmd  *exec.Cmd
	log  string
	done chan struct{}
}

// startKinds starts varlatchd on in, in the world's environment, and waits
// until it answers GET /v1/meta. The test's cleanup stops it if the test
// did not.
func startKinds(t *testing.T, bin string, w *kindsWorld, in kindsInstall) *kindsService {
	t.Helper()
	s := &kindsService{log: filepath.Join(filepath.Dir(in.Conf), "serve.log"), done: make(chan struct{})}
	f, err := os.OpenFile(s.log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s.cmd = exec.Command(bin, "serve", "--config", in.Conf)
	s.cmd.Env = w.env()
	s.cmd.Stdout, s.cmd.Stderr = f, f
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.cmd.Wait(); close(s.done) }()
	t.Cleanup(func() { s.stop(t) })
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		select {
		case <-s.done:
			t.Fatalf("varlatchd exited at start:\n%s", s.tail())
		default:
		}
		if res, err := http.Get(in.Base + "/v1/meta"); err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return s
			}
		}
	}
	t.Fatalf("varlatchd did not answer within 30 s:\n%s", s.tail())
	return nil
}

// stop stops varlatchd (SIGTERM), at most 30 seconds; again, nothing.
func (s *kindsService) stop(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(30 * time.Second):
		_ = s.cmd.Process.Kill()
		<-s.done
		t.Errorf("varlatchd did not stop within 30 s:\n%s", s.tail())
	}
}

// tail is the end of its log (varlatchd's log holds no credential).
func (s *kindsService) tail() string {
	b, _ := os.ReadFile(s.log)
	if len(b) > 4000 {
		b = b[len(b)-4000:]
	}
	return string(b)
}

// kindsMade is what applyKinds made, by kind, for the assertions after a
// reverse migration: ids, and the cursors the background work moved.
type kindsMade struct {
	Org, Project, Environment, Item string
	// ValueVersion is the new value's version; RotationVersion the
	// rotation's primary (the new value) and RetiringVersion the version
	// it retires.
	ValueVersion, RotationVersion, RetiringVersion string
	// Passkey is the new passkey; Session the browser session its
	// ceremony started, BrowserCredential the browser credential minted
	// from that session, and BrowserToken that credential's bearer
	// (vlt_web_), which authenticates /v1/me until the session ends.
	Passkey, PasskeyIdentity, Session, BrowserCredential, BrowserToken string
	// ServiceIdentity holds RevokedCredential (revoked) and Grant.
	ServiceIdentity, RevokedCredential, Grant string
	// SyncTarget ran: SyncRun is its generation after the run, its last
	// result SyncResult.
	SyncTarget, SyncRun, SyncResult string
	Webhook, AuditExport            string
	// The cursors the delivery and the batch moved (event_order): the
	// webhook's past where it was at its registration, the audit export's
	// past 0, where it begins.
	WebhookCursor, AuditExportCursor int64
}

// kindsClient calls the API as the Installation Admin.
type kindsClient struct {
	t     *testing.T
	base  string
	token string
}

// call sends a JSON request and answers the status and the body; a body
// is never printed (a few hold a secret once).
func (c kindsClient) call(method, path string, body any) (int, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "varlatch-g5-kinds")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

// errorCode is an error answer's code and message, never its whole body.
func errorCode(b []byte) string {
	var e struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil {
		return "(not an error answer)"
	}
	return e.Error.Code + ": " + e.Error.Message
}

// ok sends the request and decodes a 2xx answer into out (when not nil).
func (c kindsClient) ok(what, method, path string, body, out any) {
	c.t.Helper()
	status, b := c.call(method, path, body)
	if status >= 300 {
		c.t.Fatalf("%s: %d %s", what, status, errorCode(b))
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		c.t.Fatalf("%s: the answer is not the expected JSON", what)
	}
}

// readDB opens the database at path read-only.
func readDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// waitFor polls done every half second, at most d; false if it never held.
func waitFor(d time.Duration, done func() bool) bool {
	for deadline := time.Now().Add(d); ; time.Sleep(500 * time.Millisecond) {
		if done() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// applyKinds makes one change of each kind on the running installation in
// (served at in.Base), and waits until the background ones are recorded in
// its database (read-only): the webhook's cursor moved past a delivery the
// receiver got, the Sync Target's run recorded its result and the
// deployment holds the values, the audit export's cursor moved past a
// batch the bucket holds. bin is the varlatchd the recovery link comes
// from (`admin recover --identity`, through the running daemon).
func applyKinds(t *testing.T, w *kindsWorld, bin string, in kindsInstall) kindsMade {
	t.Helper()
	c := kindsClient{t: t, base: in.Base, token: in.Admin}
	suffix := hex.EncodeToString(randomBytes(4))
	slug := "kinds-" + suffix
	org := "/v1/organizations/" + slug
	env := org + "/projects/api/environments/production"
	var made kindsMade
	made.Project, made.Environment, made.Item = "api", "production", "API_KEY"

	// The Organization, its Project, an environment and a Contract.
	var created struct{ ID string }
	c.ok("creating the Organization", "POST", "/v1/organizations", map[string]any{"name": "G5 kinds", "slug": slug}, &created)
	made.Org = created.ID
	c.ok("creating the Project", "POST", org+"/projects", map[string]any{"slug": "api", "name": "API", "contractAuthority": "managed"}, nil)
	c.ok("creating the environment", "POST", org+"/projects/api/environments", map[string]any{"name": "production", "tier": "production"}, nil)
	items := []map[string]any{
		{"name": "API_KEY", "required": map[string]any{"kind": "never"}, "sensitive": true, "type": "string"},
		{"name": "PORT", "required": map[string]any{"kind": "never"}, "sensitive": false, "type": "string"},
	}
	var revision struct{ ID string }
	c.ok("pushing the Contract", "POST", org+"/projects/api/contract/revisions", map[string]any{"contract": map[string]any{"schemaVersion": 1, "items": items}}, &revision)
	c.ok("activating the Contract", "POST", org+"/projects/api/contract/revisions/"+revision.ID+"/activate", map[string]any{}, nil)

	// 7. A webhook first, so the other changes' events reach it.
	var hook struct{ ID string }
	c.ok("registering the webhook", "POST", org+"/webhooks", map[string]any{"url": w.webhook.URL + "/hook/" + suffix}, &hook)
	made.Webhook = hook.ID
	// Its cursor starts at the log's end when it registered.
	db := readDB(t, in.DB)
	defer db.Close()
	var registered int64
	if err := db.QueryRow("SELECT cursor_order FROM webhooks WHERE id = ?", made.Webhook).Scan(&registered); err != nil {
		t.Fatal(err)
	}

	// 8. The audit export, from the beginning of the log.
	destination := map[string]any{"endpoint": w.bucket.URL, "region": "us-east-1", "bucket": s3fake.BucketLocked, "prefix": "g5", "pathStyle": true}
	credential := map[string]any{"accessKeyId": s3fake.KeyGood, "secretAccessKey": w.bucketSecret}
	var export struct{ ID string }
	c.ok("creating the audit export", "POST", org+"/audit-export", map[string]any{"destination": destination, "credential": credential,
		"retention": map[string]any{"mode": "governance", "days": 1}}, &export)
	made.AuditExport = export.ID

	// 1. A new value.
	var version struct{ VersionID string }
	c.ok("setting API_KEY", "PUT", env+"/values/API_KEY", map[string]any{"value": "key-" + hex.EncodeToString(randomBytes(8))}, &version)
	c.ok("setting PORT", "PUT", env+"/values/PORT", map[string]any{"value": "8080"}, nil)
	made.ValueVersion = version.VersionID

	// 2. A rotation of it.
	var rotation struct {
		PrimaryVersionID  string
		RetiringVersionID *string
	}
	c.ok("rotating API_KEY", "POST", env+"/values/API_KEY/rotations", map[string]any{"value": "key-" + hex.EncodeToString(randomBytes(8)), "graceSeconds": 3600}, &rotation)
	made.RotationVersion = rotation.PrimaryVersionID
	if rotation.RetiringVersionID != nil {
		made.RetiringVersion = *rotation.RetiringVersionID
	}

	// 4 and 5. A service identity, a Grant to it, its credential revoked.
	var service struct{ ID string }
	c.ok("creating a service identity", "POST", org+"/identities", map[string]any{"name": "g5 service", "kind": "service"}, &service)
	made.ServiceIdentity = service.ID
	var grant struct{ ID string }
	c.ok("granting it", "POST", org+"/grants", map[string]any{"subjectIdentityId": service.ID,
		"scope": map[string]any{"kind": "project", "projectId": projectID(t, c, org)}, "actions": []string{"config.value.read"}}, &grant)
	made.Grant = grant.ID
	var creds struct {
		Items []struct{ ID string }
	}
	c.ok("listing its credentials", "GET", org+"/identities/"+service.ID+"/credentials", nil, &creds)
	if len(creds.Items) != 1 {
		t.Fatalf("the service identity has %d credentials, not its first one", len(creds.Items))
	}
	made.RevokedCredential = creds.Items[0].ID
	c.ok("revoking its credential", "DELETE", org+"/identities/"+service.ID+"/credentials/"+made.RevokedCredential, nil, nil)

	// 6. A Convex Connection and Target, against the fake deployment.
	var conn struct{ ID string }
	c.ok("creating the Convex Connection", "POST", org+"/platform-connections", map[string]any{"platform": "convex",
		"baseIdentity": w.platform.URL, "name": "Convex", "credential": "prod:g5-" + hex.EncodeToString(randomBytes(12))}, &conn)
	var target struct{ ID string }
	c.ok("creating the Convex Target", "POST", env+"/sync-targets", map[string]any{"connectionId": conn.ID, "destination": map[string]any{},
		"mapping": map[string]any{"kind": "wildcard"}}, &target)
	made.SyncTarget = target.ID

	// 3. A new passkey, last: the Installation Admin's, from a recovery
	// link, enrolled over HTTP; its session's browser credential minted.
	enrollPasskey(t, bin, in, &made)

	// The background work: each recorded in the database.
	scalar := func(q string, args ...any) (v sql.NullString) {
		_ = db.QueryRow(q, args...).Scan(&v)
		return v
	}
	if !waitFor(150*time.Second, func() bool {
		got := false
		for _, d := range w.received() {
			got = got || d.Method == "POST" && d.Path == "/hook/"+suffix && d.Signature != ""
		}
		cur := scalar("SELECT cursor_order FROM webhooks WHERE id = ?", made.Webhook)
		n, _ := strconv.ParseInt(cur.String, 10, 64)
		made.WebhookCursor = n
		return got && n > registered
	}) {
		t.Fatalf("no webhook delivery recorded (%d requests received; the cursor at %d, %d at registration)", len(w.received()), made.WebhookCursor, registered)
	}
	if !waitFor(150*time.Second, func() bool {
		r := scalar("SELECT last_result FROM sync_targets WHERE id = ?", made.SyncTarget)
		g := scalar("SELECT generation FROM sync_targets WHERE id = ?", made.SyncTarget)
		made.SyncResult, made.SyncRun = r.String, g.String
		_, delivered := w.convexValues()["API_KEY"]
		return r.Valid && delivered
	}) {
		t.Fatalf("no Sync Target run recorded (last result %q)", made.SyncResult)
	}
	if !waitFor(150*time.Second, func() bool {
		cur := scalar("SELECT cursor_order FROM audit_exports WHERE id = ?", made.AuditExport)
		n, _ := strconv.ParseInt(cur.String, 10, 64)
		made.AuditExportCursor = n
		return n > 0 && len(w.bucket.Keys(s3fake.BucketLocked)) > 0
	}) {
		t.Fatalf("no audit export batch recorded (%d objects in the bucket)", len(w.bucket.Keys(s3fake.BucketLocked)))
	}
	return made
}

// projectID is the Project's id (a Grant names it by id).
func projectID(t *testing.T, c kindsClient, org string) string {
	t.Helper()
	var p struct{ ID string }
	c.ok("reading the Project", "GET", org+"/projects/api", nil, &p)
	if p.ID == "" {
		t.Fatal("the Project has no id")
	}
	return p.ID
}

// recoveryLink is `varlatchd admin recover`'s link.
var recoveryLink = regexp.MustCompile(`(?m)^  \S+/enroll#(\S+)$`)

// enrollPasskey runs the registration ceremony as a browser does: a
// recovery link for the Installation Admin (through the running daemon;
// `recover --new-admin` is for an installation with none, and recovery
// revokes none of the admin's credentials),
// the CSRF token from GET /auth/session, the options and the registration
// from the installation's origin, a software authenticator answering; then
// the session's browser credential, minted by POST /auth/varlatch-token.
func enrollPasskey(t *testing.T, bin string, in kindsInstall, made *kindsMade) {
	t.Helper()
	cmd := exec.Command(bin, "admin", "recover", "--identity", in.AdminID, "--config", in.Conf)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("recover: %v: %s", err, stderr.String())
	}
	m := recoveryLink.FindStringSubmatch(stdout.String())
	if m == nil {
		t.Fatal("recover printed no enrollment link")
	}
	grant := m[1]
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	csrf := func() string {
		res, err := browser.Get(in.Base + "/auth/session")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var s struct{ CsrfToken string }
		if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&s) != nil || s.CsrfToken == "" {
			t.Fatalf("GET /auth/session: %d", res.StatusCode)
		}
		return s.CsrfToken
	}
	post := func(what, path string, body any, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, err := http.NewRequest("POST", in.Base+path, bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", in.Public)
		req.Header.Set("Varlatch-CSRF", csrf())
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode >= 300 {
			t.Fatalf("%s: %d %s", what, res.StatusCode, errorCode(raw))
		}
		if out != nil && json.Unmarshal(raw, out) != nil {
			t.Fatalf("%s: the answer is not the expected JSON", what)
		}
	}
	var opts struct{ PublicKey auth.CreationOptions }
	post("the registration options", "/auth/passkey/registration/options", map[string]any{"token": grant}, &opts)
	key := authtest.New(t)
	var reg struct {
		PasskeyID, IdentityID string
		SignedIn              bool
	}
	post("the registration", "/auth/passkey/registration", map[string]any{"response": json.RawMessage(key.Register(t, opts.PublicKey, in.Public)), "name": "G5"}, &reg)
	if !reg.SignedIn || reg.PasskeyID == "" {
		t.Fatal("the registration did not sign the browser in")
	}
	made.Passkey, made.PasskeyIdentity = reg.PasskeyID, reg.IdentityID
	var bearer struct{ Token string }
	post("minting the browser credential", "/auth/varlatch-token", map[string]any{}, &bearer)
	if !strings.HasPrefix(bearer.Token, "vlt_web_") {
		t.Fatal("the browser credential is not a browser bearer")
	}
	made.BrowserToken = bearer.Token
	if status, _ := (kindsClient{t: t, base: in.Base, token: bearer.Token}).call("GET", "/v1/me", nil); status != http.StatusOK {
		t.Fatalf("the browser credential does not authenticate /v1/me: %d", status)
	}
	db := readDB(t, in.DB)
	defer db.Close()
	err := db.QueryRow(`SELECT id, auth_session_id FROM credentials WHERE identity_id = ? AND kind = 'browser' AND revoked_at IS NULL`,
		reg.IdentityID).Scan(&made.BrowserCredential, &made.Session)
	if err != nil {
		t.Fatalf("the browser credential's row: %v", err)
	}
}

// One change of each kind, made by a running varlatchd through its own
// code paths, each recorded in its database (G5's reverse half makes these
// before its reverse migration).
func TestG5Kinds(t *testing.T) {
	bin := build(t)
	w := newKindsWorld(t)
	in := freshInstall(t, bin, w)
	s := startKinds(t, bin, w, in)
	made := applyKinds(t, w, bin, in)
	s.stop(t)
	db := readDB(t, in.DB)
	defer db.Close()
	count := func(what, q string, args ...any) {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: %d rows (%v)", what, n, err)
		}
	}
	count("the new value's version", "SELECT count(*) FROM value_versions WHERE id = ?", made.ValueVersion)
	count("the rotation's primary version", "SELECT count(*) FROM value_versions WHERE id = ?", made.RotationVersion)
	count("the rotation's retiring version", "SELECT count(*) FROM env_values WHERE current_version_id = ? AND retiring_version_id = ?", made.RotationVersion, made.RetiringVersion)
	count("the new passkey", "SELECT count(*) FROM passkeys WHERE id = ?", made.Passkey)
	count("the browser session", "SELECT count(*) FROM auth_sessions WHERE id = ?", made.Session)
	count("the browser credential", "SELECT count(*) FROM credentials WHERE id = ? AND kind = 'browser' AND auth_session_id = ? AND revoked_at IS NULL", made.BrowserCredential, made.Session)
	count("the revoked credential", "SELECT count(*) FROM credentials WHERE id = ? AND revoked_at IS NOT NULL", made.RevokedCredential)
	count("the Grant", "SELECT count(*) FROM grants WHERE id = ? AND subject_identity_id = ?", made.Grant, made.ServiceIdentity)
	count("the Sync Target's run", "SELECT count(*) FROM sync_targets WHERE id = ? AND last_result IS NOT NULL AND last_attempt_at IS NOT NULL", made.SyncTarget)
	count("the webhook's delivery", "SELECT count(*) FROM webhooks WHERE id = ? AND cursor_order > 0 AND last_attempt_at IS NOT NULL", made.Webhook)
	count("the audit export's batch", "SELECT count(*) FROM audit_exports WHERE id = ? AND cursor_order > 0", made.AuditExport)
	if made.RetiringVersion != made.ValueVersion {
		t.Errorf("the rotation retires %s, not the value set before it", made.RetiringVersion)
	}
	if made.WebhookCursor <= 0 || made.AuditExportCursor <= 0 || made.SyncRun == "" {
		t.Errorf("cursors %d, %d; run %q", made.WebhookCursor, made.AuditExportCursor, made.SyncRun)
	}
	if t.Failed() {
		t.Logf("varlatchd's log:\n%s", s.tail())
	}
}
