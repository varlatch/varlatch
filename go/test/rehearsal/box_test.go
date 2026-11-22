// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The box profile (internal docs/design/go-step8-rehearsals.md, internal#221):
// the harness run on the experiments server, as root by the owner, for the
// cases a workstation cannot make. What it adds to the workstation
// profile:
//   - real systemd: the target varlatchd is the unit
//     varlatchd-rh-<run>-<case>.service, which varlatch migrate starts and
//     stops (--unit);
//   - public ingress: Caddy with certificates from Pebble on an address the
//     owner chose (VL_RH_PUBLIC_BIND), and the target's own ACME;
//   - the Coolify domain move: the source and the target are apps the
//     owner creates in the lab Coolify, the harness pausing for each step
//     only the owner can make;
//   - a guard: every container on the box that is not this run's
//     (vl-rh-<run>-...) is recorded before the run and must still be
//     running after it (the lab Coolify's proxy and apps included).
//
// Pauses: the harness prints what the owner does, then waits for the file
// $VL_RH_CONTINUE_DIR/<step> (`touch` it), so it works over ssh and tmux.

type profileConfig struct {
	box                    bool
	target, ingress        string
	publicName, publicBind string
	source, kill, sync     string
	continueDir            string
	goImage                string // the 0.50 image for the image target, name@sha256:...
	coolifySourceDir       string // the source app's directory in the lab Coolify
	// B6: the archive VL_RH_SOURCE=restore:<archive> names, and its keys
	// (VL_RH_RESTORE_BEK, VL_RH_RESTORE_KEK), all files the operator copied
	// to this host; the harness never fetches one.
	restore, restoreBEK, restoreKEK string
	bundleOut                       string // VL_RH_ONLY=bundle: where the synthetic archive and its keys go
}

var prof profileConfig

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// loadProfile reads and checks the run's profile. A case that is not
// built yet, or needs what the owner has not given, is refused here, by
// name, before anything starts.
func loadProfile(t *testing.T) {
	t.Helper()
	p, err := readProfile(os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	prof = p
}

// readProfile is loadProfile's reading and checks, for a process of that
// effective user ID.
func readProfile(euid int) (profileConfig, error) {
	prof := profileConfig{
		box: env("VL_RH_PROFILE", "workstation") == "box", target: env("VL_RH_TARGET", "host"), ingress: env("VL_RH_INGRESS", "proxy"),
		publicName: os.Getenv("VL_RH_PUBLIC_NAME"), publicBind: os.Getenv("VL_RH_PUBLIC_BIND"),
		source: env("VL_RH_SOURCE", "seed"), kill: os.Getenv("VL_RH_KILL"), sync: os.Getenv("VL_RH_SYNC"),
		continueDir: env("VL_RH_CONTINUE_DIR", filepath.Join(workDir, "continue")),
		goImage:     os.Getenv("VL_RH_GO_IMAGE"), coolifySourceDir: os.Getenv("VL_RH_COOLIFY_SOURCE_DIR"),
		restoreBEK: os.Getenv("VL_RH_RESTORE_BEK"), restoreKEK: os.Getenv("VL_RH_RESTORE_KEK"), bundleOut: os.Getenv("VL_RH_BUNDLE_OUT"),
	}
	only := os.Getenv("VL_RH_ONLY")
	if p := env("VL_RH_PROFILE", "workstation"); p != "workstation" && p != "box" {
		return prof, fmt.Errorf("VL_RH_PROFILE is workstation or box, not %q", p)
	}
	if !slices.Contains([]string{"proxy", "public", "coolify", "tailnet", "combined"}, prof.ingress) {
		return prof, fmt.Errorf("VL_RH_INGRESS is proxy, public, coolify, tailnet or combined, not %q", prof.ingress)
	}
	if prof.box && euid != 0 {
		return prof, errors.New("the box profile runs as root (the owner's): sudo -i, then run.sh")
	}
	switch {
	case !prof.box && prof.ingress != "proxy":
		return prof, fmt.Errorf("VL_RH_INGRESS=%s runs on the box only (VL_RH_PROFILE=box)", prof.ingress)
	case prof.ingress == "tailnet" || prof.ingress == "combined":
		return prof, errors.New("the tailnet handoff (B4) needs varlatch migrate's tailnet options (step 7.5b2's wiring), which this stack does not have yet")
	case prof.sync != "":
		return prof, errors.New("Sync Targets to real endpoints (B5) need the owner's destinations (internal#221, question 2); not built yet")
	case strings.HasPrefix(prof.source, "restore:"):
		prof.restore = strings.TrimPrefix(prof.source, "restore:")
		if err := checkRestore(prof); err != nil {
			return prof, err
		}
	case prof.source != "seed":
		return prof, fmt.Errorf("VL_RH_SOURCE is seed or restore:<archive>, not %q", prof.source)
	case prof.target == "image" && prof.ingress != "coolify":
		return prof, errors.New("the image target runs with the Coolify ingress only (B3); with Compose it is not built yet")
	case prof.target != "host" && prof.target != "image":
		return prof, fmt.Errorf("VL_RH_TARGET is host or image, not %q", prof.target)
	case prof.ingress == "public":
		if prof.publicName == "" || net.ParseIP(prof.publicBind) == nil || net.ParseIP(prof.publicBind).IsUnspecified() {
			return prof, errors.New("public ingress (B2) needs VL_RH_PUBLIC_NAME and VL_RH_PUBLIC_BIND, the address 80 and 443 are free on (internal#221, question 1); never 0.0.0.0")
		}
		for _, port := range []string{"80", "443"} {
			l, err := net.Listen("tcp", net.JoinHostPort(prof.publicBind, port))
			if err != nil {
				return prof, fmt.Errorf("%s:%s is not free (%v): the run never stops what holds it", prof.publicBind, port, err)
			}
			l.Close()
		}
	case prof.ingress == "coolify":
		if prof.target != "image" || prof.goImage == "" || prof.coolifySourceDir == "" || prof.publicName == "" {
			return prof, errors.New("the Coolify domain move (B3) needs VL_RH_TARGET=image, VL_RH_GO_IMAGE (name@sha256:...), VL_RH_COOLIFY_SOURCE_DIR and VL_RH_PUBLIC_NAME")
		}
		// What the owner's source app is made from: the release's Coolify
		// variables (images.sh writes them) and the candidate checkout's
		// Coolify Compose file and README.
		for _, f := range []string{filepath.Join(releaseDir, "coolify-image-digests.env"), filepath.Join(tsCheckout, "infra", "compose", "docker-compose.coolify.yml"), filepath.Join(tsCheckout, "infra", "coolify", "README.md")} {
			if _, err := os.Stat(f); err != nil {
				return prof, fmt.Errorf("the Coolify domain move (B3) needs %s: run images.sh again (it writes coolify-image-digests.env), from a checkout of the 0.23.0 candidate (#373's branch, which has the Coolify files); %v", f, err)
			}
		}
	}
	if prof.kill != "" && prof.kill != "transfer" && prof.kill != "barrier" {
		return prof, fmt.Errorf("VL_RH_KILL is transfer or barrier, not %q", prof.kill)
	}
	switch {
	case only != "" && only != "setup" && only != "kill" && only != "bundle":
		return prof, fmt.Errorf("VL_RH_ONLY is setup, kill or bundle, not %q", only)
	case only == "kill" && prof.kill == "":
		// Alone, it would run nothing between the guard and the report.
		return prof, errors.New("VL_RH_ONLY=kill needs VL_RH_KILL (transfer or barrier): it runs the kill case alone")
	case only == "bundle":
		if prof.restore != "" || prof.kill != "" || prof.ingress != "proxy" {
			return prof, errors.New("VL_RH_ONLY=bundle makes the synthetic archive alone: on a seeded source (VL_RH_SOURCE=seed), with the own proxy, no VL_RH_KILL")
		}
		if !filepath.IsAbs(prof.bundleOut) {
			return prof, errors.New("VL_RH_ONLY=bundle needs VL_RH_BUNDLE_OUT, an absolute path: the directory the archive and its keys go to")
		}
		if entries, err := os.ReadDir(prof.bundleOut); err == nil && len(entries) > 0 {
			return prof, fmt.Errorf("VL_RH_BUNDLE_OUT %s is not empty: the run never replaces an archive or a key", prof.bundleOut)
		}
	}
	return prof, nil
}

// checkRestore checks B6's inputs before anything starts: the archive and
// its two keys are regular files on this host (a path, never a URL: the
// harness fetches nothing), the keys readable by their owner only.
func checkRestore(prof profileConfig) error {
	if prof.ingress != "proxy" || prof.target != "host" {
		return errors.New("the restored-production run (B6) runs with the own proxy's ingress and the host-install target (VL_RH_INGRESS=proxy, VL_RH_TARGET=host)")
	}
	if strings.Contains(prof.restore, "://") || !filepath.IsAbs(prof.restore) {
		return fmt.Errorf("VL_RH_SOURCE=restore:<archive> takes the archive's absolute path on this host, copied there by hand, not %q: the harness fetches nothing", prof.restore)
	}
	if prof.restoreBEK == "" || prof.restoreKEK == "" {
		return errors.New("the restored-production run (B6) needs the archive's keys: VL_RH_RESTORE_BEK (its Backup Encryption Key file) and VL_RH_RESTORE_KEK (the installation's Root KEK file)")
	}
	for _, f := range []struct{ what, path string }{{"the archive", prof.restore}, {"VL_RH_RESTORE_BEK", prof.restoreBEK}, {"VL_RH_RESTORE_KEK", prof.restoreKEK}} {
		st, err := os.Lstat(f.path)
		switch {
		case err != nil:
			return fmt.Errorf("%s: %v", f.what, err)
		case !st.Mode().IsRegular():
			return fmt.Errorf("%s %s is not a regular file", f.what, f.path)
		case f.what != "the archive" && st.Mode().Perm()&0o077 != 0:
			return fmt.Errorf("%s %s is readable by others (mode %04o): copy it with mode 0600", f.what, f.path, st.Mode().Perm())
		}
	}
	return nil
}

// --- the guard: nothing of the box's own is touched ---

// othersRunning are the running containers that are not this run's.
func othersRunning(t *testing.T) []string {
	t.Helper()
	r := must(t, run("", nil, nil, "docker", "ps", "--format", "{{.Names}}"), "docker ps")
	var out []string
	for _, n := range strings.Fields(r.stdout) {
		if !strings.HasPrefix(n, "vl-rh-"+runID+"-") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// guardOthers records the box's own containers now and, when the run ends,
// checks that every one of them still runs.
func guardOthers(t *testing.T) {
	before := othersRunning(t)
	measure("guard: other containers running at the start", fmt.Sprint(len(before)))
	t.Cleanup(func() {
		after := othersRunning(t)
		var gone []string
		for _, n := range before {
			if !slices.Contains(after, n) {
				gone = append(gone, n)
			}
		}
		record(t, 0, "nothing of the host's own was stopped", len(gone) == 0, fmt.Sprintf("%d before, %d after; gone: %v", len(before), len(after), gone))
	})
}

// --- pauses for the owner ---

// pauses counts the run's pauses for the owner.
var pauses int

// pause prints what the owner does, then waits until they touch
// <continueDir>/<step>. run.sh sizes the test's timeout for
// VL_RH_PAUSE_BUDGET pauses at their longest, so one more fails the run
// here, with its cleanups, before the timeout could panic past them.
func pause(t *testing.T, step string, lines ...string) {
	t.Helper()
	pauses++
	if b, err := strconv.Atoi(os.Getenv("VL_RH_PAUSE_BUDGET")); err == nil && pauses > b {
		t.Fatalf("the owner's step %q is pause %d, more than the %d run.sh sized the test's timeout for", step, pauses, b)
	}
	if err := os.MkdirAll(prof.continueDir, 0o700); err != nil {
		t.Fatal(err)
	}
	done := filepath.Join(prof.continueDir, step)
	_ = os.Remove(done)
	fmt.Fprintf(os.Stderr, "\n==== the owner's step: %s ====\n", step)
	for _, l := range lines {
		fmt.Fprintln(os.Stderr, "  "+l)
	}
	fmt.Fprintf(os.Stderr, "  Then: touch %s\n\n", done)
	began := time.Now()
	limitStr := env("VL_RH_PAUSE_TIMEOUT", "2h")
	limit, err := time.ParseDuration(limitStr)
	if err != nil || limit <= 0 {
		t.Fatalf("VL_RH_PAUSE_TIMEOUT %q: invalid positive duration", limitStr)
	}
	for time.Since(began) < limit {
		if _, err := os.Stat(done); err == nil {
			measure("pause: "+step, time.Since(began).Round(time.Second).String())
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("the owner's step %q was not continued within %s", step, limit)
}

// --- real systemd (box): the target as a unit of the run's own ---

func (in *installation) unitName() string { return "varlatchd-rh-" + runID + "-" + in.name }

// installUnit writes the run's unit for the target and reloads systemd.
func (in *installation) installUnit(t *testing.T) {
	t.Helper()
	unit := fmt.Sprintf("[Unit]\nDescription=varlatchd (rehearsal %s, %s)\n\n[Service]\nExecStart=%s serve --config %s\nRestart=no\n\n[Install]\nWantedBy=multi-user.target\n",
		runID, in.name, filepath.Join(binDir, "varlatchd"), in.conf)
	path := filepath.Join("/etc/systemd/system", in.unitName()+".service")
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	must(t, run("", nil, nil, "systemctl", "daemon-reload"), "systemctl daemon-reload")
}

// removeUnit stops and removes the run's unit (its exact name only).
func (in *installation) removeUnit() {
	run("", nil, nil, "systemctl", "disable", "--now", in.unitName()+".service")
	_ = os.Remove(filepath.Join("/etc/systemd/system", in.unitName()+".service"))
	run("", nil, nil, "systemctl", "daemon-reload")
}

// --- public ingress (box): Pebble and its DNS on the run's network ---

const (
	pebbleImage = "ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef"
	dnsImage    = "ghcr.io/letsencrypt/pebble-challtestsrv@sha256:0152c8cb506e2ecba2900ed47d23932e27e3e6575a7d2c8ef93c7719ee3dea4c"
)

type acmeStack struct {
	network, pebble, dns string
	hostDirectory        string // the ACME directory as this host reaches it
	apiRoot, issuedRoot  string // PEM files: Pebble's API certificate's CA, and the CA it issues from
}

// startACME runs Pebble and its DNS (the public name resolving to the
// run's address only there) on a network of the run's own.
func startACME(t *testing.T, dir string) *acmeStack {
	t.Helper()
	a := &acmeStack{network: "vl-rh-" + runID + "-acme", pebble: "vl-rh-" + runID + "-pebble", dns: "vl-rh-" + runID + "-dns"}
	must(t, run("", nil, nil, "docker", "network", "create", a.network), "the ACME network")
	t.Cleanup(func() {
		run("", nil, nil, "docker", "rm", "-fv", a.pebble, a.dns)
		run("", nil, nil, "docker", "network", "rm", a.network)
	})
	must(t, run("", nil, nil, "docker", "run", "-d", "--name", a.dns, "--network", a.network, dnsImage,
		"-defaultIPv4", prof.publicBind, "-defaultIPv6", "", "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""), "Pebble's DNS")
	pebbleCfg := filepath.Join(dir, "pebble-config.json")
	const cfgJSON = `{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 80,
    "tlsPort": 443,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false,
    "domainBlocklist": ["blocked-domain.example"],
    "retryAfter": { "authz": 1, "order": 1 }
  }
}
`
	if err := os.WriteFile(pebbleCfg, []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	api, mgmt := freePort(t), freePort(t)
	must(t, run("", nil, nil, "docker", "run", "-d", "--name", a.pebble, "--network", a.network, "--network-alias", "pebble",
		"-e", "PEBBLE_VA_NOSLEEP=1", "-e", "PEBBLE_WFE_NONCEREJECT=0",
		"-v", pebbleCfg+":/pebble-config.json:ro",
		"-p", "127.0.0.1:"+api+":14000", "-p", "127.0.0.1:"+mgmt+":15000", pebbleImage, "-config", "/pebble-config.json", "-dnsserver", a.dns+":8053"), "Pebble")
	a.hostDirectory = "https://localhost:" + api + "/dir"
	a.apiRoot = filepath.Join(dir, "pebble-api-root.pem")
	must(t, run("", nil, nil, "docker", "cp", a.pebble+":/test/certs/pebble.minica.pem", a.apiRoot), "Pebble's API CA")
	// The CA Pebble issues from, from its management interface, whose
	// certificate the API's CA signed.
	pool := x509.NewCertPool()
	if b, _ := os.ReadFile(a.apiRoot); !pool.AppendCertsFromPEM(b) {
		t.Fatal("Pebble's API CA did not parse")
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	var root []byte
	for deadline := time.Now().Add(30 * time.Second); len(root) == 0; time.Sleep(500 * time.Millisecond) {
		if resp, err := c.Get("https://127.0.0.1:" + mgmt + "/roots/0"); err == nil {
			root, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				root = nil
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Pebble's management interface did not answer")
		}
	}
	a.issuedRoot = filepath.Join(dir, "pebble-issued-root.pem")
	if err := os.WriteFile(a.issuedRoot, root, 0o644); err != nil {
		t.Fatal(err)
	}
	return a
}

// tlsClient is a client for the public name at the run's address, trusting
// the CA Pebble issues from.
func tlsClient(t *testing.T, a *acmeStack) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(a.issuedRoot)
	if !pool.AppendCertsFromPEM(b) {
		t.Fatal("Pebble's issuing CA did not parse")
	}
	dial := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: prof.publicName},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial.DialContext(ctx, network, net.JoinHostPort(prof.publicBind, "443"))
		},
	}}
}

// composeOverride is the run's Compose file for public ingress: Caddy
// trusts Pebble's API and reaches it on the run's network.
func composeOverride(a *acmeStack) string {
	return `# Written by the rehearsal harness (public ingress with Pebble).
services:
  caddy:
    environment:
      SSL_CERT_FILE: /rehearsal/pebble-api-root.pem
    volumes:
      - ` + a.apiRoot + `:/rehearsal/pebble-api-root.pem:ro
    networks: [default, acme]
networks:
  acme:
    external: true
    name: ` + a.network + `
`
}

// --- the Coolify domain move (box, B3) ---

// coolifyCase: the source and the 0.50 target are apps the owner creates
// in the lab Coolify; the migration pauses at each step only the owner can
// make (exit 75), the harness then resuming.
func coolifyCase(t *testing.T, rel release, s3 *s3Server) {
	const item = 11
	digests, err := os.ReadFile(filepath.Join(releaseDir, "coolify-image-digests.env"))
	if err != nil {
		t.Fatal(err)
	}
	// The source's secrets as host files (infra/coolify/README.md step 4),
	// the operator's backup key and destination: generated by the run,
	// shown to the owner as paths only.
	base := filepath.Join("/srv/vl-rh", runID)
	t.Cleanup(func() {
		if os.Getenv("VL_RH_KEEP") != "1" {
			_ = os.RemoveAll(base)
		}
	})
	secretsDir, op, tmpDir := filepath.Join(base, "secrets"), filepath.Join(base, "operator"), filepath.Join(base, "tmp")
	for _, d := range []string{secretsDir, op, tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The source app's secrets are 0644 files in 0700 directories, as
	// infra/coolify/README.md has them: its containers' own users (uid 999)
	// must read them, which a root-owned 0600 file refuses (varlatchd then
	// does not start); the directories keep everyone else out. MkdirAll
	// leaves an existing directory's mode, and the umask may narrow a new
	// one, so each is set here.
	for _, d := range []string{filepath.Dir(base), base, secretsDir, op, tmpDir} {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var lines []string
	for _, f := range []struct{ name, variable string }{
		{"varlatch-kek", "VARLATCH_KEK_HOST_PATH"}, {"postgres-superuser-password", "POSTGRES_SUPERUSER_PASSWORD_HOST_PATH"},
		{"varlatch-migrate-password", "VARLATCH_MIGRATE_PASSWORD_HOST_PATH"}, {"varlatch-runtime-password", "VARLATCH_RUNTIME_PASSWORD_HOST_PATH"},
		{"convex-db-password", "CONVEX_DB_PASSWORD_HOST_PATH"}, {"convex-instance-secret", "CONVEX_INSTANCE_SECRET_HOST_PATH"},
	} {
		v := secret(hexBytes(32))
		if err := os.WriteFile(filepath.Join(secretsDir, f.name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, f.variable+"="+filepath.Join(secretsDir, f.name))
	}
	bek := filepath.Join(op, "backup-key")
	if err := os.WriteFile(bek, []byte(secret(hexBytes(32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3.createBucket(t, "vl-rh-coolify")
	destinations, readCreds := filepath.Join(op, "backup-destinations.json"), filepath.Join(op, "read.json")
	s3.writeDestination(t, destinations, "vl-rh-coolify", "write.json")
	s3.writeCredentials(t, readCreds)
	pause(t, "source-app",
		"In the lab Coolify (never production's), in a throwaway project, create a Docker Compose app from",
		"the 0.23.0 candidate's checkout, Docker Compose Location /infra/compose/docker-compose.coolify.yml,",
		"its domain https://"+prof.publicName+" on varlatch-web port 80, and these variables (the run's images):",
		strings.TrimSpace(string(digests)),
		"the secrets as host files (paths only):",
		strings.Join(lines, "\n  "),
		"and VARLATCH_PUBLIC_URL=https://"+prof.publicName+", the rest as infra/coolify/README.md step 4 says. Deploy it.",
		"Its resource directory must be "+prof.coolifySourceDir+".")
	client := &http.Client{Timeout: 10 * time.Second}
	get := func() (int, string) {
		resp, err := client.Get("https://" + prof.publicName + "/v1/meta")
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		var meta map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&meta)
		return resp.StatusCode, fmt.Sprint(meta["serverVersion"], " ", meta["installationId"])
	}
	code, before := get()
	record(t, item, "the source app serves 0.23.0 at the public URL", code == 200 && strings.HasPrefix(before, "0.23.0"), before)
	target := filepath.Join(base, "go")
	for _, d := range []string{"data", "keys"} {
		if err := os.MkdirAll(filepath.Join(target, d), 0o700); err != nil {
			t.Fatal(err)
		}
		must(t, run("", nil, nil, "chown", "65532:65532", filepath.Join(target, d)), "own the image's "+d)
	}
	conf := filepath.Join(target, "varlatchd.conf")
	svc := fmt.Sprintf("listen = 0.0.0.0:8080\npublic_url = https://%s\ndata_dir = /var/lib/varlatch\nroot_kek_file = /keys/root-kek\nbackup_key_file = /keys/backup-key\nbackup_interval = off\n", prof.publicName)
	if err := os.WriteFile(conf, []byte(svc), 0o644); err != nil {
		t.Fatal(err)
	}
	pause(t, "target-app",
		"In the same project, create the 0.50 app from the image "+prof.goImage+" in setup mode, nothing listening,",
		"its service named varlatchd, with the bind paths "+filepath.Join(target, "data")+" -> /var/lib/varlatch, "+
			filepath.Join(target, "keys")+" -> /keys, "+conf+" -> /etc/varlatch/varlatchd.conf, and no domain yet. Do not deploy it.")
	args := []string{"migrate", "--ingress", "coolify", "--from", prof.coolifySourceDir, "--to-data", filepath.Join(target, "data"),
		"--to-keys", filepath.Join(target, "keys"), "--to-config", conf, "--to-image", prof.goImage, "--to-service", "varlatchd",
		"--bek-file", bek, "--backup-destination", "offsite", "--destinations-file", destinations, "--read-credentials-file", readCreds,
		"--ts-cli", "varlatch-ts", "--transfer-timeout", "5m"}
	tsCLI := filepath.Join(base, "bin")
	_ = os.MkdirAll(tsCLI, 0o755)
	cli := filepath.Join(releaseDir, "varlatch-cli-0.23.0.cjs")
	if err := os.WriteFile(filepath.Join(tsCLI, "varlatch-ts"), []byte("#!/bin/sh\nexec node "+cli+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// --rollback takes the source, the target and the transfer's timeout
	// only (the rest is in the journal); its --resume is migrate's.
	rollbackArgs := []string{"migrate", "--rollback", "--from", prof.coolifySourceDir, "--to-data", filepath.Join(target, "data"),
		"--to-keys", filepath.Join(target, "keys"), "--to-config", conf, "--to-image", prof.goImage, "--to-service", "varlatchd",
		"--ts-cli", "varlatch-ts", "--transfer-timeout", "5m"}
	migrateUntilDone := func(what string, first []string) ran {
		a := slices.Clone(first)
		for step := 1; ; step++ {
			r := run(prof.coolifySourceDir, []string{"VARLATCH_MIGRATE_PIN=" + rel.pin(), "PATH=" + tsCLI + ":" + os.Getenv("PATH"), "TMPDIR=" + tmpDir}, nil, filepath.Join(binDir, "varlatch"), a...)
			if r.code != 75 {
				return r
			}
			pause(t, fmt.Sprintf("%s-%d", what, step), "varlatch migrate stopped for your step (exit 75):", redact(lastLines(r.stdout+"\n"+r.stderr, 12)))
			a = append(slices.Clone(args), "--resume")
		}
	}
	r := migrateUntilDone("migrate", args)
	record(t, item, "the migration opens on the Go app", r.code == 0, r.String())
	code, after := get()
	record(t, item, "the public URL answers from the Go app", code == 200 && !strings.HasPrefix(after, "0.23.0"), after)
	r = migrateUntilDone("rollback", rollbackArgs)
	record(t, item, "--rollback, the domain moved back by hand", r.code == 0, r.String())
	code, back := get()
	record(t, item, "the public URL answers from 0.23.0 again", code == 200 && strings.HasPrefix(back, "0.23.0"), back)
	pause(t, "cleanup", "In the lab Coolify, delete the two apps of this run and their volumes, and the throwaway project.")
	_ = os.RemoveAll(base)
}

// publicCase (box, B2): the source behind Caddy with a Pebble certificate
// on the run's address; the migration stops Caddy, the target obtains its
// own certificate from Pebble on the same name and binds 80 and 443.
func publicCase(t *testing.T, rel release, s3 *s3Server) {
	const item = 13
	in := newInstallation(t, rel, s3, "public")
	registerSecrets(in)
	if os.Getenv("VL_RH_SEED") != "0" {
		s := seed(t, in)
		record(t, 9, "seeded through the real /v1", true, fmt.Sprintf("%d values, %d versions", s.values, s.versions))
	}
	issuer := func() string {
		conn, err := tls.Dial("tcp", net.JoinHostPort(prof.publicBind, "443"), in.client.Transport.(*http.Transport).TLSClientConfig)
		if err != nil {
			return "error: " + err.Error()
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].Issuer.CommonName
	}
	before := issuer()
	record(t, item, "the source's Caddy serves a Pebble certificate", strings.Contains(before, "Pebble"), before)
	migration(t, in, rel, s3)
	after := issuer()
	record(t, item, "the target serves its own Pebble certificate on the same name", strings.Contains(after, "Pebble"), after)
}
