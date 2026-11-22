// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The sync case (VL_RH_SYNC=fakes; B5 of internal#221, on a workstation):
// a source with Sync Targets to GitHub and a Coolify application, migrated,
// then the Targets pushed from Go. The platforms are the conformance
// suites' stand-ins (scripts/conformance/lib/platform-fakes.cjs, which
// run.sh copies beside the binaries), in a container of the run's own on a
// network of the run's own. Their host names lead there: in the source's
// varlatchd through Compose's extra_hosts, and in the runner container
// (where migrate and the target varlatchd run) through its own
// /etc/hosts. Both trust a CA made for the run. Each side's outbound allow
// list lets the names through, as an operator's would: the source's
// VARLATCH_OUTBOUND_ALLOW and the target's outbound_allow (migrate carries
// neither over). The owner's session runs B5 against the real Coolify and
// GitHub instead.

// fakeHosts are the names the stand-ins answer as (platform-fakes.cjs).
var fakeHosts = []string{"api.github.com", "coolify.conformance.test", "convex.conformance.test"}

const (
	// The runner's own base image, which has Node.
	fakesImage       = "node@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc"
	fakesControlPort = "18788"
	fakesApp         = "/applications/app-conformance"
	// What both sides allow: the two platforms the Targets reach.
	syncAllow = "api.github.com:443,coolify.conformance.test:443"
	// The source's mount of the run's CA.
	syncMount = "/vl-rh-sync"
	syncItem  = 13
)

// platformFakes is the run's stand-in platforms: their container, network,
// address, and the directory with their certificate and the run's CA.
type platformFakes struct {
	t                      *testing.T
	name, network, ip, dir string
}

// fakesState is what the stand-ins hold (GET /_state): secret names by
// repository (GitHub keeps sealed values only), the Coolify resources'
// stored and running values, every request (never a credential), the
// writes held, abandoned and released, and the answered writes by
// repository.
type fakesState struct {
	GitHub   map[string][]string          `json:"github"`
	Coolify  map[string]map[string]string `json:"coolify"`
	Running  map[string]map[string]string `json:"running"`
	Requests []struct {
		Method string `json:"method"`
		Host   string `json:"host"`
		Path   string `json:"path"`
	} `json:"requests"`
	Held []struct {
		Repo      string `json:"repo"`
		Name      string `json:"name"`
		Connected bool   `json:"connected"`
	} `json:"held"`
	Abandoned []struct {
		Repo string `json:"repo"`
		Name string `json:"name"`
	} `json:"abandoned"`
	Deliveries []struct {
		Repo      string `json:"repo"`
		Name      string `json:"name"`
		Delivered *bool  `json:"delivered"`
	} `json:"deliveries"`
	Writes map[string]int `json:"writes"`
}

// coolifyWrites counts the variable writes the Coolify stand-in was sent.
func (s fakesState) coolifyWrites() int {
	n := 0
	for _, r := range s.Requests {
		if r.Host == "coolify.conformance.test" && (r.Method == "PATCH" || r.Method == "POST") && strings.Contains(r.Path, "/envs") {
			n++
		}
	}
	return n
}

// writeFakesCerts writes the run's CA (ca.pem) and the stand-ins'
// certificate for names, signed by it, with its key (cert.pem, key.pem),
// into dir. Readable by the stand-ins' user: they are this run's only.
func writeFakesCerts(dir string, names []string) error {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vl-rh sync stand-ins CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "vl-rh sync stand-ins"}, DNSNames: names,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	files := map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: leafDER},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: keyDER},
	}
	for name, block := range files {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// goRoots is the target varlatchd's trust roots (its SSL_CERT_FILE): the
// system's, when the runner has them, and the run's CA.
func goRoots(dir, system string) (string, error) {
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return "", err
	}
	roots, _ := os.ReadFile(system)
	if len(roots) > 0 && !bytes.HasSuffix(roots, []byte("\n")) {
		roots = append(roots, '\n')
	}
	path := filepath.Join(dir, "go-roots.pem")
	return path, os.WriteFile(path, append(roots, ca...), 0o644)
}

// syncOverlay is the source's Compose overlay: its varlatchd trusts the
// run's CA (NODE_EXTRA_CA_CERTS, from dir's source.env), reaches the
// stand-ins' network, and finds the platforms' names at their address.
// The variable comes through env_file, not environment: an overlay's
// environment merged into the base file's makes `docker compose config
// --no-interpolate` (Compose 5.6) print the service's environment as a
// list, which migrate's preflight cannot read ("docker compose config did
// not name the installation's Compose project", run r16s).
func syncOverlay(network, ip, dir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Written by the rehearsal's sync case: the platform stand-ins.\nservices:\n  varlatchd:\n    env_file:\n      - %s/source.env\n    extra_hosts:\n", dir)
	for _, h := range fakeHosts {
		fmt.Fprintf(&b, "      - \"%s:%s\"\n", h, ip)
	}
	fmt.Fprintf(&b, "    volumes:\n      - %s:%s:ro\n    networks:\n      vl-rh-sync: {}\nnetworks:\n  vl-rh-sync:\n    external: true\n    name: %s\n", dir, syncMount, network)
	return b.String()
}

// hostsMarker ends each line the case adds to the runner's /etc/hosts.
const hostsMarker = "# vl-rh sync stand-ins"

// withFakeHosts is hosts with one line naming the platforms at ip, and
// without any line an earlier run of the case left.
func withFakeHosts(hosts, ip string) string {
	out := withoutFakeHosts(hosts)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + ip + " " + strings.Join(fakeHosts, " ") + " " + hostsMarker + "\n"
}

// withoutFakeHosts is hosts without the case's lines.
func withoutFakeHosts(hosts string) string {
	var keep []string
	for _, l := range strings.SplitAfter(hosts, "\n") {
		if !strings.HasSuffix(strings.TrimRight(l, "\n"), hostsMarker) {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "")
}

// startFakes starts the stand-ins in their own container and network, by
// the run's names, removed by those names when the case ends.
func startFakes(t *testing.T) *platformFakes {
	t.Helper()
	f := &platformFakes{t: t, name: "vl-rh-" + runID + "-sync-fakes", network: "vl-rh-" + runID + "-sync", dir: filepath.Join(workDir, "sync-fakes")}
	src := filepath.Join(binDir, "platform-fakes.cjs")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("the platform stand-ins (run.sh copies scripts/conformance/lib/platform-fakes.cjs to %s): %v", binDir, err)
	}
	if err := os.MkdirAll(f.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(f.dir, 0o755)
	if err := os.WriteFile(filepath.Join(f.dir, "platform-fakes.cjs"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFakesCerts(f.dir, fakeHosts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "source.env"), []byte("NODE_EXTRA_CA_CERTS="+syncMount+"/ca.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must(t, run("", nil, nil, "docker", "network", "create", "--label", "org.varlatch.rehearsal="+runID, f.network), "create the stand-ins' network")
	t.Cleanup(func() { run("", nil, nil, "docker", "network", "rm", f.network) })
	// Not root: port 443 inside its own network namespace only.
	must(t, run("", nil, nil, "docker", "run", "-d", "--name", f.name, "--network", f.network, "-u", "1000:1000",
		"--sysctl", "net.ipv4.ip_unprivileged_port_start=0", "-e", "PLATFORM_FAKES_HOST=0.0.0.0",
		"-v", f.dir+":/fakes:ro", fakesImage, "node", "/fakes/platform-fakes.cjs", "443", fakesControlPort, "/fakes/cert.pem", "/fakes/key.pem", "/fakes"),
		"start the platform stand-ins")
	t.Cleanup(func() { run("", nil, nil, "docker", "rm", "-fv", f.name) })
	f.ip = strings.TrimSpace(must(t, run("", nil, nil, "docker", "inspect", "-f", `{{(index .NetworkSettings.Networks "`+f.network+`").IPAddress}}`, f.name), "the stand-ins' address").stdout)
	if f.ip == "" {
		t.Fatal("the stand-ins have no address on their network")
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if _, err := f.control("GET", "/_state", ""); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("the platform stand-ins did not answer: %v; %s", err, lastLines(run("", nil, nil, "docker", "logs", f.name).stderr, 5))
		}
	}
	return f
}

// control is a request to the stand-ins' control port, from inside their
// container (it listens on its loopback only).
func (f *platformFakes) control(method, path, body string) ([]byte, error) {
	script := `const [p, m, b] = process.argv.slice(1); fetch("http://127.0.0.1:` + fakesControlPort + `" + p, { method: m, body: b || undefined })` +
		`.then(async (r) => { const t = await r.text(); if (!r.ok) { process.stderr.write(r.status + " " + t); process.exit(1); } process.stdout.write(t); }, (e) => { process.stderr.write(String(e)); process.exit(1); })`
	r := run("", nil, nil, "docker", "exec", f.name, "node", "-e", script, path, method, body)
	if r.code != 0 {
		return nil, errors.New(r.String())
	}
	return []byte(r.stdout), nil
}

func (f *platformFakes) state() fakesState {
	f.t.Helper()
	b, err := f.control("GET", "/_state", "")
	if err != nil {
		f.t.Fatalf("the stand-ins' state: %v", err)
	}
	var s fakesState
	if err := json.Unmarshal(b, &s); err != nil {
		f.t.Fatalf("the stand-ins' state: %v", err)
	}
	return s
}

// github is a control operation on the GitHub stand-in (hold, release).
func (f *platformFakes) github(op map[string]any) string {
	f.t.Helper()
	body, _ := json.Marshal(op)
	b, err := f.control("POST", "/_github", string(body))
	if err != nil {
		f.t.Fatalf("the GitHub stand-in's %v: %v", op["op"], err)
	}
	return string(b)
}

// extra is what the source and the target get for the stand-ins.
func (f *platformFakes) extra() installExtra {
	roots, err := goRoots(f.dir, "/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		f.t.Fatal(err)
	}
	return installExtra{
		env:         map[string]string{"VARLATCH_OUTBOUND_ALLOW": syncAllow},
		composeFile: "docker-compose.sync.yml", composeText: syncOverlay(f.network, f.ip, f.dir),
		conf:       "outbound_allow = " + syncAllow + "\n",
		serviceEnv: []string{"SSL_CERT_FILE=" + roots},
	}
}

// pointHosts names the platforms at the stand-ins in this process's
// /etc/hosts: the runner container's own, never the host's (the profile
// refuses the box), restored when the case ends.
func (f *platformFakes) pointHosts() {
	t := f.t
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("the sync case edits /etc/hosts in the runner container only; this is not one")
	}
	orig, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/hosts", []byte(withFakeHosts(string(orig), f.ip)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if b, err := os.ReadFile("/etc/hosts"); err == nil {
			_ = os.WriteFile("/etc/hosts", []byte(withoutFakeHosts(string(b))), 0o644)
		}
	})
}

// pollUntil calls done every gap until it holds or d has passed; it
// answers whether it held.
func pollUntil(d, gap time.Duration, done func() bool) bool {
	for deadline := time.Now().Add(d); ; time.Sleep(gap) {
		if done() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// syncTarget is the part of a Sync Target's view the case reads.
type syncTarget struct {
	LastResult    string `json:"lastResult"`
	LastAttemptAt string `json:"lastAttemptAt"`
	FailureCount  int    `json:"failureCount"`
}

func (s syncTarget) ok() bool {
	return s.FailureCount == 0 && regexp.MustCompile(`^(ok|converged)`).MatchString(s.LastResult)
}

func (s syncTarget) String() string {
	return fmt.Sprintf("%q, %d failures, attempted %s", s.LastResult, s.FailureCount, s.LastAttemptAt)
}

func syncCase(t *testing.T, rel release, s3 *s3Server) {
	const item = syncItem
	f := startFakes(t)
	in := newInstallation(t, rel, s3, "sync", f.extra())
	registerSecrets(in)
	f.pointHosts()
	c := adminClient(t, in)
	suffix := hexBytes(4)
	slug := "sync-" + suffix
	base := "/v1/organizations/" + slug
	env := base + "/projects/api/environments/production"
	repo := "acme/api-" + suffix
	c.ok("POST", "/v1/organizations", map[string]any{"name": "Sync rehearsal", "slug": slug})
	c.ok("POST", base+"/projects", map[string]any{"slug": "api", "name": "API", "contractAuthority": "managed"})
	c.ok("POST", base+"/projects/api/environments", map[string]any{"name": "production", "tier": "production"})
	var items []map[string]any
	for _, it := range []struct {
		name      string
		sensitive bool
	}{{"API_KEY", true}, {"BROKEN_TOKEN", false}, {"DEBUG", false}, {"PORT", false}} {
		items = append(items, map[string]any{"name": it.name, "required": map[string]any{"kind": "never"}, "sensitive": it.sensitive, "type": "string"})
	}
	revision := str(c.ok("POST", base+"/projects/api/contract/revisions", map[string]any{"contract": map[string]any{"schemaVersion": 1, "items": items}}), "id")
	c.ok("POST", base+"/projects/api/contract/revisions/"+revision+"/activate", map[string]any{})
	put := func(name, value string) { c.ok("PUT", env+"/values/"+name, map[string]any{"value": value}) }
	apiKey := secret("key-" + hexBytes(8))
	put("API_KEY", apiKey)
	put("DEBUG", "false")
	put("PORT", "8080")
	// The GitHub stand-in takes a credential starting with "conformance-".
	gh := str(c.ok("POST", base+"/platform-connections", map[string]any{"platform": "github-actions", "baseIdentity": "acme", "name": "GitHub",
		"credential": secret("conformance-" + hexBytes(8))}), "id")
	coolify := str(c.ok("POST", base+"/platform-connections", map[string]any{"platform": "coolify", "baseIdentity": "https://coolify.conformance.test", "name": "Coolify",
		"credential": secret("conformance-coolify-" + hexBytes(8))}), "id")
	tGh := str(c.ok("POST", env+"/sync-targets", map[string]any{"connectionId": gh, "destination": map[string]any{"repo": "api-" + suffix}, "mapping": map[string]any{"kind": "wildcard"}}), "id")
	tApp := str(c.ok("POST", env+"/sync-targets", map[string]any{"connectionId": coolify, "destination": map[string]any{"applicationUuid": "app-conformance"},
		"mapping": map[string]any{"kind": "explicit", "items": []map[string]any{{"name": "PORT"}, {"name": "API_KEY"}}}, "redeploy": true}), "id")
	target := func(id string) syncTarget {
		code, out := c.send("GET", env+"/sync-targets/"+id, nil)
		var v syncTarget
		if code == 200 {
			b, _ := json.Marshal(out)
			_ = json.Unmarshal(b, &v)
		}
		return v
	}
	names := func(s fakesState) string { return strings.Join(s.GitHub[repo], ",") }

	// 1. The source delivers: GitHub holds every name, the application
	// stores and runs what its Target maps.
	var st fakesState
	delivered := pollUntil(150*time.Second, 2*time.Second, func() bool {
		st = f.state()
		app, running := st.Coolify[fakesApp], st.Running[fakesApp]
		return names(st) == "API_KEY,DEBUG,PORT" && app["PORT"] == "8080" && app["API_KEY"] == apiKey && running["PORT"] == "8080" && target(tGh).ok() && target(tApp).ok()
	})
	record(t, item, "the source delivers to GitHub and the Coolify application", delivered,
		fmt.Sprintf("GitHub %s; GitHub Target %s; Coolify Target %s", names(st), target(tGh), target(tApp)))
	if !delivered {
		return
	}

	// 2. The barrier waits for a write in flight: the GitHub stand-in holds
	// the repository's writes; DEBUG changes; once the source's write of it
	// is held, the barrier is opened. The source gives up on a write after
	// 10 s (packages/sync DEFAULT_TIMEOUT_MS), so the barrier starts at
	// once and the write is released within a few seconds.
	f.github(map[string]any{"op": "hold", "repo": repo})
	put("DEBUG", "true")
	heldAt := time.Time{}
	held := pollUntil(150*time.Second, 200*time.Millisecond, func() bool {
		st = f.state()
		for _, h := range st.Held {
			if h.Repo == repo && h.Name == "DEBUG" && h.Connected {
				heldAt = time.Now()
				return true
			}
		}
		return false
	})
	if !held {
		f.github(map[string]any{"op": "release", "repo": repo})
		record(t, item, "the barrier waits for a Sync Target's write in flight", false, "the source's write of DEBUG never reached the GitHub stand-in")
		return
	}
	barrierDone := make(chan ran, 1)
	go func() { barrierDone <- in.admin(nil, "migration", "barrier", "--drain-seconds", "20") }()
	var status string
	waiting := pollUntil(6*time.Second, 300*time.Millisecond, func() bool {
		status = strings.Join(strings.Fields(in.admin(nil, "migration", "status").stdout), "")
		return strings.Contains(status, `"kind":"migration"`) && strings.Contains(status, `"sync":`)
	})
	time.Sleep(time.Second)
	running := len(barrierDone) == 0
	record(t, item, "the barrier waits for a Sync Target's write in flight", waiting && running,
		fmt.Sprintf("status %s; the barrier still draining %v, %v after the write was held", trim(status), running, time.Since(heldAt).Round(time.Millisecond)))
	released := f.github(map[string]any{"op": "release", "repo": repo})
	r := <-barrierDone
	var b barrierAnswer
	drained := r.code == 0 && json.Unmarshal([]byte(lastLine(r.stdout)), &b) == nil && b.Gate.Kind == "migration"
	measure("item 13: the barrier's drain", string(b.Drained))
	st = f.state()
	once := 0
	for _, d := range st.Deliveries {
		if d.Repo == repo && d.Name == "DEBUG" && d.Delivered != nil && *d.Delivered {
			once++
		}
	}
	record(t, item, "the held write is delivered once and the barrier drains after it", drained && bytes.Contains(b.Drained, []byte(`"sync"`)) && once == 1 && len(st.Abandoned) == 0,
		fmt.Sprintf("released %s; delivered %d times, %d abandoned; drained %s; %s", trim(released), once, len(st.Abandoned), string(b.Drained), r.String()))
	if drained {
		rl := in.admin(nil, "migration", "release", "--id", b.Gate.ID)
		code, _ := in.get("/v1/meta")
		record(t, item, "release lifts the barrier", rl.code == 0 && code == 200, fmt.Sprintf("%s; /v1/meta %d", rl.String(), code))
	}
	settled := pollUntil(90*time.Second, 2*time.Second, func() bool { return target(tGh).ok() && target(tApp).ok() })
	if !settled {
		measure("item 13: the Targets before the migration", fmt.Sprintf("GitHub %s; Coolify %s", target(tGh), target(tApp)))
	}

	// 3. The migration, with both Targets settled on the source.
	st = f.state()
	ghWrites, coolWrites := st.Writes[repo], st.coolifyWrites()
	r = in.migrateEnv(rel, true, rel.pin())
	record(t, item, "the migration opens on the target", r.code == 0, r.String()+" "+lastLines(r.stdout, 4))
	if r.code != 0 {
		measure("item 13: migrate's stdout", lastLines(r.stdout, 20))
		return
	}
	_, meta := in.get("/v1/meta")
	measure("item 13: the target's /v1/meta", trim(meta))
	// The target's allow list lets both destinations through; without it
	// (an operator who did not carry VARLATCH_OUTBOUND_ALLOW over), the
	// check names what would be refused.
	vd := filepath.Join(binDir, "varlatchd")
	oc := run("", nil, nil, vd, "admin", "outbound", "check", "--config", in.conf)
	record(t, item, "the target's outbound check allows both destinations", oc.code == 0, oc.String()+" "+lastLines(oc.stdout, 4))
	none := run("", nil, nil, vd, "admin", "outbound", "check", "--config", in.conf, "--allow", "")
	measure("item 13: the target's outbound check without outbound_allow", fmt.Sprintf("exit %d: %s", none.code, lastLines(none.stdout, 4)))

	// 4. Go sends nothing the source delivered: both Targets pushed, each
	// runs on Go, and no write reaches a platform.
	pushedAt := time.Now()
	codes := []int{}
	for _, id := range []string{tGh, tApp} {
		code, _ := c.send("POST", env+"/sync-targets/"+id+"/push", map[string]any{})
		codes = append(codes, code)
	}
	ranOnGo := func(id string) bool {
		at, err := time.Parse(time.RFC3339Nano, target(id).LastAttemptAt)
		return err == nil && at.After(pushedAt.Add(-time.Second))
	}
	both := pollUntil(150*time.Second, 2*time.Second, func() bool { return ranOnGo(tGh) && ranOnGo(tApp) })
	st = f.state()
	record(t, item, "after the migration, Go sends nothing the source delivered", both && st.Writes[repo] == ghWrites && st.coolifyWrites() == coolWrites && target(tGh).ok() && target(tApp).ok(),
		fmt.Sprintf("push answered %v; ran on Go %v; GitHub writes %d then %d; Coolify writes %d then %d; GitHub Target %s; Coolify Target %s",
			codes, both, ghWrites, st.Writes[repo], coolWrites, st.coolifyWrites(), target(tGh), target(tApp)))

	// 5. A change made on Go is pushed from Go.
	put("PORT", "9090")
	pushed := pollUntil(150*time.Second, 2*time.Second, func() bool {
		st = f.state()
		return st.Coolify[fakesApp]["PORT"] == "9090" && st.Running[fakesApp]["PORT"] == "9090" && st.Writes[repo] == ghWrites+1
	})
	record(t, item, "a change on Go is pushed from Go", pushed,
		fmt.Sprintf("Coolify PORT %s, running %s; GitHub writes %d (want %d)", st.Coolify[fakesApp]["PORT"], st.Running[fakesApp]["PORT"], st.Writes[repo], ghWrites+1))

	// 6. A failing Target (#369): GitHub refuses BROKEN_TOKEN; its Target
	// degrades, varlatchd keeps serving, and the Coolify Target converges
	// a change made after it.
	put("BROKEN_TOKEN", "zzz")
	var degraded syncTarget
	failed := pollUntil(150*time.Second, 2*time.Second, func() bool {
		degraded = target(tGh)
		return regexp.MustCompile(`BROKEN_TOKEN \(HTTP 500\)`).MatchString(degraded.LastResult) && degraded.FailureCount >= 1
	})
	record(t, item, "a name GitHub refuses degrades its Target", failed, degraded.String())
	apiKey2 := secret("key-" + hexBytes(8))
	put("API_KEY", apiKey2)
	converged := pollUntil(150*time.Second, 2*time.Second, func() bool {
		st = f.state()
		return st.Coolify[fakesApp]["API_KEY"] == apiKey2 && st.Running[fakesApp]["API_KEY"] == apiKey2
	})
	code, ready := in.get("/readyz")
	pid := 0
	if b, err := os.ReadFile(filepath.Join(in.state, "service.pid")); err == nil {
		_, _ = fmt.Sscan(string(b), &pid)
	}
	record(t, item, "varlatchd keeps serving and the Coolify Target converges", converged && code == 200 && pid > 0 && alive(pid) && target(tApp).FailureCount == 0,
		fmt.Sprintf("Coolify API_KEY updated %v; /readyz %d %s; varlatchd running %v; Coolify Target %s; GitHub Target %s",
			converged, code, trim(ready), pid > 0 && alive(pid), target(tApp), target(tGh)))
}
