// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestRehearsal runs the must-cover list (internal docs/design/go-step7.md
// 7.8b) against a real installation of the release: items 1 to 8 on one
// installation, then the port-collision case of item 6 on a second.
func TestRehearsal(t *testing.T) {
	rel := loadRelease(t)
	report.Run, report.Started, report.Images = runID, time.Now().UTC(), rel.Images
	defer writeReport(t)
	s3 := startS3(t)
	secret(s3.secret)
	t.Run("main", func(t *testing.T) { mainCases(t, rel, s3) })
	if os.Getenv("VL_RH_ONLY") == "setup" {
		return
	}
	t.Run("collision", func(t *testing.T) { collisionCase(t, rel, s3) })
}

func mainCases(t *testing.T, rel release, s3 *s3Server) {
	in := newInstallation(t, rel, s3, "main")
	registerSecrets(in)
	if os.Getenv("VL_RH_SEED") != "0" {
		s := seed(t, in)
		record(t, 9, "seeded through the real /v1", true, fmt.Sprintf("%d values, %d versions, identities, a Role, a Group, a Team, Grants, in %s (%d rate-limited answers waited out)", s.values, s.versions, s.took.Round(time.Millisecond), s.rateLimited))
	}
	if os.Getenv("VL_RH_ONLY") == "setup" {
		t.Logf("set up %s in %s (VL_RH_ONLY=setup)", in.project, in.dir)
		return
	}
	imagePin(t, in, rel)
	backups(t, in, rel, s3)
	export(t, in)
	barrier(t, in)
	migration(t, in, rel, s3)
}

// registerSecrets keeps the installation's keys and passwords out of the
// report.
func registerSecrets(in *installation) {
	for _, f := range []string{filepath.Join(in.dir, "secrets", "varlatch-kek"), in.bek} {
		if b, err := os.ReadFile(f); err == nil {
			secret(strings.TrimSpace(string(b)))
		}
	}
	if b, err := os.ReadFile(filepath.Join(in.dir, ".env")); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(l, "="); ok && (strings.Contains(k, "PASSWORD") || strings.Contains(k, "SECRET")) {
				secret(v)
			}
		}
	}
}

// --- item 8: the image pin ---

func imagePin(t *testing.T, in *installation, rel release) {
	const item = 8
	// The constants (no override): 0.23.0 is not published, so every
	// source is refused.
	r := in.migrateEnv(rel, false, "", "--dry-run")
	record(t, item, "no pin: refused as unpublished", r.code != 0 && strings.Contains(r.stderr, "not yet published"), r.String())
	// Another digest than the source's.
	other := rel.pin()[:strings.Index(rel.pin(), "@")] + "@sha256:" + strings.Repeat("0", 64)
	r = in.migrateEnv(rel, true, other, "--dry-run")
	// The message names both images; the CLI's fail-safe masks a registry
	// with a port as a URL's user name and password (finding of run r1).
	record(t, item, "another digest: refused", r.code != 0 && !strings.Contains(r.stderr, "not yet published"), r.String())
	if strings.Contains(r.stderr, "[redacted]@") {
		differs(item, "G5's pin is ghcr.io/varlatch/varlatchd@sha256:..., a repository without a port.",
			"with a registry that has a port (a mirror, a private registry, this harness's), the refusal's image references read [redacted]@sha256:...: the fail-safe takes host:port/repo before the at-sign for a URL's credentials",
			"migrate's diagnostics: the operator cannot read which image was found or wanted")
	}
	// An image built here, never pushed: no registry digest of its own.
	local := "vl-rh-" + runID + "-local/varlatchd:0.23.0"
	must(t, run("", nil, nil, "docker", "tag", rel.Images["varlatchd"][:strings.Index(rel.Images["varlatchd"], "@")], local), "tag a local image")
	t.Cleanup(func() { run("", nil, nil, "docker", "image", "rm", local) })
	in.swapImage(t, local)
	r = in.migrateEnv(rel, true, rel.pin(), "--dry-run")
	record(t, item, "a locally built image: refused (no registry digest)", r.code != 0 && !strings.Contains(r.stderr, "not yet published"), r.String())
	in.swapImage(t, rel.Images["varlatchd"])
}

// swapImage points the source's varlatchd service at image and recreates
// it.
func (in *installation) swapImage(t *testing.T, image string) {
	t.Helper()
	p := filepath.Join(in.dir, "docker-compose.yml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^(  varlatchd:\n(?:    .*\n)*?    image: ).*$`)
	if !re.Match(b) {
		t.Fatal("no image line in the varlatchd service")
	}
	b = re.ReplaceAll(b, []byte("${1}"+image))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, in.compose("up", "-d", "--wait", "varlatchd"), "recreate varlatchd on "+image)
}

// migrateEnv is migrate with the pin override set to pin (or unset).
func (in *installation) migrateEnv(rel release, withPin bool, pin string, extra ...string) ran {
	args := []string{"migrate", "--ingress", "proxy", "--from", in.dir, "--config", in.conf,
		"--bek-file", in.bek, "--backup-destination", "offsite", "--destinations-file", in.destinations,
		"--read-credentials-file", in.readCreds, "--ts-cli", "varlatch-ts", "--transfer-timeout", "90s", "--drain", "20s"}
	env := []string{"PATH=" + in.fakebin + ":" + os.Getenv("PATH"), "VL_RH_STATE=" + in.state, "TMPDIR=" + in.state}
	if withPin {
		env = append(env, "VARLATCH_MIGRATE_PIN="+pin)
	}
	return run(in.dir, env, nil, filepath.Join(binDir, "varlatch"), append(args, extra...)...)
}

// --- item 7: the TypeScript CLI's backups ---

func backups(t *testing.T, in *installation, rel release, s3 *s3Server) {
	const item = 7
	ts := filepath.Join(in.fakebin, "varlatch-ts")
	kek := filepath.Join(in.dir, "secrets", "varlatch-kek")
	base := []string{"admin", "backup"}
	create := func(dest string) ran {
		return run(in.dir, nil, nil, ts, append(base, "create", "--dir", in.dir, "--bek-file", in.bek, "--kek-file", kek, "--destination", "offsite", "--destinations-file", dest)...)
	}
	// A destination whose bucket does not exist.
	missing := filepath.Join(filepath.Dir(in.destinations), "missing-bucket.json")
	s3.writeDestination(t, missing, "vl-rh-no-such-bucket", "write.json")
	r := create(missing)
	record(t, item, "create to a missing bucket: fails", r.code != 0, r.String())
	if r.code == 0 {
		differs(item, "the stand-in's create fails only when told to.", "create to a bucket that does not exist exited 0: "+lastLines(r.stdout, 2), "migrate would carry on with no uploaded archive")
	}
	// A good one, then its object corrupted, then verify.
	r = create(in.destinations)
	m := regexp.MustCompile(`Archive created: .* \(([0-9a-f-]{36})\)`).FindStringSubmatch(r.stdout)
	if !record2(t, item, "create and upload", r.code == 0 && m != nil && strings.Contains(r.stdout, "Upload completed to "), r.String()) {
		return
	}
	archive := m[1]
	verify := func(creds string) ran {
		return run(in.dir, nil, nil, ts, append(base, "verify", "--dir", in.dir, "--bek-file", in.bek, "--kek-file", kek, "--destination", "offsite",
			"--destinations-file", in.destinations, "--archive", archive, "--read-credentials-file", creds, "--record")...)
	}
	r = verify(in.readCreds)
	record(t, item, "verify downloads and passes", r.code == 0 && strings.Contains(r.stdout, `"integrity":true`), r.String())
	measure("item 7: TypeScript backup create", "see checks")
	// Wrong read credentials.
	wrong := filepath.Join(filepath.Dir(in.readCreds), "wrong-read.json")
	b, _ := json.Marshal(map[string]string{"accessKeyId": s3.user, "secretAccessKey": hexBytes(20)})
	_ = os.WriteFile(wrong, b, 0o600)
	r = verify(wrong)
	record(t, item, "verify with wrong read credentials: fails", r.code != 0, r.String())
	// The object corrupted in the bucket.
	key := "rehearsal/" + archive + ".vltbak"
	must(t, s3.s3(t, "flip-byte", "vl-rh-main", key), "corrupt the object")
	r = verify(in.readCreds)
	record(t, item, "verify a corrupted object: fails", r.code != 0 || !strings.Contains(r.stdout, `"integrity":true`), r.String())
	// The migration's preflight with wrong read credentials refuses.
	saved := in.readCreds
	in.readCreds = wrong
	r = in.migrateEnv(rel, true, rel.pin(), "--dry-run")
	in.readCreds = saved
	record(t, item, "preflight with wrong read credentials: refused", r.code != 0, r.String())
	in.afterFailedDryRun(t, rel, item)
}

func record2(t *testing.T, item int, name string, ok bool, detail string) bool {
	record(t, item, name, ok, detail)
	return ok
}

// --- item 1: the export on PostgreSQL ---

func export(t *testing.T, in *installation) {
	const item = 1
	if os.Getenv("VL_RH_BACKUPS_WORKAROUND") == "1" {
		differs(item, "G5's stand-in writes the bundle itself, into the Compose directory's backups/.",
			"the real export runs in the TypeScript varlatchd container as uid 999 and writes --out /backups/<name>; setup makes backups/ 0700 and the operator's, so it cannot: \"Operator command failed; check configuration and maintenance status.\" (exit 1, the CLI's catch-all; run r1). This run opens backups/ to 0777 to reach the later items",
			"blocker: every real migration's dry run fails at its export")
	}
	key := secret(hexBytes(32))
	out := func(name string, dry bool, stdin string) ran {
		args := []string{"migration", "export", "--out", "/backups/" + name, "--digests"}
		if dry {
			args = append(args, "--dry-run")
		}
		return in.admin([]byte(stdin), args...)
	}
	// No barrier: a real export is refused.
	r := out("no-barrier.bundle", false, key+"\n")
	record(t, item, "export without a barrier: refused", r.code != 0 && strings.Contains(r.stderr, "no migration barrier is held"), r.String())
	compareRefusal(item, "export without a barrier", "varlatchd admin migration export: no migration barrier is held; nothing was exported (exit 1)", r)
	// A run key that is not 64 hex digits.
	r = out("bad-key.bundle", true, "not-a-key\n")
	record(t, item, "a malformed run key: refused", r.code != 0 && strings.Contains(r.stderr, "64 lowercase hex digits"), r.String())
	compareRefusal(item, "a malformed run key", "the run key on standard input is not 64 lowercase hex digits (exit 1)", r)
	// No run key at all (stdin closed).
	r = out("no-key.bundle", true, "")
	record(t, item, "no run key: refused", r.code != 0, r.String())
	// The dry run: a consistent snapshot of the running installation.
	r = out("dry.bundle", true, key+"\n")
	ok := r.code == 0 && json.Valid([]byte(strings.TrimSpace(lastLine(r.stdout))))
	record(t, item, "dry-run export", ok, r.String())
	if ok {
		measure("item 1: dry-run export", r.took.Round(time.Millisecond).String())
		if fi, err := os.Stat(filepath.Join(in.dir, "backups", "dry.bundle")); err == nil {
			measure("item 1: bundle size (empty installation)", fmt.Sprintf("%d bytes", fi.Size()))
		}
		if strings.Contains(r.stdout, `"frozenPoint":{}`) {
			differs(item, `the stand-in's export prints {"frozenPoint":{},"bundle":{},"preflight":{"ok":true}}.`, lastLine(r.stdout), "")
		} else {
			differs(item, `the stand-in's export prints empty frozenPoint and bundle objects.`, "the real one: "+lastLine(r.stdout), "migrate parses only what it needs; the real fields are richer")
		}
	}
	_ = os.Remove(filepath.Join(in.dir, "backups", "dry.bundle"))
	// Killed mid-export: the .partial, then the next export's cleanup.
	killed := killMidExport(t, in, key)
	record(t, item, "killed mid-export: no bundle, the .partial removed by the next export", killed.ok, killed.detail)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// compareRefusal records a difference when the real refusal is not the
// stand-in's (its text and exit status).
func compareRefusal(item int, what, standIn string, r ran) {
	real := fmt.Sprintf("%s (exit %d)", strings.TrimSpace(lastLine(r.stderr)), r.code)
	if real != standIn {
		differs(item, what+": "+standIn+".", real+".", "")
	}
}

type outcome struct {
	ok     bool
	detail string
}

func killMidExport(t *testing.T, in *installation, key string) outcome {
	backups := filepath.Join(in.dir, "backups")
	done := make(chan ran, 1)
	go func() {
		done <- in.admin([]byte(key+"\n"), "migration", "export", "--out", "/backups/killed.bundle", "--digests", "--dry-run")
	}()
	killedAt := time.Duration(0)
	began := time.Now()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		matches, _ := filepath.Glob(filepath.Join(backups, "killed.bundle*.partial"))
		if len(matches) == 0 {
			matches, _ = filepath.Glob(filepath.Join(backups, "*.partial"))
		}
		if len(matches) > 0 {
			k := in.inside(`for (const d of require("fs").readdirSync("/proc")) { if (!/^\d+$/.test(d)) continue;
				try { const c = require("fs").readFileSync("/proc/" + d + "/cmdline", "utf8"); if (c.includes("migration") && c.includes("export") && +d !== process.pid) process.kill(+d, "SIGKILL"); } catch {} }`)
			killedAt = time.Since(began)
			if k.code != 0 {
				return outcome{false, "the kill failed: " + k.String()}
			}
			break
		}
		select {
		case r := <-done:
			_ = os.Remove(filepath.Join(backups, "killed.bundle"))
			return outcome{true, fmt.Sprintf("not reached: the export finished in %s before a .partial was seen (%s); needs PR3's seed size", r.took.Round(time.Millisecond), r.String())}
		default:
		}
	}
	r := <-done
	partials, _ := filepath.Glob(filepath.Join(backups, "*.partial"))
	_, bundleErr := os.Stat(filepath.Join(backups, "killed.bundle"))
	detail := fmt.Sprintf("killed after %s: exit %d, %d .partial left, bundle present %v", killedAt.Round(time.Millisecond), r.code, len(partials), bundleErr == nil)
	next := in.admin([]byte(key+"\n"), "migration", "export", "--out", "/backups/killed.bundle", "--digests", "--dry-run")
	partialsAfter, _ := filepath.Glob(filepath.Join(backups, "killed.bundle*.partial"))
	_ = os.Remove(filepath.Join(backups, "killed.bundle"))
	detail += fmt.Sprintf("; the next export: exit %d, .partial left %d", next.code, len(partialsAfter))
	return outcome{r.code != 0 && bundleErr != nil && next.code == 0 && len(partialsAfter) == 0, detail}
}

// --- items 2 and 3: the barrier, a restart behind it, its answers ---

type barrierAnswer struct {
	Gate struct {
		ID    string `json:"id"`
		Kind  string `json:"kind"`
		Phase string `json:"phase"`
	} `json:"gate"`
	Drained json.RawMessage `json:"drained"`
	Frozen  json.RawMessage `json:"frozen"`
}

func barrier(t *testing.T, in *installation) {
	// Item 3: a request in flight while the barrier drains. A slow upload
	// to the public URL holds a request open for several seconds.
	inflight := slowRequest(in.publicURL+"/v1/organizations", 6*time.Second)
	time.Sleep(500 * time.Millisecond)
	r := in.admin(nil, "migration", "barrier", "--drain-seconds", "15")
	var b barrierAnswer
	ok := r.code == 0 && json.Unmarshal([]byte(lastLine(r.stdout)), &b) == nil && b.Gate.Kind == "migration"
	record(t, 3, "barrier opened and drained", ok, r.String())
	slow := <-inflight
	if ok {
		measure("item 3: drained", string(b.Drained))
		measure("item 3: frozen", string(b.Frozen))
		measure("item 3: the in-flight request", slow)
		if strings.Contains(slow, "503") {
			differs(3, "G5's barrier drains in 3 ms, waiting for nothing, with nothing in flight.",
				"a request still uploading its body when the barrier opened was not waited for (drained "+string(b.Drained)+") and was answered 503 when its body ended ("+slow+")",
				"in-flight writes whose body is still arriving are refused with a retry, not drained; the drain counts requests from when their handler runs")
		}
		if !bytes.Contains(b.Drained, []byte(`"waitedFor"`)) {
			differs(3, `the stand-in drains with {"ms":3,"waitedFor":{}}.`, "drained: "+string(b.Drained), "decision 19's drain report reads waitedFor")
		} else {
			differs(3, `the stand-in drains in 3 ms, waiting for nothing.`, "drained: "+string(b.Drained)+"; the in-flight request: "+slow, "")
		}
		if b.Gate.Phase != "frozen" {
			differs(3, `the stand-in's barrier gate has phase "frozen".`, fmt.Sprintf("phase %q", b.Gate.Phase), "")
		}
	}
	code, body := in.get("/readyz")
	measure("item 2: /readyz behind the barrier", fmt.Sprintf("%d %s", code, trim(body)))
	code, body = in.get("/v1/meta")
	measure("item 2: /v1/meta behind the barrier", fmt.Sprintf("%d %s", code, trim(body)))
	if code != 503 {
		differs(2, "the stand-in's public URL answers 503 behind any gate.", fmt.Sprintf("/v1/meta behind the barrier: %d %s", code, trim(body)), "migrate's checks of the public URL")
	}
	// Item 2: the barrier survives a restart of varlatchd.
	must(t, in.compose("restart", "varlatchd"), "restart varlatchd")
	waitReady(in, 60*time.Second)
	st := in.admin(nil, "migration", "status")
	record(t, 2, "the barrier survives a restart", st.code == 0 && strings.Contains(st.stdout, `"kind":"migration"`) && strings.Contains(st.stdout, b.Gate.ID), st.String()+" "+trim(st.stdout))
	if ok {
		rel := in.admin(nil, "migration", "release", "--id", b.Gate.ID)
		record(t, 2, "release lifts it", rel.code == 0 && strings.Contains(rel.stdout, `"released":true`), rel.String())
		code, _ := in.get("/v1/meta")
		record(t, 2, "the installation answers again", code == 200, fmt.Sprintf("/v1/meta %d", code))
	}
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// waitReady waits until the varlatchd container answers its status.
func waitReady(in *installation, d time.Duration) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if r := in.admin(nil, "migration", "status"); r.code == 0 {
			return
		}
	}
}

// slowRequest POSTs a body that trickles in over d, and reports how it
// ended.
func slowRequest(u string, d time.Duration) <-chan string {
	out := make(chan string, 1)
	go func() {
		pr, pw := io.Pipe()
		go func() {
			end := time.Now().Add(d)
			for time.Now().Before(end) {
				_, _ = pw.Write([]byte("{"))
				time.Sleep(250 * time.Millisecond)
			}
			_ = pw.Close()
		}()
		began := time.Now()
		req, _ := http.NewRequest(http.MethodPost, u, pr)
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 3 * d}).Do(req)
		if err != nil {
			out <- fmt.Sprintf("error after %s: %v", time.Since(began).Round(time.Millisecond), err)
			return
		}
		resp.Body.Close()
		out <- fmt.Sprintf("%d after %s", resp.StatusCode, time.Since(began).Round(time.Millisecond))
	}()
	return out
}

// --- the migration: items 4, 5, 6, 2 (switched) and 7 (finish) ---

func migration(t *testing.T, in *installation, rel release, s3 *s3Server) {
	// Item 4: the dry run's checks, the TypeScript decision table among
	// them, on the real export.
	r := in.migrateEnv(rel, true, rel.pin(), "--dry-run")
	record(t, 4, "dry run: every check passes on the real export", r.code == 0 && strings.Contains(r.stdout, "checks passed true"), r.String()+" "+lastLines(r.stdout, 3))
	measure("item 4: the dry run's report", lastLines(r.stdout, 4))
	projected := regexp.MustCompile(`Projected downtime (\S+) fits`).FindStringSubmatch(r.stdout)
	if r.code != 0 {
		in.afterFailedDryRun(t, rel, 4)
		return
	}
	// The migration itself, a prober timing what clients see.
	stop := make(chan struct{})
	var gaps []string
	var mu sync.Mutex
	var longest time.Duration
	go probe(in.publicURL+"/v1/meta", stop, func(gap time.Duration, from, to string) {
		mu.Lock()
		defer mu.Unlock()
		gaps = append(gaps, fmt.Sprintf("%s (%s -> %s)", gap.Round(time.Millisecond), from, to))
		if gap > longest {
			longest = gap
		}
	})
	r = in.migrateEnv(rel, true, rel.pin())
	time.Sleep(2 * time.Second)
	close(stop)
	record(t, 6, "the migration opens on the target", r.code == 0, r.String()+" "+lastLines(r.stdout, 4))
	mu.Lock()
	measure("downtime as clients saw it (longest gap)", longest.Round(time.Millisecond).String())
	// O7: the downtime budget is 10 minutes; the dry run's projection must
	// cover what clients saw (a projection below it would let a migration
	// past --max-downtime that then overruns it).
	proj := "none"
	if projected != nil {
		proj = projected[1]
	}
	pd, perr := time.ParseDuration(proj)
	record(t, 10, "downtime within O7's 10 minutes, and within the dry run's projection", longest < 10*time.Minute && perr == nil && longest <= pd,
		fmt.Sprintf("clients saw %s; projected %s", longest.Round(time.Millisecond), proj))
	measure("gaps", strings.Join(gaps, "; "))
	mu.Unlock()
	measure("migrate's own report", lastLines(r.stdout, 6))
	if r.code != 0 {
		measure("migrate's stdout", lastLines(r.stdout, 20))
		return
	}
	_, body := in.get("/v1/meta")
	record(t, 6, "the public URL answers from the target", strings.Contains(body, in.installationID) && !strings.Contains(body, `"serverVersion":"0.23.0"`), trim(body))
	// Item 5: the source behind its migrated-out gate.
	ready := in.inside(`fetch("http://127.0.0.1:8686/readyz").then(async r => console.log(r.status, await r.text())).catch(e => console.log("error", e.message))`)
	record(t, 5, "the source's /readyz says migrated-out", strings.Contains(ready.stdout, "migrated-out"), trim(ready.stdout))
	meta := in.inside(`fetch("http://127.0.0.1:8686/v1/meta").then(async r => console.log(r.status, await r.text())).catch(e => console.log("error", e.message))`)
	record(t, 5, "the source refuses reads (503)", strings.HasPrefix(strings.TrimSpace(meta.stdout), "503"), trim(meta.stdout))
	// Item 2: switched, a restart of the source stays refusing.
	must(t, in.compose("restart", "varlatchd"), "restart the source's varlatchd")
	time.Sleep(5 * time.Second)
	meta = in.inside(`fetch("http://127.0.0.1:8686/v1/meta").then(async r => console.log(r.status, await r.text())).catch(e => console.log("error", e.message))`)
	record(t, 2, "after a restart, the switched source still refuses", strings.HasPrefix(strings.TrimSpace(meta.stdout), "503"), trim(meta.stdout))
	// Item 7: a TypeScript backup behind the migrated-out gate.
	ts := filepath.Join(in.fakebin, "varlatch-ts")
	b := run(in.dir, nil, nil, ts, "admin", "backup", "create", "--dir", in.dir, "--bek-file", in.bek, "--kek-file", filepath.Join(in.dir, "secrets", "varlatch-kek"),
		"--destination", "offsite", "--destinations-file", in.destinations)
	measure("item 7: a TypeScript backup behind the migrated-out gate", b.String()+" "+lastLines(b.stdout, 2))
	// Item 7: --finish --delete-old-data, its final archive verified.
	if b.code != 0 && strings.Contains(b.stderr, "maintenance is active") {
		differs(7, "G5's varlatch-ts makes the backup whatever the source's gate.",
			"the TypeScript CLI's admin backup create refuses behind the migrated-out gate: \"Installation maintenance is active; capture refused\"",
			"blocker: migrate --finish --delete-old-data cannot make its final archive of the old installation, so it never removes the old volumes")
	}
	f := in.migrateFinish(rel)
	record(t, 7, "finish with --delete-old-data", f.code == 0, f.String()+" "+lastLines(f.stdout, 4))
	vols := run("", nil, nil, "docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+in.project)
	measure("item 7: the source's volumes after finish", strings.Join(strings.Fields(vols.stdout), ", "))
	measure("item 7: objects in the bucket after finish", strings.Join(s3.objects(t, "vl-rh-main"), ", "))
}

func (in *installation) migrateFinish(rel release) ran {
	args := []string{"migrate", "--finish", "--delete-old-data", "--from", in.dir, "--config", in.conf, "--bek-file", in.bek,
		"--backup-destination", "offsite", "--destinations-file", in.destinations, "--read-credentials-file", in.readCreds, "--ts-cli", "varlatch-ts"}
	env := []string{"PATH=" + in.fakebin + ":" + os.Getenv("PATH"), "VL_RH_STATE=" + in.state, "TMPDIR=" + in.state, "VARLATCH_MIGRATE_PIN=" + rel.pin()}
	return run(in.dir, env, nil, filepath.Join(binDir, "varlatch"), args...)
}

// probe polls u every 250 ms until stop, reporting each stretch without a
// 200 (its length, and the answers either side of it).
func probe(u string, stop <-chan struct{}, gap func(time.Duration, string, string)) {
	c := &http.Client{Timeout: 2 * time.Second}
	var downSince time.Time
	last := "200"
	for {
		select {
		case <-stop:
			if !downSince.IsZero() {
				gap(time.Since(downSince), last, "(still down)")
			}
			return
		case <-time.After(250 * time.Millisecond):
		}
		answer := "error"
		if resp, err := c.Get(u); err == nil {
			answer = fmt.Sprint(resp.StatusCode)
			resp.Body.Close()
		}
		switch {
		case answer != "200" && downSince.IsZero():
			downSince, last = time.Now(), answer
		case answer == "200" && !downSince.IsZero():
			gap(time.Since(downSince), last, answer)
			downSince = time.Time{}
		}
	}
}

// --- item 6: the dashboard's port held by something else ---

func collisionCase(t *testing.T, rel release, s3 *s3Server) {
	const item = 6
	in := newInstallation(t, rel, s3, "collision")
	registerSecrets(in)
	// Something of this run's takes the dashboard's port as soon as the
	// migration stops the dashboard (before the target varlatchd starts).
	if err := os.WriteFile(filepath.Join(in.state, "squat"), []byte("127.0.0.1:"+in.webPort), 0o600); err != nil {
		t.Fatal(err)
	}
	r := in.migrateEnv(rel, true, rel.pin())
	record(t, item, "the target cannot bind the port: the migration does not open", r.code != 0, r.String()+" "+lastLines(r.stdout, 4))
	st := in.admin(nil, "migration", "status")
	measure("item 6: the source's gate after the failed transfer", trim(st.stdout))
	web := in.compose("ps", "--format", "{{.Service}} {{.State}}", "varlatch-web")
	measure("item 6: the dashboard after the failed transfer", strings.TrimSpace(web.stdout))
	measure("item 6: the journal after the failed transfer", fmt.Sprint(in.journal()["phase"]))
	// The squatter leaves; --resume (or --abort) brings it back.
	_ = os.Remove(filepath.Join(in.state, "squat"))
	if b, err := os.ReadFile(filepath.Join(in.state, "squatter.pid")); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			time.Sleep(500 * time.Millisecond)
		}
	}
	ab := in.migrateEnv(rel, true, rel.pin(), "--abort")
	measure("item 6: --abort once the port is free", ab.String()+" "+lastLines(ab.stdout, 3))
	code, body := in.get("/v1/meta")
	record(t, item, "after --abort the source answers again", code == 200 && strings.Contains(body, `"serverVersion":"0.23.0"`), fmt.Sprintf("%d %s", code, trim(body)))
}

// afterFailedDryRun: a dry run that fails after its journal is written
// leaves the migration "interrupted in phase started", which refuses the
// next run until --abort (finding of run r1). It is aborted here, and the
// finding recorded once.
func (in *installation) afterFailedDryRun(t *testing.T, rel release, item int) {
	j := in.journal()
	if j == nil {
		return
	}
	differs(item, "G5 never runs a dry run that fails after its journal is written.",
		fmt.Sprintf("a failed --dry-run leaves migration.json (phase %v); the next run, a dry run included, is refused until --resume or --abort", j["phase"]),
		"an operator whose first dry run fails must know to --abort before trying again")
	ab := in.migrateEnv(rel, true, rel.pin(), "--abort")
	record(t, item, "--abort undoes a failed dry run", ab.code == 0, ab.String())
	measure(fmt.Sprintf("item %d: the journal after --abort", item), fmt.Sprint(in.journal()["phase"]))
}
