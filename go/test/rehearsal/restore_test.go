// SPDX-License-Identifier: Apache-2.0

//go:build rehearsal && linux

package rehearsal_test

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// B6 (internal docs/design/go-step8-rehearsals.md; go-step8.md phase 2):
// the migration of a 0.23.0 installation restored from a backup archive
// the operator copied to this host by hand, with its two keys
// (VL_RH_SOURCE=restore:<archive>, VL_RH_RESTORE_BEK, VL_RH_RESTORE_KEK).
// The harness never fetches an archive, and nothing the archive holds
// reaches the report: the CLI's reads are compared in memory and reported
// as counts and verdicts, the installation's id and the reader's
// credential are registered as secrets, and the keys' copies are removed
// with the installation.
//
// Item 14, on the archive restored by the TypeScript host CLI:
//   - a reader: a CLI credential for the installation's first enabled
//     Installation Admin (admin recover --identity, on this copy only), and
//     the CLI's reads through the public URL (Organizations, Projects,
//     Environments, the names of one Environment's values, and the values
//     themselves as an HMAC under a key of the run's);
//   - the dry run, then the migration with a prober (the downtime, within
//     O7 and the dry run's projection);
//   - parity: the source's own export at the frozen point (behind its
//     migrated-out gate), its tables, rows, digests and decisions, against
//     what migrate's checks report (the journal's copy, and the checks
//     rows, encryption-classes and authorization), every check passed;
//     the CLI's reads the same on Go;
//   - a day of changes on Go through the CLI, then --rollback: the reverse
//     checks, the TypeScript release's export after it against the
//     reverse, and the CLI's reads with the changes;
//   - --finish --delete-old-data (Go's copy discarded), the migration
//     again with the same parity and reads, --finish --delete-old-data;
//   - the converter (migrate --from-archive) on the archive.
//
// VL_RH_ONLY=bundle (item 15) makes the synthetic production-shaped
// archive this case runs on without the owner: the seed, with what a
// production installation adds (a second Organization's Project, a
// machine's service credential, a webhook, a deleted value, a rotation),
// captured by the TypeScript host CLI, with its keys, into
// VL_RH_BUNDLE_OUT.

const restoreItem, bundleItem = 14, 15

// restoredInstallation is the archive restored onto a fresh installation
// of the release, up and serving.
func restoredInstallation(t *testing.T, rel release, s3 *s3Server, name string) *installation {
	t.Helper()
	for _, f := range []string{prof.restoreBEK, prof.restoreKEK} {
		if b, err := os.ReadFile(f); err == nil {
			secret(strings.TrimSpace(string(b)))
		}
	}
	in := prepareInstallation(t, rel, s3, name, &operatorKeys{kek: prof.restoreKEK, bek: prof.restoreBEK})
	registerSecrets(in)
	// Before the copy first starts (the restore starts it): its Compose
	// configuration and Go's say it reaches nothing.
	if ok, detail := in.isolatedBeforeStart(); !record2(t, restoreItem, name+": before the copy starts: isolated", ok, detail) {
		t.FailNow()
	}
	ts := filepath.Join(in.fakebin, "varlatch-ts")
	r := run(in.dir, nil, nil, ts, "admin", "backup", "restore", "--in", prof.restore, "--bek-file", in.bek,
		"--kek-file", filepath.Join(in.dir, "secrets", "varlatch-kek"), "--dir", in.dir)
	if m := regexp.MustCompile(`Restore completed for (\S+?):`).FindStringSubmatch(r.stdout); m != nil {
		secret(m[1])
	}
	if !record2(t, restoreItem, name+": the archive restored by the TypeScript host CLI", r.code == 0 && strings.Contains(r.stdout, "Restore completed for "), r.String()) {
		t.FailNow()
	}
	measure("item 14: "+name+": restore", r.took.Round(time.Millisecond).String())
	a := answersWithin(func() (int, string) { return in.get("/readyz") }, func(code int, _ string) bool { return code == 200 }, 3*time.Minute, time.Second)
	_, body := in.get("/v1/meta")
	var meta struct {
		InstallationID string `json:"installationId"`
		ServerVersion  string `json:"serverVersion"`
	}
	_ = json.Unmarshal([]byte(body), &meta)
	in.installationID = secret(meta.InstallationID)
	ok := a.ok && meta.ServerVersion == "0.23.0" && meta.InstallationID != ""
	if !record2(t, restoreItem, name+": the restored installation serves 0.23.0 at the public URL", ok, fmt.Sprintf("/readyz %d after %s; /v1/meta %s", a.code, a.took.Round(time.Millisecond), trim(redact(body)))) {
		t.FailNow()
	}
	// The restore started the copy (inside its internal network, sync and
	// the audit export off): its webhooks revoked at once, before anything
	// of the run's, then the copy checked as it runs.
	n, err := in.neutralise()
	if !record2(t, restoreItem, name+": the copy's webhooks revoked", err == nil, fmt.Sprintf("%d revoked (%v)", n, err)) {
		t.FailNow()
	}
	if ok, detail := in.isolatedRunning(); !record2(t, restoreItem, name+": the restored copy reaches nothing", ok, detail) {
		t.FailNow()
	}
	return in
}

// --- the copy's isolation (B6) ---

// isolatedBeforeStart: the copy's Compose configuration as Compose
// resolves it, before any of its containers exists (varlatchd with sync
// and the audit export off, its network internal, only the dashboard on
// another), and Go's configuration with sync and the audit export off.
func (in *installation) isolatedBeforeStart() (bool, string) {
	r := in.compose("config", "--format", "json")
	var cfg struct {
		Services map[string]struct {
			Environment map[string]*string         `json:"environment"`
			Networks    map[string]json.RawMessage `json:"networks"`
		} `json:"services"`
		Networks map[string]struct {
			Internal bool `json:"internal"`
		} `json:"networks"`
	}
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &cfg) != nil {
		return false, "docker compose config: " + r.String()
	}
	var bad []string
	env := cfg.Services["varlatchd"].Environment
	for _, k := range []string{"VARLATCH_SYNC", "VARLATCH_AUDIT_EXPORT"} {
		if v := env[k]; v == nil || *v != "off" {
			bad = append(bad, k+" is not off")
		}
	}
	if !cfg.Networks["default"].Internal {
		bad = append(bad, "the default network is not internal")
	}
	for name, svc := range cfg.Services {
		for net := range svc.Networks {
			if net != "default" && !(name == "varlatch-web" && net == "edge") {
				bad = append(bad, name+" is on the network "+net)
			}
		}
	}
	conf, err := os.ReadFile(in.conf)
	if err != nil || !strings.Contains(string(conf), "\nsync = off\n") || !strings.Contains(string(conf), "\naudit_export = off\n") {
		bad = append(bad, "Go's configuration does not say sync = off and audit_export = off")
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, "VARLATCH_SYNC=off, VARLATCH_AUDIT_EXPORT=off, the network internal (the dashboard alone on a second, for its port); Go's sync = off, audit_export = off"
}

// neutralise revokes every webhook of the copy that is not (the
// harness's SQL, never product code): 0.23.0 delivers to webhooks whose
// revoked_at is null only.
func (in *installation) neutralise() (int, error) {
	r := in.psql("WITH r AS (UPDATE webhooks SET revoked_at = now() WHERE revoked_at IS NULL RETURNING 1) SELECT count(*) FROM r")
	if r.code != 0 {
		return 0, errors.New("psql: " + r.String())
	}
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(r.stdout), "%d", &n)
	return n, err
}

// psql is one query of the copy's database, its answer unaligned.
func (in *installation) psql(query string) ran {
	return run(in.dir, nil, nil, "docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "varlatch", "-At", "-c", query)
}

// isolatedRunning: the running copy's varlatchd has sync and the audit
// export off, no webhook is live, and a request from inside it to an
// address outside does not leave its network.
func (in *installation) isolatedRunning() (bool, string) {
	var bad []string
	r := run(in.dir, nil, nil, "docker", "compose", "exec", "-T", "varlatchd", "printenv", "VARLATCH_SYNC", "VARLATCH_AUDIT_EXPORT")
	if strings.Fields(r.stdout) == nil || strings.Join(strings.Fields(r.stdout), " ") != "off off" {
		bad = append(bad, "varlatchd's sync and audit export: "+strings.Join(strings.Fields(r.stdout), " "))
	}
	live := in.psql("SELECT count(*) FROM webhooks WHERE revoked_at IS NULL")
	if strings.TrimSpace(live.stdout) != "0" {
		bad = append(bad, "live webhooks: "+strings.TrimSpace(live.stdout)+" "+live.String())
	}
	// An address, not a name: the network, not DNS, refuses it.
	out := in.inside(`fetch("http://1.1.1.1/", { signal: AbortSignal.timeout(5000) }).then(r => console.log("reached", r.status)).catch(e => console.log("refused", e.cause?.code ?? e.name))`)
	egress := strings.TrimSpace(out.stdout)
	if !strings.HasPrefix(egress, "refused") {
		bad = append(bad, "a request from varlatchd to 1.1.1.1: "+egress)
	}
	if len(bad) > 0 {
		return false, strings.Join(bad, "; ")
	}
	return true, "sync and the audit export off, no live webhook, a request from varlatchd to 1.1.1.1 " + egress
}

func restoreCase(t *testing.T, rel release, s3 *s3Server) {
	const item = restoreItem
	in := restoredInstallation(t, rel, s3, "restored")
	if os.Getenv("VL_RH_ONLY") == "setup" {
		t.Logf("restored %s in %s (VL_RH_ONLY=setup)", in.project, in.dir)
		return
	}
	rd := newReader(t, in)
	if rd == nil {
		return
	}
	before, err := rd.read()
	if !record2(t, item, "the CLI reads the restored source", err == nil, rd.describe(before, err)) {
		return
	}
	// The dry run, then the migration.
	r := in.migrateEnv(rel, true, rel.pin(), "--dry-run")
	if !record2(t, item, "dry run: every check passes on the restored data", r.code == 0 && strings.Contains(r.stdout, "checks passed true"), r.String()+" "+lastLines(r.stdout, 3)) {
		in.afterFailedDryRun(t, rel, item)
		return
	}
	projected := regexp.MustCompile(`Projected downtime (\S+) fits`).FindStringSubmatch(r.stdout)
	measure("item 14: the dry run's report", lastLines(r.stdout, 4))
	if !forwardAndCheck(t, in, rel, "the migration", projected, rd, before) {
		return
	}
	// A day of changes on Go, through the CLI.
	changes, err := rd.change()
	if !record2(t, item, "a day of changes on Go through the CLI", err == nil, fmt.Sprintf("%d values set (%v)", changes, err)) {
		return
	}
	changed, err := rd.read()
	record(t, item, "the CLI reads the changes on Go", err == nil && changed.parts["values"] != before.parts["values"] && changed.parts["value names"] != before.parts["value names"],
		rd.describe(changed, err))
	// The rollback.
	r = run(in.dir, in.migrateEnvVars(rel, true, rel.pin()), nil, filepath.Join(binDir, "varlatch"), in.rollbackArgs()...)
	record(t, item, "--rollback", r.code == 0, r.String()+" "+lastLines(r.stdout, 4))
	if r.code != 0 {
		measure("item 14: --rollback's stdout", lastLines(r.stdout, 20))
		return
	}
	a := answersWithin(func() (int, string) { return in.get("/v1/meta") }, sourceAnswers(in.installationID), sourceAnswerDeadline, 250*time.Millisecond)
	record(t, item, "after the rollback the public URL answers from 0.23.0", a.ok, fmt.Sprintf("%d %s after %v", a.code, trim(a.body), a.took.Round(time.Millisecond)))
	// The TypeScript side runs again, on a database rebuilt from Go's:
	// as isolated as before (the webhooks come back revoked).
	isolated, detail := in.isolatedRunning()
	record(t, item, "after the rollback the copy reaches nothing", isolated, detail)
	reverseParity(t, in)
	back, err := rd.read()
	record(t, item, "the CLI reads after the rollback: the day's changes are on 0.23.0", err == nil && sameReads(changed, back), rd.compare(changed, back, err))
	// Go's copy discarded, then the migration again.
	f := in.migrateFinish(rel)
	record(t, item, "--finish --delete-old-data after the rollback: Go's copy discarded", f.code == 0, f.String()+" "+lastLines(f.stdout, 3))
	if f.code != 0 {
		return
	}
	if !forwardAndCheck(t, in, rel, "the migration again", nil, rd, changed) {
		// Finding of r16f: Go's discarded copy leaves its data directory's
		// backups/ (the final archive's local file), which the new
		// migration's import refuses only after the barrier. As an
		// operator would: moved aside (kept), and the migration again.
		backups := filepath.Join(in.data, "backups")
		if _, err := os.Stat(backups); err != nil {
			return
		}
		aside := filepath.Join(in.targetDir, "go-backups-of-the-discarded-copy")
		if err := os.Rename(backups, aside); err != nil {
			record(t, item, "Go's backups/ moved aside", false, err.Error())
			return
		}
		measure("item 14: before the migration again", "Go's discarded copy left backups/ in the data directory, which the import refuses (after the barrier, the dry run having passed); moved aside, kept")
		if !forwardAndCheck(t, in, rel, "the migration again, Go's backups/ moved aside", nil, rd, changed) {
			return
		}
	}
	f = in.migrateFinish(rel)
	record(t, item, "--finish --delete-old-data after the migration again", f.code == 0, f.String()+" "+lastLines(f.stdout, 4))
	vols := run("", nil, nil, "docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+in.project)
	measure("item 14: the source's volumes after finish", fmt.Sprint(len(strings.Fields(vols.stdout))))
	convertArchive(t, in, rel)
}

// forwardAndCheck is the migration with its prober, then the parity of
// what it copied and the CLI's reads on Go against want.
func forwardAndCheck(t *testing.T, in *installation, rel release, what string, projected []string, rd *reader, want reads) bool {
	const item = restoreItem
	stop := make(chan struct{})
	var mu sync.Mutex
	var longest time.Duration
	var gaps []string
	go probe(in.publicURL+"/v1/meta", in.client, stop, func(gap time.Duration, from, to string) {
		mu.Lock()
		defer mu.Unlock()
		gaps = append(gaps, fmt.Sprintf("%s (%s -> %s)", gap.Round(time.Millisecond), from, to))
		longest = max(longest, gap)
	})
	r := in.migrateEnv(rel, true, rel.pin())
	time.Sleep(2 * time.Second)
	close(stop)
	record(t, item, what+": opens on the target", r.code == 0, r.String()+" "+lastLines(r.stdout, 4))
	mu.Lock()
	measure("item 14: "+what+": downtime as clients saw it (longest gap)", longest.Round(time.Millisecond).String())
	measure("item 14: "+what+": gaps", strings.Join(gaps, "; "))
	seen := longest
	mu.Unlock()
	if r.code != 0 {
		measure("item 14: "+what+": migrate's stdout", lastLines(r.stdout, 20))
		return false
	}
	if projected != nil {
		pd, err := time.ParseDuration(projected[1])
		record(t, item, what+": downtime within O7's 10 minutes and the dry run's projection", err == nil && seen < 10*time.Minute && seen <= pd,
			fmt.Sprintf("clients saw %s; projected %s", seen.Round(time.Millisecond), projected[1]))
	} else {
		record(t, item, what+": downtime within O7's 10 minutes", seen < 10*time.Minute, fmt.Sprintf("clients saw %s", seen.Round(time.Millisecond)))
	}
	_, body := in.get("/v1/meta")
	record(t, item, what+": the public URL answers from the target", strings.Contains(body, in.installationID) && !strings.Contains(body, `"serverVersion":"0.23.0"`), trim(body))
	forwardParity(t, in, what)
	got, err := rd.read()
	record(t, item, what+": the CLI reads the same on Go", err == nil && sameReads(want, got), rd.compare(want, got, err))
	return true
}

// --- parity: the source's export against migrate's checks ---

// exportCounts is the bundle summary of the TypeScript export's last
// line on standard error (#373); the bundle itself is counted, not kept.
type exportCounts struct {
	Bundle struct {
		Tables    int64 `json:"tables"`
		Rows      int64 `json:"rows"`
		Digests   int64 `json:"digests"`
		Decisions int64 `json:"decisions"`
	} `json:"bundle"`
	bytes int64
}

// sourceExport runs the source's export as migrate does (a run key of its
// own on standard input, the digests computed), a dry run of the running
// installation or, behind its migrated-out gate, at its frozen point.
func (in *installation) sourceExport(dry bool) (exportCounts, error) {
	args := []string{"compose", "exec", "-T", "varlatchd", "node", "dist/cli.js", "admin", "migration", "export", "--out", "-", "--digests"}
	if dry {
		args = append(args, "--dry-run")
	}
	cmd := exec.Command("docker", args...)
	cmd.Dir = in.dir
	cmd.Stdin = strings.NewReader(secret(hexBytes(32)) + "\n")
	var counted countWriter
	var errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &counted, &errb
	err := cmd.Run()
	var s exportCounts
	s.bytes = counted.n
	line, ok := strings.CutPrefix(lastLine(errb.String()), exportSummary)
	if err != nil || !ok {
		return s, fmt.Errorf("the export: exit %d, %s", exitCode(err), redact(lastLines(errb.String(), 3)))
	}
	if err := json.Unmarshal([]byte(line), &s); err != nil {
		return s, fmt.Errorf("the export's summary: %v", err)
	}
	return s, nil
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }

// journalCopy is what the source's journal says migrate copied and
// checked, forward (copy) and in the reverse (rollback.export, .checks).
type journalCopy struct {
	Tables, Rows int64
	Checks       *struct {
		Passed bool `json:"passed"`
		Checks []struct {
			Name    string `json:"name"`
			Passed  bool   `json:"passed"`
			Checked int64  `json:"checked"`
		} `json:"checks"`
		Faults []string `json:"faults"`
	} `json:"checks"`
}

func (c journalCopy) checked(name string) int64 {
	if c.Checks != nil {
		for _, x := range c.Checks.Checks {
			if x.Name == name {
				return x.Checked
			}
		}
	}
	return -1
}

func (in *installation) journalOf() (fwd, rev journalCopy, err error) {
	b, err := os.ReadFile(filepath.Join(in.dir, "migration.json"))
	if err != nil {
		return fwd, rev, err
	}
	var j struct {
		Copy     *journalCopy `json:"copy"`
		Rollback *struct {
			Export *journalCopy `json:"export"`
			Checks *struct {
				Passed bool `json:"passed"`
				Checks []struct {
					Name    string `json:"name"`
					Passed  bool   `json:"passed"`
					Checked int64  `json:"checked"`
				} `json:"checks"`
				Faults []string `json:"faults"`
			} `json:"checks"`
		} `json:"rollback"`
	}
	if err := json.Unmarshal(b, &j); err != nil {
		return fwd, rev, err
	}
	if j.Copy != nil {
		fwd = *j.Copy
	}
	if j.Rollback != nil {
		if j.Rollback.Export != nil {
			rev = *j.Rollback.Export
		}
		rev.Checks = j.Rollback.Checks
	}
	return fwd, rev, nil
}

// parity holds an export's counts against a copy's and its checks'.
func parity(src exportCounts, c journalCopy) (bool, string) {
	allPassed := c.Checks != nil && c.Checks.Passed
	var names []string
	if c.Checks != nil {
		for _, x := range c.Checks.Checks {
			allPassed = allPassed && x.Passed
			names = append(names, fmt.Sprintf("%s %v (%d)", x.Name, x.Passed, x.Checked))
		}
	}
	b := src.Bundle
	ok := allPassed && b.Tables == c.Tables && b.Rows == c.Rows && b.Rows == c.checked("rows") &&
		b.Digests == c.checked("encryption-classes") && b.Decisions == c.checked("authorization") && b.Tables > 0 && b.Rows > 0
	detail := fmt.Sprintf("the source's export: %d tables, %d rows, %d digests, %d decisions; the copy %d tables, %d rows; checks: %s",
		b.Tables, b.Rows, b.Digests, b.Decisions, c.Tables, c.Rows, strings.Join(names, ", "))
	if c.Checks != nil && len(c.Checks.Faults) > 0 {
		detail += "; faults: " + strings.Join(c.Checks.Faults, "; ")
	}
	return ok, detail
}

// forwardParity: the source behind its migrated-out gate exports at the
// frozen point exactly what migrate copied and its checks held.
func forwardParity(t *testing.T, in *installation, what string) {
	fwd, _, err := in.journalOf()
	if err != nil {
		record(t, restoreItem, what+": parity", false, err.Error())
		return
	}
	src, err := in.sourceExport(false)
	if err != nil {
		record(t, restoreItem, what+": parity", false, err.Error())
		return
	}
	ok, detail := parity(src, fwd)
	record(t, restoreItem, what+": parity: the source's frozen export is what migrate copied and checked", ok, detail)
}

// reverseParity: the TypeScript release serving again exports what the
// reverse imported and its checks held.
func reverseParity(t *testing.T, in *installation) {
	_, rev, err := in.journalOf()
	if err != nil {
		record(t, restoreItem, "the rollback: parity", false, err.Error())
		return
	}
	src, err := in.sourceExport(true)
	if err != nil {
		record(t, restoreItem, "the rollback: parity", false, err.Error())
		return
	}
	ok, detail := parity(src, rev)
	record(t, restoreItem, "the rollback: parity: 0.23.0's export is what the reverse imported and checked", ok, detail)
}

// --- the CLI's reads ---

// reader reads the installation through the varlatch CLI, as its
// operator would, with a credential of the copy's own.
type reader struct {
	in                *installation
	home, repo, key   string
	token             string
	org, project, env string
}

// reads are one round of the reader's reads: per read, an HMAC of what
// the CLI printed (under the run's key, never written), and counts.
type reads struct {
	parts                              map[string]string
	orgs, projects, envs, names, found int
}

func sameReads(a, b reads) bool {
	return len(a.parts) > 0 && len(a.parts) == len(b.parts) && func() bool {
		for k, v := range a.parts {
			if b.parts[k] != v {
				return false
			}
		}
		return true
	}()
}

func (rd *reader) describe(r reads, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("%d Organizations, %d Projects in the one read, %d Environments there, %d values named and %d read in them", r.orgs, r.projects, r.envs, r.names, r.found)
}

func (rd *reader) compare(want, got reads, err error) string {
	if err != nil {
		return err.Error()
	}
	var differ []string
	for _, k := range []string{"organizations", "projects", "environments", "value names", "values"} {
		if want.parts[k] != got.parts[k] {
			differ = append(differ, k)
		}
	}
	verdict := "every read the same"
	if len(differ) > 0 {
		verdict = "different: " + strings.Join(differ, ", ")
	}
	return verdict + "; " + rd.describe(got, nil)
}

// newReader makes the reader's credential (admin recover on this copy, for
// its first enabled Installation Admin) and picks what it reads: the
// first Organization, its first Project, its first Environment with values
// (VL_RH_RESTORE_READ=<org>/<project>/<environment> names them instead).
func newReader(t *testing.T, in *installation) *reader {
	const item = restoreItem
	q := run(in.dir, nil, nil, "docker", "compose", "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "varlatch", "-At", "-c",
		"SELECT id FROM identities WHERE installation_admin AND NOT disabled ORDER BY created_at, id LIMIT 1")
	admin := strings.TrimSpace(q.stdout)
	if !record2(t, item, "an enabled Installation Admin in the restored data", q.code == 0 && admin != "", q.String()) {
		return nil
	}
	secret(admin)
	r := in.admin(nil, "recover", "--identity", admin, "--cli-credential")
	token := strings.TrimSpace(lastLine(r.stdout))
	if !record2(t, item, "a CLI credential of this copy's own (admin recover --identity)", r.code == 0 && strings.HasPrefix(token, "vlt_"), r.String()) {
		return nil
	}
	rd := &reader{in: in, home: filepath.Join(in.state, "cli-home"), repo: filepath.Join(in.state, "cli-repo"), key: filepath.Join(in.state, "digest-key"), token: secret(token)}
	for _, d := range []string{rd.home, rd.repo} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(rd.key, []byte(secret(hexBytes(32))), 0o600); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("VL_RH_RESTORE_READ"); v != "" {
		parts := strings.Split(v, "/")
		if len(parts) != 3 {
			record(t, item, "VL_RH_RESTORE_READ", false, "it is <organization>/<project>/<environment>")
			return nil
		}
		rd.org, rd.project, rd.env = parts[0], parts[1], parts[2]
		return rd
	}
	err := rd.pick()
	if !record2(t, item, "the CLI finds an Environment with values to read", err == nil, fmt.Sprint(err)) {
		return nil
	}
	return rd
}

// cli runs the varlatch CLI in the reader's repository: its environment
// is its own (no shell's, no coding agent's), with the copy's credential.
// What it prints stays in memory.
func (rd *reader) cli(args ...string) ran {
	cmd := exec.Command(filepath.Join(binDir, "varlatch"), args...)
	cmd.Dir = rd.repo
	cmd.Env = []string{"PATH=" + rd.repo + ":/usr/local/bin:/usr/bin:/bin", "HOME=" + rd.home, "VARLATCH_CONFIG_DIR=" + filepath.Join(rd.home, "config"),
		"TMPDIR=" + rd.in.state, "VARLATCH_SERVER=" + rd.in.publicURL, "VARLATCH_TOKEN=" + rd.token, "VARLATCH_NO_BROWSER=1"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	began := time.Now()
	err := cmd.Run()
	return ran{code: exitCode(err), stdout: out.String(), stderr: errb.String(), took: time.Since(began)}
}

func (rd *reader) context(org, project, env string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "server = %q\n", rd.in.publicURL)
	if org != "" {
		fmt.Fprintf(&b, "organization = %q\n", org)
	}
	if project != "" {
		fmt.Fprintf(&b, "project = %q\n", project)
	}
	if env != "" {
		fmt.Fprintf(&b, "default_environment = %q\n", env)
	}
	return os.WriteFile(filepath.Join(rd.repo, "varlatch.toml"), []byte(b.String()), 0o600)
}

// listed is the CLI's JSON output, and the strings under key in its list
// (sorted).
func (rd *reader) listed(key, member string, args ...string) (string, []string, error) {
	r := rd.cli(args...)
	if r.code != 0 {
		// stderr only, redacted: it never holds a value.
		return "", nil, fmt.Errorf("varlatch %s: exit %d: %s", args[0], r.code, redact(lastLines(r.stderr, 2)))
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		return "", nil, fmt.Errorf("varlatch %s: not JSON", args[0])
	}
	var list []map[string]any
	_ = json.Unmarshal(doc[key], &list)
	var out []string
	for _, e := range list {
		if s, ok := e[member].(string); ok {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return r.stdout, out, nil
}

func (rd *reader) pick() error {
	if err := rd.context("", "", ""); err != nil {
		return err
	}
	_, orgs, err := rd.listed("organizations", "slug", "org", "list", "--json")
	if err != nil {
		return err
	}
	for _, org := range orgs {
		// project list and env list read the repository's context, which
		// names a Project and an Environment too: any slug, as they list
		// the Organization's and the Project's.
		if err := rd.context(org, "vl-rh-pick", "vl-rh-pick"); err != nil {
			return err
		}
		_, projects, err := rd.listed("projects", "slug", "project", "list", "--json")
		if err != nil {
			return err
		}
		for _, project := range projects {
			if err := rd.context(org, project, "vl-rh-pick"); err != nil {
				return err
			}
			_, envs, err := rd.listed("environments", "name", "env", "list", "--json")
			if err != nil {
				return err
			}
			for _, env := range envs {
				if _, names, err := rd.listed("items", "name", "values", "list", "--json", "-e", env); err == nil && len(names) > 0 {
					rd.org, rd.project, rd.env = org, project, env
					return nil
				}
			}
		}
	}
	return errors.New("no Environment the credential reads has a value")
}

func (rd *reader) mac(s string) string {
	key, _ := os.ReadFile(rd.key)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// read is one round: Organizations, the Projects of the one read, its
// Environments, the names of the Environment's values, and the values
// (varlatch run giving them to envdigest, this binary, which prints only
// their HMAC under the run's key).
func (rd *reader) read() (reads, error) {
	r := reads{parts: map[string]string{}}
	if err := rd.context("", "", ""); err != nil {
		return r, err
	}
	out, orgs, err := rd.listed("organizations", "slug", "org", "list", "--json")
	if err != nil {
		return r, err
	}
	r.parts["organizations"], r.orgs = rd.mac(out), len(orgs)
	if err := rd.context(rd.org, rd.project, rd.env); err != nil {
		return r, err
	}
	out, projects, err := rd.listed("projects", "slug", "project", "list", "--json")
	if err != nil {
		return r, err
	}
	r.parts["projects"], r.projects = rd.mac(out), len(projects)
	out, envs, err := rd.listed("environments", "name", "env", "list", "--json")
	if err != nil {
		return r, err
	}
	r.parts["environments"], r.envs = rd.mac(out), len(envs)
	self, _ := os.Executable()
	link := filepath.Join(rd.repo, "envdigest")
	if _, err := os.Lstat(link); err != nil {
		if err := os.Symlink(self, link); err != nil {
			return r, err
		}
	}
	// Every Environment of the Project: its values' names, and the
	// values (an HMAC each Environment, combined in order).
	var listings, digests strings.Builder
	for _, env := range envs {
		out, names, err := rd.listed("items", "name", "values", "list", "--json", "-e", env)
		if err != nil {
			return r, err
		}
		fmt.Fprintf(&listings, "%s\n%s\n", env, out)
		r.names += len(names)
		namesFile := filepath.Join(rd.in.state, "digest-names")
		if err := os.WriteFile(namesFile, []byte(strings.Join(names, "\n")), 0o600); err != nil {
			return r, err
		}
		v := rd.cli("run", "-e", env, "--", link, rd.key, namesFile)
		var found int
		var digest string
		if _, err := fmt.Sscanf(strings.TrimSpace(lastLine(v.stdout)), "%d %s", &found, &digest); v.code != 0 || err != nil {
			return r, fmt.Errorf("varlatch run: exit %d: %s", v.code, redact(lastLines(v.stderr, 2)))
		}
		fmt.Fprintf(&digests, "%s %d %s\n", env, found, digest)
		r.found += found
	}
	r.parts["value names"], r.parts["values"] = rd.mac(listings.String()), rd.mac(digests.String())
	return r, nil
}

// change sets values on Go through the CLI: one value of the read
// Environment replaced, and three new ones, each a new random value the
// CLI generates (no value on a command line).
func (rd *reader) change() (int, error) {
	if err := rd.context(rd.org, rd.project, rd.env); err != nil {
		return 0, err
	}
	_, names, err := rd.listed("items", "name", "values", "list", "--json", "-e", rd.env)
	if err != nil {
		return 0, err
	}
	n := 0
	set := func(args ...string) error {
		r := rd.cli(args...)
		if r.code != 0 {
			return fmt.Errorf("varlatch values set: exit %d: %s", r.code, redact(lastLines(r.stderr, 2)))
		}
		n++
		return nil
	}
	if len(names) > 0 {
		if err := set("values", "set", names[0], "--generate", "hex:32", "--replace", names[0], "-e", rd.env); err != nil {
			return n, err
		}
	}
	for i := 1; i <= 3; i++ {
		name := fmt.Sprintf("VL_RH_B6_CHANGE_%d", i)
		if slices.Contains(names, name) {
			continue
		}
		if err := set("values", "set", name, "--generate", "hex:32", "-e", rd.env); err != nil {
			return n, err
		}
	}
	return n, nil
}

// envDigest is this binary as envdigest <key-file> <names-file>, the
// command varlatch run gives the Environment's values to: it prints how
// many of the names it found and an HMAC (under the key) of each NAME=value
// in the names' order, never a value.
func envDigest(args []string) int {
	if len(args) != 2 {
		return 64
	}
	key, err := os.ReadFile(args[0])
	if err != nil {
		return 1
	}
	f, err := os.Open(args[1])
	if err != nil {
		return 1
	}
	defer f.Close()
	m := hmac.New(sha256.New, key)
	found := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name := sc.Text()
		v, ok := os.LookupEnv(name)
		if ok {
			found++
		}
		fmt.Fprintf(m, "%s=%v:%d:%s\n", name, ok, len(v), v)
	}
	fmt.Printf("%d %s\n", found, hex.EncodeToString(m.Sum(nil)))
	return 0
}

// --- the converter on the archive ---

func convertArchive(t *testing.T, in *installation, rel release) {
	out := filepath.Join(in.state, "converted.vltbak")
	defer os.Remove(out)
	// The converter's export runs as this process's user with no
	// capability, so it reads a key file this user owns only (r16h: the
	// synthetic archive's keys are the workstation user's): a copy of the
	// run's own, removed after.
	kek := filepath.Join(in.state, "convert-root-kek")
	b, err := os.ReadFile(prof.restoreKEK)
	if err == nil {
		err = os.WriteFile(kek, b, 0o600)
	}
	if err != nil {
		record(t, restoreItem, "the converter turns the archive into a format 3 archive", false, err.Error())
		return
	}
	defer os.Remove(kek)
	r := run(in.dir, []string{"TMPDIR=" + in.state}, nil, filepath.Join(binDir, "varlatch"), "migrate", "--from-archive", prof.restore,
		"--kek-file", kek, "--bek-file", prof.restoreBEK, "--out", out, "--ts-image", rel.pin(), "--json",
		// Its scratch varlatchd data directory where a data directory may
		// be: on a path only root may change (the target's, r16i).
		"--scratch-dir", in.targetDir)
	var res struct {
		Source struct {
			Format  int    `json:"format"`
			Release string `json:"release"`
		} `json:"source"`
		Copy struct {
			Tables int64 `json:"tables"`
			Rows   int64 `json:"rows"`
		} `json:"copy"`
		Checks struct {
			Passed bool `json:"passed"`
		} `json:"checks"`
		Output struct {
			Bytes int64 `json:"bytes"`
		} `json:"output"`
	}
	_ = json.Unmarshal([]byte(strings.TrimSpace(r.stdout)), &res)
	record(t, restoreItem, "the converter turns the archive into a format 3 archive", r.code == 0 && res.Checks.Passed && res.Copy.Rows > 0,
		fmt.Sprintf("%s; archive format %d, release %s: %d tables, %d rows, every check passed %v, %d bytes written", r, res.Source.Format, res.Source.Release, res.Copy.Tables, res.Copy.Rows, res.Checks.Passed, res.Output.Bytes))
}

// --- VL_RH_ONLY=bundle: the synthetic production-shaped archive ---

func makeBundle(t *testing.T, rel release, s3 *s3Server) {
	const item = bundleItem
	// The audit export's destination is an S3 server of the run's own on
	// the installation's network, which the outbound policy is told to
	// allow by name (its address is a private one).
	in := newInstallation(t, rel, s3, "bundle", installExtra{env: map[string]string{"VARLATCH_OUTBOUND_ALLOW": auditS3Alias + ":9000"}})
	registerSecrets(in)
	audit := startAuditS3(t, in.project+"_default")
	secret(audit.secret)
	audit.createBucket(t, "vl-rh-audit")
	s := seed(t, in)
	record(t, item, "seeded through the real /v1", true, fmt.Sprintf("%d values, %d versions, in %s", s.values, s.versions, s.took.Round(time.Millisecond)))
	shape := productionShape(t, s, audit)
	record(t, item, "production-shaped", true, shape)
	if err := os.MkdirAll(prof.bundleOut, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(prof.bundleOut, "archive.vltbak")
	kek := filepath.Join(in.dir, "secrets", "varlatch-kek")
	r := run(in.dir, nil, nil, filepath.Join(in.fakebin, "varlatch-ts"), "admin", "backup", "create", "--dir", in.dir,
		"--bek-file", in.bek, "--kek-file", kek, "--out", archive)
	if !record2(t, item, "the archive created by the TypeScript host CLI", r.code == 0 && strings.Contains(r.stdout, "Archive created: "), r.String()) {
		return
	}
	for _, f := range []struct{ from, to string }{{in.bek, "backup-key"}, {kek, "root-kek"}} {
		b, err := os.ReadFile(f.from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(prof.bundleOut, f.to), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := os.Stat(archive)
	var size int64
	if st != nil {
		size = st.Size()
	}
	about, _ := json.MarshalIndent(map[string]any{
		"what": "a synthetic production-shaped 0.23.0 archive (go/test/rehearsal, VL_RH_ONLY=bundle); no production data", "run": runID,
		"made": time.Now().UTC().Format(time.RFC3339), "archive": "archive.vltbak", "bek": "backup-key", "kek": "root-kek",
		"values": s.values, "versions": s.versions, "shape": shape, "bytes": size,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(prof.bundleOut, "bundle.json"), append(about, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	measure("item 15: the archive", fmt.Sprintf("%d bytes", size))
}

// auditS3Alias is the audit export's S3 server's name on the bundle
// installation's network.
const auditS3Alias = "vl-rh-audit-s3"

// startAuditS3 is an S3 server (MinIO, by digest) for the bundle's audit
// export, on network as auditS3Alias, and on loopback for the harness.
func startAuditS3(t *testing.T, network string) *s3Server {
	t.Helper()
	s := &s3Server{name: "vl-rh-" + runID + "-audit-minio", user: "rh" + hexBytes(6), secret: hexBytes(20)}
	port := freePort(t)
	must(t, run("", nil, nil, "docker", "run", "-d", "--name", s.name, "--network", network, "--network-alias", auditS3Alias, "-p", "127.0.0.1:"+port+":9000",
		"-e", "MINIO_ROOT_USER="+s.user, "-e", "MINIO_ROOT_PASSWORD="+s.secret, minioImage, "server", "/data"), "start the audit export's MinIO")
	// Before the installation's cleanup (registered first), which removes
	// the network this is on.
	t.Cleanup(func() { run("", nil, nil, "docker", "rm", "-fv", s.name) })
	s.endpoint = "http://127.0.0.1:" + port
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		if resp, err := http.Get(s.endpoint + "/minio/health/ready"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the audit export's MinIO did not become ready")
		}
	}
}

// productionShape adds what a production installation has beyond the
// seed: a second Organization's Project with values, a machine's service
// credential, a webhook (to a name that never resolves), a deleted value,
// a rotation in its grace window, an audit export stream (to the run's
// own S3 server), and a Platform Connection with a Sync Target (to a
// Coolify that never resolves). Left out: people with passkeys
// (WebAuthn).
func productionShape(t *testing.T, s seeded, audit *s3Server) string {
	c := s.client
	const acme, beta = "/v1/organizations/acme", "/v1/organizations/beta"
	c.ok("POST", beta+"/projects", map[string]any{"name": "Jobs", "slug": "jobs", "contractAuthority": "managed"})
	c.ok("POST", beta+"/projects/jobs/environments", map[string]any{"name": "production", "tier": "production"})
	for i := range 25 {
		c.ok("PUT", fmt.Sprintf("%s/projects/jobs/environments/production/values/JOB_%02d", beta, i), map[string]any{"value": secret("rh-" + hexBytes(16))})
	}
	cred := c.ok("POST", acme+"/identities/"+s.service+"/credentials", map[string]any{"name": "deploy-bot"})
	if tok, ok := cred["token"].(string); ok {
		secret(tok)
	}
	hook := c.ok("POST", acme+"/webhooks", map[string]any{"url": "https://hooks.rehearsal.invalid/varlatch"})
	if v, ok := hook["secret"].(string); ok {
		secret(v)
	}
	if code, _ := c.send("DELETE", acme+"/projects/api/environments/development/values/VALUE_0000", nil); code != 204 {
		t.Fatalf("seed: delete a value: %d", code)
	}
	c.ok("POST", acme+"/projects/api/environments/staging/values/VALUE_0001/rotations", map[string]any{"value": secret("rh-" + hexBytes(16)), "graceSeconds": 86400})
	c.ok("POST", acme+"/audit-export", map[string]any{
		"destination": map[string]any{"endpoint": "http://" + auditS3Alias + ":9000", "region": "us-east-1", "bucket": "vl-rh-audit", "prefix": "audit/", "pathStyle": true},
		"credential":  map[string]any{"accessKeyId": audit.user, "secretAccessKey": audit.secret},
		"from":        "beginning",
	})
	conn := str(c.ok("POST", acme+"/platform-connections", map[string]any{"platform": "coolify", "baseIdentity": "https://coolify.rehearsal.invalid",
		"name": "lab", "credential": secret("rh-" + hexBytes(24))}), "id")
	c.ok("POST", acme+"/projects/api/environments/production/sync-targets", map[string]any{"connectionId": conn,
		"destination": map[string]any{"applicationUuid": "rehearsal-app-1"}, "mapping": map[string]any{"kind": "explicit", "items": []map[string]any{{"name": "VALUE_0002"}}}})
	return "a second Organization's Project (25 values), a service credential, a webhook, a deleted value, a rotation, an audit export stream, a Platform Connection and a Sync Target"
}
