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
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
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
	goImage                string // the 0.50 image for the image target, repository:<the run's varlatchd release>@sha256:...
	coolifySourceDir       string // the source app's directory in the lab Coolify
	// The tailnet case on Tailscale's control server (the owner's
	// throwaway tailnet), instead of the run's Headscale: the OAuth
	// client's file, the nodes' reusable tagged auth key's, the tailnet's
	// MagicDNS suffix.
	tailscaleOAuth, tailscaleAuthKey, tailscaleTailnet string
	// The tailnet case's browser step (VL_RH_TAILNET_BROWSER=1): a person
	// signs in by passkey before the handoff, after it and after the
	// rollback (browser_test.go).
	browser bool
	// The combined case's: the Go app's UUID, and the name the run's Git
	// repository is served on.
	coolifyTarget, gitName string
	// B5 against the owner's throwaway destinations (VL_RH_SYNC=real).
	syncReal syncRealInputs
	// B6: the archive VL_RH_SOURCE=restore:<archive> names, and its keys
	// (VL_RH_RESTORE_BEK, VL_RH_RESTORE_KEK), all files the operator copied
	// to this host; the harness never fetches one.
	restore, restoreBEK, restoreKEK string
	memory                          bool   // VL_RH_MEMORY=1: the copy stays in memory (memory_test.go)
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
		coolifyTarget: os.Getenv("VL_RH_COOLIFY_TARGET"), gitName: os.Getenv("VL_RH_GIT_NAME"),
		restoreBEK: os.Getenv("VL_RH_RESTORE_BEK"), restoreKEK: os.Getenv("VL_RH_RESTORE_KEK"), bundleOut: os.Getenv("VL_RH_BUNDLE_OUT"),
		tailscaleOAuth: os.Getenv("VL_RH_TAILSCALE_OAUTH_FILE"), tailscaleAuthKey: os.Getenv("VL_RH_TAILSCALE_AUTH_KEY_FILE"),
		tailscaleTailnet: os.Getenv("VL_RH_TAILSCALE_TAILNET"), browser: os.Getenv("VL_RH_TAILNET_BROWSER") == "1",
		syncReal: syncRealInputs{
			githubTokenFile: os.Getenv("VL_RH_SYNC_GITHUB_TOKEN_FILE"), repo: os.Getenv("VL_RH_SYNC_GITHUB_REPO"),
			coolifyURL: os.Getenv("VL_RH_SYNC_COOLIFY_URL"), coolifyTokenFile: os.Getenv("VL_RH_SYNC_COOLIFY_TOKEN_FILE"),
			coolifyApp: os.Getenv("VL_RH_SYNC_COOLIFY_APP"), allowRepo: os.Getenv("VL_RH_SYNC_ALLOW_REPO"), allowApp: os.Getenv("VL_RH_SYNC_ALLOW_APP"),
		},
	}
	only := os.Getenv("VL_RH_ONLY")
	realTailscale := prof.tailscaleOAuth != "" || prof.tailscaleAuthKey != "" || prof.tailscaleTailnet != ""
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
	case !prof.box && prof.ingress != "proxy" && prof.ingress != "tailnet":
		return prof, fmt.Errorf("VL_RH_INGRESS=%s runs on the box only (VL_RH_PROFILE=box)", prof.ingress)
	case realTailscale && prof.ingress != "tailnet":
		return prof, errors.New("VL_RH_TAILSCALE_* goes with VL_RH_INGRESS=tailnet")
	case prof.browser && (prof.ingress != "tailnet" || prof.box):
		return prof, errors.New("VL_RH_TAILNET_BROWSER=1 is the tailnet case's (VL_RH_INGRESS=tailnet) on the workstation the browser is on, not the box")
	case realTailscale && !prof.box && !prof.browser:
		return prof, errors.New("VL_RH_TAILSCALE_* is the owner's session on the box (VL_RH_PROFILE=box), or at the browser of a workstation (VL_RH_TAILNET_BROWSER=1): without, a workstation runs the tailnet case on the run's own Headscale")
	case realTailscale && (prof.tailscaleOAuth == "" || prof.tailscaleAuthKey == "" || prof.tailscaleTailnet == ""):
		return prof, errors.New("the tailnet case on Tailscale needs VL_RH_TAILSCALE_OAUTH_FILE (the OAuth client, devices:core only), VL_RH_TAILSCALE_AUTH_KEY_FILE (a reusable auth key with tag:varlatch) and VL_RH_TAILSCALE_TAILNET (its MagicDNS suffix, e.g. tail1234.ts.net)")
	case prof.ingress == "tailnet" && (prof.kill != "" || prof.sync != "" || prof.source != "seed"):
		return prof, errors.New("VL_RH_INGRESS=tailnet runs its own cases (the handoff, a rollback, a kill mid-handoff and --abort) on seeded sources: leave VL_RH_KILL and VL_RH_SYNC unset, and VL_RH_SOURCE=seed")
	case prof.sync != "" && prof.sync != "fakes" && prof.sync != "real":
		return prof, fmt.Errorf("VL_RH_SYNC is fakes (the platform stand-ins, a workstation) or real (the owner's throwaway GitHub repository and lab Coolify application, the box), not %q", prof.sync)
	case prof.sync == "real" && !prof.box:
		return prof, errors.New("VL_RH_SYNC=real is the owner's session on the box (VL_RH_PROFILE=box): a workstation runs VL_RH_SYNC=fakes")
	case prof.sync == "real" && (prof.ingress != "proxy" || prof.target != "host" || prof.source != "seed"):
		return prof, errors.New("VL_RH_SYNC=real runs on a seeded source with the own proxy and the host-install target (VL_RH_INGRESS=proxy, VL_RH_TARGET=host, VL_RH_SOURCE=seed)")
	case prof.sync == "real":
		if err := checkSyncReal(prof.syncReal); err != nil {
			return prof, err
		}
	case prof.sync == "fakes" && prof.box:
		return prof, errors.New("VL_RH_SYNC=fakes runs on a workstation only: it points the platforms' host names at the stand-ins in the runner container's /etc/hosts, which the box profile does not have")
	case strings.HasPrefix(prof.source, "restore:"):
		prof.restore = strings.TrimPrefix(prof.source, "restore:")
		if err := checkRestore(prof); err != nil {
			return prof, err
		}
	case prof.source != "seed":
		return prof, fmt.Errorf("VL_RH_SOURCE is seed or restore:<archive>, not %q", prof.source)
	case prof.target == "image" && prof.ingress != "coolify" && prof.ingress != "combined":
		return prof, errors.New("the image target runs with the Coolify ingress only (B3); with Compose it is not built yet")
	case prof.target != "host" && prof.target != "image":
		return prof, fmt.Errorf("VL_RH_TARGET is host or image, not %q", prof.target)
	case prof.ingress == "public":
		if prof.publicName == "" || net.ParseIP(prof.publicBind) == nil || net.ParseIP(prof.publicBind).IsUnspecified() {
			return prof, errors.New("public ingress (B2) needs VL_RH_PUBLIC_NAME and VL_RH_PUBLIC_BIND, the address 80 and 443 are free on (internal#221, question 1); never 0.0.0.0")
		}
		// migrate checks the public URL by its name, from this host: the
		// name must lead here, as the run's DNS has it for Pebble.
		addrs, err := resolveHost(prof.publicName)
		if err != nil || !slices.Contains(addrs, prof.publicBind) {
			return prof, fmt.Errorf("VL_RH_PUBLIC_NAME %s resolves, on this host, to %v (%v), not VL_RH_PUBLIC_BIND %s: migrate checks the public URL by its name, so give a name that leads here (a wildcard of the box, or an /etc/hosts line)", prof.publicName, addrs, err, prof.publicBind)
		}
		for _, port := range []string{"80", "443"} {
			l, err := net.Listen("tcp", net.JoinHostPort(prof.publicBind, port))
			if err != nil {
				return prof, fmt.Errorf("%s:%s is not free (%v): the run never stops what holds it", prof.publicBind, port, err)
			}
			l.Close()
		}
	case prof.ingress == "combined":
		if err := checkCombined(prof); err != nil {
			return prof, err
		}
	case prof.ingress == "coolify":
		if prof.target != "image" || prof.goImage == "" || prof.coolifySourceDir == "" || prof.publicName == "" {
			return prof, errors.New("the Coolify domain move (B3) needs VL_RH_TARGET=image, VL_RH_GO_IMAGE (repository:<the run's varlatchd release>@sha256:...), VL_RH_COOLIFY_SOURCE_DIR and VL_RH_PUBLIC_NAME")
		}
		if err := checkImageTarget(prof.goImage); err != nil {
			return prof, err
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
	if realTailscale {
		for _, f := range []string{prof.tailscaleOAuth, prof.tailscaleAuthKey} {
			fi, err := os.Stat(f)
			if err != nil {
				return prof, fmt.Errorf("the tailnet case on Tailscale: %v", err)
			}
			if fi.Mode().Perm()&0o077 != 0 {
				return prof, fmt.Errorf("the tailnet case on Tailscale: %s is mode %04o: the OAuth client and the auth key are the owner's, 0600", f, fi.Mode().Perm())
			}
		}
	}
	if prof.kill != "" && prof.kill != "transfer" && prof.kill != "barrier" {
		return prof, fmt.Errorf("VL_RH_KILL is transfer or barrier, not %q", prof.kill)
	}
	if v := os.Getenv("VL_RH_MEMORY"); v != "" {
		switch {
		case v != "1":
			return prof, fmt.Errorf("VL_RH_MEMORY is 1 or unset, not %q", v)
		case prof.restore == "":
			return prof, errors.New("VL_RH_MEMORY=1 is a restored copy's (VL_RH_SOURCE=restore:<archive>)")
		case prof.sync != "":
			return prof, errors.New("VL_RH_MEMORY=1 runs the restored copy's cases: leave VL_RH_SYNC unset")
		case os.Getenv("VL_RH_KEEP") == "1":
			return prof, errors.New("VL_RH_MEMORY=1 leaves nothing behind: leave VL_RH_KEEP unset")
		}
		prof.memory = true
	}
	// Each is honoured or refused, never left aside: what it asks for is
	// what runs.
	switch {
	case only != "" && only != "setup" && only != "kill" && only != "sync" && only != "bundle":
		return prof, fmt.Errorf("VL_RH_ONLY is setup, kill, sync or bundle, not %q", only)
	case only == "kill" && prof.kill == "":
		// Alone, it would run nothing between the guard and the report.
		return prof, errors.New("VL_RH_ONLY=kill needs VL_RH_KILL (transfer or barrier): it runs the kill case alone")
	case only == "sync" && prof.sync != "fakes" && prof.sync != "real":
		return prof, errors.New("VL_RH_ONLY=sync needs VL_RH_SYNC=fakes or real: it runs the sync case alone")
	case only != "" && slices.Contains([]string{"coolify", "tailnet", "combined"}, prof.ingress):
		return prof, fmt.Errorf("VL_RH_INGRESS=%s runs its own cases, whole: leave VL_RH_ONLY unset", prof.ingress)
	case prof.kill != "" && prof.ingress == "coolify":
		return prof, errors.New("VL_RH_INGRESS=coolify runs its own case, with no kill in it: leave VL_RH_KILL unset")
	case only == "setup" && (prof.kill != "" || prof.sync != ""):
		return prof, errors.New("VL_RH_ONLY=setup only sets the source up: leave VL_RH_KILL and VL_RH_SYNC unset")
	case only == "kill" && prof.sync != "":
		return prof, errors.New("VL_RH_ONLY=kill runs the kill case alone: leave VL_RH_SYNC unset")
	case only == "sync" && prof.kill != "":
		return prof, errors.New("VL_RH_ONLY=sync runs the sync case alone: leave VL_RH_KILL unset")
	case only == "bundle":
		if prof.restore != "" || prof.kill != "" || prof.sync != "" || prof.ingress != "proxy" {
			return prof, errors.New("VL_RH_ONLY=bundle makes the synthetic archive alone: on a seeded source (VL_RH_SOURCE=seed), with the own proxy, no VL_RH_KILL or VL_RH_SYNC")
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

// resolveHost is how this host resolves a name; a variable, for the unit
// tests.
var resolveHost = net.LookupHost

// --- the image target's preconditions (B3) ---

// imageUID is the Go image's user and group (go/image/Dockerfile): migrate's
// image target runs the run's varlatchd as it, to read the configuration
// it derives and the bind paths.
const imageUID = 65532

// toImageForm is migrate's --to-image form (internal/migrate, imageRef):
// a repository, a tag that is the release of the varlatchd migrate runs,
// and the digest.
var toImageForm = regexp.MustCompile(`^([a-z0-9][a-z0-9._/-]*(?::[0-9]+)?/[a-z0-9._/-]+):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@(sha256:[0-9a-f]{64})$`)

// imageUserRelease runs the run's varlatchd --version, by the path migrate
// runs it, as the image's user and group with no supplementary groups, as
// migrate does: the kernel decides whether that user reaches it (modes,
// ACLs, links), and the answer is its release. Within versionProbeTimeout,
// reading at most versionProbeMax bytes of its output. A variable, for the
// unit tests.
var imageUserRelease = func() (string, error) {
	bin := filepath.Join(binDir, "varlatchd")
	ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--version")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: imageUID, Gid: imageUID, Groups: []uint32{}}}
	cmd.WaitDelay = time.Second
	out := &cappedOutput{max: versionProbeMax}
	cmd.Stdout = out
	err := cmd.Run()
	switch {
	case out.over:
		return "", fmt.Errorf("%s --version printed more than %d bytes: not varlatchd's version line", bin, versionProbeMax)
	case err != nil && ctx.Err() != nil:
		return "", fmt.Errorf("%s --version as uid and gid %d, no other groups: no answer within %s", bin, imageUID, versionProbeTimeout)
	case err != nil:
		return "", fmt.Errorf("%s --version as uid and gid %d, no other groups: %v", bin, imageUID, err)
	}
	rel, err := versionRelease(out.b)
	if err != nil {
		return "", fmt.Errorf("%s --version: %v", bin, err)
	}
	return rel, nil
}

// The version probe's limits: varlatchd answers at once with one short
// line.
var (
	versionProbeTimeout = 30 * time.Second
	versionProbeMax     = 4096
)

// cappedOutput keeps at most max bytes of what is written to it and notes
// that there was more; it never blocks the writer.
type cappedOutput struct {
	b    []byte
	max  int
	over bool
}

func (c *cappedOutput) Write(p []byte) (int, error) {
	if room := c.max - len(c.b); len(p) > room {
		c.b, c.over = append(c.b, p[:max(room, 0)]...), true
		return len(p), nil
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

// versionLine is varlatchd --version's whole output (cmd/varlatchd:
// fmt.Fprintln(stdout, server.Name, buildinfo.Version)).
var versionLine = regexp.MustCompile(`^varlatchd ([0-9A-Za-z][0-9A-Za-z.+-]*)\n$`)

// versionRelease is the release in varlatchd's version line, its "v" or
// "V" prefix trimmed; anything else is refused.
func versionRelease(out []byte) (string, error) {
	m := versionLine.FindSubmatch(out)
	if m == nil {
		return "", fmt.Errorf("printed %q, not varlatchd's version line (varlatchd <release>)", out)
	}
	return trimRelease(string(m[1])), nil
}

// trimRelease is a release without its "v" or "V" prefix, as migrate
// compares an image's tag with its varlatchd's (image.go).
func trimRelease(v string) string { return strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V") }

// checkImageTarget refuses, before the owner's first step, what migrate
// would refuse only after it: VL_RH_GO_IMAGE not in --to-image's form or
// not of the run's varlatchd release, and a run's varlatchd the image's
// user cannot run (a VL_RH_ROOT under a home of mode 0750). The value
// refused is not repeated: it may be a registry URL with credentials, and
// the refusal reaches the run's log.
func checkImageTarget(goImage string) error {
	m := toImageForm.FindStringSubmatch(goImage)
	if m == nil {
		return errors.New("VL_RH_GO_IMAGE is not migrate's --to-image form: give repository:<the run's varlatchd release>@sha256:<64 hex digits> (varlatchd --version in the run's bin/ names the release)")
	}
	rel, err := imageUserRelease()
	if err != nil {
		return fmt.Errorf("the image target runs the run's varlatchd as the image's user, which cannot: %v. Set VL_RH_ROOT where uid %d can reach it, outside a home of mode 0750: /srv/vl-rh-runs for example (never /srv/vl-rh, the case's own)", err, imageUID)
	}
	if trimRelease(m[2]) != rel {
		return fmt.Errorf("VL_RH_GO_IMAGE's tag is not the run's varlatchd release, %s: migrate refuses another release, so tag the image %s (go/image/build.sh --version %s, from the run's bin/)", rel, rel, rel)
	}
	return nil
}

// --- real systemd (box): the target as a unit of the run's own ---

func (in *installation) unitName() string { return "varlatchd-rh-" + runID + "-" + in.name }

// installUnit writes the run's unit for the target and reloads systemd.
func (in *installation) installUnit(t *testing.T) {
	t.Helper()
	// The case's environment for the target (service.env: its trust
	// roots), as the workstation's fake systemctl gives it.
	unit := unitFile(runID+", "+in.name, filepath.Join(in.state, "service.env"), filepath.Join(binDir, "varlatchd"), in.conf)
	if prof.memory {
		// Its log in the run's directory, not in the journal.
		log := in.targetLog()
		unit = strings.Replace(unit, "\nRestart=no\n", "\nRestart=no\nLimitCORE=0\nStandardOutput=append:"+log+"\nStandardError=append:"+log+"\n", 1)
	}
	path := filepath.Join("/etc/systemd/system", in.unitName()+".service")
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	must(t, run("", nil, nil, "systemctl", "daemon-reload"), "systemctl daemon-reload")
}

// targetLog is the file the target logs to: the stand-in systemctl's on a
// workstation, the unit's own in memory. On the box it is otherwise in the
// journal.
func (in *installation) targetLog() string { return filepath.Join(in.state, "service.log") }

// unitFile is the run's unit. How it starts and how long it may take to
// stop are the shipped unit's (go/install/varlatchd.service): without them
// systemd waits 90 s before it kills, which rehearsal B2's run b2k did.
func unitFile(what, env, bin, conf string) string {
	return fmt.Sprintf("[Unit]\nDescription=varlatchd (rehearsal %s)\n\n[Service]\nType=exec\nEnvironmentFile=-%s\nExecStart=%s serve --config %s\nRestart=no\nTimeoutStopSec=%s\n\n[Install]\nWantedBy=multi-user.target\n",
		what, env, bin, conf, unitStopTimeout)
}

// unitStopTimeout is the shipped unit's TimeoutStopSec.
const unitStopTimeout = 30 * time.Second

// stopped is one stop of a unit, as systemd's journal has it.
type stopped struct {
	took   time.Duration
	killed bool // systemd's limit passed, and it was killed
}

// The journal's messages about a unit's stop, by systemd's catalog.
const (
	msgStopping = "de5b426a63be47a7b6ac3eaac82e2f6f" // "Stopping ..."
	msgStopped  = "9d1aaa27d60140bd96365438aad20286" // "Stopped ..."
	msgFailed   = "d9b373ed55a64feb8242e02dbe79a49c" // "Failed with result ..." (UNIT_RESULT)
)

// stopsIn reads a unit's stops from journalctl -o json's lines. A stop
// whose end is not there is left out.
func stopsIn(lines string) ([]stopped, error) {
	var out []stopped
	var began int64
	killed := false
	for _, l := range strings.Split(lines, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var e struct {
			ID     string `json:"MESSAGE_ID"`
			At     string `json:"__REALTIME_TIMESTAMP"`
			Result string `json:"UNIT_RESULT"`
		}
		// A message that is not text is an array there: of no interest.
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			return nil, err
		}
		at, _ := strconv.ParseInt(e.At, 10, 64)
		switch e.ID {
		case msgStopping:
			began, killed = at, false
		case msgFailed:
			killed = killed || e.Result == "timeout"
		case msgStopped:
			if began > 0 {
				out = append(out, stopped{took: time.Duration(at-began) * time.Microsecond, killed: killed})
			}
			began = 0
		}
	}
	return out, nil
}

// targetStops are the target's stops so far: from systemd's journal on the
// box, from the stand-in systemctl's log on a workstation.
func (in *installation) targetStops() ([]stopped, error) {
	if !prof.box {
		return fakeStops(filepath.Join(in.state, "stops.log"))
	}
	run("", nil, nil, "journalctl", "--sync")
	r := run("", nil, nil, "journalctl", "-u", in.unitName()+".service", "-o", "json", "--no-pager", "--output-fields=MESSAGE_ID,UNIT_RESULT")
	if r.code != 0 {
		return nil, errors.New(r.String())
	}
	return stopsIn(r.stdout)
}

// recordStops says how long the target took to stop, each time, and that
// none took the unit's whole limit.
func (in *installation) recordStops(t *testing.T, item int, what string) {
	t.Helper()
	stops, err := in.targetStops()
	ok, said := len(stops) > 0 && err == nil, make([]string, 0, len(stops))
	for _, s := range stops {
		l := s.took.Round(time.Millisecond).String()
		if s.killed {
			l += " (killed at systemd's limit)"
		}
		said = append(said, l)
		ok = ok && !s.killed && s.took < unitStopTimeout
	}
	detail := strings.Join(said, ", ")
	if err != nil {
		detail = err.Error()
	}
	measure(fmt.Sprintf("item %d: %s: the target's stop", item, what), detail)
	record(t, item, what+": the target stops by itself within the unit's "+unitStopTimeout.String(), ok, detail)
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

// coolifyFiles are the operator's files of a run on the lab Coolify: the
// source app's secrets (their variables in lines), the operator's backup
// key and destination, and a TMPDIR the image's user can pass through.
type coolifyFiles struct {
	base, secrets, tmp           string
	lines                        []string
	bek, destinations, readCreds string
}

func coolifyFilesFor(t *testing.T, s3 *s3Server, bucket string) coolifyFiles {
	t.Helper()
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
	// does not start); the directories keep everyone else out. The way to
	// them, and TMPDIR, are 0711: migrate runs the run's varlatchd as the
	// image's user (uid 65532), which must reach the configuration migrate
	// derives under TMPDIR and the bind paths under go/, listing nothing.
	// MkdirAll leaves an existing directory's mode, and the umask may
	// narrow a new one, so each is set here.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(base), 0o711}, {base, 0o711}, {tmpDir, 0o711}, {secretsDir, 0o700}, {op, 0o700}} {
		if err := os.Chmod(d.path, d.mode); err != nil {
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
	s3.createBucket(t, bucket)
	destinations, readCreds := filepath.Join(op, "backup-destinations.json"), filepath.Join(op, "read.json")
	s3.writeDestination(t, destinations, bucket, "write.json")
	s3.writeCredentials(t, readCreds)
	return coolifyFiles{base: base, secrets: secretsDir, tmp: tmpDir, lines: lines, bek: bek, destinations: destinations, readCreds: readCreds}
}

// coolifyCase: the source and the 0.50 target are apps the owner creates
// in the lab Coolify; the migration pauses at each step only the owner can
// make (exit 75), the harness then resuming.
func coolifyCase(t *testing.T, rel release, s3 *s3Server) {
	const item = 11
	digests, err := os.ReadFile(filepath.Join(releaseDir, "coolify-image-digests.env"))
	if err != nil {
		t.Fatal(err)
	}
	f := coolifyFilesFor(t, s3, "vl-rh-coolify")
	base, tmpDir, lines, bek, destinations, readCreds := f.base, f.tmp, f.lines, f.bek, f.destinations, f.readCreds
	pause(t, "source-app",
		"In the lab Coolify (never production's), in a throwaway project, create a Docker Compose app from",
		"the 0.23.0 candidate's checkout, Base Directory /infra/compose, Docker Compose Location /docker-compose.coolify.yml,",
		"Preserve Repository on (production's layout: Coolify's docker-compose.yaml beside the repository's docker-compose.yml),",
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
	// The bind paths' directory: the image's user passes through it (0711).
	if err := os.Chmod(target, 0o711); err != nil {
		t.Fatal(err)
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
			out := r.stdout + "\n" + r.stderr
			pause(t, fmt.Sprintf("%s-%d", what, step), "varlatch migrate stopped for your step (exit 75):", redact(lastLines(out, 40)))
			a = append(slices.Clone(args), "--resume")
			if strings.Contains(out, "run varlatch migrate --rollback again") {
				// The route back asked for first: nothing of a reverse is
				// begun, so there is none to resume.
				a = slices.Clone(first)
			}
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
	if os.Getenv("VL_RH_ONLY") == "setup" {
		t.Logf("set up %s in %s (VL_RH_ONLY=setup)", in.project, in.dir)
		return
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
	if r := run("", nil, nil, "systemctl", "stop", in.unitName()+".service"); r.code != 0 {
		record(t, item, "the target is stopped", false, r.String())
	}
	in.recordStops(t, item, "public ingress")
}
