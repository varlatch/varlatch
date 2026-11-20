// SPDX-License-Identifier: Apache-2.0

//go:build unix

package migrate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The service's configuration, its container paths mapped to the bind
// paths; a file setting elsewhere refused.
func TestDeriveConfig(t *testing.T) {
	conf := "# the service's\nlisten = 0.0.0.0:8686\npublic_url = https://vault.example.test\nroot_kek_file = /keys/root-kek\n" +
		"backup_key_file = /keys/backup-key\naccess_log = /var/lib/varlatch/access.log\nbackup_destinations_file = /etc/varlatch/destinations.json\n"
	got, err := DeriveConfig(conf, "/srv/data", "/srv/keys", "/srv/conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen = 0.0.0.0:8686\n", "public_url = https://vault.example.test\n", "root_kek_file = /srv/keys/root-kek\n",
		"backup_key_file = /srv/keys/backup-key\n", "access_log = /srv/data/access.log\n", "backup_destinations_file = /srv/conf/destinations.json\n",
		"data_dir = /srv/data\n", "# the service's\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if _, err := DeriveConfig("root_kek_file = /run/secrets/kek\n", "/d", "/k", "/c"); err == nil || !strings.Contains(err.Error(), "this host cannot reach it") {
		t.Errorf("a key elsewhere: %v", err)
	}
	for _, out := range []string{"data_dir = /var/lib/varlatch/../elsewhere\nroot_kek_file = /keys/k\n", "root_kek_file = /keys/../../etc/shadow\n",
		"access_log = /var/lib/varlatch/a/../../x\nroot_kek_file = /keys/k\n"} {
		if _, err := DeriveConfig(out, "/srv/data", "/srv/keys", "/srv/conf"); err == nil || !strings.Contains(err.Error(), "leads out of") {
			t.Errorf("%q: %v", out, err)
		}
	}
	if got, err := DeriveConfig("data_dir = /var/lib/varlatch/./db/..\nroot_kek_file = /keys/k\n", "/srv/data", "/srv/keys", "/srv/conf"); err != nil || !strings.Contains(got, "data_dir = /srv/data\n") {
		t.Errorf("a path that stays: %q %v", got, err)
	}
	if got, _ := DeriveConfig("data_dir = /var/lib/varlatch\nroot_kek_file = /keys/k\n", "/d", "/k", "/c"); strings.Count(got, "data_dir") != 1 {
		t.Errorf("data_dir twice: %s", got)
	}
}

// What PrepareImage refuses, and what it writes.
func TestPrepareImage(t *testing.T) {
	me := Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	dirs := func() (string, string, string) {
		root := t.TempDir()
		data, keys, confDir := filepath.Join(root, "data"), filepath.Join(root, "keys"), filepath.Join(root, "conf")
		for _, d := range []string{data, keys, confDir} {
			_ = os.Mkdir(d, 0o700)
		}
		_ = os.WriteFile(filepath.Join(confDir, "varlatchd.conf"), []byte("root_kek_file = /keys/root-kek\npublic_url = https://vault.example.test\n"), 0o644)
		return data, keys, filepath.Join(confDir, "varlatchd.conf")
	}
	digest := "sha256:" + hexOf(randomBytes(32))
	state := func(running bool) Ran {
		return Ran{Answer: []byte(fmt.Sprintf(`{"journal":null,"database":false,"dataDir":"/x","release":"0.50.0","publicUrl":"https://vault.example.test",`+
			`"listen":"127.0.0.1:8686","listenHttps":"","migrationGate":false,"running":%v}`, running))}
	}
	for _, c := range []struct {
		name    string
		ref     string
		user    Owner
		running bool
		mode    os.FileMode
		why     string
	}{
		{"not pinned", "ghcr.io/varlatch/varlatchd:0.50.0", me, false, 0o700, "is not pinned"},
		{"another release", "ghcr.io/varlatch/varlatchd:0.50.1@" + digest, me, false, 0o700, "is release 0.50.1; this host's varlatchd is 0.50.0"},
		{"another owner", "ghcr.io/varlatch/varlatchd:0.50.0@" + digest, Owner{UID: me.UID + 1, GID: me.GID}, false, 0o700, "chown"},
		{"writable by others", "ghcr.io/varlatch/varlatchd:0.50.0@" + digest, me, false, 0o777, "writable by others"},
		{"a service that serves", "ghcr.io/varlatch/varlatchd:0.50.0@" + digest, me, true, 0o700, "must be in setup mode"},
		{"ready", "ghcr.io/varlatch/varlatchd:0.50.0@" + digest, me, false, 0o700, ""},
		{"ready, a V tag", "ghcr.io/varlatch/varlatchd:V0.50.0@" + digest, me, false, 0o700, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			data, keys, conf := dirs()
			_ = os.Chmod(data, c.mode)
			run := &scripted{t: t, answers: map[string]Ran{"/usr/bin/varlatchd admin migrate state": state(c.running)}}
			img := &Image{Host: &Host{Varlatchd: "/usr/bin/varlatchd", Run: run}, Service: "varlatch-go", Ref: c.ref, DataDir: data, KeysDir: keys, ServiceConfig: conf, User: c.user}
			cleanup, err := PrepareImage(context.Background(), img, t.TempDir(), true)
			defer cleanup()
			if c.why == "" {
				b, rerr := os.ReadFile(img.Host.Config)
				if err != nil || rerr != nil || !strings.Contains(string(b), "root_kek_file = "+filepath.Join(keys, "root-kek")) || !strings.Contains(string(b), "data_dir = "+data) {
					t.Fatalf("%v %v %s", err, rerr, b)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("%v, want %q", err, c.why)
			}
		})
	}
}

// The image's service through the engine: one stop for the operator's
// steps (start the service, move the domain), --resume until both are
// done, then switched and opened live (no stop or start). An abort while
// the service runs waits for it to be stopped, and is resumed as an undo.
func TestTheImagesSteps(t *testing.T) {
	w := newWorld(t)
	w.eng.Options.Ingress, w.eng.Options.TransferTimeout = Coolify, 4*time.Second
	w.tgt.human = true
	j, err := w.eng.Run(context.Background(), false)
	said := strings.Join(w.said, "\n")
	if !errors.Is(err, ErrAwaitingOperator) || j.Phase != Transfer || !strings.Contains(said, "step 1: Start the Go service") || !strings.Contains(said, "step 2: in Coolify, move the domain") {
		t.Fatalf("the stop: %+v %v\n%s", j, err, said)
	}
	// Not started yet: the same stop again.
	if _, err := w.eng.Resume(context.Background()); !errors.Is(err, ErrAwaitingOperator) {
		t.Fatalf("a resume before the start: %v", err)
	}
	w.tgt.running, w.prober.moved = true, true
	if j, err = w.eng.Resume(context.Background()); err != nil || j.Phase != Open || w.tgt.gate || !w.tgt.running {
		t.Fatalf("the resume: %+v %v", j, err)
	}
	for _, c := range w.tgt.calls {
		if c == "journal open" {
			t.Fatal("an image's open went through the offline journal, not the live open")
		}
	}

	w = newWorld(t)
	w.eng.Options.Ingress = Coolify
	w.tgt.human = true
	if _, err := w.eng.Run(context.Background(), false); !errors.Is(err, ErrAwaitingOperator) {
		t.Fatal(err)
	}
	w.tgt.running = true
	j, err = w.eng.Abort(context.Background())
	if err == nil || !strings.Contains(err.Error(), "undoing did not finish") || !j.Undoing || !strings.Contains(strings.Join(w.said, "\n"), "To undo, by hand: Stop the Go service") {
		t.Fatalf("an abort while the service runs: %+v %v", j, err)
	}
	w.tgt.running = false
	if j, err = w.eng.Resume(context.Background()); j.Phase != Released || err == nil || !strings.Contains(err.Error(), "reopened unchanged") {
		t.Fatalf("the resumed undo: %+v %v", j, err)
	}
}

// End to end, with this checkout's varlatchd over bind paths on this host,
// as the image's service would have them: the keys written, the journal
// into transfer (the gate), varlatchd started on the derived configuration
// (standing in for the service) answering /v1/meta only, the switch
// written beside it, and the live open through its control socket.
func TestTheImageTargetEndToEnd(t *testing.T) {
	imageEndToEnd(t, Owner{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())})
}

// The same as root, dropping to the image's user (65532) as on a host:
// runAs and chownAll for real. CI's container runs it as root.
func TestTheImageTargetEndToEndAsTheImagesUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("drops to the image's user from root only")
	}
	imageEndToEnd(t, ImageUser)
}

func imageEndToEnd(t *testing.T, user Owner) {
	if testing.Short() {
		t.Skip("builds varlatchd")
	}
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	// A base the image's user reaches (0711), the binary and the bind
	// paths in it, as on a host.
	base, err := os.MkdirTemp("", "varlatch-image-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "varlatchd")
	build := exec.Command("go", "build", "-o", bin, "./cmd/varlatchd")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	stage := filepath.Join(base, "stage")
	if err := os.Mkdir(stage, 0o711); err != nil {
		t.Fatal(err)
	}
	data, keys, confDir := filepath.Join(base, "data"), filepath.Join(base, "keys"), filepath.Join(base, "conf")
	for _, d := range []string{data, keys, confDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := chownAll(user, data, keys); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	conf := filepath.Join(confDir, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte("listen = "+addr+"\npublic_url = http://"+addr+"\ndata_dir = /var/lib/varlatch\nroot_kek_file = /keys/root-kek\n"+
		"backup_key_file = /keys/backup-key\nbackup_interval = off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	img := &Image{Host: &Host{Varlatchd: bin, Run: ExecRunner{As: &user}}, Service: "varlatch-go", Ref: "ghcr.io/varlatch/varlatchd:dev@sha256:" + hexOf(randomBytes(32)),
		DataDir: data, KeysDir: keys, ServiceConfig: conf, User: user}
	ctx := context.Background()
	cleanup, err := PrepareImage(ctx, img, stage, true)
	defer cleanup()
	if err != nil && !strings.Contains(err.Error(), "is release dev") {
		t.Fatal(err)
	}
	info, st, err := img.Describe(ctx)
	if err != nil || info.Kind != "image" || info.DataDir != data || st.Running || st.Database {
		t.Fatalf("describe: %+v %+v %v", info, st, err)
	}
	kek, bek := []byte(hexOf(randomBytes(32))+"\n"), []byte(hexOf(randomBytes(32))+"\n")
	if k, b, err := img.Keys(ctx, kek, bek); err != nil || k != "written" || b != "written" {
		t.Fatalf("keys: %s %s %v", k, b, err)
	}
	if got, _ := os.ReadFile(filepath.Join(keys, "root-kek")); string(got) != string(kek) {
		t.Fatal("the Root KEK file in the keys bind path")
	}
	// Every file written in the bind paths is the image's user's.
	for _, d := range []string{data, keys} {
		_ = filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			fi, _ := e.Info()
			if uid, gid, ok := ownerOf(fi); ok && (uid != user.UID || gid != user.GID) {
				t.Errorf("%s is %d:%d, not the image's user's", p, uid, gid)
			}
			return nil
		})
	}
	j := &Journal{Format: 1, ID: "mig_dddddddddddddddddddddddddd", History: []Step{}}
	for _, p := range []Phase{Started, Transfer} {
		j.enter(p, time.Now())
		if err := img.WriteJournal(ctx, j); err != nil {
			t.Fatalf("journal %s: %v", p, err)
		}
	}
	if err := img.Start(ctx); err == nil || !strings.Contains(err.Error(), "Start the Go service varlatch-go") {
		t.Fatalf("start before the service runs: %v", err)
	}
	// The operator starts the service: here, varlatchd on the derived
	// configuration.
	svc := exec.Command(bin, "serve", "--config", img.Host.Config)
	if err := runAs(svc, user); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Process.Kill(); _ = svc.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, st, err := img.Describe(ctx); err == nil && st.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in service did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := img.Start(ctx); err != nil {
		t.Fatalf("start once it runs: %v", err)
	}
	id, version, err := HTTPProber{}.Probe(ctx, "http://"+addr)
	if err != nil || version == "" {
		t.Fatalf("/v1/meta under the gate: %s %s %v", id, version, err)
	}
	if res, err := http.Get("http://" + addr + "/v1/whoami"); err != nil || res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/v1/whoami under the gate: %v %v", res, err)
	}
	j.enter(Switched, time.Now())
	if err := img.WriteJournal(ctx, j); err != nil {
		t.Fatalf("the switch beside the service: %v", err)
	}
	if err := img.OpenLive(ctx, j.ID); err != nil {
		t.Fatalf("the live open: %v", err)
	}
	if res, err := http.Get("http://" + addr + "/v1/whoami"); err != nil || res.StatusCode == http.StatusServiceUnavailable {
		t.Fatalf("/v1/whoami after the live open: %v %v", res, err)
	}
	if _, st, err := img.Describe(ctx); err != nil || st.Gate || st.Journal == nil || st.Journal.Phase != Open {
		t.Fatalf("after the open: %+v %v", st, err)
	}
	if err := img.Stop(ctx); err == nil || !strings.Contains(err.Error(), "Stop the Go service") {
		t.Fatalf("stop while it runs: %v", err)
	}
}
