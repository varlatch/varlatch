// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The image target (go-step7 decision 20's second shape; O2): the Go
// image's service (ghcr.io/varlatch/varlatchd, slice 6.10a), created
// beforehand in setup mode with nothing listening, its data directory a
// bind path on this host (--to-data, mounted at /var/lib/varlatch), its
// keys a directory (--to-keys, mounted at /keys) and its configuration a
// file (--to-config, mounted at /etc/varlatch/varlatchd.conf).
//
// migrate fills the bind path with this host's varlatchd (the same release
// as the image), run as the image's user (uid and gid 65532) so every file
// it writes is the image's, against a configuration derived from the
// service's: its container paths mapped to the host paths. It runs no
// Docker command: starting and stopping the service are the operator's
// (in Coolify, or with Docker), each said exactly, and checked after
// (varlatchd's control socket in the bind path answers while the service
// serves; the public URL answers with the migrated installation).

// ImageUser is the image's user and group (distroless's nonroot).
var ImageUser = Owner{UID: 65532, GID: 65532}

// The image's paths.
const (
	imageData   = "/var/lib/varlatch"
	imageKeys   = "/keys"
	imageConfig = "/etc/varlatch"
)

// Image is the image target: a Host whose varlatchd runs as the image's
// user against the derived configuration, and whose service the operator
// starts and stops.
type Image struct {
	*Host
	// Service names the service, Ref the image it runs (pinned by its
	// digest), for the instructions.
	Service, Ref string
	// DataDir, KeysDir and ServiceConfig are the host paths of the bind
	// mounts.
	DataDir, KeysDir, ServiceConfig string
	// User is the image's user (ImageUser).
	User Owner
}

// leftoverConf is a derived configuration's directory.
var leftoverConf = regexp.MustCompile(`^\.varlatch-migrate-conf-[0-9]+$`)

// StageBase is the directory under the system's temporary directory that
// a migration from source stages in (its bundles, the dry run's scratch
// database, an image's derived configuration): one per source, root's,
// mode 0711 so the image's user reaches the directories given to it, and
// nothing in it but this source's runs' own.
func StageBase(source string) (string, error) {
	sum := sha256.Sum256([]byte(filepath.Clean(source)))
	dir := filepath.Join(os.TempDir(), "varlatch-migrate-"+hex.EncodeToString(sum[:8]))
	if err := os.Mkdir(dir, 0o711); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", dir)
	}
	if uid, _, ok := ownerOf(st); ok && int(uid) != os.Getuid() {
		return "", fmt.Errorf("%s is not this user's: another user made it", dir)
	}
	return dir, os.Chmod(dir, 0o711)
}

// imageRef is a pinned image reference: repository:tag@sha256:<64 hex>.
var imageRef = regexp.MustCompile(`^([a-z0-9][a-z0-9._/-]*(?::[0-9]+)?/[a-z0-9._/-]+):([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@(sha256:[0-9a-f]{64})$`)

// DeriveConfig is the service's configuration for this host's varlatchd:
// each value under the image's data, keys and configuration directories
// mapped to its bind path on this host, data_dir set (the image's default
// otherwise); every other line as it is. A value naming another container
// path of the three settings that read files is refused: this host cannot
// reach it.
func DeriveConfig(text, data, keys, confDir string) (string, error) {
	mapPath := func(v string) (string, bool, error) {
		for _, m := range []struct{ from, to string }{{imageData, data}, {imageKeys, keys}, {imageConfig, confDir}} {
			if v == m.from {
				return m.to, true, nil
			}
			if strings.HasPrefix(v, m.from+"/") {
				// Joined and cleaned, it must stay inside the bind path: a
				// ".." does not lead out of it.
				root := filepath.Clean(m.to)
				mapped := filepath.Join(root, strings.TrimPrefix(v, m.from+"/"))
				if mapped != root && !strings.HasPrefix(mapped, root+"/") {
					return "", false, fmt.Errorf("%s leads out of %s", v, m.from)
				}
				return mapped, true, nil
			}
		}
		return v, false, nil
	}
	var out strings.Builder
	sawData := false
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		key, value, ok := strings.Cut(trimmed, "=")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !ok {
			out.WriteString(line + "\n")
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		mapped, hit, err := mapPath(value)
		if err != nil {
			return "", fmt.Errorf("the service's %s: %v", key, err)
		}
		switch key {
		case "data_dir", "root_kek_file", "backup_key_file":
			if !hit {
				return "", fmt.Errorf("the service's %s is %s, outside the image's %s, %s and %s: this host cannot reach it", key, value, imageData, imageKeys, imageConfig)
			}
		}
		if key == "data_dir" {
			sawData = true
		}
		out.WriteString(key + " = " + mapped + "\n")
	}
	if !sawData {
		out.WriteString("data_dir = " + data + "\n")
	}
	return out.String(), sc.Err()
}

// PrepareImage checks the image target before anything is done, and
// writes the derived configuration (owned by the image's user, for its
// varlatchd to read) into a new directory under tmp; the caller removes
// it. It refuses a reference not pinned by its digest, or whose tag is
// not the release of this host's varlatchd; bind paths that are not
// directories owned by the image's user and closed to others (the exact
// commands to fix them said); a service configuration this host cannot
// map; and, for a new migration (fresh), a service that already serves
// varlatchd on the bind path (it must be in setup mode, nothing
// listening, until the transfer).
func PrepareImage(ctx context.Context, img *Image, tmp string, fresh bool) (cleanup func(), err error) {
	cleanup = func() {}
	m := imageRef.FindStringSubmatch(img.Ref)
	if m == nil {
		return cleanup, fmt.Errorf("--to-image %q is not pinned: give repository:tag@sha256:<digest>, the image the service runs", img.Ref)
	}
	if img.Service == "" {
		return cleanup, errors.New("--to-service names the Go service, for the steps you take")
	}
	for _, d := range []struct{ flag, path string }{{"--to-data", img.DataDir}, {"--to-keys", img.KeysDir}} {
		if err := ownedDir(d.path, img.User); err != nil {
			return cleanup, fmt.Errorf("%s %s: %v. As root: chown %d:%d %s && chmod 0700 %s", d.flag, d.path, err, img.User.UID, img.User.GID, d.path, d.path)
		}
	}
	text, err := os.ReadFile(img.ServiceConfig)
	if err != nil {
		return cleanup, fmt.Errorf("--to-config: %w", err)
	}
	derived, err := DeriveConfig(string(text), img.DataDir, img.KeysDir, filepath.Dir(img.ServiceConfig))
	if err != nil {
		return cleanup, fmt.Errorf("--to-config %s: %w", img.ServiceConfig, err)
	}
	// In this source's own directory (StageBase); what a killed run left
	// there is the engine's to remove, under its lock.
	dir, err := os.MkdirTemp(tmp, ".varlatch-migrate-conf-")
	if err != nil {
		return cleanup, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	conf := filepath.Join(dir, "varlatchd.conf")
	if err := os.WriteFile(conf, []byte(derived), 0o600); err != nil {
		return cleanup, err
	}
	if err := chownAll(img.User, dir, conf); err != nil {
		return cleanup, err
	}
	img.Host.Config = conf
	// The varlatchd here is the image's release.
	info, st, err := img.Host.Describe(ctx)
	if err != nil {
		return cleanup, err
	}
	if fresh && st.Running {
		return cleanup, fmt.Errorf("varlatchd serves on %s already: the service %s must be in setup mode, nothing listening, until migrate asks you to start it", img.DataDir, img.Service)
	}
	if tag := strings.TrimPrefix(strings.TrimPrefix(m[2], "v"), "V"); tag != info.Release {
		return cleanup, fmt.Errorf("--to-image is release %s; this host's varlatchd is %s: install the varlatchd of the image's release (the release's assets)", tag, info.Release)
	}
	return cleanup, nil
}

// ownedDir checks a bind path: a directory (not a link), owned by o,
// writable by no one else.
func ownedDir(path string, o Owner) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("not a directory")
	}
	if uid, gid, ok := ownerOf(st); ok && (uid != o.UID || gid != o.GID) {
		return fmt.Errorf("owned by %d:%d, not the image's user %d:%d", uid, gid, o.UID, o.GID)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by others (mode %o)", st.Mode().Perm())
	}
	return nil
}

// chownAll gives paths to o, unless this process is o already.
func chownAll(o Owner, paths ...string) error {
	if int(o.UID) == os.Getuid() && int(o.GID) == os.Getgid() {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, int(o.UID), int(o.GID)); err != nil {
			return err
		}
	}
	return nil
}

// Start is the operator's: the service started (a HumanStep) unless it
// serves already (varlatchd answers on the bind path's control socket).
func (img *Image) Start(ctx context.Context) error {
	running, err := img.running(ctx)
	if err != nil || running {
		return err
	}
	return &HumanStep{Instruction: fmt.Sprintf("Start the Go service %s (image %s, with %s mounted at %s, %s at %s and %s at %s/varlatchd.conf): "+
		"in Coolify, Deploy it; with Docker Compose, docker compose up -d %s. It starts isolated by the migration's gate.",
		img.Service, img.Ref, img.DataDir, imageData, img.KeysDir, imageKeys, img.ServiceConfig, imageConfig, img.Service)}
}

// Stop is the operator's: the service stopped (a HumanStep) unless it is.
func (img *Image) Stop(ctx context.Context) error {
	running, err := img.running(ctx)
	if err != nil || !running {
		return err
	}
	return &HumanStep{Instruction: fmt.Sprintf("Stop the Go service %s: in Coolify, Stop it; with Docker Compose, docker compose stop %s.", img.Service, img.Service)}
}

// Describe is the host's, of the bind path, named an image target; its
// configuration the service's file (the derived one is this run's only).
func (img *Image) Describe(ctx context.Context) (TargetInfo, TargetState, error) {
	info, st, err := img.Host.Describe(ctx)
	info.Kind, info.Config = "image", img.ServiceConfig
	return info, st, err
}

func (img *Image) running(ctx context.Context) (bool, error) {
	_, st, err := img.Host.Describe(ctx)
	return st.Running, err
}
