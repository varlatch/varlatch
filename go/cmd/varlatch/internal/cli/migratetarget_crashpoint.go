// SPDX-License-Identifier: Apache-2.0

//go:build crashpoint

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/setup"
	"github.com/varlatch/varlatch/go/lib/diskprobe"
)

// G5's seam, in the crashpoint build only (never a release): with
// VARLATCH_MIGRATE_TARGET_ROOT, the target is made under that directory
// instead of /, by this user, its varlatch user a record in a file there
// (no useradd, no chown, as a test may not change the host's accounts);
// systemctl and varlatchd are this host's (the test's stand-ins on PATH).
func targetHost(varlatchd string, env []string) (setup.Host, bool) {
	root := os.Getenv("VARLATCH_MIGRATE_TARGET_ROOT")
	if root == "" {
		return setup.SystemHost{Varlatchd: varlatchd, Env: env}, false
	}
	return rootedHost{sys: setup.SystemHost{Varlatchd: varlatchd, Env: env}, root: root}, true
}

type rootedHost struct {
	sys  setup.SystemHost
	root string
}

func (h rootedHost) users() string { return filepath.Join(h.root, "users") }

func (h rootedHost) Path(p string) string { return filepath.Join(h.root, p) }
func (h rootedHost) LookupUser(name string) (int, int, bool, error) {
	b, err := os.ReadFile(h.users())
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	return os.Getuid(), os.Getgid(), strings.Contains(string(b), name+"\n"), nil
}
func (h rootedHost) CreateUser(name string) error {
	f, err := os.OpenFile(h.users(), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(name + "\n")
	return err
}
func (h rootedHost) DeleteUser(name string) error {
	b, err := os.ReadFile(h.users())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.WriteFile(h.users(), []byte(strings.ReplaceAll(string(b), name+"\n", "")), 0o600)
}
func (rootedHost) LoginShell(string) (string, error)            { return "/usr/sbin/nologin", nil }
func (rootedHost) SupplementaryGroups(string) ([]string, error) { return nil, nil }
func (rootedHost) SysUIDMax() int                               { return 1 << 30 }
func (rootedHost) Chown(string, int, int) error                 { return nil }
func (rootedHost) ChownFile(*os.File, int, int) error           { return nil }

func (h rootedHost) Owner(path string) (int, int, error)      { return h.sys.Owner(path) }
func (h rootedHost) Systemctl(args ...string) (string, error) { return h.sys.Systemctl(args...) }
func (h rootedHost) SystemctlStdout(args ...string) (string, error) {
	return h.sys.SystemctlStdout(args...)
}

// LookupGroup: the test root keeps no groups.
func (rootedHost) LookupGroup(string) (bool, error) { return false, nil }
func (rootedHost) Probe(context.Context, string) (diskprobe.Result, error) {
	return diskprobe.Result{}, errors.New("no probe under a test root")
}
func (h rootedHost) CheckConfig(path string) (string, error) {
	cmd := exec.Command(h.sys.Varlatchd, "admin", "config", "check", "--config", path)
	cmd.Env = append(append([]string{}, h.sys.Env...), "CREDENTIALS_DIRECTORY="+h.Path(setup.EtcDir))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return strings.TrimSpace(string(out)), nil
	}
	return "", err
}
func (rootedHost) Ready(context.Context, string) error {
	return errors.New("no readiness under a test root")
}

// Admin: making a target runs no varlatchd admin command of setup's (its
// configuration is checked by CheckConfig), so none runs under a test root.
func (rootedHost) Admin(context.Context, ...string) ([]byte, error) {
	return nil, errors.New("no varlatchd admin under a test root")
}
