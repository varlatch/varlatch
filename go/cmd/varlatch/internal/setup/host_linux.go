// SPDX-License-Identifier: Apache-2.0

//go:build linux

package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/diskprobe"
)

// SystemHost is the real host: useradd, systemctl, varlatchd at
// Varlatchd. Its environment is the run's, without any credential
// (VARLATCH_TOKEN and the like): setup passes none on, and passes no key.
type SystemHost struct {
	// Varlatchd is varlatchd's path (the one beside varlatch).
	Varlatchd string
	// Env is the environment children run with.
	Env []string
}

func (SystemHost) Path(p string) string { return p }

func (SystemHost) LookupUser(name string) (int, int, bool, error) {
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return 0, 0, false, nil
	}
	if err != nil {
		return 0, 0, false, err
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, false, fmt.Errorf("setup: the user %s has ids %s:%s", name, u.Uid, u.Gid)
	}
	return uid, gid, true, nil
}

func (h SystemHost) CreateUser(name string) error {
	cmd := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name)
	cmd.Env = h.Env
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("setup: useradd %s: %v %s", name, err, oneLine(string(out)))
	}
	return nil
}

// LoginShell is the user's passwd entry's shell, as getent sees it (the
// name service's users too), or /etc/passwd's without getent.
func (h SystemHost) LoginShell(name string) (string, error) {
	cmd := exec.Command("getent", "passwd", name)
	cmd.Env = h.Env
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		out, err = os.ReadFile("/etc/passwd")
	}
	if err != nil {
		return "", fmt.Errorf("setup: reading the user %s's entry: %v", name, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 7 && f[0] == name {
			return strings.TrimSpace(f[6]), nil
		}
	}
	return "", fmt.Errorf("setup: the user %s has no passwd entry", name)
}

// SupplementaryGroups is `id -nG` (every group of the user, the name
// service's too) without `id -gn` (its primary group).
func (h SystemHost) SupplementaryGroups(name string) ([]string, error) {
	run := func(args ...string) (string, error) {
		cmd := exec.Command("id", append(args, "--", name)...)
		cmd.Env = h.Env
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("setup: reading the user %s's groups (id %s): %v", name, strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	all, err := run("-nG")
	if err != nil {
		return nil, err
	}
	primary, err := run("-gn")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range strings.Fields(all) {
		if g != primary && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out, nil
}

// SysUIDMax is /etc/login.defs' SYS_UID_MAX, 999 when it gives none.
func (SystemHost) SysUIDMax() int {
	b, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return 999
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "SYS_UID_MAX" {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 999
}

func (SystemHost) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

func (h SystemHost) Systemctl(args ...string) (string, error) {
	cmd := exec.Command("systemctl", args...)
	cmd.Env = h.Env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (SystemHost) Probe(ctx context.Context, dir string) (diskprobe.Result, error) {
	return diskprobe.Run(ctx, diskprobe.Options{Dir: dir, Unnamed: true})
}

// CheckConfig runs `varlatchd admin config check --config path` with the
// keys' directory as its credentials, as the unit hands them over; what it
// answers for a valid configuration (its facts) is not needed here.
func (h SystemHost) CheckConfig(path string) (string, error) {
	cmd := exec.Command(h.Varlatchd, "admin", "config", "check", "--config", path)
	cmd.Env = append(append([]string{}, h.Env...), "CREDENTIALS_DIRECTORY="+filepath.Dir(RootKEK))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return oneLine(string(out)), nil
	}
	return "", err
}

// Admin runs `varlatchd admin <args> --config /etc/varlatch/varlatchd.conf`,
// with the credentials directory a host command outside the unit needs.
// What it prints (which may hold a one-time link) is returned, never put
// in an error; what it says when it fails is.
func (h SystemHost) Admin(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, h.Varlatchd, append(append([]string{"admin"}, args...), "--config", ConfigFile)...)
	cmd.Env = append(append([]string{}, h.Env...), "CREDENTIALS_DIRECTORY="+filepath.Dir(RootKEK))
	out, said, err := runChild(cmd)
	if err != nil {
		clear(out)
		return nil, fmt.Errorf("setup: varlatchd admin %s: %v %s", args[0], err, oneLine(string(said)))
	}
	return out, nil
}

// runChild runs cmd and returns what it printed and what it said, each
// read whole from its pipe before the wait (as internal/cli's runChild).
func runChild(cmd *exec.Cmd) (answer, said []byte, err error) {
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(errPipe)
		done <- b
	}()
	answer, _ = io.ReadAll(outPipe)
	said = <-done
	return answer, said, cmd.Wait()
}

func (SystemHost) Ready(ctx context.Context, listen string) error {
	host := listen
	if strings.HasPrefix(host, ":") || strings.HasPrefix(host, "0.0.0.0:") {
		host = "127.0.0.1:" + host[strings.LastIndex(host, ":")+1:]
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+host+"/readyz", nil)
		if res, err := client.Do(req); err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// readNoFollow reads a file, never through a symbolic link (O_NOFOLLOW).
func readNoFollow(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s is a symbolic link", path)
		}
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
