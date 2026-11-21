// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/write"
)

// Host commands write through the daemon (feature-parity decision 11).
// The write path's gates are in the daemon's memory (go/server/write), so
// a command that wrote beside a running varlatchd could commit in the
// middle of an effect the daemon holds open. So:
//
//   - serve holds an exclusive lock on varlatchd.lock in the data
//     directory for its whole life (lockDataDir); a second serve, or a
//     serve while an offline command runs, refuses to start;
//   - serve listens on varlatchd.sock in the data directory (mode 0600)
//     and accepts a connection only from its own user or root (the peer's
//     credentials, SO_PEERCRED). A command sent there runs inside the
//     daemon, with its storage engine, its gates and its writer;
//   - `varlatchd admin ...` first tries the socket. If nothing answers, it
//     takes the lock without waiting: with it, it runs the same command
//     offline, in its own process; without it (a varlatchd holds the lock
//     but its socket does not answer) it refuses and writes nothing.

// The data directory's files of this mechanism.
const (
	ControlSocket = "varlatchd.sock"
	LockFile      = "varlatchd.lock"
)

var errLocked = errors.New("the data directory's lock is held")

// maxSocketPath is the longest path a Unix socket address holds on Linux
// (sun_path is 108 bytes, with its terminating NUL).
const maxSocketPath = 107

// controlTimeout bounds one command sent to the socket.
var controlTimeout = 5 * time.Minute

// hostEnv is what a host command runs with: the daemon's, or an offline
// command's own.
type hostEnv struct {
	cfg     *config.Config
	store   *storage.DB
	rootKEK []byte
	gates   *write.Gates
	// admission is the maintenance gate, backups the backup service
	// (backup.go).
	admission *maintenance.Admission
	backups   *backups.Service
	log       *slog.Logger
	// tune adjusts the backup service's options (tests).
	tune func(*backups.Options)
	// tailnet is the tailnet node's pin and report, in a running varlatchd
	// with tailnet = on; nil otherwise.
	tailnet *tailnet.Manager
	// serving is set once the HTTP listener serves, in a running
	// varlatchd; nil offline. admin status reports it.
	serving *atomic.Bool
	// ready is the /readyz checks of a running varlatchd; nil offline.
	ready func(context.Context) (schema, kek, inst bool)
}

type controlRequest struct {
	Args []string `json:"args"`
}

type controlResponse struct {
	Stdout []byte `json:"stdout"`
	Stderr []byte `json:"stderr"`
	Status int    `json:"status"`
}

// controlServer serves host commands on the daemon's socket.
type controlServer struct {
	ln       *net.UnixListener
	env      *hostEnv
	log      *slog.Logger
	inFlight sync.WaitGroup
	// accepting is closed when the accept loop has returned: no handler is
	// registered after it.
	accepting chan struct{}
	// handled, when set (tests), runs as each handler starts.
	handled func()
}

// listenControl opens the socket. The caller holds the data directory's
// lock, so a socket file already there is a dead daemon's, and goes.
func listenControl(env *hostEnv, log *slog.Logger) (*controlServer, error) {
	path := filepath.Join(env.cfg.DataDir, ControlSocket)
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("the socket's path %s is longer than a Unix socket's %d bytes: give varlatchd a data directory with a shorter path", path, maxSocketPath)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// The socket is created under a umask that keeps it the owner's only;
	// the mode is set again after, and the peer check is what decides.
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return &controlServer{ln: ln, env: env, log: log, accepting: make(chan struct{})}, nil
}

// serve accepts commands until the listener closes. Handlers are
// registered only here, on this goroutine, so once it returns no handler
// starts.
func (c *controlServer) serve(ctx context.Context) {
	defer close(c.accepting)
	for {
		conn, err := c.ln.AcceptUnix()
		if err != nil {
			return
		}
		c.inFlight.Add(1)
		go func() {
			defer c.inFlight.Done()
			defer conn.Close()
			if c.handled != nil {
				c.handled()
			}
			c.handle(ctx, conn)
		}()
	}
}

// close stops accepting, waits for the accept loop to return (a connection
// it accepted just before is registered by then), then for every command
// in flight: only then may the database close.
func (c *controlServer) close() {
	_ = c.ln.Close()
	<-c.accepting
	c.inFlight.Wait()
}

func peerAllowed(uid int) bool { return uid == 0 || uid == os.Getuid() }

func (c *controlServer) handle(ctx context.Context, conn *net.UnixConn) {
	uid, ok := peerUID(conn)
	if !ok || !peerAllowed(uid) {
		c.log.Warn("control socket: a connection from another user was refused", "uid", uid)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(controlTimeout))
	var req controlRequest
	if err := json.NewDecoder(io.LimitReader(conn, 2<<20)).Decode(&req); err != nil || len(req.Args) == 0 {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(commandTimeout(req.Args)))
	var stdout, stderr bytes.Buffer
	status := runHost(ctx, c.env, req.Args, &stdout, &stderr)
	_ = json.NewEncoder(conn).Encode(controlResponse{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Status: status})
}

// controlAnswers is whether a varlatchd answers on the data directory dir's
// control socket (its own Unix socket, never a destination): the probe a
// command that must not run beside a running varlatchd makes first.
func controlAnswers(dir string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("unix", filepath.Join(dir, ControlSocket), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// route runs a host command: through the daemon's socket, else offline
// under the lock, else not at all. args[0] is the command.
func route(cfg *config.Config, args []string, stdout, stderr io.Writer) int {
	what := "varlatchd admin " + args[0]
	owner, id, err := checkClientDir(cfg.DataDir, os.Getuid())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v; nothing was sent or written\n", what, err)
		return ExitConfig
	}
	if uc, status := daemonConn(cfg, owner, what, stderr); status != ExitOK {
		return status
	} else if uc != nil {
		return viaSocket(uc, what, args, stdout, stderr)
	}
	// The lock comes first, as the TypeScript admin CLI takes its operator
	// lease before it reads the gate: flock needs varlatchd.lock to exist
	// (an empty file, no state), and a gate read before the lock could
	// change before the command runs (a daemon starting meanwhile).
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		fmt.Fprintf(stderr, "%s: a varlatchd holds the data directory %s, but its control socket does not answer; nothing was written. "+
			"Check that varlatchd is running and ready, then run the command again.\n", what, cfg.DataDir)
		return ExitFailure
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s: cannot lock the data directory %s: %v\n", what, cfg.DataDir, err)
		return ExitFailure
	}
	defer unlock()
	if owner >= 0 {
		if err := sameDir(cfg.DataDir, id); err != nil {
			fmt.Fprintf(stderr, "%s: %v; nothing was written\n", what, err)
			return ExitFailure
		}
	}
	// Offline, nothing opens the database before it is needed: its first
	// use creates the schema and the installation.
	//   - The maintenance commands and backup status work on the data
	//     directory's files only (maintenance.json, backups/*.json).
	//   - Under a gate, a command that writes and a backup run are refused
	//     before the database is opened, as in the daemon.
	if fileOnly(args) {
		env := &hostEnv{cfg: cfg, admission: maintenance.Open(cfg.DataDir, nil), log: slog.New(slog.NewTextHandler(stderr, nil))}
		env.backups = newBackups(env)
		return runHost(context.Background(), env, args, stdout, stderr)
	}
	if maintenance.Open(cfg.DataDir, nil).Isolated() {
		switch {
		case writes(args[0]):
			fmt.Fprintf(stderr, "%s: %s\n", what, MaintenanceRefusal)
			return ExitFailure
		case args[0] == "backup":
			fmt.Fprintf(stderr, "%s %s: %s\n", what, args[1], backups.ErrMaintenance.Error())
			return ExitFailure
		}
	}
	env, status := openOffline(cfg, what, stderr)
	if env == nil {
		return status
	}
	defer env.store.Close()
	return runHost(context.Background(), env, args, stdout, stderr)
}

// daemonConn is a connection to the varlatchd answering on the data
// directory's control socket: nil (ExitOK) when none answers; a refusal,
// printed, when the process there is not the data directory's owner (or
// root), so a socket someone else put there is refused before anything is
// sent.
func daemonConn(cfg *config.Config, owner int, what string, stderr io.Writer) (*net.UnixConn, int) {
	path := filepath.Join(cfg.DataDir, ControlSocket)
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return nil, ExitOK
	}
	uc := conn.(*net.UnixConn)
	if peer, ok := peerUID(uc); !ok || !serverPeerAllowed(peer, owner) {
		_ = uc.Close()
		fmt.Fprintf(stderr, "%s: the process on %s is not the data directory's owner (uid %d) or root; nothing was sent or written\n", what, path, owner)
		return nil, ExitConfig
	}
	return uc, ExitOK
}

// fileOnly reports whether a host command reads and writes only the data
// directory's files, never the database: the maintenance commands and
// backup status.
func fileOnly(args []string) bool {
	return args[0] == "maintenance" || args[0] == "backup" && len(args) > 1 && args[1] == "status"
}

func viaSocket(conn *net.UnixConn, what string, args []string, stdout, stderr io.Writer) int {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(commandTimeout(args)))
	if err := json.NewEncoder(conn).Encode(controlRequest{Args: args}); err != nil {
		fmt.Fprintf(stderr, "%s: the control socket: %v\n", what, err)
		return ExitFailure
	}
	_ = conn.CloseWrite()
	var resp controlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		// Refused (another user), or the daemon stopped meanwhile: whether
		// the command ran is unknown.
		fmt.Fprintf(stderr, "%s: varlatchd's control socket gave no answer (%v); check varlatchd's log before running the command again\n", what, err)
		return ExitFailure
	}
	_, _ = stdout.Write(resp.Stdout)
	_, _ = stderr.Write(resp.Stderr)
	return resp.Status
}
