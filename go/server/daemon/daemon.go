// SPDX-License-Identifier: AGPL-3.0-or-later

// Package daemon is `varlatchd serve` (ADR-0059 step 3.2): it reads the
// configuration, opens the database with the storage engine, prepares the
// schema and the installation, checks the Root KEK against the
// installation's canary, and serves HTTP until SIGTERM or SIGINT.
package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/clientaddr"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/web"
)

// Exit statuses of `varlatchd serve`.
const (
	// ExitOK: stopped by SIGTERM or SIGINT, cleanly.
	ExitOK = 0
	// ExitFailure: anything a retry may fix (the disk, the database, the
	// network, a busy port); the unit restarts varlatchd.
	ExitFailure = 1
	// ExitConfig: a configuration error no retry can fix (EX_CONFIG): an
	// unparsable configuration file, an unknown or repeated setting, an
	// invalid value, missing or unparsable Root KEK material, and a Root KEK
	// that does not open this installation's canary (the installation was
	// read; the key is not its key). Never a failure to read the disk or the
	// database, or anything on DNS or the network: those may pass. The unit
	// has RestartPreventExitStatus=78, so systemd does not restart it.
	ExitConfig = 78
)

// StopTimeout is how long a stop waits for requests in flight, within the
// unit's TimeoutStopSec (30 s), leaving time for the writer to commit.
const StopTimeout = 20 * time.Second

// How long a client may take, so a slow or stalled one cannot hold a
// connection open: the request line and headers (10 s), the whole request
// including its body (300 s, Node.js's requestTimeout, which bounded the
// TypeScript server), and an idle keep-alive connection between requests.
// A handler that streams a long response (server-sent events) clears its own
// read deadline. Variables so tests can shorten them.
var (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 300 * time.Second
	idleTimeout       = 120 * time.Second
)

// Options are what Serve needs besides the configuration file.
type Options struct {
	ConfigPath string
	Stderr     io.Writer
	// Ready, if set, receives the listener's address once it accepts
	// connections (tests).
	Ready func(addr net.Addr)
	// Signals, if set, replaces SIGTERM and SIGINT (tests).
	Signals <-chan os.Signal
}

// Serve runs the server and returns its exit status.
func Serve(opts Options) int { return serve(opts, nil) }

// hooks are what tests add to serving; a production build has none.
type hooks struct {
	// storage adds to the engine's options (a checkpoint log, a shorter
	// checkpoint period in a test).
	storage func(*storage.Options)
}

func serve(opts Options, h *hooks) int {
	if h == nil {
		h = &hooks{}
	}
	log := slog.New(slog.NewTextHandler(opts.Stderr, nil))
	fail := func(status int, msg string, args ...any) int {
		log.Error(msg, args...)
		return status
	}
	// A core dump or ptrace by another process of the same user would see
	// the Root KEK.
	if err := disableDumps(); err != nil {
		return fail(ExitFailure, "could not set PR_SET_DUMPABLE to 0", "error", err)
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		var cerr *config.Error
		if errors.As(err, &cerr) {
			return fail(ExitConfig, "the configuration file is not valid; fix it and start varlatchd again", "file", opts.ConfigPath, "error", err)
		}
		return fail(ExitFailure, "cannot read the configuration file", "file", opts.ConfigPath, "error", err)
	}
	material, err := os.ReadFile(cfg.RootKEKFile)
	if err != nil {
		return fail(ExitFailure, "cannot read the Root KEK file", "file", cfg.RootKEKFile, "error", err)
	}
	rootKEK, err := envelope.ParseRootKEK(string(material))
	clear(material)
	if err != nil {
		return fail(ExitConfig, "the Root KEK file does not hold a Root KEK", "file", cfg.RootKEKFile, "error", err)
	}
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		return fail(ExitFailure, "the data directory is not there", "dir", cfg.DataDir, "error", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The dashboard's live updates: woken by every commit (ADR-0059
	// Decision 4). The hub is made once the database is open; commits
	// before that have nobody to tell.
	var live atomic.Pointer[realtime.Hub]
	sopts := storage.Options{Path: cfg.DatabasePath(), OnCommit: func() {
		if hub := live.Load(); hub != nil {
			hub.Notify()
		}
	}}
	if h.storage != nil {
		h.storage(&sopts)
	}
	store, err := storage.Open(ctx, sopts)
	if err != nil {
		return fail(ExitFailure, "cannot open the database", "file", cfg.DatabasePath(), "error", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			log.Error("closing the database", "error", err)
		}
	}()
	if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
		return fail(ExitFailure, "the database cannot be used", "file", cfg.DatabasePath(), "error", err)
	}
	inst, created, err := ensureInstallation(ctx, store, rootKEK)
	if err != nil {
		return fail(ExitFailure, "cannot prepare the installation", "error", err)
	}
	if created {
		log.Info("installation initialized", "installationId", inst.ID)
	}
	if !verify(rootKEK, inst) {
		// The installation was read and the key is not its key: restarting
		// cannot change that, only configuring the right Root KEK can.
		return fail(ExitConfig, "the configured Root KEK does not open this installation's canary; refusing to start with a wrong key (ADR-0019): configure this installation's Root KEK and start varlatchd again")
	}

	var trusts func(string) bool
	if cfg.TrustedProxies != "" {
		tp, err := clientaddr.NewTrustedProxies(cfg.TrustedProxies, nil, log, nil)
		if err != nil {
			return fail(ExitConfig, "trusted_proxies", "error", err)
		}
		tp.Start(ctx, 10*time.Second)
		trusts = tp.Trusts
	}
	var accessOut io.Writer
	switch cfg.AccessLog {
	case "off":
	case "stdout":
		accessOut = os.Stdout
	default:
		f, err := os.OpenFile(cfg.AccessLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return fail(ExitFailure, "cannot open the access log", "file", cfg.AccessLog, "error", err)
		}
		defer f.Close()
		accessOut = f
	}

	hub := realtime.New(realtime.Options{Store: store, Log: log})
	live.Store(hub)
	hubDone := make(chan struct{})
	go func() {
		defer close(hubDone)
		if err := hub.Run(ctx); err != nil {
			log.Error("realtime: the publisher stopped; live updates are unavailable until varlatchd restarts", "error", err)
		}
	}()
	defer func() { cancel(); <-hubDone }()
	// The read path of values (ADR-0059 step 3.6). Its report counts run
	// after their responses: a stop waits for them before the database
	// closes.
	readPath := values.New(store, rootKEK, values.Options{Log: log})
	defer readPath.Settled()
	handler, err := httpserver.New(httpserver.Options{
		Version:        buildinfo.Version,
		PublicURL:      cfg.PublicURL,
		Sync:           cfg.Sync,
		SyncAdapters:   cfg.SyncAdapters,
		TrustedProxies: trusts,
		AccessLog:      httpserver.NewAccessLog(accessOut),
		Web:            web.FS(),
		Backend:        &backend{store: store, rootKEK: rootKEK},
		Auth:           auth.New(store, auth.Options{PublicURL: cfg.PublicURL, Log: log, RootKEK: rootKEK}),
		Realtime:       hub,
		Values:         readPath,
		Log:            log,
	})
	if err != nil {
		return fail(ExitFailure, "building the HTTP handler", "error", err)
	}
	if _, ok := web.Embedded(); !ok {
		log.Warn("this varlatchd was built without the dashboard; it serves a placeholder page (go generate ./server/web)")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(ExitFailure, "cannot listen", "address", cfg.Listen, "error", err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		ConnContext:       httpserver.ConnContext,
	}
	// Shutdown waits for requests to finish, and an event stream does not
	// by itself: the hub ends every stream first.
	srv.RegisterOnShutdown(hub.Close)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("varlatchd is serving", "version", buildinfo.Version, "address", ln.Addr().String(), "installationId", inst.ID)
	if opts.Ready != nil {
		opts.Ready(ln.Addr())
	}

	signals := opts.Signals
	if signals == nil {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(ch)
		signals = ch
	}
	select {
	case err := <-served:
		return fail(ExitFailure, "the listener stopped", "error", err)
	case sig := <-signals:
		log.Info("stopping", "signal", sig.String())
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), StopTimeout)
	defer stopCancel()
	if err := srv.Shutdown(stopCtx); err != nil {
		log.Warn("requests still in flight at the stop deadline were cut off", "error", err)
		_ = srv.Close()
	}
	cancel()
	log.Info("stopped")
	return ExitOK
}

type installation struct {
	ID     string
	Canary envelope.Envelope
}

// ensureInstallation returns the installation, creating it with its KEK
// canary and its installation.initialized audit event on first start, in
// one write job, as the TypeScript server's ensureInstallation does.
func ensureInstallation(ctx context.Context, store *storage.DB, rootKEK []byte) (installation, bool, error) {
	var inst installation
	created := false
	err := store.Write(ctx, func(tx *storage.Tx) error {
		created = false
		q := query.New(tx)
		row, err := q.GetInstallation(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			id := ids.New(ids.Installation)
			canary, err := envelope.NewCanary(rootKEK, id)
			if err != nil {
				return err
			}
			b, err := json.Marshal(canary)
			if err != nil {
				return err
			}
			if err := q.CreateInstallation(ctx, query.CreateInstallationParams{ID: id, KekCanary: string(b)}); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Type:     "installation.initialized",
				Decision: audit.Info,
				Metadata: jsvalue.Object{{Key: "installationId", Value: id}},
			}); err != nil {
				return err
			}
			inst, created = installation{ID: id, Canary: canary}, true
			return nil
		}
		if err != nil {
			return err
		}
		inst = installation{ID: row.ID}
		if err := json.Unmarshal([]byte(row.KekCanary), &inst.Canary); err != nil {
			return fmt.Errorf("the installation's canary is not an envelope: %w", err)
		}
		return nil
	})
	return inst, created, err
}

func verify(rootKEK []byte, inst installation) bool {
	return envelope.VerifyCanary(rootKEK, inst.Canary, inst.ID)
}

// NewBackend is the HTTP layer's Backend serve uses: the installation and
// readiness, read from store (the read path's parity tests use it).
func NewBackend(store *storage.DB, rootKEK []byte) httpserver.Backend {
	return &backend{store: store, rootKEK: rootKEK}
}

// backend answers the HTTP layer's reads.
type backend struct {
	store   *storage.DB
	rootKEK []byte
}

func (b *backend) InstallationID(ctx context.Context) (string, error) {
	row, err := query.New(b.store.Reader()).GetInstallation(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return row.ID, err
}

// Ready checks, as the TypeScript server's /readyz: the schema version is
// this build's, the loaded Root KEK opens the canary, the installation
// exists.
func (b *backend) Ready(ctx context.Context) (schema, kek, inst bool) {
	q := query.New(b.store.Reader())
	if v, err := q.GetSchemaVersion(ctx); err == nil {
		schema = v.Version == db.SchemaVersion || (v.Version > db.SchemaVersion && v.CompatibleFrom <= db.SchemaVersion)
	}
	row, err := q.GetInstallation(ctx)
	if err != nil {
		return schema, false, false
	}
	var canary envelope.Envelope
	if json.Unmarshal([]byte(row.KekCanary), &canary) == nil {
		kek = envelope.VerifyCanary(b.rootKEK, canary, row.ID)
	}
	return schema, kek, true
}
