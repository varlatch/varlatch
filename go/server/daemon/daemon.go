// SPDX-License-Identifier: AGPL-3.0-or-later

// Package daemon is `varlatchd serve` (ADR-0059 step 3.2): it reads the
// configuration, opens the database with the storage engine, prepares the
// schema and the installation, checks the Root KEK against the
// installation's canary, and serves HTTP until SIGTERM or SIGINT.
package daemon

import (
	"context"
	"crypto/x509"
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
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auditexport"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/capabilities"
	"github.com/varlatch/varlatch/go/server/clientaddr"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/githubapps"
	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/maintenance"
	"github.com/varlatch/varlatch/go/server/orgdeletion"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/publictls"
	"github.com/varlatch/varlatch/go/server/realtime"
	"github.com/varlatch/varlatch/go/server/security"
	"github.com/varlatch/varlatch/go/server/servecli"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/tailnet"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/web"
	"github.com/varlatch/varlatch/go/server/webhooks"
	"github.com/varlatch/varlatch/go/server/write"
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

// hooks are what the benchmark build (the g9a build tag, bench_g9a.go) and
// tests add to serving; a production build has none. Everything else, the
// storage engine's settings included, is the production path's.
type hooks struct {
	// storage adds observers to the engine's options (a checkpoint log),
	// and may set the WAL bound a smoke plan names (or, in a test, a
	// shorter checkpoint period).
	storage func(*storage.Options)
	// prepare runs once the installation is verified, before the listener
	// opens (seeding).
	prepare func(ctx context.Context, store *storage.DB, rootKEK []byte, log *slog.Logger) error
	// wrap wraps the HTTP handler (the run's control routes).
	wrap func(http.Handler) http.Handler
	// stop ends serving, as a signal does.
	stop <-chan struct{}
	// stopped runs once the listener has shut down, before the database
	// closes (the run's last events); closed once the database has closed.
	stopped func()
	closed  func()
	// writer sees the daemon's write path once it exists (tests: an
	// external effect held open inside the daemon).
	writer func(*write.Writer)
	// backups tunes the backup service (tests: a slower sealing pace).
	backups func(*backups.Options)
	// outbound adds to the outbound policy's options before it is made
	// (the g9a build: the fake provider's certificate among the roots).
	outbound func(*outbound.Options)
	// sync sees the parts a converge engine is made of once they exist
	// (the g9a build drives its own engine's runs, sync = off).
	sync func(writer *write.Writer, approvals *auth.Service, policy *outbound.Policy)
	// beforeSubscribe runs as a dashboard asks for its live updates, admitted.
	beforeSubscribe func()
	// tailnetControl replaces the tailnet node's control server (tests: an
	// in-process one), and tailnetCerts where the browser endpoint's
	// certificate comes from (tests: a test CA, since a real one needs
	// Let's Encrypt).
	tailnetControl string
	tailnetCerts   tailnet.CertSource
	// publicTLS tunes public HTTPS's certificate manager (tests: Pebble's
	// root for its API, a short check interval and backoff), and
	// publicReady receives the HTTPS and plain HTTP listeners' addresses
	// (nil when that listener is off).
	publicTLS   func(*publictls.Options)
	publicReady func(https, http net.Addr)
}

// productionStorage is the storage engine's options for serving: the
// defaults ADR-0059 Decision 2 fixes, and the realtime hub's commit hook.
// The g9a build compares its effective settings with these.
func productionStorage(path string, onCommit func()) storage.Options {
	return storage.Options{Path: path, OnCommit: onCommit}
}

// benchCommand is `varlatchd g9a`, in a build with the g9a tag only
// (bench_g9a.go); nil otherwise.
var benchCommand func(args []string, stderr io.Writer) int

// Bench runs `varlatchd g9a` (ADR-0059 G9a's benchmark build), or refuses in
// a build without it.
func Bench(args []string, stderr io.Writer) int {
	if benchCommand == nil {
		fmt.Fprintln(stderr, "varlatchd g9a: this varlatchd was built without the g9a build tag; the benchmark needs go build -tags g9a ./cmd/varlatchd")
		return 64
	}
	return benchCommand(args, stderr)
}

// observeSettings, when set (tests), receives the storage engine's
// effective settings each time serving opens the database.
var observeSettings func(storage.Settings)

func serve(opts Options, h *hooks) int {
	if h == nil {
		h = &hooks{}
	}
	if h.closed != nil {
		defer h.closed() // after every other deferred call: the database is closed
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
	// Mid-migration, the old installation may still reopen: the new one
	// does not serve until `varlatch migrate` opens it (go-step7 decision 14).
	if err := migrationGate(cfg.DataDir); err != nil {
		return fail(ExitConfig, "varlatchd does not start: "+err.Error())
	}
	// Mid-upgrade, only the start the upgrade itself makes, held.
	configDir := filepath.Dir(opts.ConfigPath)
	upgrading, err := upgradeStart(configDir, buildinfo.Version)
	if err != nil {
		return fail(ExitConfig, "varlatchd does not start: "+err.Error())
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
	// No key in the environment (lib/keyenv): checked before anything is
	// opened, against the Root KEK and, when one is configured, the BEK.
	keys := []keyenv.Key{{What: keyenv.RootKEK, Bytes: rootKEK}}
	if cfg.BackupKeyFile != "" {
		if raw, err := os.ReadFile(cfg.BackupKeyFile); err == nil {
			if bek, err := backup.ParseKey(string(raw)); err == nil {
				keys = append(keys, keyenv.Key{What: keyenv.BEK, Bytes: bek})
				defer clear(bek)
			}
			clear(raw)
		}
	}
	if why := keyenv.Refusal(os.Environ(), keys...); why != "" {
		return fail(ExitConfig, why)
	}
	if st, err := os.Stat(cfg.DataDir); err != nil || !st.IsDir() {
		return fail(ExitFailure, "the data directory is not there", "dir", cfg.DataDir, "error", err)
	}
	// It holds the control socket and the lock: only this user may change
	// its entries (datadir_unix.go).
	dataDirID, err := checkServeDir(cfg.DataDir, os.Getuid())
	if err != nil {
		return fail(ExitConfig, "the data directory is not safe for the control socket and the lock file; fix its owner or mode and start varlatchd again", "error", err)
	}
	// One running owner of the data directory (feature-parity decision
	// 11): held until serve returns, after the database closed.
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return fail(ExitFailure, "another varlatchd, or a varlatchd admin command running offline, holds this data directory's lock; refusing to start",
			"dir", cfg.DataDir, "lock", LockFile)
	}
	if err != nil {
		return fail(ExitFailure, "cannot lock the data directory", "dir", cfg.DataDir, "error", err)
	}
	defer unlock()
	if err := sameDir(cfg.DataDir, dataDirID); err != nil {
		return fail(ExitFailure, "the data directory changed while varlatchd took its lock", "error", err)
	}

	// Before SQLite is first used: without a place for its temporary files
	// the first larger write would fail, in a varlatchd that looks healthy.
	temp, err := storage.PrepareTemp(cfg.DataDir)
	if err != nil {
		return fail(ExitFailure, "varlatchd does not start: "+err.Error())
	}
	log.Info("SQLite's temporary files", "dir", temp)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The dashboard's live updates: woken by every commit (ADR-0059
	// Decision 4). The hub is made once the database is open; commits
	// before that have nobody to tell.
	var live atomic.Pointer[realtime.Hub]
	sopts := productionStorage(cfg.DatabasePath(), func() {
		if hub := live.Load(); hub != nil {
			hub.Notify()
		}
	})
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
	// The engine's effective settings, as it read them back from each
	// connection (ADR-0059 Decision 2): the durability pragmas, the WAL
	// bound, the batch size and the checkpoint period.
	settings := store.Settings()
	if b, err := json.Marshal(settings); err == nil {
		log.Info("storage settings", "settings", string(b))
	}
	// A conformance build warns when its host override is on.
	if conformanceWarnings != nil {
		conformanceWarnings(log)
	}
	if observeSettings != nil {
		observeSettings(settings)
	}
	// A restore that did not complete left its gate (or the gate cannot be
	// read): the database may be the restore's, half done. varlatchd
	// serves isolated, 503 MAINTENANCE, and touches nothing in it: no
	// schema, no installation, no canary check, until the restore is run
	// again (server/backups Restore).
	var inst installation
	if g, err := backup.ReadGate(cfg.DataDir); err != nil || g != nil && g.Kind == "restore" {
		log.Warn("a restore has not completed: varlatchd answers 503 MAINTENANCE and leaves the database as it is; run varlatchd admin backup restore again", "file", filepath.Join(cfg.DataDir, backup.GateFile))
	} else {
		if _, err := db.Init(ctx, store, buildinfo.Version); err != nil {
			return fail(ExitFailure, "the database cannot be used", "file", cfg.DatabasePath(), "error", err)
		}
		var created bool
		inst, created, err = ensureInstallation(ctx, store, rootKEK)
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
	}
	if h.prepare != nil && inst.ID != "" {
		if err := h.prepare(ctx, store, rootKEK, log); err != nil {
			return fail(ExitFailure, "preparing the run", "error", err)
		}
	}
	// The write path's gates, shared by requests and host commands
	// (go/server/write); host commands arrive on the control socket, open
	// before the listener so a command run once /readyz answers finds it.
	gates := write.NewGates()
	// The maintenance admission (a gate left open holds across a restart)
	// and the backup service, shared by requests, host commands and the
	// schedule.
	admission := maintenance.Open(cfg.DataDir, nil)
	if g, err := admission.Gate(); err != nil {
		log.Error("the maintenance gate cannot be read; varlatchd answers 503 MAINTENANCE until it is repaired", "file", filepath.Join(cfg.DataDir, backup.GateFile), "error", err)
	} else if g != nil {
		log.Warn("installation maintenance is active; varlatchd answers 503 MAINTENANCE until it ends", "kind", g.Kind, "lease", g.ID)
	}
	if upgrading {
		admission.HoldForUpgrade()
		log.Warn("an upgrade is checking this varlatchd: it answers 503 MAINTENANCE and does nothing else until the upgrade is over; when none runs any more, sudo varlatch upgrade finishes or undoes it")
		go endUpgradeHold(ctx, configDir, admission, log)
	}
	// A restore's hold (backup.Hold): the workers that deliver or destroy
	// (below, admission.EnterWork) wait until the host operator resumes.
	if admission.Held() {
		log.Warn("the installation was restored from an archive and is held: its background work (sync, webhooks, audit export, organization deletion) does not run until varlatchd admin restore resume", "file", filepath.Join(cfg.DataDir, backup.HoldFile))
	}
	// Public HTTPS (step 6's decision 4), when listen_https is set: the
	// certificate manager first, so the listeners report can show it.
	var public *publictls.Manager
	if p := cfg.PublicHTTPS; p != nil {
		popts := publictls.Options{
			Host: p.Host, CA: p.CA, Email: p.Email, DataDir: cfg.DataDir,
			TLSPort: publictls.PortOf(p.Listen), HTTPPort: publictls.PortOf(p.RedirectListen), Log: log,
			// The issuance count, in the database: it survives a backup and
			// a restore (step 6 decision 16).
			Issuances: publictls.StoreIssuances{DB: store}, IssuanceLimit: publictls.LimitFor(p.CA),
		}
		popts.ListenHost, _, _ = net.SplitHostPort(p.Listen)
		if p.CARootFile != "" {
			pem, err := os.ReadFile(p.CARootFile)
			if err != nil {
				return fail(ExitFailure, "cannot read acme_ca_root", "file", p.CARootFile, "error", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return fail(ExitConfig, "acme_ca_root holds no PEM certificate", "file", p.CARootFile)
			}
			popts.CARoots = roots
		}
		if h.publicTLS != nil {
			h.publicTLS(&popts)
		}
		public, err = publictls.New(popts)
		if err != nil {
			return fail(ExitFailure, "public HTTPS", "error", err)
		}
		defer public.Close()
	}
	capRepair := &capabilities.Repair{}
	env := &hostEnv{cfg: cfg, store: store, rootKEK: rootKEK, gates: gates, admission: admission, capabilityRepair: capRepair, log: log, tune: h.backups, public: public,
		serving: &atomic.Bool{}, ready: (&backend{store: store, rootKEK: rootKEK}).Ready,
		// Host commands are served before the hub is made.
		endStreams: func() {
			if hub := live.Load(); hub != nil {
				hub.EndStreams()
			}
		}}
	env.backups = newBackups(env)
	// The tailnet listener (step 4.13b), when tailnet = on: its node starts
	// now and joins its tailnet in the background; the ordinary listener
	// reports what it observes (GET /v1/installation/listeners).
	var tn *tailnetRunner
	if cfg.Tailnet != nil {
		var err error
		controlURL := cfg.Tailnet.ControlURL
		switch {
		case h.tailnetControl != "":
			controlURL = h.tailnetControl
		case testTailnetControl != "":
			// A crashpoint build's G5 gate only (tailnethook_crashpoint.go).
			controlURL = testTailnetControl
		}
		if tn, err = startTailnet(cfg, controlURL, h.tailnetCerts, log); err != nil {
			return fail(ExitFailure, "cannot start the tailnet node", "error", err)
		}
		env.tailnet = tn.manager
		env.node = tn
		// A start that fails after this point leaves the tailnet too.
		defer tn.stop(context.Background())
	}
	control, err := listenControl(env, log)
	if err != nil {
		return fail(ExitFailure, "cannot open the control socket in the data directory", "socket", ControlSocket, "error", err)
	}
	go control.serve(ctx)
	defer control.close()
	if err := sameDir(cfg.DataDir, dataDirID); err != nil {
		return fail(ExitFailure, "the data directory changed while varlatchd opened its control socket", "error", err)
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

	hub := realtime.New(realtime.Options{Store: store, Log: log, BeforeSubscribe: h.beforeSubscribe})
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
	approvals := auth.New(store, auth.Options{PublicURL: cfg.PublicURL, Log: log, RootKEK: rootKEK, PersonGate: gates.PersonGate})
	readPath := values.New(store, rootKEK, values.Options{Log: log, Approvals: approvals, Gates: gates, Admit: admission.Enter})
	defer readPath.Settled()
	writer := &write.Writer{Store: store, Gates: gates}
	if h.writer != nil {
		h.writer(writer)
	}
	// The Security Control report summary (feature-parity decision 10):
	// every minute, each hour's report counts become audit events once the
	// hour has been over for 10 minutes. A stop ends it before the
	// database closes.
	reportDone := make(chan struct{})
	go func() {
		defer close(reportDone)
		security.RunLoop(ctx, writer, security.SummaryInterval, time.Now, log, admission.Enter)
	}()
	defer func() { cancel(); <-reportDone }()
	// Scheduled backups (backup_interval). A stop ends a run in progress,
	// which removes its temporary files, before the database closes.
	backupDone := make(chan struct{})
	go func() {
		defer close(backupDone)
		env.backups.Loop(ctx)
	}()
	defer func() { cancel(); <-backupDone }()
	// The outbound policy (ADR-0057), from outbound_allow (validated by
	// config.Parse).
	allow, err := outbound.ParseAllow(cfg.OutboundAllow)
	if err != nil {
		return fail(ExitConfig, "outbound_allow", "error", err)
	}
	policyOptions := outbound.Options{Log: log}
	if h.outbound != nil {
		h.outbound(&policyOptions)
	}
	policy := outbound.New(allow, policyOptions)
	defer policy.Close()
	if h.sync != nil {
		h.sync(writer, approvals, policy)
	}
	// Webhook delivery (feature-parity decision 10): a pass at once, then
	// every 30 seconds, through the outbound policy. A stop ends it before
	// the policy and the database close; an attempt cut short is not
	// recorded, and the next start sends it again.
	webhookDone := make(chan struct{})
	go func() {
		defer close(webhookDone)
		hooks := &webhooks.Service{Writer: writer, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Log: log}
		hooks.RunLoop(ctx, webhooks.Interval, admission.EnterWork)
	}()
	defer func() { cancel(); <-webhookDone }()
	// The converge engine (ADR-0031, ADR-0050; feature-parity decision 7),
	// when the host left sync on: a pass at once, then every 30 seconds,
	// each Target under its lease, through the outbound policy. A stop ends
	// it before the policy and the database close; a run cut short keeps
	// its lease until it expires, as a crash would.
	if cfg.Sync {
		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			engine := &syncs.Service{Writer: writer, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Adapters: cfg.SyncAdapters, Log: log}
			engine.RunLoop(ctx, syncs.SyncInterval, admission.EnterWork)
		}()
		defer func() { cancel(); <-syncDone }()
	} else {
		log.Info("sync targets disabled by sync = off (CLI mode remains available)")
	}
	// The audit export worker (ADR-0056 Decisions 2 and 3), when the host
	// left the export on: a pass at once, then every minute, each export
	// under its lease and its gate, through the outbound policy. A stop
	// ends it before the policy and the database close; an upload cut
	// short is not recorded, and its plan is sent again.
	if cfg.AuditExport {
		exportDone := make(chan struct{})
		go func() {
			defer close(exportDone)
			worker := &auditexport.Service{Writer: writer, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Now: time.Now, Enabled: true, Log: log}
			worker.RunLoop(ctx, auditexport.Interval, admission.EnterWork)
		}()
		defer func() { cancel(); <-exportDone }()
	}
	// Organization deletions that are due (ADR-0051 Decision 6), in every
	// serving varlatchd: a pass at once, then every minute, inside the
	// maintenance admission; each pass also ends audit export drains past
	// their deadline, whatever audit_export says. A stop ends it before the
	// policy and the database close; a deletion cut short rolls back and
	// runs again at the next start.
	deletionDone := make(chan struct{})
	go func() {
		defer close(deletionDone)
		drains := &auditexport.Service{Writer: writer, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Now: time.Now, Log: log}
		deletions := &orgdeletion.Service{Writer: writer, Approvals: approvals, Drains: drains, Now: time.Now, Log: log}
		deletions.RunLoop(ctx, orgdeletion.Interval, admission.EnterWork)
	}()
	defer func() { cancel(); <-deletionDone }()
	// The GitHub App registration sweep (ADR-0054 amendment D): a pass at
	// once, then every minute, inside the maintenance admission; pending
	// conversions past their hour lose their key.
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		apps := &githubapps.Service{Writer: writer, Approvals: approvals, RootKEK: rootKEK, Policy: policy, Now: time.Now, Log: log}
		apps.RunSweepLoop(ctx, githubapps.SweepInterval, admission.EnterWork)
	}()
	defer func() { cancel(); <-sweepDone }()
	// A passkey's relying party is the public URL's host, and browsers
	// refuse an IP address as one: the dashboard cannot sign in there.
	if u := cfg.PublicURL; u != nil && net.ParseIP(u.Hostname()) != nil {
		log.Warn("public_url names an IP address, which browsers refuse as a passkey's relying party: the dashboard cannot sign in at it. Use a host name, such as http://localhost:8686 on this machine", "publicUrl", u.String())
	}
	hopts := httpserver.Options{
		Outbound:        policy,
		Version:         buildinfo.Version,
		ReleaseCheckDir: cfg.DataDir,
		PublicURL:       cfg.PublicURL,
		Sync:            cfg.Sync,
		AuditExportOff:  !cfg.AuditExport,
		SyncAdapters:    cfg.SyncAdapters,
		TrustedProxies:  trusts,
		AccessLog:       httpserver.NewAccessLog(accessOut),
		Web:             web.FS(),
		Backend:         &backend{store: store, rootKEK: rootKEK},
		Auth:            approvals,
		Realtime:        hub,
		Values:          readPath,
		Writer:          writer,
		RootKEK:         rootKEK,
		Maintenance:     admission,
		Held:            admission.Held,
		Capabilities:    capRepair,
		Backups:         env.backups,
		Log:             log,
	}
	if public != nil {
		hopts.PublicListener = func() any { return public.Report() }
	}
	if cfg.ServeCLI {
		// serve_cli (ADR-0058 Decision 3; go/server/servecli): this
		// release's CLI and installers, from github.com through the
		// outbound policy, verified before anything is cached or served.
		o := servecli.Options{
			Version:  buildinfo.Version,
			Origin:   cfg.PublicURL.Scheme + "://" + cfg.PublicURL.Host,
			CacheDir: filepath.Join(cfg.DataDir, "cli"),
			Source: servecli.GitHub(release.Downloader{
				Hosts: release.GitHubHosts, Transport: policy.Transport(outbound.GitHub), UserAgent: "varlatchd/" + buildinfo.Version,
			}, buildinfo.Version),
			Trusted: func(ctx context.Context) (root.TrustedMaterial, error) {
				return release.LiveTrustedRootWith(ctx, filepath.Join(cfg.DataDir, "sigstore"), policy.Client(outbound.GitHub))
			},
		}
		if conformanceCLIRelease != nil {
			conformanceCLIRelease(&o, log)
		}
		served := servecli.Start(ctx, o, log)
		hopts.CLI = func() http.Handler {
			if r := served.Current(); r != nil {
				return r
			}
			return nil
		}
	}
	if tn != nil {
		hopts.TailnetListeners = tn.manager.Report
		if tn.cert != nil {
			hopts.BrowserEndpoint = tn.manager.BrowserEndpoint
		}
	}
	handler, err := httpserver.New(hopts)
	if err != nil {
		return fail(ExitFailure, "building the HTTP handler", "error", err)
	}
	var tailnetHandler, browserHandler http.Handler
	if tn != nil {
		// The same API, without the dashboard, the browser session, the
		// live updates, the public URL or proxies: every request is a
		// tailnet peer's, resolved from its connection.
		topts := hopts
		topts.PublicURL, topts.TrustedProxies, topts.Web, topts.Realtime = nil, nil, nil, nil
		topts.Tailnet = &httpserver.TailnetListener{Resolve: tn.resolver.Resolve, Admit: tn.manager.Admit}
		th, err := httpserver.New(topts)
		if err != nil {
			return fail(ExitFailure, "building the tailnet listener's HTTP handler", "error", err)
		}
		tailnetHandler = th
		if b := tn.browserEndpoint(); b != nil {
			// The browser endpoint (ADR-0046): the same device check, over
			// HTTPS, for the allowlisted dashboard origins.
			topts.Tailnet = &httpserver.TailnetListener{Resolve: tn.resolver.Resolve, Admit: tn.manager.Admit, Browser: b}
			bh, err := httpserver.New(topts)
			if err != nil {
				return fail(ExitFailure, "building the browser endpoint's HTTP handler", "error", err)
			}
			browserHandler = bh
		}
	}
	if _, ok := web.Embedded(); !ok {
		log.Warn("this varlatchd was built without the dashboard; it serves a placeholder page (go generate ./server/web)")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fail(ExitFailure, "cannot listen", "address", cfg.Listen, "error", err)
	}
	var root http.Handler = handler
	if h.wrap != nil {
		root = h.wrap(handler)
	}
	srv := &http.Server{
		Handler:           root,
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
	env.serving.Store(true)
	log.Info("varlatchd is serving", "version", buildinfo.Version, "address", ln.Addr().String(), "installationId", inst.ID)
	// Capabilities wait for the repair of what earlier releases'
	// retirements left live (capabilities.Repair): 503 MAINTENANCE until it
	// has run, inside the maintenance admission. It starts once the
	// listener serves, in bounded write jobs, so it never holds the start;
	// then every two seconds while it has not run: behind a gate, an
	// upgrade's hold or after a failure. A gate makes it run again.
	repairDone := make(chan struct{})
	go func() {
		defer close(repairDone)
		capRepair.Loop(ctx, 2*time.Second, writer, admission.Enter, admission.Isolated, time.Now, log)
	}()
	defer func() { cancel(); <-repairDone }()
	var publicServers []*http.Server
	publicDone := make(chan struct{})
	if public != nil {
		servers, err := servePublic(cfg, public, root, log, served, h)
		if err != nil {
			_ = srv.Close()
			return fail(ExitFailure, "cannot listen", "error", err)
		}
		publicServers = servers
		go func() {
			defer close(publicDone)
			public.Run(ctx)
		}()
	} else {
		close(publicDone)
	}
	if tn != nil {
		go tn.serve(ctx, tailnetHandler, browserHandler)
	}
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
	case <-h.stop:
		log.Info("stopping", "reason", "the run ended")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), StopTimeout)
	defer stopCancel()
	for _, ps := range publicServers {
		go func() { _ = ps.Shutdown(stopCtx) }()
	}
	if err := srv.Shutdown(stopCtx); err != nil {
		log.Warn("requests still in flight at the stop deadline were cut off", "error", err)
		_ = srv.Close()
	}
	for _, ps := range publicServers {
		if err := ps.Shutdown(stopCtx); err != nil {
			_ = ps.Close()
		}
	}
	if h.stopped != nil {
		h.stopped()
	}
	cancel()
	<-publicDone
	if tn != nil {
		tn.stop(stopCtx)
		<-tn.done
	}
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
