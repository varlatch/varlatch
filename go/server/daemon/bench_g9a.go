// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package daemon

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/bench/g9a"
	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/outbound"
	"github.com/varlatch/varlatch/go/server/stages"
	"github.com/varlatch/varlatch/go/server/syncs"
	"github.com/varlatch/varlatch/go/server/values"
	"github.com/varlatch/varlatch/go/server/write"
)

// The G9a build (ADR-0059 step 3.6, varlatchd-core decisions 6 and 7):
//
//	varlatchd g9a -plan <plan.json> -data <dir> -out <dir> [-listen <addr>]
//
// serves a G9a run with the production serve path: the same storage
// engine, settings, HTTP layer and read path of values, on a fresh
// installation. What this build adds is workload drivers and
// instrumentation only (the Apache harness's runner, go/bench/g9a):
//
//   - the W1 seed in the production tables: 5,000 secret versions (20
//     environments of 125 Secrets, two versions each), 50 identities (30
//     people, members with an Organization Grant, and 20 service
//     identities with a Grant on one environment each, every one with a
//     credential), 20 Sync Targets on 4 Platform Connections;
//   - converge runs on the real engine (server/syncs) against a Coolify
//     instance the run starts (benchCoolify), once a period, each after
//     changing values in every Target's environment;
//   - the plan's backups, real ones (server/backups: the paced snapshot
//     on this server's own storage instance, the paced sealing, the
//     archive's check and local retention), and the event log: every
//     checkpoint, the WAL,
//     memory and CPU samples, fsync under load;
//   - /run/plan, /run/manifest, /run/start and /run/stop, outside /v1 and
//     outside the request window and the access log.
//
// The load (k6) asks for disclosures, POST …/disclosures, from 20 loopback
// source addresses, one identity's credential each, with the production
// request window in force. Built only with the g9a build tag: a release
// has none of this. The binary reports its storage engine's effective
// settings and whether they are the production build's (system.json).

func init() { benchCommand = runBench }

// BenchAddresses are the load's source addresses: 127.0.0.2 to 127.0.0.21.
var BenchAddresses = func() []string {
	out := make([]string, 20)
	for i := range out {
		out[i] = fmt.Sprintf("127.0.0.%d", i+2)
	}
	return out
}()

const (
	benchProjects     = 4
	benchEnvsPer      = 5 // 20 environments, one Sync Target each
	benchSecretsPer   = 125
	benchPeople       = 30
	benchServices     = 20
	benchKeyFormat    = "SECRET_%03d"
	benchOrgSlug      = "g9a"
	benchSecretLength = 48
)

func runBench(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("varlatchd g9a", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planPath := fs.String("plan", "", "the run's plan (g9a plan)")
	data := fs.String("data", "", "the data directory: its disk is the one measured; it must hold no database")
	out := fs.String("out", "", "the output directory for the run's files")
	listen := fs.String("listen", "127.0.0.1:8080", "the address the load connects to")
	profile := fs.Int("profile", 0, "seconds of CPU profile to take from the load's start (POST /run/start), into cpu.pprof in the output directory (0: none)")
	var dest benchDestination
	fs.StringVar(&dest.File, "backup-destinations", "", "a destinations file (absolute): the plan's backups upload to its destination named by -backup-destination, as backup_destinations_file sets it")
	fs.StringVar(&dest.Name, "backup-destination", "", "the destination in -backup-destinations the backups upload to")
	if err := fs.Parse(args); err != nil || *planPath == "" || *data == "" || *out == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: varlatchd g9a -plan <plan.json> -data <dir> -out <dir> [-listen <addr>] [-profile <s>] [-backup-destinations <file> -backup-destination <name>]")
		return 64
	}
	if (dest.File == "") != (dest.Name == "") {
		fmt.Fprintln(stderr, "varlatchd g9a: -backup-destinations and -backup-destination go together")
		return 64
	}
	if dest.File != "" {
		// The destination must be in the file, before anything is seeded:
		// a run that names one never falls back to local archives.
		if !filepath.IsAbs(dest.File) {
			fmt.Fprintf(stderr, "varlatchd g9a: -backup-destinations: %s is not an absolute path\n", dest.File)
			return 64
		}
		if _, err := backup.ReadDestination(dest.File, dest.Name); err != nil {
			fmt.Fprintf(stderr, "varlatchd g9a: -backup-destination %s: %v\n", dest.Name, err)
			return ExitConfig
		}
	}
	p, err := g9a.ReadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd g9a: %v\n", err)
		return ExitConfig
	}
	if *profile < 0 || *profile > 3600 {
		fmt.Fprintln(stderr, "varlatchd g9a: -profile: 0 to 3600 seconds")
		return 64
	}
	coolify, err := startBenchCoolify(benchProjects * benchEnvsPer)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd g9a: the Coolify instance: %v\n", err)
		return ExitFailure
	}
	defer coolify.close()
	conf, err := benchInstallation(*data, *out, *listen, coolify.Port(), dest)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd g9a: %v\n", err)
		return ExitFailure
	}
	return benchServe(Options{ConfigPath: conf, Stderr: stderr}, p, *data, *out, time.Duration(*profile)*time.Second, coolify)
}

// benchDestination is where the run's backups upload (ADR-0059 amendment
// 6: G9's backups are the shipped backup path, writing to an S3-compatible
// server on the same host): a destinations file and the name of one of its
// destinations, as varlatchd.conf's backup_destinations_file and
// backup_destination. Empty, the archives stay in the data directory.
type benchDestination struct{ File, Name string }

// benchInstallation makes a fresh installation for the run: a Root KEK in
// the data directory, and varlatchd.conf in the output directory (kept
// with the report), with the access log there too.
func benchInstallation(data, out, listen string, coolifyPort int, dest benchDestination) (string, error) {
	for _, d := range []string{data, out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
	}
	if _, err := os.Stat(filepath.Join(data, config.DatabaseFile)); err == nil {
		return "", fmt.Errorf("%s holds a database: every run starts from a fresh one", data)
	}
	kekFile := filepath.Join(data, "root-kek")
	if err := os.WriteFile(kekFile, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		return "", err
	}
	// The plan's backups are real ones, sealed with a key of their own;
	// the run drives them, so the schedule is off. The run drives the
	// converge engine's passes too, so its own loop is off (sync = off),
	// and outbound_allow opens the run's Coolify instance on loopback.
	bekFile := filepath.Join(data, "backup-key")
	if err := os.WriteFile(bekFile, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		return "", err
	}
	conf := filepath.Join(out, g9a.FileConfig)
	text := fmt.Sprintf("# Written by varlatchd g9a for one run.\nlisten = %s\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\nbackup_key_file = %s\nbackup_interval = off\nbackup_keep = 2\nsync = off\noutbound_allow = 127.0.0.1/32:%d\n",
		listen, data, kekFile, filepath.Join(out, g9a.FileAccessLog), bekFile, coolifyPort)
	if dest.File != "" {
		// Each backup then uploads its archive, and a failed upload fails
		// the backup (backups.Service.Run returns the upload's error).
		text += fmt.Sprintf("backup_destinations_file = %s\nbackup_destination = %s\n", dest.File, dest.Name)
	}
	return conf, os.WriteFile(conf, []byte(text), 0o644)
}

// benchServe serves the run: serve with the run's hooks.
func benchServe(opts Options, p g9a.Plan, data, out string, profile time.Duration, coolify *benchCoolify) int {
	log := slog.New(slog.NewTextHandler(opts.Stderr, nil))
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "varlatchd g9a: %v\n", err)
		return ExitConfig
	}
	t := &benchTarget{plan: p, cfg: cfg, log: log, coolify: coolify}
	runner, err := g9a.NewRunner(g9a.RunnerOptions{DataDir: data, OutDir: out, Plan: p, Target: t,
		Logf: func(format string, args ...any) { log.Info(fmt.Sprintf(format, args...)) }})
	if err != nil {
		fmt.Fprintf(opts.Stderr, "varlatchd g9a: %v\n", err)
		return ExitFailure
	}
	hist := stages.NewHistogram()
	// The load's CPU profile: started when the load starts (POST /run/start,
	// which k6 sends once it is initialized), stopped after its length or
	// when the run ends, whichever is first.
	var prof struct {
		sync.Mutex
		f       *os.File
		started bool
		start   time.Time
	}
	stopProfile := func() {
		prof.Lock()
		defer prof.Unlock()
		if prof.f != nil {
			pprof.StopCPUProfile()
			_ = prof.f.Close()
			prof.f = nil
			// When it ran, for the report to set against the load's requests.
			b, _ := json.Marshal(g9a.ProfileSpan{StartUs: prof.start.UnixMicro(), EndUs: time.Now().UnixMicro()})
			if err := os.WriteFile(filepath.Join(out, g9a.FileCPUWindow), append(b, '\n'), 0o644); err != nil {
				log.Error("the CPU profile's window", "error", err)
			}
		}
	}
	startProfile := func() {
		prof.Lock()
		defer prof.Unlock()
		if profile <= 0 || prof.started {
			return
		}
		prof.started = true
		f, err := os.Create(filepath.Join(out, g9a.FileCPUProfile))
		if err == nil {
			if err = pprof.StartCPUProfile(f); err != nil {
				_ = f.Close()
			}
		}
		if err != nil {
			log.Error("the load's CPU profile", "error", err)
			return
		}
		prof.f, prof.start = f, time.Now()
		time.AfterFunc(profile, stopProfile)
		log.Info("CPU profile started", "seconds", profile.Seconds())
	}
	h := &hooks{
		storage: func(o *storage.Options) {
			// The plan's bound: the shipped one for the gate, a small one for
			// a smoke run (recorded, and the report says the plan differs).
			o.WALBound = p.WALBound
			o.OnCheckpoint = runner.OnCheckpoint
		},
		prepare: func(ctx context.Context, store *storage.DB, rootKEK []byte, log *slog.Logger) error {
			t.store, t.rootKEK = store, rootKEK
			t0 := time.Now()
			log.Info("seeding W1", "targets", p.Targets)
			manifest, writes, err := seedW1(ctx, store, rootKEK, p.Targets, coolify.URL(), p.BoundRun())
			if err != nil {
				return fmt.Errorf("seed: %w", err)
			}
			t.writes, t.manifest = writes, manifest
			seeded := time.Since(t0)
			if err := runner.WriteManifest(manifest); err != nil {
				return err
			}
			sys := g9a.System{Target: g9a.TargetVarlatchd, Build: benchBuild(), Settings: store.Settings(), Addresses: BenchAddresses}
			if sys.Production, sys.SettingsNote, err = compareProduction(ctx, data, store.Settings()); err != nil {
				return err
			}
			log.Info("effective storage settings", "production", sys.Production, "note", sys.SettingsNote)
			return runner.Prepare(ctx, sys, seeded)
		},
		wrap: func(next http.Handler) http.Handler {
			control := benchControl(runner.Handler(), hist, startProfile)
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				arrived := time.Now()
				if strings.HasPrefix(r.URL.Path, "/run/") {
					control.ServeHTTP(w, r)
					return
				}
				if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/disclosures") {
					next.ServeHTTP(w, r)
					return
				}
				rec := &statusRecorder{ResponseWriter: w}
				// The disclosure's stages (step 4 decision 7), and whether
				// one of its writes was answered SQLITE_BUSY (Decision 2:
				// never).
				ctx := stages.With(r.Context(), hist, arrived)
				ctx, busy := storage.WithBusyNote(ctx)
				next.ServeHTTP(rec, r.WithContext(ctx))
				stages.Flush(ctx)
				runner.Count(rec.status != http.StatusOK, busy())
			})
		},
		// The engine's provider: the run's Coolify, its certificate
		// trusted by the outbound policy, which still decides every
		// connection (outbound_allow opens its loopback port).
		outbound: func(o *outbound.Options) {
			o.TLS = &tls.Config{RootCAs: coolify.roots, MinVersion: tls.VersionTLS12}
		},
		sync: t.startEngine,
		stop: runner.Done(),
		stopped: func() {
			stopProfile()
			runner.Finish()
			if t.values != nil {
				// The added disclosures' report counts, before the database closes.
				t.values.Settled()
			}
			if err := writeStages(out, hist); err != nil {
				log.Error("the run's stage timings", "error", err)
			}
		},
		closed: func() {
			if err := runner.Close(); err != nil {
				log.Error("the run's event log", "error", err)
			}
		},
	}
	return serve(opts, h)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func benchBuild() g9a.Build {
	b := g9a.Build{Version: buildinfo.Version, Tags: "g9a"}
	if exe, err := os.Executable(); err == nil {
		if f, err := os.Open(exe); err == nil {
			h := sha256.New()
			if _, err := io.Copy(h, f); err == nil {
				b.SHA256 = hex.EncodeToString(h.Sum(nil))
			}
			_ = f.Close()
		}
	}
	return b
}

// compareProduction opens a scratch database with the options a
// production serve builds (productionStorage) and compares its effective
// settings with the run's. The plan's WAL bound may differ (a smoke run);
// anything else makes the run's settings not the production build's.
func compareProduction(ctx context.Context, dir string, got storage.Settings) (bool, string, error) {
	probe, err := os.MkdirTemp(dir, "production-settings-")
	if err != nil {
		return false, "", err
	}
	defer os.RemoveAll(probe)
	store, err := storage.Open(ctx, productionStorage(filepath.Join(probe, config.DatabaseFile), nil))
	if err != nil {
		return false, "", err
	}
	want := store.Settings()
	if err := store.Close(); err != nil {
		return false, "", err
	}
	note := ""
	if got.WALBound != want.WALBound {
		note = fmt.Sprintf("the plan's WAL bound %d bytes (production %d)", got.WALBound, want.WALBound)
		got.WALBound = want.WALBound
	}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		return false, strings.TrimPrefix(note+"; ", "; ") + fmt.Sprintf("this build %s, production %s", g, w), nil
	}
	return true, note, nil
}

// benchTarget is the run's target: this server's storage instance, its
// converge engine and the run's Coolify.
type benchTarget struct {
	plan    g9a.Plan
	cfg     *config.Config
	log     *slog.Logger
	coolify *benchCoolify
	store   *storage.DB
	rootKEK []byte
	running atomic.Bool
	runs    atomic.Int64

	writes    *benchWrites
	writer    *write.Writer
	approvals *auth.Service
	engine    *syncs.Service
	principal *auth.Principal
	setupErr  error

	// A bound run's added writes (Write): the load's identities, the read
	// path of values its disclosures go through, and their principals.
	manifest   []g9a.ManifestEntry
	values     *values.Service
	principals sync.Map // token -> *auth.Principal

	mu        sync.Mutex
	collected []g9a.TargetRun
}

func (t *benchTarget) WALSize() int64 { return t.store.Metrics().WALBytes }

// Backup is a real backup (server/backups, as the schedule runs one): the
// snapshot paced as the plan says, the paced sealing, the archive's check
// and local retention, into the run's data directory.
func (t *benchTarget) Backup(ctx context.Context, _ int, o storage.SnapshotOptions) (g9a.BackupStats, error) {
	res, err := backups.New(backups.Options{Config: t.cfg, Store: t.store, RootKEK: t.rootKEK, Log: t.log, Snapshot: o}).Run(ctx)
	if err == nil && t.cfg.BackupDestinationsFile != "" && res.Delivery == nil {
		// Run returns the upload's error; a backup with a destination and
		// no recorded delivery is a failed one all the same.
		err = fmt.Errorf("the archive %s was not uploaded to %s", res.ArchiveID, t.cfg.BackupDestination)
	}
	st := g9a.BackupStats{Snapshot: res.Snapshot, Seal: time.Duration(res.Capture.DumpMs) * time.Millisecond, ArchiveBytes: res.Bytes}
	if res.Delivery != nil {
		st.UploadedTo = res.Delivery.Destination
	}
	return st, err
}

// seedW1 writes W1 in the production tables, in jobs of the size an
// import would write, and returns the load's manifest: one entry per
// source address, alternately a person's and a service identity's
// credential, each with the Secrets of one environment.
func seedW1(ctx context.Context, store *storage.DB, rootKEK []byte, targets int, coolifyURL string, boundRun bool) ([]g9a.ManifestEntry, *benchWrites, error) {
	if targets != benchProjects*benchEnvsPer {
		return nil, nil, fmt.Errorf("W1 has %d Sync Targets; the plan names %d", benchProjects*benchEnvsPer, targets)
	}
	adapter, err := vsync.GetAdapter("coolify")
	if err != nil {
		return nil, nil, err
	}
	base, err := adapter.CanonicalizeBaseIdentity(coolifyURL)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UnixMicro()
	org := ids.New("org")
	orgKEK, wrapped, err := envelope.WrapOrgKEK(rootKEK, org)
	if err != nil {
		return nil, nil, err
	}
	defer clear(orgKEK)
	w, _ := json.Marshal(wrapped)
	keys := make([]string, benchSecretsPer)
	items := make([]any, benchSecretsPer)
	for i := range keys {
		keys[i] = fmt.Sprintf(benchKeyFormat, i)
		items[i] = map[string]any{"name": keys[i], "type": "string", "required": map[string]any{"kind": "never"}, "sensitive": true}
	}
	contract := map[string]any{"schemaVersion": 1, "semanticsVersion": 3, "items": items}
	contractText, _ := json.Marshal(contract)
	canon, err := envelope.CanonicalJSON(map[string]any{"schemaVersion": 1, "semanticsVersion": 3, "items": items})
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256([]byte(canon))
	contentHash := "sha256:" + hex.EncodeToString(sum[:])

	type env struct{ id, name, project, projectSlug string }
	var envs []env
	var loadEnv env // a bound run's value writes' environment
	people := make([]string, benchPeople)
	services := make([]string, benchServices)
	tokens := map[string]string{}
	exec := func(tx *storage.Tx, q string, args ...any) error {
		_, err := tx.ExecContext(ctx, q, args...)
		return err
	}
	// The Organization, its people and service identities, their
	// credentials, the Projects with their Contracts and environments, the
	// Connections and the Sync Targets.
	err = store.Write(ctx, func(tx *storage.Tx) error {
		envs, tokens = envs[:0], map[string]string{}
		if err := exec(tx, `INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, ?, 'G9a', ?)`, org, benchOrgSlug, string(w)); err != nil {
			return err
		}
		for i := range people {
			id := ids.New(ids.Identity)
			people[i] = id
			if err := exec(tx, `INSERT INTO identities (id, kind, name) VALUES (?, 'human', ?)`, id, fmt.Sprintf("person %d", i)); err != nil {
				return err
			}
			if err := exec(tx, `INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'member')`, org, id); err != nil {
				return err
			}
			issued, err := auth.IssueCredential(ctx, tx, now, auth.Issue{IdentityID: id, Kind: "cli", OrganizationID: &org})
			if err != nil {
				return err
			}
			tokens[id] = issued.Token
		}
		for i := range services {
			id := ids.New(ids.Identity)
			services[i] = id
			if err := exec(tx, `INSERT INTO identities (id, kind, name, organization_id) VALUES (?, 'service', ?, ?)`, id, fmt.Sprintf("service %d", i), org); err != nil {
				return err
			}
			issued, err := auth.IssueCredential(ctx, tx, now, auth.Issue{IdentityID: id, Kind: "service", OrganizationID: &org})
			if err != nil {
				return err
			}
			tokens[id] = issued.Token
		}
		tiers := []string{"development", "staging", "production"}
		for pi := range benchProjects {
			project, slug, rev, conn := ids.New("prj"), fmt.Sprintf("svc-%d", pi), ids.New("rev"), ids.New("pcn")
			if err := exec(tx, `INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES (?, ?, ?, ?, 'git')`, project, org, slug, slug); err != nil {
				return err
			}
			if err := exec(tx, `INSERT INTO contract_revisions (id, project_id, content_hash, contract, created_by) VALUES (?, ?, ?, ?, ?)`, rev, project, contentHash, string(contractText), people[0]); err != nil {
				return err
			}
			if err := exec(tx, `UPDATE projects SET active_contract_revision_id = ? WHERE id = ?`, rev, project); err != nil {
				return err
			}
			// A Coolify Connection to the run's instance (benchCoolify),
			// as createPlatformConnection stores one.
			credential, err := envelope.Seal(orgKEK, []byte("g9a-coolify-token-"+conn), envelope.PlatformCredentialContext(org, conn))
			if err != nil {
				return err
			}
			c, _ := json.Marshal(credential)
			if err := exec(tx, `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES (?, ?, 'coolify', ?, ?, ?)`, conn, org, base, slug, string(c)); err != nil {
				return err
			}
			for ei := range benchEnvsPer {
				e := env{id: ids.New("env"), name: fmt.Sprintf("env-%d", ei), project: project, projectSlug: slug}
				if err := exec(tx, `INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, ?, 'shared', ?)`, e.id, project, e.name, tiers[ei%len(tiers)]); err != nil {
					return err
				}
				// One Coolify application each, every Secret mapped.
				app := benchApp(len(envs))
				dest, err := adapter.CanonicalizeDestination(vsync.Object{{Key: "applicationUuid", Value: app}})
				if err != nil {
					return err
				}
				fields, _ := json.Marshal(map[string]any{"applicationUuid": app})
				if err := exec(tx, `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping, created_by)
					VALUES (?, ?, ?, ?, ?, ?, ?, '{"kind":"wildcard"}', ?)`, ids.New("snt"), org, project, e.id, conn, string(fields),
					vsync.CanonicalDestinationIdentity("coolify", base, dest.Key), people[0]); err != nil {
					return err
				}
				envs = append(envs, e)
			}
		}
		// A bound run's value writes go to an environment of their own, in
		// a Project with the same Contract and no Connection or Sync
		// Target, so the converge runs' work does not change.
		if boundRun {
			project, slug, rev := ids.New("prj"), "write-load", ids.New("rev")
			if err := exec(tx, `INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES (?, ?, ?, ?, 'git')`, project, org, slug, slug); err != nil {
				return err
			}
			if err := exec(tx, `INSERT INTO contract_revisions (id, project_id, content_hash, contract, created_by) VALUES (?, ?, ?, ?, ?)`, rev, project, contentHash, string(contractText), people[0]); err != nil {
				return err
			}
			if err := exec(tx, `UPDATE projects SET active_contract_revision_id = ? WHERE id = ?`, rev, project); err != nil {
				return err
			}
			loadEnv = env{id: ids.New("env"), name: "env-0", project: project, projectSlug: slug}
			if err := exec(tx, `INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, ?, 'shared', 'development')`, loadEnv.id, project, loadEnv.name); err != nil {
				return err
			}
		}
		// Each person reveals the Organization's Secrets through a Grant
		// (the member role alone does not reveal a production tier's).
		for _, person := range people {
			if err := exec(tx, `INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions, created_by) VALUES (?, ?, ?, '{"kind":"organization"}', '["config.metadata.read","config.value.read","secret.reveal"]', ?)`,
				ids.New("grt"), org, person, people[0]); err != nil {
				return err
			}
		}
		// Service identity i reveals its own environment's Secrets.
		for i, s := range services {
			scope, _ := json.Marshal(map[string]any{"kind": "environments", "projectId": envs[i].project,
				"selector": map[string]any{"kind": "environments", "environmentIds": []string{envs[i].id}}})
			if err := exec(tx, `INSERT INTO grants (id, organization_id, subject_identity_id, scope, actions, created_by) VALUES (?, ?, ?, ?, '["config.metadata.read","config.value.read","secret.reveal"]', ?)`,
				ids.New("grt"), org, s, string(scope), people[0]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	// The values: two versions of each Secret, one environment per job.
	valued := envs
	if boundRun {
		valued = append(slices.Clone(envs), loadEnv)
	}
	for _, e := range valued {
		err := store.Write(ctx, func(tx *storage.Tx) error {
			for _, key := range keys {
				value, previous, current := ids.New("val"), ids.New("ver"), ids.New("ver")
				if err := exec(tx, `INSERT INTO env_values (id, environment_id, item_name) VALUES (?, ?, ?)`, value, e.id, key); err != nil {
					return err
				}
				for _, v := range []struct{ id, prev string }{{previous, ""}, {current, previous}} {
					sealed, err := values.SealValue(orgKEK, org, value, v.id, []byte(benchSecret(v.id)))
					if err != nil {
						return err
					}
					pl, _ := json.Marshal(sealed.Payload)
					dk, _ := json.Marshal(sealed.WrappedDEK)
					var prev any
					if v.prev != "" {
						prev = v.prev
					}
					if err := exec(tx, `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, previous_version_id, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
						v.id, value, string(pl), string(dk), prev, people[0]); err != nil {
						return err
					}
				}
				if err := exec(tx, `UPDATE env_values SET current_version_id = ? WHERE id = ?`, current, value); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	manifest := make([]g9a.ManifestEntry, len(BenchAddresses))
	for i, addr := range BenchAddresses {
		// Alternately a person (any environment, as a member) and a service
		// identity (its own environment).
		var identity string
		e := envs[i%len(envs)]
		if i%2 == 0 {
			identity = people[i/2]
		} else {
			identity = services[i]
			e = envs[i]
		}
		manifest[i] = g9a.ManifestEntry{Address: addr, Identity: identity, Token: tokens[identity], Org: benchOrgSlug,
			Project: e.projectSlug, Env: e.name, Keys: keys}
	}
	writes := &benchWrites{token: tokens[people[0]], org: org, keys: keys}
	for _, e := range envs {
		writes.envs = append(writes.envs, benchEnv{project: e.project, id: e.id})
	}
	if boundRun {
		writes.load = &benchEnv{project: loadEnv.project, id: loadEnv.id}
	}
	return manifest, writes, nil
}

// benchSecret is a Secret's value: 48 characters from its version's id.
func benchSecret(version string) string {
	sum := sha256.Sum256([]byte(version))
	return hex.EncodeToString(sum[:])[:benchSecretLength]
}

// The converge runs (feature-parity decision 7, 4.9d): the real engine
// (server/syncs) against benchCoolify, through the outbound policy. Each
// run first changes ChangesPerRun values in every Target's environment as
// a person's write does (values.SetValue: a new version and its
// value.written event), then runs one engine pass (RunOnce) as the sync
// loop would: its trigger scan marks the Targets those events name, and
// each Target's run writes its changed values to its application, a
// provider call each, every call waiting the plan's provider delay. The
// engine reports each Target's run (OnRun): its commits one by one, their
// time queued for the writer and in their jobs, and the WAL bytes their
// batches wrote (this build's storage counts them).

// benchWrites is what a run needs to change values: the writer's
// credential (a person of the seed), its Organization, the environments
// and the Secrets' names.
type benchWrites struct {
	token, org string
	keys       []string
	envs       []benchEnv
	// load is a bound run's value writes' environment (nil otherwise).
	load *benchEnv
}

type benchEnv struct{ project, id string }

// startEngine is the run's engine, on the daemon's write path, approvals
// and outbound policy (hooks.sync), and its first pass with no provider
// delay: it writes every Target's values to its application, the
// platforms' state the load starts from, untimed.
func (t *benchTarget) startEngine(w *write.Writer, approvals *auth.Service, policy *outbound.Policy) {
	t.writer, t.approvals = w, approvals
	if t.plan.BoundRun() {
		t.values = values.New(t.store, t.rootKEK, values.Options{Log: t.log, Approvals: approvals})
	}
	t.engine = &syncs.Service{Writer: w, Approvals: approvals, RootKEK: t.rootKEK, Policy: policy, Log: t.log, OnRun: t.onRun}
	t.coolify.setDelay(0)
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	t.engine.RunOnce(ctx, syncs.RunOptions{})
	t.take()
	first := t.coolify.takeTimings()
	var ok int
	err := t.store.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sync_targets WHERE failure_count = 0 AND last_result IS NOT NULL AND lease_expires_at IS NULL`).Scan(&ok)
	if err != nil || ok != t.plan.Targets {
		t.setupErr = fmt.Errorf("the first converge pass left %d of %d Targets converged (%v)", ok, t.plan.Targets, err)
		t.log.Error("first converge pass", "error", t.setupErr)
	}
	t.log.Info("first converge pass", "targets", ok, "values", t.coolify.writes.Load(), "seconds", time.Since(t0).Seconds(), "providerCalls", len(first))
	t.coolify.setDelay(time.Duration(t.plan.ProviderDelayMs) * time.Millisecond)
}

// onRun keeps a Target run's report (syncs.Service.OnRun).
func (t *benchTarget) onRun(st syncs.RunStats) {
	run := g9a.TargetRun{Target: st.TargetID, Commits: st.Commits, SharedCommits: st.SharedCommits, WALBytes: st.WALBytes,
		QueuedUs: st.Queued.Microseconds(), InJobsUs: st.InJobs.Microseconds(), CompletionUs: st.Completion.Microseconds(), DurationUs: st.Duration.Microseconds()}
	for _, j := range st.Jobs {
		run.Jobs = append(run.Jobs, g9a.JobRun{Point: j.Point, QueuedUs: j.Queued.Microseconds(), InJobUs: j.InJob.Microseconds(), CompletionUs: j.Completion.Microseconds(),
			WALBytes: j.WALBytes, BatchJobs: j.BatchJobs, Committed: j.Committed})
	}
	t.mu.Lock()
	t.collected = append(t.collected, run)
	t.mu.Unlock()
}

// take answers the Target runs reported since the last take.
func (t *benchTarget) take() []g9a.TargetRun {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.collected
	t.collected = nil
	return out
}

// Converge runs one converge: the values changed, then an engine pass.
func (t *benchTarget) Converge(ctx context.Context) g9a.ConvergeResult {
	if !t.running.CompareAndSwap(false, true) {
		return g9a.ConvergeResult{Err: g9a.ErrConvergeRunning}
	}
	defer t.running.Store(false)
	if t.setupErr != nil {
		return g9a.ConvergeResult{Err: t.setupErr}
	}
	run := int(t.runs.Add(1))
	t.coolify.takeTimings() // only this run's calls from here
	if err := t.change(ctx, run); err != nil {
		return g9a.ConvergeResult{Err: fmt.Errorf("changing values: %w", err)}
	}
	calls, writes := t.coolify.calls.Load(), t.coolify.writes.Load()
	t.engine.RunOnce(ctx, syncs.RunOptions{})
	runs := t.take()
	res := g9a.ConvergeResult{Targets: len(runs), Values: int(t.coolify.writes.Load() - writes), Calls: t.coolify.calls.Load() - calls, Runs: runs,
		ProviderCallsUs: t.coolify.takeTimings()}
	if err := t.store.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sync_targets WHERE failure_count > 0`).Scan(&res.PushFailed); err != nil {
		res.Err = err
	}
	return res
}

// change writes ChangesPerRun new values in every Target's environment,
// a different set each run, as PUT …/values/{item} writes them (its
// authorization, the HTTP layer's, is not the converge's cost).
func (t *benchTarget) change(ctx context.Context, run int) error {
	if t.principal == nil {
		p, _, err := t.approvals.Authenticate(ctx, t.writes.token)
		if err != nil {
			return err
		}
		t.principal = p
	}
	q := query.New(t.store.Reader())
	k := t.plan.ChangesPerRun
	for _, e := range t.writes.envs {
		project, err := q.LiveProject(ctx, query.LiveProjectParams{OrganizationID: t.writes.org, SlugOrID: e.project})
		if err != nil {
			return err
		}
		env, err := q.LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: e.project, NameOrID: e.id})
		if err != nil {
			return err
		}
		target := values.Target{OrganizationID: t.writes.org, Project: project, Env: env}
		for i := range k {
			item := t.writes.keys[(run*k+i)%len(t.writes.keys)]
			value := benchSecret(fmt.Sprintf("%s/%s/%d", e.id, item, run))
			if _, _, _, err := values.SetValue(ctx, t.writer, t.rootKEK, t.principal, target, item, values.SetInput{Value: value},
				write.Claim{IdentityID: t.principal.Identity.ID}, time.Now); err != nil {
				return fmt.Errorf("%s: %w", item, err)
			}
		}
	}
	return nil
}

// Write makes one of a bound run's added writes (g9a.Writer), in the
// server, through the production paths, with SQLITE_BUSY noted as for the
// load's disclosures:
//   - a disclosure: manifest entry n mod 20 asks for one of its Secrets, as
//     k6 does, through the read path of values (its audit event committed
//     before the value is decrypted); it must answer that one value;
//   - a value write: a new version of one Secret in the bound run's own
//     environment (values.SetValue, as PUT …/values/{item} writes it), by
//     the converge runs' writer.
func (t *benchTarget) Write(ctx context.Context, kind g9a.WriteKind, n int) (bool, error) {
	ctx, busy := storage.WithBusyNote(ctx)
	var err error
	switch kind {
	case g9a.WriteDisclose:
		err = t.addedDisclosure(ctx, n)
	case g9a.WriteValue:
		err = t.addedValueWrite(ctx, n)
	default:
		err = fmt.Errorf("unknown write kind %q", kind)
	}
	return busy(), err
}

// benchDisclosureRoute is the route the read path names a disclosure by.
const benchDisclosureRoute = "/v1/organizations/:org/projects/:project/environments/:environment/disclosures"

func (t *benchTarget) addedDisclosure(ctx context.Context, n int) error {
	if t.values == nil || len(t.manifest) == 0 {
		return errors.New("the bound run's read path is not set up")
	}
	m := t.manifest[n%len(t.manifest)]
	key := m.Keys[(n/len(t.manifest))%len(m.Keys)]
	p, err := t.principalFor(ctx, m.Token)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string][]string{"items": {key}})
	res, err := t.values.Disclose(ctx, values.Request{Principal: p, RequestID: fmt.Sprintf("g9a-write-%d", n), Method: http.MethodPost, Route: benchDisclosureRoute,
		Org: m.Org, Project: m.Project, Environment: m.Env}, body)
	if err != nil {
		return err
	}
	if items, _ := res.Get("items"); reflect.ValueOf(items).Kind() != reflect.Slice || reflect.ValueOf(items).Len() != 1 {
		return fmt.Errorf("the disclosure of %s answered %s", key, jsvalue.Stringify(res))
	}
	return nil
}

func (t *benchTarget) addedValueWrite(ctx context.Context, n int) error {
	if t.writes == nil || t.writes.load == nil || t.writer == nil {
		return errors.New("the bound run's environment is not set up")
	}
	p, err := t.principalFor(ctx, t.writes.token)
	if err != nil {
		return err
	}
	q := query.New(t.store.Reader())
	project, err := q.LiveProject(ctx, query.LiveProjectParams{OrganizationID: t.writes.org, SlugOrID: t.writes.load.project})
	if err != nil {
		return err
	}
	env, err := q.LiveEnvironment(ctx, query.LiveEnvironmentParams{ProjectID: t.writes.load.project, NameOrID: t.writes.load.id})
	if err != nil {
		return err
	}
	item := t.writes.keys[n%len(t.writes.keys)]
	value := benchSecret(fmt.Sprintf("write-load/%s/%d", item, n))
	_, _, _, err = values.SetValue(ctx, t.writer, t.rootKEK, p, values.Target{OrganizationID: t.writes.org, Project: project, Env: env}, item,
		values.SetInput{Value: value}, write.Claim{IdentityID: p.Identity.ID}, time.Now)
	return err
}

// principalFor authenticates a seeded credential once.
func (t *benchTarget) principalFor(ctx context.Context, token string) (*auth.Principal, error) {
	if p, ok := t.principals.Load(token); ok {
		return p.(*auth.Principal), nil
	}
	if t.approvals == nil {
		return nil, errors.New("not serving yet")
	}
	p, _, err := t.approvals.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}
	t.principals.Store(token, p)
	return p, nil
}

// writeStages writes the run's per-stage timings of its disclosures
// (stages.Summary, one per stage) when the run ends.
func writeStages(out string, h *stages.Histogram) error {
	b, err := json.MarshalIndent(h.Summaries(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, g9a.FileStages), append(b, '\n'), 0o644)
}

// benchControl adds to the run's control routes (outside /v1, the request
// window and the access log):
//
//	GET /run/stages              the disclosures' stage timings so far
//	GET /run/profile?seconds=N   a CPU profile of the next N seconds (1 to
//	                             600, default 30), in pprof's format, as
//	                             net/http/pprof serves it
func benchControl(runner http.Handler, h *stages.Histogram, loadStarted func()) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/run/", runner)
	mux.HandleFunc("POST /run/start", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		runner.ServeHTTP(rec, r)
		if rec.status == 0 || rec.status == http.StatusOK {
			loadStarted()
		}
	})
	mux.HandleFunc("GET /run/stages", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.Summaries())
	})
	mux.HandleFunc("GET /run/profile", func(w http.ResponseWriter, r *http.Request) {
		seconds := 30
		if v := r.URL.Query().Get("seconds"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 600 {
				http.Error(w, "seconds: 1 to 600", http.StatusBadRequest)
				return
			}
			seconds = n
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if err := pprof.StartCPUProfile(w); err != nil {
			// Another profile is running.
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		select {
		case <-time.After(time.Duration(seconds) * time.Second):
		case <-r.Context().Done():
		}
		pprof.StopCPUProfile()
	})
	return mux
}
