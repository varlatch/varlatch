// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build g9a

package daemon

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/bench/g9a"
	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/backups"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/stages"
	"github.com/varlatch/varlatch/go/server/values"
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
//   - the converge simulation, reconcileTarget's successful path
//     (converge), once a period for every Target;
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
	if err := fs.Parse(args); err != nil || *planPath == "" || *data == "" || *out == "" {
		fmt.Fprintln(stderr, "usage: varlatchd g9a -plan <plan.json> -data <dir> -out <dir> [-listen <addr>]")
		return 64
	}
	p, err := g9a.ReadPlan(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd g9a: %v\n", err)
		return ExitConfig
	}
	conf, err := benchInstallation(*data, *out, *listen)
	if err != nil {
		fmt.Fprintf(stderr, "varlatchd g9a: %v\n", err)
		return ExitFailure
	}
	if *profile < 0 || *profile > 3600 {
		fmt.Fprintln(stderr, "varlatchd g9a: -profile: 0 to 3600 seconds")
		return 64
	}
	return benchServe(Options{ConfigPath: conf, Stderr: stderr}, p, *data, *out, time.Duration(*profile)*time.Second)
}

// benchInstallation makes a fresh installation for the run: a Root KEK in
// the data directory, and varlatchd.conf in the output directory (kept
// with the report), with the access log there too.
func benchInstallation(data, out, listen string) (string, error) {
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
	// converge too (the simulation below, until 4.9's G9a smoke moves it
	// to the engine), so the engine's own loop is off: sync = off.
	bekFile := filepath.Join(data, "backup-key")
	if err := os.WriteFile(bekFile, []byte(hex.EncodeToString(envelope.GenerateKey())+"\n"), 0o600); err != nil {
		return "", err
	}
	conf := filepath.Join(out, g9a.FileConfig)
	text := fmt.Sprintf("# Written by varlatchd g9a for one run.\nlisten = %s\ndata_dir = %s\nroot_kek_file = %s\naccess_log = %s\nbackup_key_file = %s\nbackup_interval = off\nbackup_keep = 2\nsync = off\n",
		listen, data, kekFile, filepath.Join(out, g9a.FileAccessLog), bekFile)
	return conf, os.WriteFile(conf, []byte(text), 0o644)
}

// benchServe serves the run: serve with the run's hooks.
func benchServe(opts Options, p g9a.Plan, data, out string, profile time.Duration) int {
	log := slog.New(slog.NewTextHandler(opts.Stderr, nil))
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "varlatchd g9a: %v\n", err)
		return ExitConfig
	}
	t := &benchTarget{plan: p, cfg: cfg, log: log}
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
			manifest, err := seedW1(ctx, store, rootKEK, p.Targets)
			if err != nil {
				return fmt.Errorf("seed: %w", err)
			}
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
		stop: runner.Done(),
		stopped: func() {
			stopProfile()
			runner.Finish()
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

// benchTarget is the run's target: this server's storage instance and the
// converge simulation.
type benchTarget struct {
	plan    g9a.Plan
	cfg     *config.Config
	log     *slog.Logger
	store   *storage.DB
	rootKEK []byte
	running atomic.Bool
	runs    atomic.Int64
}

func (t *benchTarget) WALSize() int64 { return t.store.Metrics().WALBytes }

// Backup is a real backup (server/backups, as the schedule runs one): the
// snapshot paced as the plan says, the paced sealing, the archive's check
// and local retention, into the run's data directory.
func (t *benchTarget) Backup(ctx context.Context, _ int, o storage.SnapshotOptions) (g9a.BackupStats, error) {
	res, err := backups.New(backups.Options{Config: t.cfg, Store: t.store, RootKEK: t.rootKEK, Log: t.log, Snapshot: o}).Run(ctx)
	return g9a.BackupStats{Snapshot: res.Snapshot, Seal: time.Duration(res.Capture.DumpMs) * time.Millisecond, ArchiveBytes: res.Bytes}, err
}

// seedW1 writes W1 in the production tables, in jobs of the size an
// import would write, and returns the load's manifest: one entry per
// source address, alternately a person's and a service identity's
// credential, each with the Secrets of one environment.
func seedW1(ctx context.Context, store *storage.DB, rootKEK []byte, targets int) ([]g9a.ManifestEntry, error) {
	if targets != benchProjects*benchEnvsPer {
		return nil, fmt.Errorf("W1 has %d Sync Targets; the plan names %d", benchProjects*benchEnvsPer, targets)
	}
	now := time.Now().UnixMicro()
	org := ids.New("org")
	orgKEK, wrapped, err := envelope.WrapOrgKEK(rootKEK, org)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	sum := sha256.Sum256([]byte(canon))
	contentHash := "sha256:" + hex.EncodeToString(sum[:])

	type env struct{ id, name, project, projectSlug string }
	var envs []env
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
			credential, err := envelope.Seal(orgKEK, []byte("g9a-platform-token-"+conn), envelope.PlatformCredentialContext(org, conn))
			if err != nil {
				return err
			}
			c, _ := json.Marshal(credential)
			if err := exec(tx, `INSERT INTO platform_connections (id, organization_id, platform, base_identity, name, credential_envelope) VALUES (?, ?, 'vercel', 'team_g9a', ?, ?)`, conn, org, slug, string(c)); err != nil {
				return err
			}
			for ei := range benchEnvsPer {
				e := env{id: ids.New("env"), name: fmt.Sprintf("env-%d", ei), project: project, projectSlug: slug}
				if err := exec(tx, `INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, ?, 'shared', ?)`, e.id, project, e.name, tiers[ei%len(tiers)]); err != nil {
					return err
				}
				dest, _ := json.Marshal(map[string]any{"projectId": slug + "-" + e.name})
				if err := exec(tx, `INSERT INTO sync_targets (id, organization_id, project_id, environment_id, connection_id, destination, canonical_destination, mapping, created_by)
					VALUES (?, ?, ?, ?, ?, ?, ?, '{"kind":"wildcard"}', ?)`, ids.New("snt"), org, project, e.id, conn, string(dest), slug+"-"+e.name, people[0]); err != nil {
					return err
				}
				envs = append(envs, e)
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
		return nil, err
	}
	// The values: two versions of each Secret, one environment per job.
	for _, e := range envs {
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
			return nil, err
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
	return manifest, nil
}

// benchSecret is a Secret's value: 48 characters from its version's id.
func benchSecret(version string) string {
	sum := sha256.Sum256([]byte(version))
	return hex.EncodeToString(sum[:])[:benchSecretLength]
}

// The converge simulation (varlatchd-core decision 7): reconcileTarget's
// successful path (services/varlatchd/src/domain/syncdelivery.ts), for
// every Target in turn, as runSyncOnce takes them, with k changed
// destinations per run. Each "job" is one write job of the single writer,
// so group commit may share fsyncs between them as in production; reads
// run on the read pool, outside any write; no write is held across the
// simulated provider call. 2k + 7 commits per Target and run.

const (
	leaseTTL      = 300 * time.Second // LEASE_TTL_SECONDS
	runBudget     = 240 * time.Second // RUN_BUDGET_SECONDS
	providerDelay = 200 * time.Millisecond
)

// Converge runs one converge over every Sync Target.
func (t *benchTarget) Converge(ctx context.Context) g9a.ConvergeResult {
	if !t.running.CompareAndSwap(false, true) {
		return g9a.ConvergeResult{Err: g9a.ErrConvergeRunning}
	}
	defer t.running.Store(false)
	run := t.runs.Add(1)
	rows, err := t.store.Reader().QueryContext(ctx, `SELECT id FROM sync_targets WHERE revoked_at IS NULL ORDER BY id`)
	if err != nil {
		return g9a.ConvergeResult{Err: err}
	}
	var targets []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return g9a.ConvergeResult{Err: err}
		}
		targets = append(targets, id)
	}
	rows.Close()
	res := g9a.ConvergeResult{}
	for _, id := range targets {
		n, err := t.reconcile(ctx, id, int(run))
		if err != nil {
			res.Err = fmt.Errorf("target %s: %w", id, err)
			return res
		}
		res.Targets++
		res.Values += n
	}
	return res
}

type leased struct {
	organizationID, projectID, environmentID, connectionID string
	generation                                             int64
}

// reconcile is one Target's run: the TypeScript statement each step
// reproduces is named on it.
func (t *benchTarget) reconcile(ctx context.Context, targetID string, run int) (int, error) {
	k := t.plan.ChangesPerRun
	now := func() int64 { return time.Now().UnixMicro() }

	// 1. The lease, one job: the Target's generation and lease columns, and
	// the sync_runs row (reconcileTarget: WITH lease AS (UPDATE sync_targets
	// ... RETURNING ...), run AS (INSERT INTO sync_runs ...)).
	var l leased
	err := t.store.Write(ctx, func(tx *storage.Tx) error {
		n := now()
		err := tx.QueryRowContext(ctx, `UPDATE sync_targets
			SET generation = generation + 1, lease_expires_at = ?, needs_sync = 0, last_attempt_at = ?
			WHERE id = ? AND revoked_at IS NULL AND state = 'active'
			  AND (lease_expires_at IS NULL OR lease_expires_at < ?)
			  AND NOT EXISTS (SELECT 1 FROM organization_freezes f WHERE f.organization_id = sync_targets.organization_id AND f.lifted_at IS NULL)
			RETURNING organization_id, project_id, environment_id, connection_id, generation`,
			n+leaseTTL.Microseconds(), n, targetID, n).Scan(&l.organizationID, &l.projectID, &l.environmentID, &l.connectionID, &l.generation)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sync_runs (target_id, generation, deadline) VALUES (?, ?, ?)`, targetID, l.generation, n+runBudget.Microseconds())
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("lease: %w", err)
	}

	// 2. Reads, outside any write: the Connection and the Organization's
	// KEK (reconcileTarget's connRes), the Project and the environment
	// (reconcileUnderLease), the values it will push and their ciphertext
	// (renderEffectiveOutput, decryptForSync), and the ledger.
	r := t.store.Reader()
	var credential, wrappedKEK sql.NullString
	if err := r.QueryRowContext(ctx, `SELECT c.credential_envelope, o.wrapped_org_kek FROM platform_connections c
		JOIN organizations o ON o.id = ? AND o.deleted_at IS NULL WHERE c.id = ?`, l.organizationID, l.connectionID).Scan(&credential, &wrappedKEK); err != nil {
		return 0, fmt.Errorf("connection: %w", err)
	}
	var present int
	if err := r.QueryRowContext(ctx, `SELECT count(*) FROM projects p JOIN environments e ON e.project_id = p.id
		WHERE p.id = ? AND p.deleted_at IS NULL AND e.id = ? AND e.deleted_at IS NULL`, l.projectID, l.environmentID).Scan(&present); err != nil || present != 1 {
		return 0, fmt.Errorf("environment: %v (%d)", err, present)
	}
	q := query.New(r)
	current, err := q.CurrentValuesOfEnvironment(ctx, l.environmentID)
	if err != nil {
		return 0, fmt.Errorf("values: %w", err)
	}
	versionIDs := make([]string, len(current))
	entries := make([]string, len(current))
	for i, v := range current {
		versionIDs[i], entries[i] = v.CurrentVersionID.String, v.ItemName+"@"+v.CurrentVersionID.String
	}
	cipher, err := q.CapturedCiphertext(ctx, versionIDs)
	if err != nil {
		return 0, fmt.Errorf("ciphertext: %w", err)
	}
	ledger, err := r.QueryContext(ctx, `SELECT dest_name, fingerprint, state, generation, repaired_at FROM sync_ledger WHERE target_id = ?`, targetID)
	if err != nil {
		return 0, fmt.Errorf("ledger: %w", err)
	}
	for ledger.Next() {
	}
	_ = ledger.Close()

	resource := jsvalue.Object{{Key: "targetId", Value: targetID}, {Key: "environmentId", Value: l.environmentID}}
	event := func(typ string, metadata jsvalue.Object) audit.Event {
		org, action := l.organizationID, "config.sync.manage"
		return audit.Event{Type: typ, Decision: audit.Info, OrganizationID: &org, Action: &action, Resource: resource, Metadata: metadata}
	}
	// 3. sync.values_decrypted, one job, committed before any of those
	// values is decrypted (renderEffectiveOutput's audit callback,
	// recordAuditEvent), then the decryption.
	if err := t.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := audit.Record(ctx, tx, event("sync.values_decrypted", jsvalue.Object{
			{Key: "purpose", Value: "sync-reconcile"}, {Key: "items", Value: strings.Join(entries, ",")}, {Key: "generation", Value: l.generation},
		}))
		return err
	}); err != nil {
		return 0, fmt.Errorf("sync.values_decrypted: %w", err)
	}
	var wrapped envelope.Envelope
	if err := json.Unmarshal([]byte(wrappedKEK.String), &wrapped); err != nil {
		return 0, err
	}
	orgKEK, err := envelope.UnwrapOrgKEK(t.rootKEK, wrapped, l.organizationID)
	if err != nil {
		return 0, err
	}
	defer clear(orgKEK)
	rowOf := map[string]string{}
	for _, v := range current {
		rowOf[v.CurrentVersionID.String] = v.ID
	}
	plain := map[string]string{}
	for _, c := range cipher {
		var payload, dek envelope.Envelope
		if json.Unmarshal([]byte(c.Payload.String), &payload) != nil || json.Unmarshal([]byte(c.WrappedDek.String), &dek) != nil {
			return 0, errors.New("a value version is not an envelope")
		}
		b, err := envelope.DecryptValue(orgKEK, l.organizationID, rowOf[c.ID], c.ID, envelope.EncryptedValue{Payload: payload, WrappedDEK: dek})
		if err != nil {
			return 0, err
		}
		plain[c.ID] = string(b)
	}
	// The k changed destinations of this run, and their fingerprints
	// (fingerprint: an HMAC keyed per Target).
	fpKey := hmac.New(sha256.New, orgKEK)
	fpKey.Write([]byte("sync-fingerprint:" + targetID))
	key := fpKey.Sum(nil)
	type write struct{ name, version, fingerprint string }
	writes := make([]write, k)
	for i := range k {
		v := current[(run*k+i)%len(current)]
		m := hmac.New(sha256.New, key)
		m.Write([]byte(v.ItemName + "\x00" + plain[v.CurrentVersionID.String]))
		writes[i] = write{v.ItemName, v.CurrentVersionID.String, "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))}
	}

	// guarded is recordGuardedEvent: the event only while the Target's
	// generation is still this run's.
	guarded := func(e audit.Event) error {
		return t.store.Write(ctx, func(tx *storage.Tx) error {
			var gen int64
			if err := tx.QueryRowContext(ctx, `SELECT generation FROM sync_targets WHERE id = ?`, targetID).Scan(&gen); err != nil {
				return err
			}
			if gen != l.generation {
				return errors.New("lease lost")
			}
			_, err := audit.Record(ctx, tx, e)
			return err
		})
	}
	// ledgerSet: the guard, then the ledger upsert.
	ledgerSet := func(name, state, fingerprint string) error {
		return t.store.Write(ctx, func(tx *storage.Tx) error {
			var gen int64
			if err := tx.QueryRowContext(ctx, `SELECT generation FROM sync_targets WHERE id = ?`, targetID).Scan(&gen); err != nil {
				return err
			}
			if gen != l.generation {
				return errors.New("lease lost")
			}
			n := now()
			var repaired any
			if state == "written" || state == "tombstone" {
				repaired = n
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO sync_ledger (target_id, dest_name, fingerprint, state, generation, last_error, repaired_at)
				VALUES (?, ?, ?, ?, ?, NULL, ?)
				ON CONFLICT (target_id, dest_name) DO UPDATE
				  SET fingerprint = excluded.fingerprint, state = excluded.state, generation = excluded.generation,
				      last_error = NULL, updated_at = ?, repaired_at = excluded.repaired_at`,
				targetID, name, fingerprint, state, l.generation, repaired, n)
			return err
		})
	}
	writeEntries := make([]string, k)
	for i, w := range writes {
		writeEntries[i] = w.name + "@" + w.version
	}
	// 4. The guarded sync.push_attempted, one job.
	if err := guarded(event("sync.push_attempted", jsvalue.Object{
		{Key: "destination", Value: "vercel:" + targetID}, {Key: "items", Value: strings.Join(writeEntries, ",")},
		{Key: "deletes", Value: ""}, {Key: "generation", Value: l.generation}, {Key: "forced", Value: false},
	})); err != nil {
		return 0, fmt.Errorf("sync.push_attempted: %w", err)
	}
	// 5. k jobs, one intent-write ledger entry each.
	for _, w := range writes {
		if err := ledgerSet(w.name, "intent-write", w.fingerprint); err != nil {
			return 0, fmt.Errorf("intent-write: %w", err)
		}
	}
	// 6. The provider call, outside any transaction.
	select {
	case <-time.After(providerDelay):
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	// 7. k jobs, one written ledger entry each.
	for _, w := range writes {
		if err := ledgerSet(w.name, "written", w.fingerprint); err != nil {
			return 0, fmt.Errorf("written: %w", err)
		}
	}
	// 8. The guarded sync.push_result, one job.
	if err := guarded(event("sync.push_result", jsvalue.Object{
		{Key: "written", Value: k}, {Key: "deleted", Value: 0}, {Key: "failed", Value: 0}, {Key: "held", Value: 0},
		{Key: "generation", Value: l.generation}, {Key: "result", Value: "ok"},
	})); err != nil {
		return 0, fmt.Errorf("sync.push_result: %w", err)
	}
	// 9. The result columns on the Target, one job (UPDATE sync_targets SET
	// failure_count = 0, next_attempt_at = NULL, last_result = $2 WHERE id =
	// $1 AND generation = $3).
	if err := t.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sync_targets SET failure_count = 0, next_attempt_at = NULL, last_result = 'ok' WHERE id = ? AND generation = ?`, targetID, l.generation)
		return err
	}); err != nil {
		return 0, fmt.Errorf("result: %w", err)
	}
	// 10. Two jobs: the lease released, the run's row deleted
	// (reconcileTarget's finally).
	if err := t.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE sync_targets SET lease_expires_at = NULL WHERE id = ? AND generation = ?`, targetID, l.generation)
		return err
	}); err != nil {
		return 0, fmt.Errorf("release: %w", err)
	}
	if err := t.store.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM sync_runs WHERE target_id = ? AND generation = ?`, targetID, l.generation)
		return err
	}); err != nil {
		return 0, fmt.Errorf("run row: %w", err)
	}
	return k, nil
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
