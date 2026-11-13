// SPDX-License-Identifier: Apache-2.0

package g9a

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
)

// The workload stands in for varlatchd until Order step 3 builds it: a
// schema shaped like Varlatch's, seeded with workload W1 (5,000 secret
// versions, 50 identities, 20 Sync Targets), a secret retrieval that
// authorizes, decrypts through the real envelope code and commits its
// audit row before answering, and a converge run that reads every value of
// a target's environment and writes the run, its status and its audit rows
// in short write transactions around a simulated push. The G9a gate itself
// runs against the real server (ADR-0059, Order step 3).

const schema = `
CREATE TABLE organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  kek_wrapped TEXT NOT NULL CHECK (json_valid(kek_wrapped))
) STRICT;
CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL,
  last_used_us INTEGER
) STRICT;
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id),
  token_hash BLOB NOT NULL UNIQUE,
  revoked_us INTEGER,
  last_used_us INTEGER
) STRICT;
CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL
) STRICT;
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id),
  identity_id TEXT NOT NULL REFERENCES identities(id),
  PRIMARY KEY (group_id, identity_id)
) STRICT;
CREATE INDEX group_members_identity ON group_members(identity_id);
CREATE TABLE environments (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id),
  name TEXT NOT NULL
) STRICT;
CREATE TABLE secrets (
  id TEXT PRIMARY KEY,
  environment_id TEXT NOT NULL REFERENCES environments(id),
  key TEXT NOT NULL,
  current_version INTEGER NOT NULL,
  UNIQUE (environment_id, key)
) STRICT;
CREATE TABLE secret_versions (
  secret_id TEXT NOT NULL REFERENCES secrets(id),
  version INTEGER NOT NULL,
  value TEXT NOT NULL CHECK (json_valid(value)),
  created_by TEXT NOT NULL REFERENCES identities(id),
  PRIMARY KEY (secret_id, version)
) STRICT;
CREATE TABLE grants (
  id TEXT PRIMARY KEY,
  subject_kind TEXT NOT NULL CHECK (subject_kind IN ('identity','group')),
  subject_id TEXT NOT NULL,
  environment_id TEXT NOT NULL REFERENCES environments(id),
  permission TEXT NOT NULL CHECK (permission IN ('secret.use','secret.reveal'))
) STRICT;
CREATE INDEX grants_lookup ON grants(environment_id, permission, subject_kind, subject_id);
CREATE TABLE sync_targets (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL REFERENCES organizations(id),
  environment_id TEXT NOT NULL REFERENCES environments(id),
  name TEXT NOT NULL
) STRICT;
CREATE TABLE sync_runs (
  id INTEGER PRIMARY KEY,
  target_id TEXT NOT NULL REFERENCES sync_targets(id),
  started_us INTEGER NOT NULL,
  finished_us INTEGER,
  status TEXT NOT NULL CHECK (status IN ('running','ok','failed')),
  pushed INTEGER NOT NULL DEFAULT 0,
  error TEXT
) STRICT;
CREATE INDEX sync_runs_target ON sync_runs(target_id, started_us);
CREATE TABLE sync_status (
  target_id TEXT PRIMARY KEY REFERENCES sync_targets(id),
  last_run_id INTEGER NOT NULL REFERENCES sync_runs(id),
  last_status TEXT NOT NULL CHECK (last_status IN ('ok','failed')),
  fingerprint BLOB NOT NULL,
  updated_us INTEGER NOT NULL
) STRICT;
CREATE TABLE audit_events (
  position INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  org_id TEXT NOT NULL REFERENCES organizations(id),
  at_us INTEGER NOT NULL,
  actor_identity_id TEXT REFERENCES identities(id),
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allowed','denied','ok','failed')),
  request_id TEXT,
  detail TEXT CHECK (detail IS NULL OR json_valid(detail))
) STRICT;
CREATE INDEX audit_actor ON audit_events(actor_identity_id, at_us);
CREATE INDEX audit_subject ON audit_events(subject_id, at_us);
`

// W1's shape.
const (
	w1Identities      = 50
	w1SecretsPerEnv   = 125 // 20 environments × 125 secrets × 2 versions = 5,000 versions
	w1Versions        = 2
	lastUsedDebounce  = 60 * time.Second
	convergeParallel  = 4
	pushMin, pushMax  = 200 * time.Millisecond, 800 * time.Millisecond
	pushFailPercent   = 5
	seedSecretsPerJob = 25
)

// Credential is one retrieval the load may make: an identity's token and a
// secret it may reveal. The manifest lists them for k6.
type Credential struct {
	Env   string `json:"env"`
	Key   string `json:"key"`
	Token string `json:"token"`
}

// Workload is the stand-in server's data and operations.
type Workload struct {
	db      *storage.DB
	rootKEK []byte
	orgID   string

	busy atomic.Int64 // SQLITE_BUSY seen by a retrieval

	convergeRunning atomic.Bool
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Seed creates the schema and W1 with targets Sync Targets (one per
// environment), and returns the manifest of retrievals.
func Seed(ctx context.Context, db *storage.DB, rootKEK []byte, targets int) ([]Credential, error) {
	orgID := newID()
	orgKEK, wrapped, err := envelope.WrapOrgKEK(rootKEK, orgID)
	if err != nil {
		return nil, err
	}
	wrappedJSON, _ := json.Marshal(wrapped)
	type ident struct{ id, token string }
	idents := make([]ident, w1Identities)
	envs := make([]string, targets)
	err = db.Write(ctx, func(tx *storage.Tx) error {
		for _, stmt := range strings.Split(schema, ";\n") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("schema: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO organizations VALUES (?, 'g9a', ?)`, orgID, string(wrappedJSON)); err != nil {
			return err
		}
		group := newID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO groups VALUES (?, ?, 'everyone')`, group, orgID); err != nil {
			return err
		}
		for i := range idents {
			idents[i] = ident{newID(), "vl_g9a_" + newID()}
			if _, err := tx.ExecContext(ctx, `INSERT INTO identities (id, org_id, name) VALUES (?, ?, ?)`, idents[i].id, orgID, fmt.Sprint("identity-", i)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO credentials (id, identity_id, token_hash) VALUES (?, ?, ?)`, newID(), idents[i].id, tokenHash(idents[i].token)); err != nil {
				return err
			}
			// Half reach secrets through the group, half through direct grants.
			if i%2 == 0 {
				if _, err := tx.ExecContext(ctx, `INSERT INTO group_members VALUES (?, ?)`, group, idents[i].id); err != nil {
					return err
				}
			}
		}
		for e := range envs {
			envs[e] = newID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO environments VALUES (?, ?, ?)`, envs[e], orgID, fmt.Sprint("env-", e)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO grants VALUES (?, 'group', ?, ?, 'secret.reveal')`, newID(), group, envs[e]); err != nil {
				return err
			}
			for i := 1; i < len(idents); i += 2 {
				if _, err := tx.ExecContext(ctx, `INSERT INTO grants VALUES (?, 'identity', ?, ?, 'secret.reveal')`, newID(), idents[i].id, envs[e]); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sync_targets VALUES (?, ?, ?, ?)`, newID(), orgID, envs[e], fmt.Sprint("target-", e)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Secrets in small jobs, as an import would write them.
	var manifest []Credential
	for e, env := range envs {
		for first := 0; first < w1SecretsPerEnv; first += seedSecretsPerJob {
			err := db.Write(ctx, func(tx *storage.Tx) error {
				for k := first; k < min(first+seedSecretsPerJob, w1SecretsPerEnv); k++ {
					sid, key := newID(), fmt.Sprintf("SECRET_%03d", k)
					if _, err := tx.ExecContext(ctx, `INSERT INTO secrets VALUES (?, ?, ?, ?)`, sid, env, key, w1Versions); err != nil {
						return err
					}
					for v := 1; v <= w1Versions; v++ {
						plain := make([]byte, 24+mrand.IntN(40))
						_, _ = rand.Read(plain)
						ev, err := envelope.EncryptValue(orgKEK, orgID, sid, strconv.Itoa(v), []byte(hex.EncodeToString(plain)))
						if err != nil {
							return err
						}
						j, _ := json.Marshal(ev)
						if _, err := tx.ExecContext(ctx, `INSERT INTO secret_versions VALUES (?, ?, ?, ?)`, sid, v, string(j), idents[0].id); err != nil {
							return err
						}
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
		for k := range w1SecretsPerEnv {
			manifest = append(manifest, Credential{Env: env, Key: fmt.Sprintf("SECRET_%03d", k), Token: idents[(e*w1SecretsPerEnv+k)%len(idents)].token})
		}
	}
	return manifest, nil
}

// OpenWorkload uses a seeded database.
func OpenWorkload(ctx context.Context, db *storage.DB, rootKEK []byte) (*Workload, error) {
	w := &Workload{db: db, rootKEK: rootKEK}
	if err := db.Reader().QueryRowContext(ctx, `SELECT id FROM organizations`).Scan(&w.orgID); err != nil {
		return nil, fmt.Errorf("workload: not seeded: %w", err)
	}
	return w, nil
}

var (
	errDenied   = errors.New("denied")
	errNotFound = errors.New("not found")
)

// isBusy reports SQLITE_BUSY or SQLITE_LOCKED, which G9a requires never to
// reach a client.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "SQLITE_BUSY") || strings.Contains(s, "SQLITE_LOCKED") || strings.Contains(s, "database is locked")
}

// Retrieve reveals one secret: authorize and read in one read transaction,
// decrypt through the envelope, then commit the audit row (and a debounced
// last-used time) before the value is returned.
func (w *Workload) Retrieve(ctx context.Context, token, env, key, requestID string) ([]byte, error) {
	var credID, identID, secretID string
	var credLastUsed sql.NullInt64
	var version int64
	var valueJSON, kekJSON string
	allowed := false
	err := func() error {
		tx, err := w.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		err = tx.QueryRowContext(ctx, `SELECT c.id, c.identity_id, c.last_used_us FROM credentials c
			WHERE c.token_hash = ? AND c.revoked_us IS NULL`, tokenHash(token)).Scan(&credID, &identID, &credLastUsed)
		if errors.Is(err, sql.ErrNoRows) {
			return errDenied
		}
		if err != nil {
			return err
		}
		var one int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM grants g WHERE g.environment_id = ? AND g.permission = 'secret.reveal'
			AND ((g.subject_kind = 'identity' AND g.subject_id = ?)
			  OR (g.subject_kind = 'group' AND g.subject_id IN (SELECT group_id FROM group_members WHERE identity_id = ?)))
			LIMIT 1`, env, identID, identID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return errDenied
		}
		if err != nil {
			return err
		}
		allowed = true
		err = tx.QueryRowContext(ctx, `SELECT s.id, s.current_version, v.value, o.kek_wrapped
			FROM secrets s
			JOIN environments e ON e.id = s.environment_id
			JOIN organizations o ON o.id = e.org_id
			JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version
			WHERE s.environment_id = ? AND s.key = ?`, env, key).Scan(&secretID, &version, &valueJSON, &kekJSON)
		if errors.Is(err, sql.ErrNoRows) {
			return errNotFound
		}
		return err
	}()
	if errors.Is(err, errDenied) && !allowed {
		var actor any
		if identID != "" {
			actor = identID
		}
		_ = w.audit(ctx, actor, "secret.reveal", "secret", env+"/"+key, "denied", requestID, "")
		return nil, errDenied
	}
	if err != nil {
		return nil, w.noteBusy(err)
	}

	var wrapped envelope.Envelope
	if err := json.Unmarshal([]byte(kekJSON), &wrapped); err != nil {
		return nil, err
	}
	orgKEK, err := envelope.UnwrapOrgKEK(w.rootKEK, wrapped, w.orgID)
	if err != nil {
		return nil, err
	}
	var ev envelope.EncryptedValue
	if err := json.Unmarshal([]byte(valueJSON), &ev); err != nil {
		return nil, err
	}
	vs := strconv.FormatInt(version, 10)
	value, err := envelope.DecryptValue(orgKEK, w.orgID, secretID, vs, ev)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	err = w.db.Write(ctx, func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, org_id, at_us, actor_identity_id, action, subject_type, subject_id, outcome, request_id, detail)
			VALUES (?, ?, ?, ?, 'secret.reveal', 'secret', ?, 'allowed', ?, ?)`,
			newID(), w.orgID, us(now), identID, secretID, requestID, `{"version":`+vs+`}`); err != nil {
			return err
		}
		if !credLastUsed.Valid || now.Sub(time.UnixMicro(credLastUsed.Int64)) > lastUsedDebounce {
			if _, err := tx.ExecContext(ctx, `UPDATE credentials SET last_used_us = ? WHERE id = ?`, us(now), credID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE identities SET last_used_us = ? WHERE id = ?`, us(now), identID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, w.noteBusy(err)
	}
	return value, nil
}

func (w *Workload) noteBusy(err error) error {
	if isBusy(err) {
		w.busy.Add(1)
	}
	return err
}

func (w *Workload) audit(ctx context.Context, actor any, action, subjectType, subjectID, outcome, requestID, detail string) error {
	var d any
	if detail != "" {
		d = detail
	}
	return w.db.Write(ctx, func(tx *storage.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, org_id, at_us, actor_identity_id, action, subject_type, subject_id, outcome, request_id, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, newID(), w.orgID, us(time.Now()), actor, action, subjectType, subjectID, outcome, requestID, d)
		return err
	})
}

// ConvergeResult summarizes one converge run.
type ConvergeResult struct {
	Targets, Values, PushFailed int
	Err                         error
}

// Converge runs one simulated converge over every Sync Target, a few at a
// time. A run already in progress makes it return at once (Targets 0).
func (w *Workload) Converge(ctx context.Context) ConvergeResult {
	if !w.convergeRunning.CompareAndSwap(false, true) {
		return ConvergeResult{Err: errors.New("previous converge still running")}
	}
	defer w.convergeRunning.Store(false)
	type target struct{ id, env string }
	var targets []target
	rows, err := w.db.Reader().QueryContext(ctx, `SELECT id, environment_id FROM sync_targets ORDER BY name`)
	if err != nil {
		return ConvergeResult{Err: err}
	}
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.env); err != nil {
			rows.Close()
			return ConvergeResult{Err: err}
		}
		targets = append(targets, t)
	}
	rows.Close()

	var mu sync.Mutex
	res := ConvergeResult{Targets: len(targets)}
	sem := make(chan struct{}, convergeParallel)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			n, ok, err := w.convergeTarget(ctx, t.id, t.env)
			mu.Lock()
			defer mu.Unlock()
			res.Values += n
			if !ok {
				res.PushFailed++
			}
			if err != nil && res.Err == nil {
				res.Err = fmt.Errorf("target %s: %w", t.id, err)
			}
		}()
	}
	wg.Wait()
	return res
}

func (w *Workload) convergeTarget(ctx context.Context, targetID, env string) (int, bool, error) {
	var runID int64
	start := time.Now()
	err := w.db.Write(ctx, func(tx *storage.Tx) error {
		if err := tx.QueryRowContext(ctx, `INSERT INTO sync_runs (target_id, started_us, status) VALUES (?, ?, 'running') RETURNING id`,
			targetID, us(start)).Scan(&runID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, org_id, at_us, action, subject_type, subject_id, outcome)
			VALUES (?, ?, ?, 'sync.run.started', 'sync_target', ?, 'ok')`, newID(), w.orgID, us(start), targetID)
		return err
	})
	if err != nil {
		return 0, false, err
	}

	type item struct {
		sid, key, value string
		version         int64
	}
	var items []item
	var kekJSON string
	err = func() error {
		tx, err := w.db.Reader().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if err := tx.QueryRowContext(ctx, `SELECT kek_wrapped FROM organizations WHERE id = ?`, w.orgID).Scan(&kekJSON); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `SELECT s.id, s.key, s.current_version, v.value FROM secrets s
			JOIN secret_versions v ON v.secret_id = s.id AND v.version = s.current_version
			WHERE s.environment_id = ? ORDER BY s.key`, env)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.sid, &it.key, &it.version, &it.value); err != nil {
				return err
			}
			items = append(items, it)
		}
		return rows.Err()
	}()
	if err != nil {
		return 0, false, err
	}
	var wrapped envelope.Envelope
	if err := json.Unmarshal([]byte(kekJSON), &wrapped); err != nil {
		return 0, false, err
	}
	orgKEK, err := envelope.UnwrapOrgKEK(w.rootKEK, wrapped, w.orgID)
	if err != nil {
		return 0, false, err
	}
	fp := sha256.New()
	for _, it := range items {
		var ev envelope.EncryptedValue
		if err := json.Unmarshal([]byte(it.value), &ev); err != nil {
			return 0, false, err
		}
		v, err := envelope.DecryptValue(orgKEK, w.orgID, it.sid, strconv.FormatInt(it.version, 10), ev)
		if err != nil {
			return 0, false, err
		}
		fp.Write([]byte(it.key))
		fp.Write(v)
	}

	// The push to the provider, outside any transaction.
	select {
	case <-time.After(pushMin + time.Duration(mrand.Int64N(int64(pushMax-pushMin)+1))):
	case <-ctx.Done():
		return 0, false, ctx.Err()
	}
	pushed := mrand.IntN(100) >= pushFailPercent
	status, errText := "ok", any(nil)
	if !pushed {
		status, errText = "failed", "simulated: provider returned 502"
	}

	end := us(time.Now())
	err = w.db.Write(ctx, func(tx *storage.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE sync_runs SET finished_us = ?, status = ?, pushed = ?, error = ? WHERE id = ?`,
			end, status, len(items), errText, runID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sync_status VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (target_id) DO UPDATE SET last_run_id = excluded.last_run_id, last_status = excluded.last_status,
			fingerprint = excluded.fingerprint, updated_us = excluded.updated_us`,
			targetID, runID, status, fp.Sum(nil), end); err != nil {
			return err
		}
		if pushed {
			for _, it := range items {
				if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, org_id, at_us, action, subject_type, subject_id, outcome, detail)
					VALUES (?, ?, ?, 'secret.synced', 'secret', ?, 'ok', ?)`, newID(), w.orgID, end, it.sid, `{"target":"`+targetID+`"}`); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_events (id, org_id, at_us, action, subject_type, subject_id, outcome, detail)
			VALUES (?, ?, ?, 'sync.run.finished', 'sync_target', ?, ?, ?)`, newID(), w.orgID, end, targetID, statusOutcome(status), `{"run":`+strconv.FormatInt(runID, 10)+`}`)
		return err
	})
	return len(items), pushed, err
}

func statusOutcome(status string) string {
	if status == "ok" {
		return "ok"
	}
	return "failed"
}
