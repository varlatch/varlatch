// SPDX-License-Identifier: AGPL-3.0-or-later

package custody

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Custody Attestations (domain/custody.ts, ADR-0035 D9): an Infrastructure
// Operator's dated statement that a separately held copy of a recovery key
// exists. The installation can check that a key works, never that a copy
// exists elsewhere, so this is recorded as a claim (a Security Audit
// Event), shown as a claim and aged. The Root KEK's names the key version
// it covers, so replacing the key voids it. No key material or hash of it
// is recorded.

// The keys and methods an attestation names.
var (
	Keys    = []string{"root-kek", "backup-key"}
	Methods = []string{"passphrase-escrow", "shamir-split", "copy"}
)

const attestedEvent = "installation.custody_attested"

// Attestation is one attestation: KeyVersion is the Root KEK's version,
// nil for the backup key.
type Attestation struct {
	Key        string `json:"key"`
	Method     string `json:"method"`
	At         string `json:"at"`
	KeyVersion *int64 `json:"keyVersion"`
}

// Status is custodyStatus: the latest attestation per key, the Root KEK's
// only for its current version.
type Status struct {
	RootKEKVersion int64                   `json:"rootKekVersion"`
	Attestations   map[string]*Attestation `json:"attestations"`
}

// MarshalJSON keeps the TypeScript key order: root-kek, then backup-key.
func (s Status) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"rootKekVersion":%d,"attestations":{`, s.RootKEKVersion)
	for i, k := range Keys {
		if i > 0 {
			b.WriteByte(',')
		}
		v := []byte("null")
		if a := s.Attestations[k]; a != nil {
			var err error
			if v, err = json.Marshal(a); err != nil {
				return nil, err
			}
		}
		fmt.Fprintf(&b, "%q:%s", k, v)
	}
	b.WriteString("}}")
	return b.Bytes(), nil
}

func notInitialized() error {
	return domainerr.New("VALIDATION_FAILED", "Installation is not initialized")
}

func kekVersion(ctx context.Context, db query.DBTX) (int64, error) {
	var v int64
	err := db.QueryRowContext(ctx, "SELECT root_kek_version FROM installation LIMIT 1").Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, notInitialized()
	}
	return v, err
}

// Attest records an attestation (attestCustody).
func Attest(ctx context.Context, store *storage.DB, key, method string) (Attestation, error) {
	if !slices.Contains(Keys, key) {
		return Attestation{}, domainerr.New("VALIDATION_FAILED", "key must be one of "+strings.Join(Keys, ", "))
	}
	if !slices.Contains(Methods, method) {
		return Attestation{}, domainerr.New("VALIDATION_FAILED", "method must be one of "+strings.Join(Methods, ", "))
	}
	a := Attestation{Key: key, Method: method}
	err := store.Write(ctx, func(tx *storage.Tx) error {
		meta := jsvalue.Object{{Key: "key", Value: key}, {Key: "method", Value: method}}
		a.KeyVersion = nil
		if key == "root-kek" {
			v, err := kekVersion(ctx, tx)
			if err != nil {
				return err
			}
			a.KeyVersion = &v
			meta = append(meta, jsvalue.Member{Key: "keyVersion", Value: float64(v)})
		}
		r, err := audit.Record(ctx, tx, audit.Event{Type: attestedEvent, Decision: audit.Info, Metadata: meta})
		if err != nil {
			return err
		}
		a.At = audit.ISOTime(r[0].OccurredAt)
		return nil
	})
	return a, err
}

// StatusOf is custodyStatus, read from db.
func StatusOf(ctx context.Context, db query.DBTX) (Status, error) {
	version, err := kekVersion(ctx, db)
	if err != nil {
		return Status{}, err
	}
	rows, err := db.QueryContext(ctx, "SELECT metadata, occurred_at FROM audit_events WHERE event_type = ? ORDER BY event_order DESC", attestedEvent)
	if err != nil {
		return Status{}, err
	}
	defer rows.Close()
	st := Status{RootKEKVersion: version, Attestations: map[string]*Attestation{}}
	for rows.Next() {
		var raw sql.NullString
		var at int64
		if err := rows.Scan(&raw, &at); err != nil {
			return Status{}, err
		}
		var meta struct {
			Key        string   `json:"key"`
			Method     string   `json:"method"`
			KeyVersion *float64 `json:"keyVersion"`
		}
		if !raw.Valid || json.Unmarshal([]byte(raw.String), &meta) != nil || !slices.Contains(Keys, meta.Key) || st.Attestations[meta.Key] != nil {
			continue
		}
		var kv *int64
		if meta.KeyVersion != nil {
			v := int64(*meta.KeyVersion)
			kv = &v
		}
		if meta.Key == "root-kek" && (kv == nil || *kv != version) {
			continue
		}
		st.Attestations[meta.Key] = &Attestation{Key: meta.Key, Method: meta.Method, At: audit.ISOTime(at), KeyVersion: kv}
	}
	return st, rows.Err()
}
