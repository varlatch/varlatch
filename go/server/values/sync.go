// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
)

// SyncRead is what the converge engine reads of a Target's environment
// (reconcileUnderLease and renderEffectiveOutput): under the Target's
// standing authority, so no authorization and no freeze check here.
type SyncRead struct {
	// Gone is a deleted Project or environment ("environment-gone").
	Gone bool
	// Expired is an environment past its expiry ("environment-expired").
	Expired bool
	// Items are resolveItems's, each with the active Contract's
	// sensitivity (absent from it: sensitive).
	Items []Item
}

// ReadForSync reads, in db (one snapshot), the Project and the environment
// by id (both live), then the environment's resolved items at now.
func ReadForSync(ctx context.Context, db query.DBTX, projectID, environmentID string, now int64) (SyncRead, error) {
	q := query.New(db)
	project, err := q.SyncProject(ctx, projectID)
	if errors.Is(err, sql.ErrNoRows) {
		return SyncRead{Gone: true}, nil
	}
	if err != nil {
		return SyncRead{}, err
	}
	env, err := q.SyncEnvironment(ctx, environmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return SyncRead{Gone: true}, nil
	}
	if err != nil {
		return SyncRead{}, err
	}
	if env.ExpiresAt.Valid && env.ExpiresAt.Int64 <= now {
		return SyncRead{Expired: true}, nil
	}
	st := State{Env: query.LiveEnvironmentRow{ID: env.ID, ParentEnvironmentID: env.ParentEnvironmentID}}
	if project.ActiveContractRevisionID.Valid {
		rev, err := q.ProjectContractRevision(ctx, query.ProjectContractRevisionParams{ID: project.ActiveContractRevisionID.String, ProjectID: project.ID})
		if errors.Is(err, sql.ErrNoRows) {
			return SyncRead{}, domainerr.NotFound("Contract revision")
		}
		if err != nil {
			return SyncRead{}, err
		}
		var c contractDoc
		if err := json.Unmarshal([]byte(rev.Contract), &c); err != nil {
			return SyncRead{}, fmt.Errorf("values: the active Contract of %s is not JSON: %w", project.ID, err)
		}
		st.contract = &c
	}
	// Seeds of one-time codes (ADR-0061) and OAuth connections (ADR-0062) are
	// never synced.
	r, err := resolve(ctx, q, &st, now)
	if err != nil {
		return SyncRead{}, err
	}
	return SyncRead{Items: r.items}, nil
}

// OpenForSync is decryptForSync: one version, read when it is opened (after
// the decryption's audit event committed). An erased version is never
// decrypted: it fails closed as missing.
func OpenForSync(ctx context.Context, db query.DBTX, orgKEK []byte, organizationID, valueRowID, versionID string) (string, error) {
	rows, err := query.New(db).CapturedCiphertext(ctx, []string{versionID})
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", domainerr.New("INTERNAL", "Missing value version")
	}
	if marked(rows[0].Payload.String) {
		return "", errSeed
	}
	var v envelope.EncryptedValue
	if err := json.Unmarshal([]byte(rows[0].Payload.String), &v.Payload); err != nil {
		return "", fmt.Errorf("values: the payload of %s is not an envelope: %w", versionID, err)
	}
	if err := json.Unmarshal([]byte(rows[0].WrappedDek.String), &v.WrappedDEK); err != nil {
		return "", fmt.Errorf("values: the wrapped DEK of %s is not an envelope: %w", versionID, err)
	}
	plain, err := envelope.DecryptValue(orgKEK, organizationID, valueRowID, versionID, v)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	return decode(plain), nil
}

// ExpandForSync is expandReferences(raw, lookup, true): a reference it
// cannot expand, and a size or work limit, fail with the message the
// TypeScript ReferenceExpansionError carries (ExpansionMessage).
func ExpandForSync(raw string, lookup func(string) (string, bool)) (string, error) {
	return expandStrict(raw, lookup)
}

// ExpansionMessage is a ReferenceExpansionError's message, when err is
// one.
func ExpansionMessage(err error) (string, bool) {
	var u *unresolvedError
	if errors.As(err, &u) {
		return u.message, true
	}
	var d *domainerr.Error
	if errors.As(err, &d) && d.Code == "VALIDATION_FAILED" {
		return d.Message, true
	}
	return "", false
}
