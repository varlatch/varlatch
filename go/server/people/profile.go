// SPDX-License-Identifier: AGPL-3.0-or-later

package people

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// ProfileChange is PATCH /v1/me/profile's body: a new display name, and an
// image to set (an inline data URL or an https URL) or clear (Image nil
// with SetImage), each optional.
type ProfileChange struct {
	Name     *string
	SetImage bool
	Image    *string
}

// UpdateProfile is updateMyProfile: a person's own display name (kept in
// identities.name, which listings and audit provenance show, and in their
// account) and image. Their gate is exclusive when the name changes.
func UpdateProfile(ctx context.Context, w *write.Writer, p *auth.Principal, change ProfileChange, now func() time.Time) (jsvalue.Object, error) {
	actor := p.Identity.ID
	mode := write.Shared
	if change.Name != nil {
		mode = write.Exclusive
	}
	var out jsvalue.Object
	err := w.Job(ctx, []write.Gate{write.Person(actor, mode)}, func(ctx context.Context, tx *storage.Tx) error {
		q := query.New(tx)
		at := now().UnixMicro()
		if change.Name != nil {
			name, err := write.Text(*change.Name)
			if err != nil {
				return err
			}
			if err := q.SetIdentityName(ctx, query.SetIdentityNameParams{Name: name, ID: actor}); err != nil {
				return err
			}
			if err := q.SetAuthUserName(ctx, query.SetAuthUserNameParams{Name: name, UpdatedAt: at, IdentityID: actor}); err != nil {
				return err
			}
		}
		if change.SetImage {
			var image sql.NullString
			if change.Image != nil {
				stored, err := write.Text(*change.Image)
				if err != nil {
					return err
				}
				image = sql.NullString{String: stored, Valid: true}
			}
			if err := q.SetAuthUserImage(ctx, query.SetAuthUserImageParams{Image: image, UpdatedAt: at, IdentityID: actor}); err != nil {
				return err
			}
		}
		if _, err := audit.Record(ctx, tx, audit.Event{Type: "identity.profile_updated", Decision: audit.Info, ActorIdentityID: &actor,
			Resource: jsvalue.Object{{Key: "identityId", Value: actor}},
			Metadata: jsvalue.Object{{Key: "nameChanged", Value: change.Name != nil}, {Key: "imageChanged", Value: change.SetImage}}}); err != nil {
			return err
		}
		name := p.Identity.Name
		if change.Name != nil {
			name = *change.Name
		}
		var email, image any
		row, err := q.ProfileOfIdentity(ctx, actor)
		switch {
		case err == nil:
			email = row.Email
			if row.Image.Valid {
				image = row.Image.String
			}
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		out = jsvalue.Object{{Key: "identityId", Value: actor}, {Key: "name", Value: name}, {Key: "email", Value: email}, {Key: "image", Value: image}}
		return nil
	})
	return out, err
}
