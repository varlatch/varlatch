// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"

	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The installation reads of step 4.1c (ADR-0059): getInstallationRelease
// and getInstallationBackups, for Installation Admins, as http/app.ts
// answers them on a server without a maintenance directory. The release
// check's record is written by `varlatch upgrade --check` (ADR-0049),
// which step 6 brings, so there is none to read yet; the backup supervisor
// is step 4.14's, so there are no archives yet.

func (r reply) VisitGetInstallationReleaseResponse(w http.ResponseWriter) error { return r.visit(w) }
func (r reply) VisitGetInstallationBackupsResponse(w http.ResponseWriter) error { return r.visit(w) }

// installationAdmin refuses anyone but an Installation Admin, as the
// TypeScript routes do (not audited there).
func installationAdmin(ctx context.Context) error {
	if !principalOf(ctx).Identity.InstallationAdmin {
		return domainerr.New("PERMISSION_DENIED", "Installation Admin required")
	}
	return nil
}

// GetInstallationRelease is GET /v1/installation/release: installationRelease
// with no record (releaseNotice.ts): this server's version, nothing newer
// known, no attempt, and a record that is not unreadable.
func (o *operations) GetInstallationRelease(ctx context.Context, _ api.GetInstallationReleaseRequestObject) (api.GetInstallationReleaseResponseObject, error) {
	if err := installationAdmin(ctx); err != nil {
		return nil, err
	}
	return ok(jsvalue.Object{
		{Key: "running", Value: o.s.opts.Version}, {Key: "newer", Value: nil}, {Key: "latest", Value: nil},
		{Key: "lastAttempt", Value: nil}, {Key: "unreadable", Value: false},
	}), nil
}

// GetInstallationBackups is GET /v1/installation/backups (backupStatus):
// the archives' status records, newest first, and the warnings. Without a
// backup service (a server built without one), no archives and the warning
// that says so.
func (o *operations) GetInstallationBackups(ctx context.Context, _ api.GetInstallationBackupsRequestObject) (api.GetInstallationBackupsResponseObject, error) {
	if err := installationAdmin(ctx); err != nil {
		return nil, err
	}
	if o.s.opts.Backups == nil {
		return ok(jsvalue.Object{{Key: "archives", Value: []any{}}, {Key: "warnings", Value: []any{"Backup supervisor is not configured"}}}), nil
	}
	raw, err := o.s.opts.Backups.StatusJSON()
	if err != nil {
		return nil, err
	}
	status, err := jsvalue.Parse(raw)
	if err != nil {
		return nil, err
	}
	return ok(status), nil
}
