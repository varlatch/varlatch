// SPDX-License-Identifier: AGPL-3.0-or-later

package httpserver

import (
	"context"
	"net/http"

	"github.com/varlatch/varlatch/go/lib/release"
	"github.com/varlatch/varlatch/go/server/api"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/upgradecheck"
)

// The installation reads of step 4.1c (ADR-0059): getInstallationRelease
// and getInstallationBackups, for Installation Admins, as http/app.ts
// answers them. The release check's record is written by `varlatch upgrade
// --check` (ADR-0049; step 6.6b).

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

// GetInstallationRelease is GET /v1/installation/release, as
// releaseNotice.ts answers it: the host's last look for a newer release
// (release-check.json, which `varlatch upgrade --check` records), compared
// with this server's own version at read time, so the notice ends when the
// upgrade lands; the link is built from validated fields. A record that
// cannot be read is said (unreadable), never an error.
func (o *operations) GetInstallationRelease(ctx context.Context, _ api.GetInstallationReleaseRequestObject) (api.GetInstallationReleaseResponseObject, error) {
	if err := installationAdmin(ctx); err != nil {
		return nil, err
	}
	running := o.s.opts.Version
	var check *release.ReleaseCheck
	unreadable := false
	if dir := o.s.opts.ReleaseCheckDir; dir != "" {
		var err error
		if check, err = release.ReadReleaseCheck(dir); err != nil {
			check, unreadable = nil, true
		}
	}
	var newer, latest, lastAttempt any
	if check != nil {
		failed := any(nil)
		if check.LastAttempt.Failed != nil {
			failed = *check.LastAttempt.Failed
		}
		lastAttempt = jsvalue.Object{{Key: "checkedAt", Value: check.LastAttempt.CheckedAt}, {Key: "repo", Value: check.LastAttempt.Repo}, {Key: "failed", Value: failed}}
		if s := check.LastSuccess; s != nil {
			order, ok := release.CompareVersions(s.Latest.Version, running)
			newer = ok && order > 0
			published := any(nil)
			if s.Latest.PublishedAt != nil {
				published = *s.Latest.PublishedAt
			}
			link, err := release.ReleaseURL(s.Repo, s.Latest.Version)
			if err != nil {
				return nil, err
			}
			latest = jsvalue.Object{
				{Key: "version", Value: s.Latest.Version}, {Key: "publishedAt", Value: published}, {Key: "url", Value: link},
				{Key: "repo", Value: s.Repo}, {Key: "releaseSet", Value: s.ReleaseSet}, {Key: "checkedAt", Value: s.CheckedAt},
			}
		}
	}
	doc := jsvalue.Object{
		{Key: "running", Value: running}, {Key: "newer", Value: newer}, {Key: "latest", Value: latest},
		{Key: "lastAttempt", Value: lastAttempt}, {Key: "unreadable", Value: unreadable},
	}
	if o.s.opts.UpgradeHost != nil {
		doc = append(doc, o.upgradePreflight(ctx, check, running)...)
	}
	return ok(doc), nil
}

// upgradePreflight is the Release tab's pre-flight (ADR-0065 phase 1;
// server/upgradecheck): the deployment kind, this server's schema, the
// verified target of the newer release, whether it is rollback-safe for
// this release as `varlatch upgrade` judges it, and the checklist. Only the
// Go server answers these members.
func (o *operations) upgradePreflight(ctx context.Context, check *release.ReleaseCheck, running string) jsvalue.Object {
	host := o.s.opts.UpgradeHost(ctx)
	in := upgradecheck.Input{Now: o.s.opts.Now(), Running: running, Check: check, Host: host}
	if dir := o.s.opts.ReleaseCheckDir; dir != "" {
		in.Target, in.TargetErr = release.ReadReleaseTarget(dir)
	}
	r := upgradecheck.Judge(in)
	var target, safe, lines any
	if t := r.Target; t != nil {
		failed := any(nil)
		if t.Failed != nil {
			failed = *t.Failed
		}
		var verified any
		if v := t.Verified; v != nil {
			previous := any(nil)
			if p := v.Previous; p != nil {
				previous = jsvalue.Object{{Key: "version", Value: p.Version}, {Key: "schemaVersion", Value: p.SchemaVersion}}
			}
			verified = jsvalue.Object{
				{Key: "schemaVersion", Value: v.SchemaVersion}, {Key: "compatibleFrom", Value: v.CompatibleFrom}, {Key: "rollbackSafe", Value: v.RollbackSafe},
				{Key: "previous", Value: previous}, {Key: "endsRollbackWindow", Value: v.EndsRollbackWindow}, {Key: "image", Value: v.Image},
			}
		}
		target = jsvalue.Object{{Key: "version", Value: t.Version}, {Key: "checkedAt", Value: t.CheckedAt}, {Key: "failed", Value: failed}, {Key: "verified", Value: verified}}
	}
	if r.RollbackSafe != nil {
		safe = *r.RollbackSafe
	}
	if r.Lines != nil {
		list := make([]any, 0, len(r.Lines))
		for _, l := range r.Lines {
			remedy := any(nil)
			if l.Remedy != "" {
				remedy = l.Remedy
			}
			list = append(list, jsvalue.Object{{Key: "id", Value: l.ID}, {Key: "status", Value: string(l.Status)}, {Key: "title", Value: l.Title}, {Key: "detail", Value: l.Detail}, {Key: "remedy", Value: remedy}})
		}
		lines = list
	}
	return jsvalue.Object{
		{Key: "deployment", Value: string(host.Deployment)}, {Key: "schemaVersion", Value: host.Schema},
		{Key: "target", Value: target}, {Key: "rollbackSafe", Value: safe}, {Key: "preflight", Value: lines},
	}
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
