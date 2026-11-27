// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/varlatch/varlatch/go/lib/buildinfo"
	"github.com/varlatch/varlatch/go/lib/keyenv"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/db"
)

// inImage reports whether varlatchd runs as the single-container image:
// the image sets keyenv.ImageMarker (VARLATCH_IMAGE, go/image/Dockerfile),
// the switch admin and the CLI already read there. Never a guess from the
// filesystem.
func inImage() bool { return os.Getenv(keyenv.ImageMarker) != "" }

// upgradeIfRollbackSafe is db.UpgradeIfRollbackSafe; tests replace it for
// an upgrade that is not rollback-safe, which no released step is.
var upgradeIfRollbackSafe = db.UpgradeIfRollbackSafe

// imageUpgradeProcedure is what an operator of the image does for an
// upgrade varlatchd does not apply at start.
const imageUpgradeProcedure = "varlatchd does not apply such an upgrade when it starts: " +
	"redeploy the previous image's digest, take a backup with it (varlatchd admin backup run) and keep it off the host, stop the container, " +
	"run this image once on the same data volume, keys and configuration with `admin schema upgrade`, then deploy this image again; " +
	"after that, going back to the previous digest needs that backup restored"

// schemaAtStart is serve's schema step: db.Init, and in the
// single-container image the schema upgrade when the database's schema is
// older than this varlatchd's and the upgrade is rollback-safe.
//
// In the image an installation is upgraded by deploying a newer release's
// digest (docs/self-hosting/docker-and-coolify.md, Upgrading by digest);
// `varlatch upgrade`, which takes a snapshot and runs the schema upgrade
// inside its journal, is for the host target only. Without this step a
// newer image on an older database only stopped, again and again, until
// the old digest was deployed back. A rollback-safe upgrade (the release
// that wrote the database opens it afterwards) keeps the way back the
// operator already has, the previous digest, with no restore, so serve runs
// it: db.UpgradeIfRollbackSafe, the code path `varlatchd admin schema
// upgrade` runs (one write job, the release recorded as updated_by_release),
// under the data directory's lock serve holds, before the control socket
// or a listener opens. One that is not rollback-safe changes nothing and
// stops serve with imageUpgradeProcedure.
//
// On the host target, an older database stays refused: `varlatch upgrade`
// upgrades it, with its snapshot and its way back.
func schemaAtStart(ctx context.Context, store *storage.DB, log *slog.Logger) error {
	_, err := db.Init(ctx, store, buildinfo.Version)
	var verr *db.VersionError
	if !errors.As(err, &verr) || verr.Database >= verr.Binary || !inImage() {
		return err
	}
	log.Info("the database's schema is older than this varlatchd's: upgrading it before serving, if the upgrade is rollback-safe",
		"from", verr.Database, "to", verr.Binary, "release", buildinfo.Version)
	up, err := upgradeIfRollbackSafe(ctx, store, buildinfo.Version)
	if nerr := (*db.NotRollbackSafeError)(nil); errors.As(err, &nerr) {
		return fmt.Errorf("%w; nothing was changed: %s", err, imageUpgradeProcedure)
	}
	if err != nil {
		return fmt.Errorf("upgrading the database's schema: %w; nothing was changed", err)
	}
	if up.Changed {
		log.Info("upgraded the database's schema; it still opens in the release that wrote it, so the previous image's digest goes back to it",
			"from", up.From, "to", up.To, "compatibleFrom", up.CompatibleFrom, "release", buildinfo.Version)
	}
	_, err = db.Init(ctx, store, buildinfo.Version)
	return err
}
