// SPDX-License-Identifier: AGPL-3.0-or-later

package backups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varlatch/varlatch/go/lib/backup"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/ids"
)

// TestBucket is the bucket test against the configured destination (G13):
// a test archive of this installation (its canary and identity, and a
// marker in place of the database, so nothing of the installation's data
// leaves) is sealed with the BEK, uploaded as <prefix>bucket-test/<id>.vltbak,
// and checked as lib/backup's TestBucket checks it. The object stays in
// the bucket for its retention.
func (s *Service) TestBucket(ctx context.Context) (backup.BucketReport, error) {
	cfg := s.o.Config
	if cfg.BackupDestinationsFile == "" {
		return backup.BucketReport{}, errors.New("no destination is configured (backup_destinations_file)")
	}
	bek, err := s.bek()
	if err != nil {
		return backup.BucketReport{}, err
	}
	defer bek.Clear()
	client, d, err := s.client()
	if err != nil {
		return backup.BucketReport{}, err
	}
	id := ids.UUID()
	work := filepath.Join(s.dir, Dir, ".work-"+id)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return backup.BucketReport{}, err
	}
	defer os.RemoveAll(work)

	meta, err := liveMetadata(ctx, s)
	if err != nil {
		return backup.BucketReport{}, err
	}
	marker := filepath.Join(work, backup.ComponentDatabase)
	if err := os.WriteFile(marker, []byte("varlatch bucket test "+id+"\n"), 0o600); err != nil {
		return backup.BucketReport{}, err
	}
	configuration := filepath.Join(work, backup.ComponentConfiguration)
	if err := writeConfiguration(configuration, cfg); err != nil {
		return backup.BucketReport{}, err
	}
	manifest, err := s.manifest(id, iso(s.o.Now()), meta, marker, configuration)
	if err != nil {
		return backup.BucketReport{}, err
	}
	archive := filepath.Join(work, "test.vltbak")
	if err := backup.Seal(archive, manifest, []string{marker, configuration}, bek, backup.SealOptions{}); err != nil {
		return backup.BucketReport{}, err
	}
	verify := func(path string) error {
		o, err := backup.Open(path, bek, work)
		if err != nil {
			return err
		}
		defer o.Close()
		if o.Manifest.ArchiveID != id {
			return errors.New("the object holds another archive")
		}
		candidates := map[int][]byte{}
		for _, v := range o.Manifest.RequiredKeyVersions {
			candidates[v] = s.o.RootKEK
		}
		if !backup.CheckKeys(o.Manifest, candidates) {
			return errors.New("the Root KEK does not open its canary")
		}
		return nil
	}
	return client.TestBucket(ctx, backup.BucketTestKey(d, id), archive, work, verify), nil
}

// liveMetadata is the installation's metadata from the live database, for
// the bucket test's archive.
func liveMetadata(ctx context.Context, s *Service) (metadata, error) {
	var m metadata
	var canary, state string
	r := s.o.Store.Reader()
	if err := r.QueryRowContext(ctx, "SELECT id, kek_canary, root_kek_version, key_rotation_state FROM installation").Scan(&m.installationID, &canary, &m.keyVersion, &state); err != nil {
		return m, fmt.Errorf("no installation: %w", err)
	}
	if err := json.Unmarshal([]byte(canary), &m.canary); err != nil {
		return m, err
	}
	m.schemaVersion = db.SchemaVersion
	return m, nil
}
