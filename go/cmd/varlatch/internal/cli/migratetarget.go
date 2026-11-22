// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/migrate"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/setup"
)

// setupMaker makes a migration's host target with setup's steps (slice
// 7.4e): the answers from the source (its public URL; its ingress shape;
// for an own proxy, the dashboard's address the proxy targets), the
// operator's for what the source cannot say (--acme-email, --listen).
type setupMaker struct {
	host   setup.Host
	given  setup.Answers
	accept bool
	say    func(string) error
}

func (m *setupMaker) Missing() bool {
	_, err := os.Stat(m.host.Path(setup.ConfigFile))
	return errors.Is(err, fs.ErrNotExist)
}

func (m *setupMaker) Make(ctx context.Context, src migrate.IngressInfo, kind migrate.Ingress, earlier []string, made func(string) error) error {
	a := m.given
	a.PublicURL = strings.TrimSuffix(src.PublicURL, "/")
	switch kind {
	case migrate.Public:
		a.Ingress = setup.Public
	case migrate.Proxy:
		a.Ingress = setup.Proxy
		if a.Listen == "" {
			// The address the operator's proxy targets, which the source's
			// dashboard frees at the transfer.
			a.Listen = src.WebAddress
		}
	case migrate.Coolify:
		// Coolify's proxy targets the Go installation's plain listener
		// (--listen, setup's default otherwise).
		a.Ingress = setup.Proxy
	}
	if a.Backups == "" {
		a.Backups = "host"
	}
	_, err := setup.PrepareTarget(ctx, setup.Options{Host: m.host, Given: a, Say: m.say, AcceptExistingUser: m.accept, Ours: earlier}, made)
	return err
}

func (m *setupMaker) Undo(made []string) error { return setup.UndoTarget(m.host, made, m.say) }

func (m *setupMaker) KeyItems() (string, string) { return setup.MadeRootKEK, setup.MadeBackupKey }

func (m *setupMaker) Present(item string) (bool, error) { return setup.ItemPresent(m.host, item) }

// targetCredentials is the environment of the target's varlatchd: with
// CREDENTIALS_DIRECTORY the configuration's directory when the
// configuration names no root_kek_file (a target setup's way, or one migrate
// makes: the keys are the unit's credentials beside it, where `admin
// migrate keys` writes them), as the unit would hand them over.
func targetCredentials(env []string, config string) []string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "CREDENTIALS_DIRECTORY=") {
			return env
		}
	}
	b, err := os.ReadFile(config)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return env
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, _, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if ok && strings.TrimSpace(k) == "root_kek_file" {
			return env
		}
	}
	return append(env, "CREDENTIALS_DIRECTORY="+filepath.Dir(config))
}
