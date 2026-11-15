// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package daemon

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/values"
)

// The conformance harness's seed on the Go server (varlatchd-core decision
// 5): `varlatchd admin conformance-seed --identity <id> --config <file>`,
// with the seeded Secret's value on standard input, writes what the
// runner's /v1 seed writes (scripts/conformance/run.mjs seed): the
// Organization acme with the identity as its admin, the Project api (git
// authority) with the development and production environments, the
// runner's Contract as the TypeScript server stores it (seed_contract.json,
// written by go-values-fixture.test.ts) activated, and two development
// values, DATABASE_URL (the Secret) and PORT, sealed under the
// Organization's KEK. In one write job, straight to the database: the /v1
// writes that would make them come in ADR-0059 step 4, and the runner uses
// them again then. Built only with the conformance build tag.

//go:embed seed_contract.json
var seedContractFile []byte

func init() {
	conformanceSeed = func(ctx context.Context, env *hostEnv, args []string, secret []byte, stdout, stderr io.Writer) int {
		identity := ""
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "--identity" && i+1 < len(args):
				identity = args[i+1]
				i++
			default:
				fmt.Fprintln(stderr, "varlatchd admin conformance-seed: --identity <id> [--config <file>], the Secret's value on standard input")
				return 64
			}
		}
		fail := func(err error) int {
			fmt.Fprintf(stderr, "varlatchd admin conformance-seed: %v\n", err)
			return ExitFailure
		}
		if !fixtureID.MatchString(identity) {
			return fail(errors.New("--identity must name an identity"))
		}
		out, err := seed(ctx, env.store, env.rootKEK, identity, strings.TrimRight(string(secret), "\n"))
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
}

func seed(ctx context.Context, store *storage.DB, rootKEK []byte, identity, secret string) (map[string]string, error) {
	var contract struct {
		Contract    string `json:"contract"`
		ContentHash string `json:"contentHash"`
	}
	if err := json.Unmarshal(seedContractFile, &contract); err != nil {
		return nil, err
	}
	org, project, rev := ids.New("org"), ids.New("prj"), ids.New("rev")
	dev, prod := ids.New("env"), ids.New("env")
	err := store.Write(ctx, func(tx *storage.Tx) error {
		kek, wrapped, err := envelope.WrapOrgKEK(rootKEK, org)
		if err != nil {
			return err
		}
		defer clear(kek)
		w, _ := json.Marshal(wrapped)
		steps := []struct {
			q    string
			args []any
		}{
			{`INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, 'acme', 'Acme', ?)`, []any{org, string(w)}},
			{`INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'admin')`, []any{org, identity}},
			{`INSERT INTO projects (id, organization_id, slug, name, contract_authority) VALUES (?, ?, 'api', 'API', 'git')`, []any{project, org}},
			{`INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, 'development', 'shared', 'development')`, []any{dev, project}},
			{`INSERT INTO environments (id, project_id, name, kind, tier) VALUES (?, ?, 'production', 'shared', 'production')`, []any{prod, project}},
			{`INSERT INTO contract_revisions (id, project_id, content_hash, contract, created_by) VALUES (?, ?, ?, ?, ?)`, []any{rev, project, contract.ContentHash, contract.Contract, identity}},
			{`UPDATE projects SET active_contract_revision_id = ? WHERE id = ?`, []any{rev, project}},
		}
		for _, s := range steps {
			if _, err := tx.ExecContext(ctx, s.q, s.args...); err != nil {
				return err
			}
		}
		for _, v := range []struct{ name, value string }{{"DATABASE_URL", secret}, {"PORT", "3000"}} {
			value, version := ids.New("val"), ids.New("ver")
			sealed, err := values.SealValue(kek, org, value, version, []byte(v.value))
			if err != nil {
				return err
			}
			p, _ := json.Marshal(sealed.Payload)
			d, _ := json.Marshal(sealed.WrappedDEK)
			if _, err := tx.ExecContext(ctx, `INSERT INTO env_values (id, environment_id, item_name) VALUES (?, ?, ?)`, value, dev, v.name); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO value_versions (id, value_id, payload, wrapped_dek, created_by) VALUES (?, ?, ?, ?, ?)`, version, value, string(p), string(d), identity); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE env_values SET current_version_id = ? WHERE id = ?`, version, value); err != nil {
				return err
			}
		}
		return nil
	})
	return map[string]string{"organizationId": org, "projectId": project}, err
}
