// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/server/migration/bundle"
	"github.com/varlatch/varlatch/go/server/migration/canonical"
)

// ClassNames are the encryption classes (decision 7), in their order.
var ClassNames = []string{
	envelope.PurposeAuditExportCredential, envelope.PurposeAuditExportDrain, envelope.PurposeDEK,
	envelope.PurposeGitHubAppKey, envelope.PurposeJWTSigningKey, envelope.PurposeKEKCanary,
	envelope.PurposeOrgKEK, envelope.PurposePlatformCredential, envelope.PurposeValue,
	envelope.PurposeWebhookSecret,
}

// classTables are the table each class is read from, for the report.
var classTables = map[string]string{
	envelope.PurposeKEKCanary:             "installation",
	envelope.PurposeOrgKEK:                "organizations",
	envelope.PurposeDEK:                   "value_versions",
	envelope.PurposeValue:                 "value_versions",
	envelope.PurposeWebhookSecret:         "webhooks",
	envelope.PurposePlatformCredential:    "platform_connections",
	envelope.PurposeGitHubAppKey:          "github_apps",
	envelope.PurposeAuditExportCredential: "audit_exports",
	envelope.PurposeAuditExportDrain:      "audit_exports",
	envelope.PurposeJWTSigningKey:         "signing_keys",
}

// classes is the encryption-class check: every encrypted item of the
// target opened with the Root KEK (and the keys under it), its keyed digest
// computed, and the digests held against the bundle's, item by item. The
// plaintexts are cleared once digested; only the digests are compared, and
// neither is reported.
func (c *checker) classes(ctx context.Context, r *bundle.Reader) error {
	target, err := c.targetDigests(ctx)
	if err != nil {
		return err
	}
	n, err := r.Digests()
	if err != nil {
		return err
	}
	i := 0
	extra := func(d bundle.Digest) {
		c.fail(Classes, classTables[d.Class], d.Class, "%s: an item the source does not have", idsName(d))
	}
	for range n {
		d, err := r.Digest()
		if err != nil {
			return err
		}
		c.checked(Classes, 1)
		for i < len(target) && bundle.CompareDigests(target[i], d) < 0 {
			extra(target[i])
			i++
		}
		if i >= len(target) || bundle.CompareDigests(target[i], d) > 0 {
			c.fail(Classes, classTables[d.Class], d.Class, "%s: missing, or it does not open", idsName(d))
			continue
		}
		if !hmac.Equal([]byte(target[i].HMAC), []byte(d.HMAC)) {
			c.fail(Classes, classTables[d.Class], d.Class, "%s: its plaintext is not the source's", idsName(d))
		}
		i++
	}
	for ; i < len(target); i++ {
		extra(target[i])
	}
	return nil
}

// idsName names an item by its ids (ids, never a value).
func idsName(d bundle.Digest) string {
	keys := make([]string, 0, len(d.IDs))
	for k := range d.IDs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + " " + d.IDs[k]
	}
	return strings.Join(parts, ", ")
}

// targetDigests opens every encrypted item of the target and digests it
// under the run key, in the bundle's order. An item that does not open is
// reported (and left out, so the bundle's digest of it shows as missing).
// An item under an Organization KEK that was destroyed is not opened, on
// either side: no key opens it, and its bytes are the rows check's.
func (c *checker) targetDigests(ctx context.Context) ([]bundle.Digest, error) {
	var out []bundle.Digest
	opened := func(class string, key []byte, raw sql.NullString, ctx envelope.Context) []byte {
		ids := map[string]string{}
		for k, v := range ctx {
			if k != "purpose" {
				ids[k] = v.(string)
			}
		}
		d := bundle.Digest{Class: class, IDs: ids}
		var env envelope.Envelope
		if !raw.Valid || json.Unmarshal([]byte(raw.String), &env) != nil {
			c.fail(Classes, classTables[class], class, "%s: not an envelope", idsName(d))
			return nil
		}
		p, err := envelope.Open(key, env, ctx)
		if err != nil {
			c.fail(Classes, classTables[class], class, "%s: does not open", idsName(d))
			return nil
		}
		in, err := canonical.DigestInput(class, ids, p)
		if err != nil {
			clear(p)
			c.fail(Classes, classTables[class], class, "%s: its ids cannot be digested", idsName(d))
			return nil
		}
		m := hmac.New(sha256.New, c.o.RunKey)
		m.Write(in)
		clear(in)
		d.HMAC = hex.EncodeToString(m.Sum(nil))
		out = append(out, d)
		return p
	}
	q := func(query string, n int) ([][]any, error) {
		rows, err := c.db.QueryContext(ctx, query)
		if err != nil {
			return nil, err
		}
		return scanAll(rows, n)
	}
	str := func(v any) string {
		switch x := v.(type) {
		case string:
			return x
		case []byte:
			return string(x)
		}
		return ""
	}
	text := func(v any) sql.NullString {
		if v == nil {
			return sql.NullString{}
		}
		return sql.NullString{String: str(v), Valid: true}
	}

	rows, err := q("SELECT id, kek_canary FROM installation", 2)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		clear(opened(envelope.PurposeKEKCanary, c.o.RootKEK, text(r[1]), envelope.KEKCanaryContext(str(r[0]))))
	}
	orgKEK := map[string][]byte{}
	defer func() {
		for _, k := range orgKEK {
			clear(k)
		}
	}()
	rows, err = q("SELECT id, wrapped_org_kek FROM organizations WHERE wrapped_org_kek IS NOT NULL AND org_kek_destroyed_at IS NULL", 2)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if k := opened(envelope.PurposeOrgKEK, c.o.RootKEK, text(r[1]), envelope.OrgKEKContext(str(r[0]))); len(k) == envelope.KeySize {
			orgKEK[str(r[0])] = k
		} else {
			clear(k)
		}
	}
	// An item under an Organization KEK that did not open: reported once
	// per Organization, its items not.
	unopened := map[string]bool{}
	under := func(class, org string) ([]byte, bool) {
		k, ok := orgKEK[org]
		if !ok && !unopened[org] {
			var destroyed int
			_ = c.db.QueryRowContext(ctx, "SELECT count(*) FROM organizations WHERE id = ? AND (wrapped_org_kek IS NULL OR org_kek_destroyed_at IS NOT NULL)", org).Scan(&destroyed)
			if destroyed == 0 {
				unopened[org] = true
				c.fail(Classes, classTables[class], class, "the items of organization %s: its KEK did not open", org)
			}
		}
		return k, ok
	}
	rows, err = q(`SELECT p.organization_id, vv.value_id, vv.id, vv.wrapped_dek, vv.payload
		FROM value_versions vv JOIN env_values v ON v.id = vv.value_id JOIN environments e ON e.id = v.environment_id JOIN projects p ON p.id = e.project_id
		WHERE vv.erased_at IS NULL`, 5)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		org, secret, version := str(r[0]), str(r[1]), str(r[2])
		k, ok := under(envelope.PurposeDEK, org)
		if !ok {
			continue
		}
		dek := opened(envelope.PurposeDEK, k, text(r[3]), envelope.DEKContext(org, secret, version))
		if len(dek) != envelope.KeySize {
			clear(dek)
			c.fail(Classes, "value_versions", envelope.PurposeValue, "organizationId %s, secretId %s, versionId %s: its DEK did not open", org, secret, version)
			continue
		}
		clear(opened(envelope.PurposeValue, dek, text(r[4]), envelope.ValueContext(org, secret, version)))
		clear(dek)
	}
	for _, s := range []struct {
		class, query string
		ctx          func(org, id string) envelope.Context
	}{
		{envelope.PurposeWebhookSecret, "SELECT organization_id, id, secret_envelope FROM webhooks WHERE secret_envelope IS NOT NULL", envelope.WebhookSecretContext},
		{envelope.PurposePlatformCredential, "SELECT organization_id, id, credential_envelope FROM platform_connections WHERE credential_envelope IS NOT NULL", envelope.PlatformCredentialContext},
		{envelope.PurposeGitHubAppKey, "SELECT organization_id, id, key_envelope FROM github_apps WHERE key_envelope IS NOT NULL", envelope.GitHubAppKeyContext},
		{envelope.PurposeGitHubAppKey, "SELECT organization_id, id, pending_key_envelope FROM github_app_registrations WHERE pending_key_envelope IS NOT NULL", envelope.GitHubAppKeyContext},
		{envelope.PurposeAuditExportCredential, "SELECT organization_id, id, credential_envelope FROM audit_exports WHERE state <> 'draining'", envelope.AuditExportCredentialContext},
	} {
		rows, err := q(s.query, 3)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if k, ok := under(s.class, str(r[0])); ok {
				clear(opened(s.class, k, text(r[2]), s.ctx(str(r[0]), str(r[1]))))
			}
		}
	}
	rows, err = q("SELECT organization_id, id, credential_envelope FROM audit_exports WHERE state = 'draining'", 3)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		clear(opened(envelope.PurposeAuditExportDrain, c.o.RootKEK, text(r[2]), envelope.AuditExportDrainContext(str(r[0]), str(r[1]))))
	}
	rows, err = q("SELECT id, private_key_wrapped FROM signing_keys", 2)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		clear(opened(envelope.PurposeJWTSigningKey, c.o.RootKEK, text(r[1]), envelope.JWTSigningKeyContext(str(r[0]))))
	}
	slices.SortFunc(out, bundle.CompareDigests)
	for i := 1; i < len(out); i++ {
		if bundle.CompareDigests(out[i-1], out[i]) == 0 {
			return nil, fmt.Errorf("check: two %s items with the same ids (%s)", out[i].Class, idsName(out[i]))
		}
	}
	return out, nil
}
