// SPDX-License-Identifier: AGPL-3.0-or-later

package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/db"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The write-side checks of the authorization vectors (step 4.4b;
// go-authz-vectors.test.ts): what a Grant may name and who may join a
// group, for every identity of the authz world in each Organization, and
// Grant declarations in their bound form.
type writeVectors struct {
	Rows []struct {
		Table string                     `json:"table"`
		Row   map[string]json.RawMessage `json:"row"`
	} `json:"rows"`
	WriteChecks []struct {
		OrganizationID string          `json:"organizationId"`
		IdentityID     string          `json:"identityId"`
		Subject        json.RawMessage `json:"subject"`
		Eligible       *Person         `json:"eligible"`
	} `json:"writeChecks"`
	GrantForms []struct {
		Declaration json.RawMessage `json:"declaration"`
		Normalized  string          `json:"normalized"`
	} `json:"grantForms"`
	SameGrants []struct {
		A, B int
		Same bool
	} `json:"sameGrants"`
}

func seedValue(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	switch x := v.(type) {
	case json.Number:
		return x.Int64()
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case map[string]any:
		if s, ok := x["$ts"].(string); ok {
			tm, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return nil, err
			}
			return tm.UnixMicro(), nil
		}
		return string(raw), nil
	case []any:
		return string(raw), nil
	}
	return v, nil
}

func seedWorld(t *testing.T, v *writeVectors) *storage.DB {
	t.Helper()
	s, err := storage.Open(context.Background(), storage.Options{Path: filepath.Join(t.TempDir(), "varlatch.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := db.Init(context.Background(), s, "0.0.0-test"); err != nil {
		t.Fatal(err)
	}
	err = s.Write(context.Background(), func(tx *storage.Tx) error {
		for _, r := range v.Rows {
			cols := make([]string, 0, len(r.Row))
			for c := range r.Row {
				cols = append(cols, c)
			}
			slices.Sort(cols)
			args := make([]any, len(cols))
			for i, c := range cols {
				val, err := seedValue(r.Row[c])
				if err != nil {
					return fmt.Errorf("%s.%s: %w", r.Table, c, err)
				}
				args[i] = val
			}
			q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", r.Table, strings.Join(cols, ", "), strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", "))
			if _, err := tx.ExecContext(context.Background(), q, args...); err != nil {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func loadWriteVectors(t *testing.T) *writeVectors {
	t.Helper()
	raw, err := os.ReadFile("../authz/testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v writeVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.WriteChecks) == 0 || len(v.GrantForms) == 0 || len(v.SameGrants) == 0 {
		t.Fatal("the vectors hold no write-side checks: regenerate them")
	}
	return &v
}

func errorText(err error) string {
	var de *domainerr.Error
	if !errors.As(err, &de) {
		return err.Error()
	}
	return string(jsvalue.Stringify(jsvalue.Object{{Key: "code", Value: de.Code}, {Key: "message", Value: de.Message}}))
}

// Every identity of the world, in each Organization: whether a Grant may
// name it (checkGrantSubject) and whether it may join a group
// (readEligibleMember), as the TypeScript code answers.
func TestWriteCheckVectors(t *testing.T) {
	v := loadWriteVectors(t)
	s := seedWorld(t, v)
	ctx := context.Background()
	for _, c := range v.WriteChecks {
		name := c.IdentityID + " in " + c.OrganizationID
		got := `"ok"`
		if err := CheckGrantSubject(ctx, s.Reader(), c.OrganizationID, c.IdentityID); err != nil {
			got = errorText(err)
		}
		want, err := jsvalue.Parse(c.Subject)
		if err != nil {
			t.Fatal(err)
		}
		if w := string(jsvalue.Stringify(want)); got != w {
			t.Errorf("%s: subject %s, TypeScript %s", name, got, w)
		}
		eligible, err := readEligibleMember(ctx, s.Reader(), c.OrganizationID, c.IdentityID)
		if err != nil {
			t.Fatal(err)
		}
		if (eligible == nil) != (c.Eligible == nil) || (eligible != nil && *eligible != *c.Eligible) {
			t.Errorf("%s: eligible %+v, TypeScript %+v", name, eligible, c.Eligible)
		}
	}
}

// declaration reads a declaration the vectors hold.
func declaration(t *testing.T, raw json.RawMessage) Declaration {
	t.Helper()
	v, err := jsvalue.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	o := v.(jsvalue.Object)
	opt := func(key string) *string {
		x, ok := o.Get(key)
		if s, isStr := x.(string); ok && isStr {
			return &s
		}
		return nil
	}
	scope, _ := o.Get("scope")
	d := Declaration{SubjectIdentityID: opt("subjectIdentityId"), SubjectGroupID: opt("subjectGroupId"), Scope: scope.(jsvalue.Object), RoleID: opt("roleId")}
	if a, ok := o.Get("actions"); ok && a != nil {
		d.Actions = stringList(a)
	}
	return d
}

// Grant declarations bind as normalizedGrant binds them (sets sorted in
// JavaScript's order, without duplicates), and sameGrant tells the same
// Grant whatever the order of members, sets or duplicates.
func TestGrantFormVectors(t *testing.T) {
	v := loadWriteVectors(t)
	decls := make([]Declaration, len(v.GrantForms))
	for i, f := range v.GrantForms {
		decls[i] = declaration(t, f.Declaration)
		if got := auth.CanonicalJSON(decls[i].Normalized()); got != f.Normalized {
			t.Errorf("form %d: %s, TypeScript %s", i, got, f.Normalized)
		}
	}
	for _, p := range v.SameGrants {
		if got := SameGrant(decls[p.A], decls[p.B]); got != p.Same {
			t.Errorf("forms %d and %d: same %v, TypeScript %v", p.A, p.B, got, p.Same)
		}
	}
}
