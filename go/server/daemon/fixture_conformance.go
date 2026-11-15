// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build conformance

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/config"
	"github.com/varlatch/varlatch/go/server/ids"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/realtime"
)

// The conformance harness's fixtures for the realtime suite (G11; the
// go-binary target's go-server capability): the Organizations, people,
// memberships and browser sessions the suite's streams need, and the
// audit events that make signals, written straight to the database
// because the /v1 writes that would make them are not built yet (ADR-0059
// step 4). Run as `varlatchd admin conformance-fixture <fixture> [args]
// --config <file>`, through the running varlatchd (control.go), which
// publishes what they commit. Built only with the conformance build
// tag: a release has none of this. Each prints one line of JSON.
//
//	world <name>                    two Organizations and three people:
//	                                alice in A, bob in B, carol in A and B
//	orgs <identity> <n>             n more Organizations, the person a member
//	session <identity>              a browser session: {"sessionId","token"}
//	events <orgs|-> <actor|-> <n>   n audit events in each Organization of a
//	                                comma-separated list (or of none), each of
//	                                another domain, all in one commit
//	remove-member <org> <identity>  the membership removed, with its event

var fixtureName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
var fixtureID = regexp.MustCompile(`^[a-z]{3}_[a-z0-9_]{1,64}$`)

// fixtureTypes are event types of distinct domains that change something
// and close nothing: a signal of n of them carries n domains.
var fixtureTypes = func() []string {
	skip := map[string]bool{"membership": true, "organization": true, "credential": true}
	seen := map[string]bool{}
	var out []string
	for _, t := range audit.EventTypes {
		d := realtime.ChangedDomain(t)
		if d == "" || skip[d] || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, t)
	}
	return out
}()

func init() {
	conformanceFixture = func(ctx context.Context, env *hostEnv, rest []string, stdout, stderr io.Writer) int {
		fail := func(err error) int {
			fmt.Fprintf(stderr, "varlatchd admin conformance-fixture: %v\n", err)
			return ExitFailure
		}
		usage := func() int {
			fmt.Fprintln(stderr, "varlatchd admin conformance-fixture: world <name> | orgs <identity> <n> | session <identity> | events <orgs|-> <actor|-> <n> | remove-member <org> <identity>")
			return 64
		}
		if len(rest) == 0 {
			return usage()
		}
		cfg, store := env.cfg, env.store
		var err error
		var out any
		switch {
		case rest[0] == "world" && len(rest) == 2 && fixtureName.MatchString(rest[1]):
			out, err = fixtureWorld(ctx, store, cfg, rest[1])
		case rest[0] == "orgs" && len(rest) == 3 && fixtureID.MatchString(rest[1]):
			n, convErr := strconv.Atoi(rest[2])
			if convErr != nil || n < 1 || n > 200 {
				return usage()
			}
			out, err = fixtureOrgs(ctx, store, cfg, rest[1], n)
		case rest[0] == "session" && len(rest) == 2 && fixtureID.MatchString(rest[1]):
			out, err = fixtureSession(ctx, store, rest[1])
		case rest[0] == "events" && len(rest) == 4:
			n, convErr := strconv.Atoi(rest[3])
			if convErr != nil || n < 1 || n > len(fixtureTypes) {
				return usage()
			}
			var orgs []*string
			if rest[1] == "-" {
				orgs = []*string{nil}
			} else {
				for _, o := range strings.Split(rest[1], ",") {
					if !fixtureID.MatchString(o) {
						return usage()
					}
					orgs = append(orgs, &o)
				}
			}
			out, err = fixtureEvents(ctx, store, orgs, optionalID(rest[2]), n)
		case rest[0] == "remove-member" && len(rest) == 3 && fixtureID.MatchString(rest[1]) && fixtureID.MatchString(rest[2]):
			out, err = fixtureRemoveMember(ctx, store, rest[1], rest[2])
		default:
			return usage()
		}
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(out)
		fmt.Fprintln(stdout, string(b))
		return ExitOK
	}
}

func optionalID(s string) *string {
	if s == "-" || !fixtureID.MatchString(s) {
		return nil
	}
	return &s
}

func rootKEKOf(cfg *config.Config) ([]byte, error) {
	material, err := os.ReadFile(cfg.RootKEKFile)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	return envelope.ParseRootKEK(string(material))
}

// insertOrganization writes a live Organization with its wrapped KEK.
func insertOrganization(ctx context.Context, tx *storage.Tx, rootKEK []byte, id, slug, name string) error {
	_, wrapped, err := envelope.WrapOrgKEK(rootKEK, id)
	if err != nil {
		return err
	}
	w, _ := json.Marshal(wrapped)
	_, err = tx.ExecContext(ctx, `INSERT INTO organizations (id, slug, name, wrapped_org_kek) VALUES (?, ?, ?, ?)`, id, slug, name, string(w))
	return err
}

func fixtureWorld(ctx context.Context, store *storage.DB, cfg *config.Config, name string) (any, error) {
	rootKEK, err := rootKEKOf(cfg)
	if err != nil {
		return nil, err
	}
	orgs := map[string]string{"a": "org_" + randomID(), "b": "org_" + randomID()}
	people := map[string]string{}
	for _, p := range []string{"alice", "bob", "carol"} {
		people[p] = ids.New(ids.Identity)
	}
	err = store.Write(ctx, func(tx *storage.Tx) error {
		for _, k := range []string{"a", "b"} {
			if err := insertOrganization(ctx, tx, rootKEK, orgs[k], name+"-"+k, name+" "+k); err != nil {
				return err
			}
		}
		for _, p := range []string{"alice", "bob", "carol"} {
			user := "usr_" + randomID()
			if _, err := tx.ExecContext(ctx, `INSERT INTO identities (id, kind, name) VALUES (?, 'human', ?)`, people[p], name+" "+p); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_users (id, name, email) VALUES (?, ?, ?)`, user, name+" "+p, user+"@conformance.invalid"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_user_links (better_auth_user_id, identity_id) VALUES (?, ?)`, user, people[p]); err != nil {
				return err
			}
		}
		for _, m := range [][2]string{{"a", "alice"}, {"b", "bob"}, {"a", "carol"}, {"b", "carol"}} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'member')`, orgs[m[0]], people[m[1]]); err != nil {
				return err
			}
		}
		return nil
	})
	return map[string]any{"organizations": orgs, "identities": people}, err
}

func fixtureOrgs(ctx context.Context, store *storage.DB, cfg *config.Config, identity string, n int) (any, error) {
	rootKEK, err := rootKEKOf(cfg)
	if err != nil {
		return nil, err
	}
	created := make([]string, 0, n)
	err = store.Write(ctx, func(tx *storage.Tx) error {
		created = created[:0]
		for range n {
			id := "org_" + randomID()
			if err := insertOrganization(ctx, tx, rootKEK, id, id, id); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO org_memberships (organization_id, identity_id, role) VALUES (?, ?, 'member')`, id, identity); err != nil {
				return err
			}
			created = append(created, id)
		}
		return nil
	})
	return map[string]any{"organizations": created}, err
}

func fixtureSession(ctx context.Context, store *storage.DB, identity string) (any, error) {
	token := randomToken()
	id := ids.New(ids.AuthSession)
	now := time.Now()
	err := store.Write(ctx, func(tx *storage.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions (id, expires_at, token_hash, created_at, updated_at, user_id)
			SELECT ?, ?, ?, ?, ?, better_auth_user_id FROM auth_user_links WHERE identity_id = ?`,
			id, now.Add(auth.SessionLifetime).UnixMicro(), auth.HashToken(token), now.UnixMicro(), now.UnixMicro(), identity)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errors.New("no such person")
		}
		return nil
	})
	return map[string]string{"sessionId": id, "token": token}, err
}

func fixtureEvents(ctx context.Context, store *storage.DB, orgs []*string, actor *string, n int) (any, error) {
	var recorded []string
	err := store.Write(ctx, func(tx *storage.Tx) error {
		recorded = recorded[:0]
		events := make([]audit.Event, 0, n*len(orgs))
		for _, org := range orgs {
			for _, t := range fixtureTypes[:n] {
				events = append(events, audit.Event{Type: t, Decision: audit.Info, OrganizationID: org, ActorIdentityID: actor})
			}
		}
		out, err := audit.Record(ctx, tx, events...)
		for _, r := range out {
			recorded = append(recorded, r.ID)
		}
		return err
	})
	return map[string]any{"events": recorded, "domains": domainsOf(fixtureTypes[:n])}, err
}

func domainsOf(types []string) []string {
	var out []string
	for _, t := range types {
		if d := realtime.ChangedDomain(t); !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

func fixtureRemoveMember(ctx context.Context, store *storage.DB, org, identity string) (any, error) {
	var id string
	err := store.Write(ctx, func(tx *storage.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE org_memberships SET removed_at = ? WHERE organization_id = ? AND identity_id = ? AND removed_at IS NULL`,
			time.Now().UnixMicro(), org, identity)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errors.New("no such membership")
		}
		out, err := audit.Record(ctx, tx, audit.Event{
			Type: "membership.removed", Decision: audit.Info, OrganizationID: &org,
			Resource: jsvalue.Object{{Key: "identityId", Value: identity}},
		})
		if err == nil {
			id = out[0].ID
		}
		return err
	})
	return map[string]string{"event": id}, err
}

func randomID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
