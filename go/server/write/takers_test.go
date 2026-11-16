// SPDX-License-Identifier: AGPL-3.0-or-later

package write_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The exclusive takers of the Organization and person gates (feature-parity
// decision 4), checked against the TypeScript code, which is frozen: every
// writer there that takes the Organization row or a person FOR UPDATE is
// listed here, with the Go writer that takes the matching gate exclusive,
// or the slice that builds it. A TypeScript site missing from the list, or
// a listed site the sources no longer have, fails the test.
//
// Found by: `organizationMode: "update"` and an organizations row locked
// for update (the Organization); a person locked with "update" (lockPerson,
// or a people entry with mode "update"; personlocks.ts defines them).
var exclusiveTakers = map[string]string{
	// The Organization gate.
	`domain/securitycontrols.ts:await lockLiveScope(db, { organizationId: input.organizationId, organizationMode: "update", duringIncidentFreeze: "recovery", people: [] });`:      "security.ChangeControl (4.3a)",
	`domain/securitycontrols.ts:await lockLiveScope(db, { organizationId: org.id, organizationMode: "update", allowFrozen: true, duringIncidentFreeze: "recovery", people: [] });`: "security.ResetControls (4.3c)",
	`domain/freeze.ts:organizationMode: "update",#1`: "freeze.Freeze (4.3c)",
	`domain/freeze.ts:organizationMode: "update",#2`: "freeze.Lift (4.3c)",
	`domain/freeze.ts:await lockLiveScope(db, { organizationId: org.id, organizationMode: "update", allowFrozen: true, duringIncidentFreeze: "freeze", people: [] });`:                                            "freeze.OperatorUnfreeze (4.3c)",
	`domain/orgdeletion.ts:scope: { organizationId, organizationMode: "update", allowFrozen: true, people: [actor.id] },`:                                                                                         "scheduling a deletion (4.12)",
	`domain/orgdeletion.ts:await lockLiveScope(db, { organizationId, organizationMode: "update", allowFrozen: true, people: [], accessCheck: "deferred" });`:                                                      "approving a deletion (4.12)",
	`domain/orgdeletion.ts:await lockLiveScope(db, { organizationId, organizationMode: "update", allowFrozen: true, duringIncidentFreeze: "recovery", people: [], accessCheck: "deferred" });`:                    "cancelling a deletion (4.12)",
	`domain/orgdeletion.ts:const org = await lockedQuery(db, { table: "organizations", mode: "update" }, "SELECT id, slug, name FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE SKIP LOCKED",`: "running a deletion (4.12)",
	// Person gates.
	`domain/protected.ts:export function effectRequester(gate: ProtectedGate): { id: string; mode: "update" | "key share" } {#1`:                                         "security.Request.RequesterGate (4.3a), its signature",
	`domain/securitycontrols.ts:await lockPerson(db, input.actorIdentityId, loosened.length > 0 ? "update" : "key share");`:                                              "security.ChangeControl: the requester exclusive when it carries an approval (4.3a)",
	`domain/freeze.ts:await lockPerson(db, input.actor.id, "update");`:                                                                                                   "freeze.Lift: the requester exclusive (4.3c)",
	`domain/approvals.ts:await lockPerson(db, input.identityId, "update");#1`:                                                                                            "auth.StartApproval (4.3b)",
	`domain/approvals.ts:await lockPerson(db, input.identityId, "update");#2`:                                                                                            "auth.ApproveApproval (4.3b)",
	`domain/approvals.ts:await lockPerson(db, input.identityId, "update");#3`:                                                                                            "auth.CancelApproval (4.3b)",
	`domain/passkeys.ts:await lockPerson(db, input.identityId, "update");#1`:                                                                                             "auth.StartConfirmation (4.3b)",
	`domain/passkeys.ts:await lockPerson(db, input.identityId, "update");#2`:                                                                                             "auth.Confirm (4.3b)",
	`domain/passkeys.ts:await lockPerson(db, input.identityId, "update");#3`:                                                                                             "auth.RemoveOwnPasskey (4.3b)",
	`domain/protected.ts:await lockPeople(tx, [...scope.people, ...more, ...(consuming ? [{ id: requester.identityId, mode: "update" as const }] : [])]);`:               "security.Request.Gates: the requester exclusive when it carries an approval (4.3a)",
	`domain/protected.ts:return { id: gate.requester.identityId, mode: gate.approvalId !== null ? "update" : "key share" };`:                                             "security.Request.RequesterGate (4.3a)",
	`domain/bootstrap.ts:await lockPeople(db, [{ id: input.identityId, mode: input.enable ? "update" : "key share" }]);`:                                                 "admin recover --enable (4.1a, daemon/admin.go)",
	`domain/identities.ts:await lockLiveScope(db, { organizationId, duringIncidentFreeze: "recovery", people: [actorIdentityId, { id: identityId, mode: "update" }] });`: "identities.Retire: the identity exclusive (4.4a)",
	`domain/identities.ts:scope: { organizationId, people: [actorIdentityId, { id: identityId, mode: "update" }] },`:                                                     "identities.Reactivate: the identity exclusive (4.4a)",
	`domain/identities.ts:await lockLiveScope(db, { organizationId, people: [actorIdentityId, { id: identityId, mode: "update" }] });`:                                   "identities.Rename: the identity exclusive (4.4a)",
	`domain/orgdeletion.ts:return suspending.map((sid) => ({ id: sid, mode: "update" as const }));`:                                                                      "scheduling a deletion: the machines it suspends (4.12)",
	`domain/orgdeletion.ts:await lockPeople(db, [actor.id, ...restoring.map((rid) => ({ id: rid, mode: "update" as const }))]);`:                                         "cancelling a deletion: the machines it restores (4.12)",
	`domain/orgdeletion.ts:await lockPeople(db, [requester, ...referenced.map((r) => r.id), ...machines.map((id) => ({ id, mode: "update" as const }))]);`:               "running a deletion: its machines (4.12)",
	`http/app.ts:await lockPeople(db, [{ id: principal.identity.id, mode: body.name !== undefined ? "update" : "key share" }]);`:                                         "updateMyProfile, renaming the person (not built yet)",
	`http/app.ts:people: [body.subjectIdentityId, ...(approvalId !== null ? [{ id: principal.identity.id, mode: "update" as const }] : [])],`:                            "access.ReplaceGrant: the requester exclusive when it carries an approval (security.Request.Gates, 4.4b)",
	`http/app.ts:approvalHeaderOf(c) !== null ? [{ id: principal.identity.id, mode: "update" as const }] : [];`:                                                          "an effect's protected writes: the requester (4.10)",
	`http/app.ts:people: approvalId !== null ? [{ id: principal.identity.id, mode: "update" }] : [],`:                                                                    "updating a Requirement, a protected write: the requester (4.4c)",
}

var (
	organizationUpdate = regexp.MustCompile(`organizationMode: "update"|table: "organizations", mode: "update"`)
	personUpdate       = regexp.MustCompile(`lockPerson\(.*"update"|mode: [^,}]*"update"`)
)

func TestExclusiveTakersAgainstTypeScript(t *testing.T) {
	root := filepath.Join("..", "..", "..", "services", "varlatchd", "src")
	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, "domain/personlocks.ts") {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		rel, _ := filepath.Rel(root, path)
		seen := map[string]int{}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "*") || strings.HasPrefix(line, "//") {
				continue
			}
			org := organizationUpdate.MatchString(line)
			person := personUpdate.MatchString(line) && !strings.Contains(line, "table:") && !strings.Contains(line, "organizationMode")
			if !org && !person {
				continue
			}
			key := filepath.ToSlash(rel) + ":" + line
			seen[key]++
			if _, listed := exclusiveTakers[key]; !listed {
				key += "#" + string(rune('0'+seen[key]))
			}
			found[key] = true
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatalf("reading the TypeScript sources: %v", err)
	}
	for site := range found {
		if _, ok := exclusiveTakers[site]; !ok {
			t.Errorf("a TypeScript writer takes the Organization or a person FOR UPDATE, and no Go taker is listed for it: %s", site)
		}
	}
	for site, taker := range exclusiveTakers {
		if !found[site] {
			t.Errorf("listed, but not in the TypeScript sources: %s (%s)", site, taker)
		}
	}
}
