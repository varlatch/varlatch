// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"testing"

	"github.com/varlatch/varlatch/go/server/auth"
)

// Setup's reissue (--revoke-unused): a new bootstrap or recovery link
// revokes the ones issued before and never used, in the same write job, so
// only the newest works; the issued event counts them; without the option
// earlier links stay valid, as the TypeScript server keeps them.
func TestReissueRevokesUnusedLinks(t *testing.T) {
	e := newEnv(t)
	first, err := e.svc.IssueBootstrapGrant(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.svc.IssueBootstrapGrant(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, first.Token); err != nil {
		t.Fatalf("without the option, an earlier link was revoked: %v", err)
	}
	third, err := e.svc.IssueBootstrapGrantRevoking(e.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range []auth.Grant{first, second} {
		if _, err := e.svc.PeekSetupGrant(e.ctx, g.Token); codeOf(err) != "INVALID_CREDENTIAL" {
			t.Errorf("an earlier link still works: %v", err)
		}
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, third.Token); err != nil {
		t.Fatalf("the new link was revoked too: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM audit_events WHERE event_type = 'bootstrap.grant_issued' AND json_extract(metadata, '$.revokedUnused') = 2`); n != 1 {
		t.Errorf("the issued event does not count the revoked links (%d)", n)
	}
	// Recovery: an administrator who never enrolled, reissued.
	reg := e.enrollWith(newSoftKey(t), browserCSRF, third.Token)
	r1, err := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: reg.IdentityID})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.svc.IssueRecoveryGrant(e.ctx, auth.Recovery{IdentityID: reg.IdentityID, RevokeUnused: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, r1.Token); codeOf(err) != "INVALID_CREDENTIAL" {
		t.Errorf("the earlier recovery link still works: %v", err)
	}
	if _, err := e.svc.PeekSetupGrant(e.ctx, r2.Token); err != nil {
		t.Errorf("the new recovery link: %v", err)
	}
}
