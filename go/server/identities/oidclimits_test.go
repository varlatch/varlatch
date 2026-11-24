// SPDX-License-Identifier: AGPL-3.0-or-later

package identities

import (
	"testing"

	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/oidc/limits"
)

// An approval of a binding binds its limits: the body it is bound to names
// them, and the summary the approver reads shows them. A binding without
// limits is bound to exactly what it always was.
func TestAnApprovalBindsTheLimits(t *testing.T) {
	m := Machine{ID: "idn_b", Name: "b", Kind: "broker"}
	in := OIDCBindingInput{Issuer: "https://issuer.example", Audience: "a", Subject: "s"}
	plain := oidcBindingCreateBinding("org_a", m, in)
	const body = `{"issuer":"https://issuer.example","audience":"a","subject":"s","claims":{}}`
	if got := string(jsvalue.Stringify(plain.Body)); got != body || len(plain.Summary.Changes) != 3 {
		t.Errorf("without limits: %s, %d changes", got, len(plain.Summary.Changes))
	}
	in.Limits = limits.Limits{ExerciseOnly: true, RunIDClaim: "job", SingleExchange: true}
	b := oidcBindingCreateBinding("org_a", m, in)
	if got := string(jsvalue.Stringify(b.Body)); got != body[:len(body)-1]+`,"exerciseOnly":true,"runIdClaim":"job","singleExchange":true}` {
		t.Errorf("with limits: %s", got)
	}
	shown := map[string]string{}
	for _, c := range b.Summary.Changes {
		shown[c.Field] = *c.To
	}
	if shown["exerciseOnly"] != "yes" || shown["singleExchange"] != "yes" || shown["runIdClaim"] != `"job"` {
		t.Errorf("the summary shows %v", shown)
	}
}
