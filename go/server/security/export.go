// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"fmt"
	"slices"

	"github.com/varlatch/varlatch/go/server/auth"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// ExportTarget is what an export's binding names: the capture's
// Organization, Project and environment.
type ExportTarget struct {
	OrganizationID         string
	ProjectID, ProjectName string
	EnvironmentID, EnvName string
}

func sortedUnique(names []string) []string {
	out := slices.Clone(names)
	slices.SortFunc(out, func(a, b string) int {
		switch {
		case jsLess(a, b):
			return -1
		case jsLess(b, a):
			return 1
		}
		return 0
	})
	return slices.Compact(out)
}

func anyList(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// ExportBinding is exportBinding (domain/exportstepup.ts, the binding
// catalogue's secret.export): target the Project and the environment; body
// the purpose, the selection mode, the requested names (items mode only,
// sorted and without duplicates) and the exact, sorted set of Secret names
// disclosed; query {}; no version. The values are never bound. nil when the
// export discloses no Secret, which needs no approval. all is the
// all-authorized-secrets scope; requested the request's items otherwise.
func ExportBinding(t ExportTarget, all bool, requested, disclosed []string) *auth.Binding {
	names := sortedUnique(disclosed)
	if len(names) == 0 {
		return nil
	}
	mode, selection := "items", "the Secrets requested"
	var req any
	if all {
		mode, selection = "all-authorized-secrets", "every Secret you may reveal"
	} else {
		req = anyList(sortedUnique(requested))
	}
	where := LabelWithID("project", t.ProjectName, t.ProjectID) + " / " + LabelWithID("environment", t.EnvName, t.EnvironmentID)
	count := fmt.Sprintf("%d Secret", len(names))
	if len(names) != 1 {
		count += "s"
	}
	str := func(s string) *string { return &s }
	changes := []auth.ApprovalChange{{Field: "selection", To: str(selection)}}
	if !all {
		changes = append(changes, auth.ApprovalChange{Field: "requested", To: str(QuotedList(sortedUnique(requested)))})
	}
	changes = append(changes, auth.ApprovalChange{Field: "disclosed", To: str(QuotedList(names))})
	org := t.OrganizationID
	return &auth.Binding{
		Operation: "secret.export", OrganizationID: &org,
		Target: map[string]string{"projectId": t.ProjectID, "environmentId": t.EnvironmentID},
		Body: jsvalue.Object{
			{Key: "purpose", Value: "export"}, {Key: "mode", Value: mode}, {Key: "requested", Value: req}, {Key: "disclosed", Value: anyList(names)},
		},
		Query:   map[string]string{},
		Summary: auth.ApprovalSummary{Title: "Export " + count + " of " + where + " to a file: " + QuotedList(names), Changes: changes},
	}
}
