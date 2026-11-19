// SPDX-License-Identifier: Apache-2.0

package envschema

import (
	"sort"
	"strings"

	"github.com/varlatch/varlatch/go/lib/contract"
)

// Environment is EnvironmentRef: what name resolution needs of an
// Environment. ParentID is "" for a root Environment.
type Environment struct {
	ID, Name  string
	ParentID  string
	HasParent bool
}

// UnknownEnvironmentNameError is the package's error for env(...) names
// that are not this project's root Environments.
type UnknownEnvironmentNameError struct {
	Unknown, Derived, Roots []string
}

func (e *UnknownEnvironmentNameError) Error() string {
	var parts []string
	if len(e.Unknown) > 0 {
		parts = append(parts, "unknown environment name(s) in env(...): "+strings.Join(e.Unknown, ", "))
	}
	if len(e.Derived) > 0 {
		parts = append(parts, "derived environment(s) in env(...): "+strings.Join(e.Derived, ", ")+"; env(...) names root environments")
	}
	roots := "(none)"
	if len(e.Roots) > 0 {
		roots = strings.Join(e.Roots, ", ")
	}
	return strings.Join(parts, "; ") + ". This project's root environments: " + roots + "."
}

// Resolve is resolveDraft: env(...) names resolved to root Environment IDs
// against the project's live Environments (an unknown or derived name
// fails, never approximated), then the Contract normalized with its
// semantics version left to the server (the push decides it).
func Resolve(d *Draft, environments []Environment) (contract.Contract, error) {
	byName := map[string]Environment{}
	for _, e := range environments {
		byName[e.Name] = e // a later one with the same name wins, as new Map(...) keeps it
	}
	unknown, derived := map[string]bool{}, map[string]bool{}
	items := make([]any, len(d.Items))
	for i, it := range d.Items {
		required := d.DefaultRequired
		if it.Required != nil {
			required = *it.Required
		}
		var req contract.Object
		switch required.Kind {
		case "always", "never":
			req = contract.Object{{Key: "kind", Value: required.Kind}}
		case "tier":
			req = contract.Object{{Key: "kind", Value: "selector"}, {Key: "selector", Value: contract.Object{{Key: "kind", Value: "tier"}, {Key: "tier", Value: required.Tier}}}}
		case "environments":
			ids := []any{}
			for _, name := range required.Names {
				e, ok := byName[name]
				switch {
				case !ok:
					unknown[name] = true
				case e.HasParent:
					derived[name] = true
				default:
					ids = append(ids, e.ID)
				}
			}
			req = contract.Object{{Key: "kind", Value: "selector"}, {Key: "selector", Value: contract.Object{{Key: "kind", Value: "environments"}, {Key: "environmentIds", Value: ids}}}}
		}
		sensitive := d.DefaultSensitive
		if it.Sensitive != nil {
			sensitive = *it.Sensitive
		}
		o := contract.Object{{Key: "name", Value: it.Name}, {Key: "required", Value: req}, {Key: "sensitive", Value: sensitive}, {Key: "type", Value: it.Type}}
		if it.EnumValues != nil {
			vs := make([]any, len(it.EnumValues))
			for j, v := range it.EnumValues {
				vs[j] = v
			}
			o = append(o, contract.Member{Key: "enumValues", Value: vs})
		}
		for _, f := range []struct {
			key string
			v   *string
		}{{"defaultValue", it.DefaultValue}, {"description", it.Description}, {"example", it.Example}} {
			if f.v != nil {
				o = append(o, contract.Member{Key: f.key, Value: *f.v})
			}
		}
		if it.RotationGraceSeconds != nil {
			o = append(o, contract.Member{Key: "rotationGraceSeconds", Value: float64(*it.RotationGraceSeconds)})
		}
		if it.RotationHint != nil {
			o = append(o, contract.Member{Key: "rotationHint", Value: *it.RotationHint})
		}
		items[i] = o
	}
	if len(unknown) > 0 || len(derived) > 0 {
		var roots []string
		for _, e := range environments {
			if !e.HasParent {
				roots = append(roots, e.Name)
			}
		}
		sort.Slice(roots, func(i, j int) bool { return utf16Less(roots[i], roots[j]) })
		return contract.Contract{}, &UnknownEnvironmentNameError{Unknown: sortedKeys(unknown), Derived: sortedKeys(derived), Roots: roots}
	}
	return contract.Normalize(contract.Object{{Key: "schemaVersion", Value: float64(1)}, {Key: "items", Value: items}}, contract.Options{VersionUndecided: true})
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return utf16Less(out[i], out[j]) })
	return out
}
