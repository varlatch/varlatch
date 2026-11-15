// SPDX-License-Identifier: Apache-2.0

package contract

import "bytes"

// Change is one item's change of sensitivity, requiredness or type.
type Change[T any] struct {
	Name     string
	From, To T
}

// Diff is diffContracts (ADR-0013 §14): what changed between two
// revisions, the security-relevant changes told apart from cosmetic ones.
type Diff struct {
	ItemsAdded, ItemsRemoved []string
	SensitivityChanged       []Change[bool]
	RequirednessChanged      []Change[Requiredness]
	TypeChanged              []Change[string]
	// OtherChanged are cosmetic edits: description, default, example, enum
	// values, rotation grace or hint.
	OtherChanged []string
	// SemanticsVersionChanged is set when the revisions use different
	// Contract Semantics: [from, to].
	SemanticsVersionChanged *[2]int
	// SecurityRelevant: an item added or removed, or a sensitivity or
	// requiredness change.
	SecurityRelevant bool
}

func cosmetic(it Item) []byte {
	o := Object{}
	if it.DefaultValue != nil {
		o = append(o, Member{"defaultValue", *it.DefaultValue})
	}
	if it.Description != nil {
		o = append(o, Member{"description", *it.Description})
	}
	if it.EnumValues != nil {
		o = append(o, it.value()[4])
	}
	if it.Example != nil {
		o = append(o, Member{"example", *it.Example})
	}
	if it.RotationGraceSeconds != nil {
		o = append(o, Member{"rotationGraceSeconds", float64(*it.RotationGraceSeconds)})
	}
	if it.RotationHint != nil {
		o = append(o, Member{"rotationHint", *it.RotationHint})
	}
	return Canonical(o)
}

// DiffContracts is diffContracts.
func DiffContracts(from, to Contract) Diff {
	d := Diff{ItemsAdded: []string{}, ItemsRemoved: []string{}, SensitivityChanged: []Change[bool]{},
		RequirednessChanged: []Change[Requiredness]{}, TypeChanged: []Change[string]{}, OtherChanged: []string{}}
	if from.Version() != to.Version() {
		d.SemanticsVersionChanged = &[2]int{from.Version(), to.Version()}
	}
	byName := func(c Contract) map[string]Item {
		m := map[string]Item{}
		for _, it := range c.Items {
			m[it.Name] = it
		}
		return m
	}
	a, b := byName(from), byName(to)
	for _, it := range to.Items {
		if _, ok := a[it.Name]; !ok {
			d.ItemsAdded = append(d.ItemsAdded, it.Name)
		}
	}
	for _, it := range from.Items {
		if _, ok := b[it.Name]; !ok {
			d.ItemsRemoved = append(d.ItemsRemoved, it.Name)
		}
	}
	for _, x := range from.Items {
		y, ok := b[x.Name]
		if !ok {
			continue
		}
		if x.Sensitive != y.Sensitive {
			d.SensitivityChanged = append(d.SensitivityChanged, Change[bool]{x.Name, x.Sensitive, y.Sensitive})
		}
		if !bytes.Equal(Canonical(x.Required.value()), Canonical(y.Required.value())) {
			d.RequirednessChanged = append(d.RequirednessChanged, Change[Requiredness]{x.Name, x.Required, y.Required})
		}
		if x.Type != y.Type {
			d.TypeChanged = append(d.TypeChanged, Change[string]{x.Name, x.Type, y.Type})
		}
		if !bytes.Equal(cosmetic(x), cosmetic(y)) {
			d.OtherChanged = append(d.OtherChanged, x.Name)
		}
	}
	d.SecurityRelevant = len(d.ItemsAdded) > 0 || len(d.ItemsRemoved) > 0 || len(d.SensitivityChanged) > 0 || len(d.RequirednessChanged) > 0
	return d
}

// Value is the diff as diffContracts returns it, for comparison and audit.
func (d Diff) Value() Object {
	names := func(s []string) []any {
		out := make([]any, len(s))
		for i, n := range s {
			out[i] = n
		}
		return out
	}
	sens := make([]any, len(d.SensitivityChanged))
	for i, c := range d.SensitivityChanged {
		sens[i] = Object{{"name", c.Name}, {"from", c.From}, {"to", c.To}}
	}
	req := make([]any, len(d.RequirednessChanged))
	for i, c := range d.RequirednessChanged {
		req[i] = Object{{"name", c.Name}, {"from", c.From.value()}, {"to", c.To.value()}}
	}
	typ := make([]any, len(d.TypeChanged))
	for i, c := range d.TypeChanged {
		typ[i] = Object{{"name", c.Name}, {"from", c.From}, {"to", c.To}}
	}
	var sv any
	if d.SemanticsVersionChanged != nil {
		sv = Object{{"from", float64(d.SemanticsVersionChanged[0])}, {"to", float64(d.SemanticsVersionChanged[1])}}
	}
	return Object{
		{"itemsAdded", names(d.ItemsAdded)}, {"itemsRemoved", names(d.ItemsRemoved)}, {"sensitivityChanged", sens},
		{"requirednessChanged", req}, {"typeChanged", typ}, {"otherChanged", names(d.OtherChanged)},
		{"semanticsVersionChanged", sv}, {"securityRelevant", d.SecurityRelevant},
	}
}
