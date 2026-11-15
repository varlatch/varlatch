// SPDX-License-Identifier: Apache-2.0

// Package contract is the Varlatch Configuration Contract model (ADR-0002,
// ADR-0012, ADR-0013, ADR-0038, ADR-0042) in Go, a port of
// packages/contract: validating and normalizing a Contract a client sends,
// its canonical bytes and content hash, the semantic diff between two
// revisions, and Contract Semantics (requiredness, validation and
// conversion of values, versions 1 to 3). The server (go/server) and the
// CLI (ADR-0059 step 5) both use it, so the same logical Contract has the
// same bytes and hash everywhere: the TypeScript package's vectors
// (packages/contract/test/vectors, and testdata/ts-vectors.json, which
// services/varlatchd/test/go-contract-vectors.test.ts writes) pin it.
//
// Pure: no I/O, no policy, no secret values.
package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
)

// SchemaVersion is the only Contract schema version.
const SchemaVersion = 1

// Tiers are the environment tiers a selector names.
var Tiers = []string{"development", "staging", "production"}

// ItemTypes are the item types, in the TypeScript package's order (zod's
// enum message lists them so).
var ItemTypes = []string{"string", "number", "integer", "boolean", "url", "email", "enum"}

// TypeSince is the first Contract Semantics version that defines each item
// type (ADR-0042).
var TypeSince = map[string]int{"string": 1, "number": 1, "integer": 3, "boolean": 1, "url": 1, "email": 1, "enum": 1}

// ReservedItemNames are names reserved for launcher metadata: varlatch run
// sets VARLATCH_RUN_CONTEXT itself.
var ReservedItemNames = []string{"VARLATCH_RUN_CONTEXT"}

// Selector is an EnvironmentSelector: root Environment IDs, or a tier.
type Selector struct {
	Kind           string // "environments" or "tier"
	EnvironmentIDs []string
	Tier           string
}

// Requiredness says where an item is required: "always", "never", or
// "selector" with its Selector.
type Requiredness struct {
	Kind     string
	Selector *Selector
}

// Item is one Contract item, normalized.
type Item struct {
	Name      string
	Required  Requiredness
	Sensitive bool
	Type      string
	// EnumValues is set iff Type is "enum": sorted, unique.
	EnumValues           []string
	DefaultValue         *string
	Description          *string
	Example              *string
	RotationGraceSeconds *int64
	RotationHint         *string
}

// Contract is a normalized Configuration Contract.
type Contract struct {
	// SemanticsVersion is the Contract Semantics version; 1 is encoded by
	// omission, so revisions made before versions existed keep their hash.
	SemanticsVersion int
	// Items are sorted by name, names unique.
	Items []Item
}

// Version is the Contract's semantics version.
func (c Contract) Version() int {
	if c.SemanticsVersion == 0 {
		return 1
	}
	return c.SemanticsVersion
}

// Value is the Contract as the TypeScript package holds it, members in its
// order (schemaVersion, semanticsVersion when not 1, items; each item's
// fields as normalizeContract sets them), for storage and answers.
func (c Contract) Value() Object {
	items := make([]any, len(c.Items))
	for i, it := range c.Items {
		items[i] = it.value()
	}
	o := Object{{"schemaVersion", float64(SchemaVersion)}}
	if c.Version() != 1 {
		o = append(o, Member{"semanticsVersion", float64(c.Version())})
	}
	return append(o, Member{"items", items})
}

func (r Requiredness) value() Object {
	o := Object{{"kind", r.Kind}}
	if r.Kind == "selector" && r.Selector != nil {
		s := Object{{"kind", r.Selector.Kind}}
		if r.Selector.Kind == "environments" {
			ids := make([]any, len(r.Selector.EnvironmentIDs))
			for i, id := range r.Selector.EnvironmentIDs {
				ids[i] = id
			}
			s = append(s, Member{"environmentIds", ids})
		} else {
			s = append(s, Member{"tier", r.Selector.Tier})
		}
		o = append(o, Member{"selector", s})
	}
	return o
}

func (it Item) value() Object {
	o := Object{{"name", it.Name}, {"required", it.Required.value()}, {"sensitive", it.Sensitive}, {"type", it.Type}}
	if it.EnumValues != nil {
		vs := make([]any, len(it.EnumValues))
		for i, v := range it.EnumValues {
			vs[i] = v
		}
		o = append(o, Member{"enumValues", vs})
	}
	for _, f := range []struct {
		key string
		v   *string
	}{{"defaultValue", it.DefaultValue}, {"description", it.Description}, {"example", it.Example}} {
		if f.v != nil {
			o = append(o, Member{f.key, *f.v})
		}
	}
	if it.RotationGraceSeconds != nil {
		o = append(o, Member{"rotationGraceSeconds", float64(*it.RotationGraceSeconds)})
	}
	if it.RotationHint != nil {
		o = append(o, Member{"rotationHint", *it.RotationHint})
	}
	return o
}

// Canonical is canonicalJson: keys sorted (UTF-16 order), arrays in order,
// no whitespace, JSON.stringify's string escaping; numbers are integers.
func Canonical(v any) []byte {
	var b bytes.Buffer
	canonical(&b, v)
	return b.Bytes()
}

func canonical(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		quote(b, x)
	case float64:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case int:
		b.WriteString(strconv.Itoa(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			canonical(b, e)
		}
		b.WriteByte(']')
	case Object:
		keys := x.keys()
		slices.SortStableFunc(keys, func(a, b string) int {
			switch {
			case less(a, b):
				return -1
			case less(b, a):
				return 1
			}
			return 0
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, k)
			b.WriteByte(':')
			v, _ := x.get(k)
			canonical(b, v)
		}
		b.WriteByte('}')
	}
}

// Bytes are the Contract's canonical bytes (canonicalContractBytes).
func (c Contract) Bytes() []byte { return Canonical(c.Value()) }

// Hash is the content hash, "sha256:<lowercase hex>" over the canonical
// bytes (contractHash).
func (c Contract) Hash() string {
	sum := sha256.Sum256(c.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}
