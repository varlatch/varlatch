// SPDX-License-Identifier: AGPL-3.0-or-later

package audit

import (
	"strings"

	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// The extraction rules of the exposure index (ADR-0052 Decision 6),
// audit/exposure.ts: shared by live indexing (Record) and, later, the
// backfill of older events, so the two can never disagree.

// Ways a person came to hold a value.
const (
	Revealed  = "revealed"
	Delivered = "delivered"
	Exported  = "export"
	Written   = "written"
)

// ExposureItem is one value version.
type ExposureItem struct {
	ItemName  string `json:"itemName"`
	VersionID string `json:"versionId"`
}

// ExposureEntry is what an event says a person received.
type ExposureEntry struct {
	OrganizationID string         `json:"organizationId"`
	IdentityID     string         `json:"identityId"`
	EnvironmentID  string         `json:"environmentId"`
	Way            string         `json:"way"`
	Items          []ExposureItem `json:"items"`
}

// Indexable is the shape of an event the rules read: as recorded, or as a
// stored row.
type Indexable struct {
	EventType       string
	ActorIdentityID *string
	OrganizationID  *string
	Resource        jsvalue.Object
	Metadata        jsvalue.Object
}

// ParseItems reads a disclosure's metadata.items: NAME@version and
// NAME@primary+retiring entries, separated by commas, both versions of a
// rotation included. Anything but a non-empty string has none.
func ParseItems(items any) []ExposureItem {
	s, ok := items.(string)
	if !ok || s == "" {
		return nil
	}
	var out []ExposureItem
	for _, entry := range strings.Split(s, ",") {
		at := strings.LastIndexByte(entry, '@')
		if at <= 0 {
			continue
		}
		name := entry[:at]
		for _, v := range strings.Split(entry[at+1:], "+") {
			if v != "" {
				out = append(out, ExposureItem{name, v})
			}
		}
	}
	return out
}

func stringField(o jsvalue.Object, key string) (string, bool) {
	v, _ := o.Get(key)
	s, ok := v.(string)
	return s, ok
}

// ExposureFromEvent is exposureFromEvent: disclosures deliver plaintext
// (secret.disclosed and value.disclosed, every mode, reference expansion
// included); writes make a value known to its writer (value.written,
// value.rotation_started, with the version in resource.versionId).
// Validation events are not evidence of possession.
func ExposureFromEvent(e Indexable) (ExposureEntry, bool) {
	env, envOK := stringField(e.Resource, "environmentId")
	if e.ActorIdentityID == nil || *e.ActorIdentityID == "" || e.OrganizationID == nil || *e.OrganizationID == "" || !envOK {
		return ExposureEntry{}, false
	}
	entry := ExposureEntry{OrganizationID: *e.OrganizationID, IdentityID: *e.ActorIdentityID, EnvironmentID: env}
	switch e.EventType {
	case "secret.disclosed", "value.disclosed":
		items, _ := e.Metadata.Get("items")
		entry.Items = ParseItems(items)
		if len(entry.Items) == 0 {
			return ExposureEntry{}, false
		}
		mode, _ := e.Metadata.Get("mode")
		purpose, _ := e.Metadata.Get("purpose")
		// A strict retrieval (varlatch run) or a scan hands values to a
		// process; an export reads them for a file; anything else shows them.
		switch {
		case purpose == "export":
			entry.Way = Exported
		case mode == "strict-retrieval" || purpose == "scan":
			entry.Way = Delivered
		default:
			entry.Way = Revealed
		}
		return entry, true
	case "value.written", "value.rotation_started":
		version, ok1 := stringField(e.Resource, "versionId")
		item, ok2 := stringField(e.Resource, "itemName")
		if !ok1 || !ok2 {
			return ExposureEntry{}, false
		}
		entry.Way = Written
		entry.Items = []ExposureItem{{item, version}}
		return entry, true
	}
	return ExposureEntry{}, false
}
