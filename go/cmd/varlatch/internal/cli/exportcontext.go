// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strconv"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch run --export-context` (apps/cli/src/exportContext.ts): a
// default run that also gives the command VARLATCH_RUN_CONTEXT, with mode
// "exported", so the Typed Accessor can enforce per-Environment
// requiredness and tell withheld items from absent ones. Names and
// identifiers only, never values.

// runContextName is RUN_CONTEXT: reserved launcher metadata. Every run
// removes an inherited one, and no stored value is injected under it.
const runContextName = "VARLATCH_RUN_CONTEXT"

// runContextMaxBytes is RUN_CONTEXT_MAX_BYTES: the context is never
// truncated.
const runContextMaxBytes = 64 * 1024

// exportContextAttempts is EXPORT_CONTEXT_ATTEMPTS.
const exportContextAttempts = 3

// exportContextError is ExportContextError: the run refuses to start,
// status 1.
func exportContextError(message string) error {
	return Fail("varlatch: "+message+". Nothing was started.", ExitFailure)
}

// configurationRead is one read of a default run: the Effective
// Configuration's stateDigest, the disclosure's (nil when nothing was
// disclosed, apiclient.Undefined when the answer had none), and the result.
type configurationRead struct {
	configurationDigest, disclosureDigest any
	effective                             any
	encode                                runContextEncoder
}

// readConsistently is readConsistently: the two requests of a run (the
// Effective Configuration, then the disclosure) agree on their state digest,
// or both are made again, up to exportContextAttempts reads in all; each
// read discloses, and is audited, again.
func (r *Run) readConsistently(read func() (configurationRead, error)) (configurationRead, error) {
	for attempt := 1; ; attempt++ {
		got, err := read()
		if err != nil {
			return got, err
		}
		if got.disclosureDigest == nil {
			return got, nil
		}
		if got.disclosureDigest != apiclient.Undefined && jsval.StrictEqual(got.disclosureDigest, got.configurationDigest) {
			return got, nil
		}
		if attempt >= exportContextAttempts {
			return got, exportContextError("the configuration changed between reading it and disclosing its Secrets, on each of " +
				strconv.Itoa(exportContextAttempts) + " attempts, so the run context could not describe the values delivered")
		}
		r.eprintln("varlatch: the configuration changed between reading it and disclosing its Secrets; reading both again " +
			"(attempt " + strconv.Itoa(attempt+1) + " of " + strconv.Itoa(exportContextAttempts) + ", another audited disclosure)")
	}
}

// exportedRunContext is exportedRunContext: for each Contract item, what
// the server did and how a default run delivered it.
func exportedRunContext(revision, environment, contractDoc, delivered any, parent parentVars, omitted map[string]bool) jsjson.Object {
	byName := map[string]any{}
	for _, item := range listOf(delivered, "items") {
		if name, ok := stringField(item, "name"); ok {
			byName[name] = item
		}
	}
	items := jsjson.Object{}
	for _, item := range listOf(contractDoc, "items") {
		name := jsjson.String(fieldOf(item, "name"))
		if name == runContextName {
			continue
		}
		got, stored := byName[name]
		left := omitted[name]
		value, hasValue := jsval.Get(got, "value")
		withheld := stored && !(hasValue && value != nil) && !(left && jsjson.Truthy(fieldOf(got, "sensitive")))
		server := "delivered"
		switch {
		case !stored:
			server = "notStored"
		case withheld:
			server = "withheld"
		}
		delivery := "absent"
		_, inherited := parent.lookup(name)
		switch {
		case left:
		case server == "delivered":
			delivery = "varlatch"
		case inherited:
			delivery = "inherited"
		}
		items = items.Set(name, jsjson.Object{{Key: "server", Value: server}, {Key: "delivery", Value: delivery}})
	}
	return jsjson.Object{
		{Key: "v", Value: float64(1)},
		{Key: "mode", Value: "exported"},
		{Key: "contractRevisionId", Value: fieldOf(revision, "revisionId")},
		{Key: "contractHash", Value: fieldOf(revision, "contentHash")},
		{Key: "semanticsVersion", Value: fieldOf(revision, "semanticsVersion")},
		{Key: "environment", Value: jsjson.Object{{Key: "rootId", Value: fieldOf(environment, "rootId")}, {Key: "tier", Value: fieldOf(environment, "tier")}}},
		{Key: "items", Value: items},
	}
}

// encodeRunContext is encodeRunContext: the context as the command
// receives it, or false when it would exceed the bound.
func encodeRunContext(ctx jsjson.Object) (string, bool) {
	encoded := jsval.NodeText(string(jsjson.Stringify(ctx)))
	return encoded, len(encoded) <= runContextMaxBytes
}

// runContextEncoder builds the context once the environment is built.
type runContextEncoder func(delivered any, parent parentVars, omitted map[string]bool) (string, error)

// prepareExportedContext is prepareExportedContext: after the Effective
// Configuration and before any Secret is disclosed, so a run that cannot
// export its context discloses nothing. The Contract is fetched by the
// revision ID the manifest names.
func (r *Run) prepareExportedContext(c *apiclient.Client, org, project string, effective any) (runContextEncoder, error) {
	manifest := fieldOf(effective, "manifest")
	if !jsjson.Truthy(manifest) || !jsjson.Truthy(fieldOf(effective, "stateDigest")) {
		return nil, exportContextError("--export-context needs a server that returns a state manifest with the configuration: Varlatch 0.11.0 or later")
	}
	revision := fieldOf(manifest, "contract")
	if !jsjson.Truthy(revision) {
		return nil, exportContextError("--export-context needs an active Contract")
	}
	fetched, err := c.GetContractRevision(context.Background(), org, project, jsjson.String(fieldOf(revision, "revisionId")))
	var apiErr *apiclient.APIError
	if errors.As(err, &apiErr) && (apiErr.Status == 403 || apiErr.Status == 404) {
		return nil, exportContextError("--export-context needs contract.read on the project, to list the Contract's items")
	} else if err != nil {
		return nil, err
	}
	contractDoc := fieldOf(fetched, "contract")
	if _, isList := fieldOf(contractDoc, "items").([]any); !jsval.StrictEqual(fieldOf(fetched, "contentHash"), fieldOf(revision, "contentHash")) || !jsjson.Truthy(contractDoc) || !isList {
		return nil, exportContextError("--export-context could not read the Contract Revision the configuration names")
	}
	environment := fieldOf(manifest, "environment")
	tooLarge := "the run context would exceed " + strconv.Itoa(runContextMaxBytes) + " bytes; it is never truncated"
	// The size depends on names only: the longest form (every item not
	// stored and inherited), checked before anything is disclosed.
	longest := map[string]string{}
	for _, item := range listOf(contractDoc, "items") {
		longest[jsjson.String(fieldOf(item, "name"))] = ""
	}
	empty := jsjson.Object{{Key: "environmentId", Value: ""}, {Key: "items", Value: []any{}}}
	if _, ok := encodeRunContext(exportedRunContext(revision, environment, contractDoc, empty, parentVars{values: longest}, nil)); !ok {
		return nil, exportContextError(tooLarge)
	}
	return func(delivered any, parent parentVars, omitted map[string]bool) (string, error) {
		encoded, ok := encodeRunContext(exportedRunContext(revision, environment, contractDoc, delivered, parent, omitted))
		if !ok {
			return "", exportContextError(tooLarge)
		}
		return encoded, nil
	}, nil
}

// parentVars is this process's environment as process.env reads it: the
// values, and the names in the order the process got them (on Windows,
// the environment block's order).
type parentVars struct {
	names  []string
	values map[string]string
}

// lookup is process.env[name]: by exact name, or on Windows without case,
// the first such name in the process's order, as GetEnvironmentVariableW
// finds it.
func (p parentVars) lookup(name string) (string, bool) {
	if v, ok := p.values[name]; ok {
		return v, true
	}
	for _, k := range p.names {
		if envNameEqual(k, name) {
			return p.values[k], true
		}
	}
	return "", false
}
