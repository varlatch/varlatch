// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/envschema"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch contract push/activate/show` (slice 5.3b of internal
// docs/design/go-cli.md): main.ts's "contract" case and contractPush.ts, on
// lib/contract and internal/envschema (the .env.schema parser, decision 8).

const (
	contractPushUsage     = "Usage: varlatch contract push --schema <.env.schema> | --file <contract.json> [--semantics <version|latest>]"
	contractActivateUsage = "Usage: varlatch contract activate <revision-id>"
	contractUsage         = "Usage: varlatch contract <push|activate|show>"
)

func contractCommand(r *Run) error {
	sub := ""
	if len(r.Args) > 0 {
		sub = r.Args[0]
	}
	cwd, err := Cwd()
	if err != nil {
		return err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return contextError(err)
	}
	api := r.client(ctx)
	switch {
	case len(r.Args) > 0 && sub == "push":
		return r.contractPush(ctx, api)
	case len(r.Args) > 0 && sub == "activate":
		if len(r.Args) < 2 {
			return UsageOnly(contractActivateUsage)
		}
		revision := r.Args[1]
		c, err := api.get()
		if err != nil {
			return err
		}
		if _, err := c.ActivateContractRevision(context.Background(), ctx.Organization, ctx.Project, revision); err != nil {
			return err
		}
		// The id as given only when it has the server's shape: a refused or
		// mistyped argument is not repeated (go/README.md, "No message holds a
		// value").
		if serverID("rev").MatchString(revision) {
			return r.println("Activated " + revision + ".")
		}
		return r.println("Activated the revision.")
	case len(r.Args) > 0 && sub == "show":
		c, err := api.get()
		if err != nil {
			return err
		}
		active, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
		if err != nil {
			return err
		}
		// The revision as the server sent it, a sensitive item's default as
		// [redacted], every string through the composed masker and the
		// fail-safe.
		// Its sensitive defaults are values: redacted wherever the document
		// repeats them, too.
		contractDoc, _ := jsval.Get(active, "contract")
		r.holdSensitiveDefaults(contractDoc)
		return r.printValue(r.maskShown(withoutSensitiveDefaults(active)))
	}
	return UsageOnly(contractUsage)
}

// contractPush is `varlatch contract push`.
func (r *Run) contractPush(ctx *clientctx.Context, api *lazyClient) error {
	var body any
	var provenance jsjson.Object
	schemaFile, _ := flagArg(r.Args, "--schema")
	jsonFile, _ := flagArg(r.Args, "--file")
	switch {
	case schemaFile != "":
		// .env.schema: parse, then resolve env(...) names against the
		// project's live root Environments. Unknown names fail loudly, never
		// approximated; the revision stores the IDs.
		if _, err := os.Stat(schemaFile); err != nil {
			return Fail("No such file: "+schemaFile, ExitFailure)
		}
		b, err := os.ReadFile(schemaFile)
		if err != nil {
			return err
		}
		draft, err := envschema.Parse(jsval.DecodeUTF8(b))
		if err != nil {
			return Fail(err.Error(), ExitFailure)
		}
		// Its sensitive defaults are values from here on, before the
		// environment list is asked for or anything resolved.
		for _, it := range draft.Items {
			sensitive := draft.DefaultSensitive
			if it.Sensitive != nil {
				sensitive = *it.Sensitive
			}
			if sensitive && it.DefaultValue != nil {
				r.holdValue(*it.DefaultValue)
			}
		}
		var environments []envschema.Environment
		if len(draft.EnvironmentNames) > 0 {
			if environments, err = r.rootEnvironments(ctx, api); err != nil {
				return err
			}
		}
		resolved, err := envschema.Resolve(draft, environments)
		if err != nil {
			var unknown *envschema.UnknownEnvironmentNameError
			if errors.As(err, &unknown) {
				// Names the server gave: escaped (issue #119).
				return Fail(r.Secrets.ServerMessage(unknown.Error()), ExitFailure)
			}
			return err
		}
		body = contractValue(resolved.Value())
		provenance = jsjson.Object{{Key: "schemaPath", Value: schemaFile}, {Key: "adapter", Value: "varlatch-env-schema"}}
	case jsonFile != "":
		if _, err := os.Stat(jsonFile); err != nil {
			return Fail("No such file: "+jsonFile, ExitFailure)
		}
		b, err := os.ReadFile(jsonFile)
		if err != nil {
			return err
		}
		if body, err = ContractFileBody(b); err != nil {
			// The parser's message is not repeated: it may quote the file.
			return Fail("varlatch: "+jsonFile+" is not valid JSON; nothing was pushed", ExitFailure)
		}
	default:
		return UsageOnly(contractPushUsage)
	}
	// A sensitive item's default is a value: no output or diagnostic shows
	// it, a server's echo of it included.
	r.holdSensitiveDefaults(body)
	if semantics, given := flagArg(r.Args, "--semantics"); given {
		// An explicit pin; without one the server keeps the active revision's
		// version (the newest for a project's first revision).
		c, err := api.get()
		if err != nil {
			return err
		}
		meta, err := c.Meta(context.Background())
		if err != nil {
			return err
		}
		supported, _ := jsval.Get(meta, "semanticsVersions")
		list, isList := supported.([]any)
		if !jsjson.Truthy(supported) || !isList {
			return Fail("This server does not support Contract Semantics versions; it needs 0.11.0 or later.", ExitFailure)
		}
		var version float64
		if semantics == "latest" {
			version = jsMax(list)
		} else {
			n, ok := jsval.ToNumber(jsval.UTF16(semantics)) // Number(text)
			version = n
			if !ok {
				version = math.NaN()
			}
		}
		if !slices.ContainsFunc(list, func(v any) bool { f, ok := v.(float64); return ok && f == version }) {
			return UsageError("--semantics must be latest or one of this server's versions: " + Printable(joinJS(list)))
		}
		body = spread(body).Set("semanticsVersion", version)
	}
	// A type newer than the version this revision will get (integer needs
	// version 3) is refused here, naming the fix, rather than by the server
	// after the push.
	if err := r.contractVersionCheck(ctx, api, body); err != nil {
		return err
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	request := jsjson.Object{{Key: "contract", Value: body}}
	if provenance != nil {
		request = append(request, jsjson.Member{Key: "provenance", Value: provenance})
	}
	revision, err := c.PushContractRevision(context.Background(), ctx.Organization, ctx.Project, request)
	if err != nil {
		return err
	}
	id, idOK, err := read(revision, true, "id")
	if err != nil {
		return err
	}
	hash, _ := jsval.Get(revision, "contentHash")
	active, activeOK := jsval.Get(revision, "active")
	if _, isBool := active.(bool); !isBool {
		// Only the protocol's boolean: anything else is not "active".
		active, activeOK = false, false
	}
	version, versionOK := jsval.Get(revision, "semanticsVersion")
	// The server's identifiers and hash only of their shapes and holding no
	// value in flight, so redaction never rewrites one: anything else is
	// not shown (null in --json), and said once on stderr.
	rev, revOK := r.serverIdentifier(id, idOK, serverID("rev"))
	hashText, hashOK := r.serverIdentifier(hash, true, contentHash)
	if !revOK || !hashOK {
		r.eprintln("varlatch: the server's revision id or content hash is not shown: it does not have the server's shape, or it holds a value this command sends")
	}
	shownRev, shownHash := UnrecognizedID, UnrecognizedHash
	var jsonRev, jsonHash any
	if revOK {
		shownRev, jsonRev = rev, rev
	}
	if hashOK {
		shownHash, jsonHash = hashText, hashText
	}
	var shownVersion any = UnrecognizedVersion
	if f, ok := version.(float64); ok && f == math.Trunc(f) && f >= 1 && f < 1000 {
		shownVersion = f
	}
	if hasArg(r.Args, "--json") {
		doc := jsjson.Object{{Key: "id", Value: jsonRev}, {Key: "contentHash", Value: jsonHash}}
		if activeOK {
			doc = append(doc, jsjson.Member{Key: "active", Value: jsjson.Truthy(active)})
		}
		if versionOK {
			doc = append(doc, jsjson.Member{Key: "semanticsVersion", Value: shownVersion})
		}
		return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "revision", Value: doc}})
	}
	mark := ""
	if jsjson.Truthy(active) {
		mark = " [active]"
	}
	if err := r.println("Revision " + shownRev + " (" + shownHash + ")" + mark); err != nil {
		return err
	}
	versionText := "undefined"
	if versionOK {
		versionText = jsjson.String(shownVersion)
	}
	if err := r.println("Contract Semantics version " + versionText); err != nil {
		return err
	}
	if !jsjson.Truthy(active) && revOK {
		return r.println("Activate with: varlatch contract activate " + shownRev)
	}
	return nil
}

// serverIdentifier is an identifier or hash from an answer as the CLI
// shows it: a string of the server's shape that holds no value in flight
// (which redaction would rewrite), else false.
func (r *Run) serverIdentifier(v any, present bool, shape *regexp.Regexp) (string, bool) {
	s, ok := v.(string)
	if !ok || !present || !shape.MatchString(s) || r.holdsValue(s) {
		return "", false
	}
	return s, true
}

// holdsValue is whether text holds a value in flight, as it is or as
// Printable shows it.
func (r *Run) holdsValue(text string) bool {
	for _, v := range r.inFlight {
		if v != "" && (strings.Contains(text, v) || strings.Contains(text, Printable(v))) {
			return true
		}
	}
	return false
}

// ContractFileBody is the Contract `contract push --file` sends: the file
// as readFileSync(path, "utf8") and JSON.parse read it.
func ContractFileBody(b []byte) (any, error) {
	text := jsval.DecodeUTF8(b)
	// readFileSync keeps a byte order mark, and JSON.parse refuses it.
	if strings.HasPrefix(text, "\uFEFF") {
		return nil, errors.New("a byte order mark is not JSON")
	}
	return jsjson.Parse([]byte(text))
}

// holdSensitiveDefaults registers the defaultValue of each item of the
// Contract being pushed that is not marked sensitive: false as a value in
// flight (Run.holdValue).
func (r *Run) holdSensitiveDefaults(body any) {
	items, _ := jsval.Get(body, "items")
	list, _ := items.([]any)
	for _, item := range list {
		if sensitive, _ := jsval.Get(item, "sensitive"); sensitive == false {
			continue
		}
		if v, ok := jsval.Get(item, "defaultValue"); ok {
			if s, isString := v.(string); isString {
				r.holdValue(s)
			}
		}
	}
}

// withoutSensitiveDefaults is a Contract revision with the defaultValue of
// each item not marked sensitive: false shown as [redacted]; the rest as
// it is.
func withoutSensitiveDefaults(revision any) any {
	o, ok := revision.(jsjson.Object)
	if !ok {
		return revision
	}
	c, ok := o.Value("contract").(jsjson.Object)
	if !ok {
		return revision
	}
	items, ok := c.Value("items").([]any)
	if !ok {
		return revision
	}
	shown := make([]any, len(items))
	for i, item := range items {
		shown[i] = item
		fields, isObject := item.(jsjson.Object)
		if !isObject {
			continue
		}
		if sensitive, _ := fields.Get("sensitive"); sensitive == false {
			continue
		}
		if _, has := fields.Get("defaultValue"); has {
			shown[i] = append(jsjson.Object(nil), fields...).Set("defaultValue", Redacted)
		}
	}
	return append(jsjson.Object(nil), o...).Set("contract", append(jsjson.Object(nil), c...).Set("items", shown))
}

// ContractShowView is a Contract revision as `contract show` shows it:
// each sensitive item's default as [redacted] (the transcripts' accepted
// difference contract-show-sensitive-default).
func ContractShowView(revision any) any { return withoutSensitiveDefaults(revision) }

// maskShown is the composed masker over every string of a value a server
// sent: what this run knows as secret (the bearer, VARLATCH_TOKEN, the
// stored credentials, the values it sends) and every token format, before
// printValue's fail-safe.
func (r *Run) maskShown(v any) any {
	switch x := v.(type) {
	case string:
		return r.Secrets.Mask(x)
	case jsjson.Object:
		// A key holding a secret is masked as values are, and kept unique:
		// a second "[redacted]" becomes "[redacted] (2)", and so on.
		out := make(jsjson.Object, 0, len(x))
		used := map[string]bool{}
		for _, m := range x {
			key := m.Key
			if masked := RedactDiagnostic(r.Secrets.Mask(key), r.inFlight...); masked != key {
				key = masked
				for n := 2; used[key]; n++ {
					key = masked + " (" + strconv.Itoa(n) + ")"
				}
			}
			used[key] = true
			out = append(out, jsjson.Member{Key: key, Value: r.maskShown(m.Value)})
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.maskShown(e)
		}
		return out
	}
	return v
}

// rootEnvironments are the project's Environments as name resolution
// reads them: the id, the name, and whether it has a parent.
func (r *Run) rootEnvironments(ctx *clientctx.Context, api *lazyClient) ([]envschema.Environment, error) {
	c, err := api.get()
	if err != nil {
		return nil, err
	}
	answer, err := c.ListEnvironments(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		return nil, err
	}
	items, ok, err := read(answer, true, "items")
	if err != nil {
		return nil, err
	}
	list, isList := items.([]any)
	if !ok || !isList {
		return nil, &clientctx.TypeError{Message: "(intermediate value).items.map is not a function"}
	}
	out := make([]envschema.Environment, len(list))
	for i, e := range list {
		// The protocol's types only (Environment: id and name strings, a
		// parent id a string or null): anything else is refused before it
		// could become an id in the Contract.
		fields, isObject := e.(jsjson.Object)
		id, idOK := fields.Get("id")
		name, nameOK := fields.Get("name")
		parent, parentOK := fields.Get("parentEnvironmentId")
		idText, idIsString := id.(string)
		nameText, nameIsString := name.(string)
		parentText, parentIsString := parent.(string)
		if !isObject || !idOK || !idIsString || !nameOK || !nameIsString || parentOK && parent != nil && !parentIsString {
			return nil, Fail("varlatch: the server's list of environments has an unexpected shape (items["+strconv.Itoa(i)+"]); nothing was pushed", ExitFailure)
		}
		out[i] = envschema.Environment{ID: idText, Name: nameText, HasParent: parentIsString, ParentID: parentText}
	}
	return out, nil
}

// contractVersionCheck is main.ts's check with contractPush.ts's
// versionNeeded and pushVersionProblem: every item type must exist at the
// semantics version the revision will get (ADR-0042), said before anything
// is sent.
func (r *Run) contractVersionCheck(ctx *clientctx.Context, api *lazyClient, body any) error {
	items, present, err := read(body, true, "items")
	if err != nil {
		return err
	}
	list, isList := items.([]any)
	if !present || items == nil || !isList {
		return nil
	}
	needed := 1
	var naming []string
	for _, item := range list {
		t, tOK, err := read(item, true, "type")
		if err != nil {
			return err
		}
		since := 1
		if s, ok := t.(string); ok {
			if v, known := contract.TypeSince[s]; known {
				since = v
			}
		}
		needed = max(needed, since)
		if since > 1 {
			name, nameOK, _ := read(item, true, "name")
			naming = append(naming, jsTemplate(name, nameOK)+" ("+jsTemplate(t, tOK)+")")
		}
	}
	if needed == 1 {
		return nil
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	meta, err := c.Meta(context.Background())
	if err != nil {
		return err
	}
	serverVersions := []any{float64(1)}
	if v, ok := jsval.Get(meta, "semanticsVersions"); ok && v != nil {
		if list, isList := v.([]any); isList {
			serverVersions = list
		}
	}
	var activeVersion *float64
	revision, err := c.GetActiveContract(context.Background(), ctx.Organization, ctx.Project)
	if err != nil {
		var a *apiclient.APIError
		if !errors.As(err, &a) || a.Status != 404 {
			return err
		}
	} else {
		v := float64(1)
		if s, ok := jsval.Get(revision, "semanticsVersion"); ok && s != nil {
			if f, isNumber := s.(float64); isNumber {
				v = f
			}
		}
		activeVersion = &v
	}
	var pinned *float64
	if p, ok := jsval.Get(body, "semanticsVersion"); ok {
		if f, isNumber := p.(float64); isNumber {
			pinned = &f
		}
	}
	newest := jsMax(serverVersions)
	names := strings.Join(naming, ", ")
	if newest < float64(needed) {
		return Fail("varlatch contract push: "+names+" needs Contract Semantics version "+jsjson.Number(float64(needed))+
			", which this server does not evaluate (it supports "+Printable(joinJS(serverVersions))+"); upgrade it to Varlatch 0.13.0 or later. Nothing was pushed.", ExitFailure)
	}
	version, why := newest, "the active revision's version, which a push keeps"
	switch {
	case pinned != nil:
		version, why = *pinned, "the version this push pins"
	case activeVersion != nil:
		version = *activeVersion
	}
	if version >= float64(needed) {
		return nil
	}
	return Fail("varlatch contract push: "+names+" needs Contract Semantics version "+jsjson.Number(float64(needed))+
		", but this revision would get version "+jsjson.Number(version)+" ("+why+"). Push with --semantics latest to move the Contract to the newest rules, then activate the revision; "+
		"or move it on the dashboard's Contract page first. Nothing was pushed.", ExitFailure)
}

// jsMax is Math.max(...list) for a list of JSON values: NaN when one is not
// a number (null counts as 0, as ToNumber reads it), -Infinity when empty.
func jsMax(list []any) float64 {
	m := math.Inf(-1)
	for _, v := range list {
		var f float64
		switch x := v.(type) {
		case float64:
			f = x
		case nil:
			f = 0
		case bool:
			if x {
				f = 1
			}
		case string:
			n, ok := jsval.ToNumber(jsval.UTF16(x))
			if !ok {
				return math.NaN()
			}
			f = n
		default:
			return math.NaN()
		}
		if math.IsNaN(f) {
			return f
		}
		m = math.Max(m, f)
	}
	return m
}

// joinJS is Array.prototype.join(", ") for JSON values: null as "".
func joinJS(list []any) string {
	parts := make([]string, len(list))
	for i, v := range list {
		if v != nil {
			parts[i] = jsjson.String(v)
		}
	}
	return strings.Join(parts, ", ")
}

// contractValue is a lib/contract value as a lib/jsjson one, members in order.
func contractValue(v any) any {
	switch x := v.(type) {
	case contract.Object:
		out := make(jsjson.Object, len(x))
		for i, m := range x {
			out[i] = jsjson.Member{Key: m.Key, Value: contractValue(m.Value)}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = contractValue(e)
		}
		return out
	}
	return v
}
