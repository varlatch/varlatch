// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch member` (capability members.lifecycle, ADR-0052), from main.ts
// and members.ts: people in the organization, with former members marked;
// removal and leaving name their target again with --confirm.

const (
	membersCapability = "members.lifecycle"
	memberUsage       = "Usage: varlatch member <list [--json]|remove <member> --confirm <member>|leave --confirm <organization>|role <member> admin|member|exposure <member> [--json]> [--server <url>]"
)

// field of a server's object, leniently: undefined when x is not one.
func fld(x any, key string) (any, bool) { return jsval.Get(x, key) }

// isMember is members.ts's isMember: a person with a role here, not removed.
func isMember(i any) bool {
	kind, _ := fld(i, "kind")
	role, roleOK := fld(i, "orgRole")
	removed, removedOK := fld(i, "removedAt")
	return kind == "human" && roleOK && jsjson.Truthy(role) && !(removedOK && jsjson.Truthy(removed))
}

// resolveMember is members.ts's resolveMember: an identity ID, or the exact
// name of exactly one live member; an ID is matched first, so a former
// member's or a machine's is refused, never read as a name.
func resolveMember(identities []any, arg string) (any, error) {
	for _, i := range identities {
		if id, _ := fld(i, "id"); id == arg {
			if isMember(i) {
				return i, nil
			}
			kind, kindOK := fld(i, "kind")
			removed, removedOK := fld(i, "removedAt")
			what := "not a member"
			switch {
			case kind != "human":
				what = "a " + jsTemplate(kind, kindOK) + " identity"
			case removedOK && jsjson.Truthy(removed):
				what = "a former member"
			}
			name, nameOK := fld(i, "name")
			return nil, Fail(Printable(arg)+" ("+text(name, nameOK)+") is "+Printable(what)+", not a member of this organization. Nothing was changed.", ExitFailure)
		}
	}
	var named []any
	for _, i := range identities {
		if name, _ := fld(i, "name"); isMember(i) && name == arg {
			named = append(named, i)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		return nil, Fail("Several members are named "+Printable(arg)+"; name one by its identity ID: "+Printable(shownValue(idList(named)))+". Nothing was changed.", ExitFailure)
	}
	return nil, Fail(arg+" is not a member of this organization (varlatch member list shows who is). Nothing was changed.", ExitFailure)
}

// resolvePerson is members.ts's resolvePerson: a current or former member,
// for the exposure report.
func resolvePerson(identities []any, arg string) (any, error) {
	isPerson := func(i any) bool {
		kind, _ := fld(i, "kind")
		role, roleOK := fld(i, "orgRole")
		removed, removedOK := fld(i, "removedAt")
		return kind == "human" && (roleOK && jsjson.Truthy(role) || removedOK && jsjson.Truthy(removed))
	}
	for _, i := range identities {
		if id, _ := fld(i, "id"); id == arg {
			if isPerson(i) {
				return i, nil
			}
			kind, kindOK := fld(i, "kind")
			what := "not a member"
			if kind != "human" {
				what = "a " + jsTemplate(kind, kindOK) + " identity"
			}
			name, nameOK := fld(i, "name")
			return nil, Fail(Printable(arg)+" ("+text(name, nameOK)+") is "+Printable(what)+", never a member of this organization.", ExitFailure)
		}
	}
	var named []any
	for _, i := range identities {
		if name, _ := fld(i, "name"); isPerson(i) && name == arg {
			named = append(named, i)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		return nil, Fail("Several people are named "+Printable(arg)+"; name one by its identity ID: "+Printable(shownValue(idList(named)))+".", ExitFailure)
	}
	return nil, Fail(arg+" is not a current or former member of this organization (varlatch member list shows who is).", ExitFailure)
}

func idList(xs []any) string {
	ids := make([]string, len(xs))
	for i, x := range xs {
		v, ok := fld(x, "id")
		ids[i] = jsTemplate(v, ok)
	}
	return strings.Join(ids, ", ")
}

// memberCommand is `varlatch member list|remove|leave|role|exposure`.
func memberCommand(r *Run) error {
	sub, hasSub := arg(r.Args, 0)
	positionals := 1
	switch sub {
	case "role":
		positionals = 3
	case "remove", "exposure":
		positionals = 2
	}
	command := "member"
	if hasSub {
		command = strings.TrimSpace("member " + sub)
	}
	parsed, err := strictOptions(command, r.Args, OptionSpec{Values: []string{"--server", "--confirm"}, Booleans: []string{"--json"}, Positionals: positionals}, memberUsage)
	if err != nil {
		return err
	}
	switch sub {
	case "list", "remove", "leave", "role", "exposure":
	default:
		return UsageOnly(memberUsage)
	}
	if parsed.Has("--json") && sub != "list" && sub != "exposure" {
		return UsageErrorWithUsage("varlatch member "+sub+": --json is for member list and member exposure.", "\n"+memberUsage)
	}
	confirm, confirmGiven := parsed.Values["--confirm"]
	if sub == "exposure" && confirmGiven {
		return UsageErrorWithUsage("varlatch member exposure: the report is read-only and needs no --confirm.", "\n"+memberUsage)
	}
	server, serverGiven := parsed.Values["--server"]
	ctx, lazy, err := r.orgContext(server, serverGiven)
	if err != nil {
		return err
	}
	serverOption := ""
	if serverGiven || r.Getenv("VARLATCH_SERVER") != "" {
		serverOption = " --server " + shellWord(shownServer(lazy.server))
	}
	org := ctx.Organization
	if sub == "list" {
		api, err := lazy.get()
		if err != nil {
			return err
		}
		page, err := api.ListIdentities(bg, org)
		if err != nil {
			return err
		}
		all, err := pageItems(page, "(await api.listIdentities(ctx.organization))", "filter")
		if err != nil {
			return err
		}
		var people []any
		for _, i := range all {
			kind, _, err := get(i, "kind")
			if err != nil {
				return err
			}
			if kind == "human" {
				people = append(people, i)
			}
		}
		if parsed.Has("--json") {
			members := make([]any, len(people))
			for n, p := range people {
				o, err := pick(p, "id", "name")
				if err != nil {
					return err
				}
				removed, removedOK, _ := get(p, "removedAt")
				role, roleOK, _ := get(p, "orgRole")
				seen, seenOK, _ := get(p, "lastSeenAt")
				var shownRole any
				if !(removedOK && jsjson.Truthy(removed)) {
					shownRole = orNull(role, roleOK)
				}
				members[n] = append(o, jsjson.Member{Key: "role", Value: shownRole}, jsjson.Member{Key: "removedAt", Value: orNull(removed, removedOK)}, jsjson.Member{Key: "lastSeenAt", Value: orNull(seen, seenOK)})
			}
			return r.printDoc(jsjson.Object{{Key: "organization", Value: org}, {Key: "members", Value: members}})
		}
		for _, p := range people {
			id, idOK, _ := get(p, "id")
			name, nameOK, _ := get(p, "name")
			removed, removedOK, _ := get(p, "removedAt")
			role, roleOK, _ := get(p, "orgRole")
			seen, seenOK, _ := get(p, "lastSeenAt")
			state := "no role"
			if removedOK && jsjson.Truthy(removed) {
				state = "former member, left " + timeOr(removed, true, "undefined")
			} else if roleOK && role != nil {
				state = jsTemplate(role, true)
			}
			if err := r.println(text(id, idOK) + "  " + text(name, nameOK) + "  (" + Printable(shownValue(state)) + ", last seen " + Printable(timeOr(seen, seenOK, "never")) + ")"); err != nil {
				return err
			}
		}
		if len(people) == 0 {
			return r.println("(none)")
		}
		return nil
	}
	if sub == "exposure" {
		return r.memberExposure(lazy, org, parsed)
	}
	target := org
	if sub != "leave" {
		if len(parsed.Positionals) < 2 {
			return UsageOnly(memberUsage)
		}
		target = parsed.Positionals[1]
	}
	if sub == "role" {
		if confirmGiven {
			return UsageErrorWithUsage("varlatch member role: a role change needs no --confirm.", "\n"+memberUsage)
		}
		if len(parsed.Positionals) < 3 || parsed.Positionals[2] != "admin" && parsed.Positionals[2] != "member" {
			return UsageOnly(memberUsage)
		}
	} else if confirmGiven && confirm != target {
		verb := "removes"
		if sub == "leave" {
			verb = "leaves"
		}
		return UsageErrorWithUsage("varlatch member "+sub+": --confirm names "+confirm+", but this command "+verb+" "+target+"; "+
			"approval for one never covers another.", "\n"+memberUsage)
	} else if !confirmGiven {
		// Removing someone, or leaving, is the human's decision: the target
		// is named again with --confirm, checked before any request.
		quoted := shellWord(target)
		rerun := "varlatch member remove " + quoted + " --confirm " + quoted + serverOption
		what := "Removing " + target + " ends their access to " + org
		whom := "them"
		if sub == "leave" {
			rerun = "varlatch member leave --confirm " + quoted + serverOption
			what = "Leaving " + target + " ends your access to it"
			whom = "the organization"
		}
		if r.Assisted.On {
			return Fail("varlatch member "+sub+": "+what+"; that is the human's decision. With their approval, add --confirm "+target+". "+
				"Or the human runs, in their own terminal:\n  "+rerun+"\nNothing was changed.", ExitConfig)
		}
		return UsageError(what + ". Name " + whom + " again to confirm:\n  " + rerun + "\nNothing was changed.")
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	has, version, err := r.capable(api, membersCapability)
	if err != nil {
		return err
	}
	if !has {
		return Fail("This server ("+version+") cannot remove members or change their role; that needs Varlatch 0.20.0 or later. Nothing was changed.", ExitFailure)
	}
	if sub == "leave" {
		removal, err := api.RemoveMember(bg, org, "me")
		if err != nil {
			return err
		}
		return r.printLines(removalLines(removal, "you", org))
	}
	page, err := api.ListIdentities(bg, org)
	if err != nil {
		return err
	}
	identities, err := pageItems(page, "(await api.listIdentities(ctx.organization))", "find")
	if err != nil {
		return err
	}
	who, err := resolveMember(identities, target)
	if err != nil {
		return err
	}
	whoID, whoIDOK := fld(who, "id")
	whoName, whoNameOK := fld(who, "name")
	if sub == "remove" {
		removal, err := api.RemoveMember(bg, org, jsTemplate(whoID, whoIDOK))
		if err != nil {
			return err
		}
		return r.printLines(removalLines(removal, sv(whoName, whoNameOK), org))
	}
	role := parsed.Positionals[2]
	changed, err := api.ChangeMemberRole(bg, org, jsTemplate(whoID, whoIDOK), role)
	if err != nil {
		return err
	}
	previous, previousOK, err := get(changed, "previousRole")
	if err != nil {
		return err
	}
	now, nowOK, _ := get(changed, "role")
	name := Printable(shownValue(jsTemplate(whoName, whoNameOK)))
	switch {
	case jsval.StrictEqual(orUndefined(previous, previousOK), orUndefined(now, nowOK)):
		article := "a member"
		if role == "admin" {
			article = "an admin"
		}
		return r.println(name + " is already " + article + " of " + org + ". Nothing was changed.")
	case role == "admin":
		return r.println(name + " is now an admin of " + org + ".")
	}
	return r.println(name + " is now a member of " + org + ". Grants given to them directly or through groups stay; " +
		"review them in the dashboard's Access page.")
}

// orUndefined is v, or apiclient.Undefined when it is not there.
func orUndefined(v any, ok bool) any {
	if !ok {
		return apiclient.Undefined
	}
	return v
}

func (r *Run) printLines(lines []string) error {
	for _, line := range lines {
		if err := r.println(line); err != nil {
			return err
		}
	}
	return nil
}

// memberExposure is `varlatch member exposure <member> [--json]`
// (ADR-0052 Decision 8): read-only; names, versions and states, never a
// value.
func (r *Run) memberExposure(lazy *lazyAPI, org string, parsed *ParsedOptions) error {
	if len(parsed.Positionals) < 2 {
		return UsageOnly(memberUsage)
	}
	target := parsed.Positionals[1]
	api, err := lazy.get()
	if err != nil {
		return err
	}
	has, version, err := r.capable(api, membersCapability)
	if err != nil {
		return err
	}
	if !has {
		return Fail("This server ("+version+") has no exposure report; that needs Varlatch 0.20.0 or later.", ExitFailure)
	}
	// An identity ID (or "me") goes to the report as it is; only a name is
	// resolved, through the identity listing.
	id := target
	if target != "me" && !identityID.MatchString(target) {
		page, err := api.ListIdentities(bg, org)
		if err != nil {
			return err
		}
		identities, err := pageItems(page, "(await api.listIdentities(ctx.organization))", "filter")
		if err != nil {
			return err
		}
		person, err := resolvePerson(identities, target)
		if err != nil {
			return err
		}
		v, ok := fld(person, "id")
		id = jsTemplate(v, ok)
	}
	report, err := api.MemberExposure(bg, org, id)
	if err != nil {
		return err
	}
	if parsed.Has("--json") {
		// NDJSON: one record per line, the member and coverage first.
		line := func(doc jsjson.Object) error { return r.outJSONLine(doc) }
		m, _ := fld(report, "member")
		coverage, coverageOK := fld(report, "coverage")
		first := jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "kind", Value: "member"}, {Key: "organization", Value: org}}
		for _, x := range spread(m) {
			first = first.Set(x.Key, x.Value)
		}
		// `coverage: report.coverage` after the spread: in place when the
		// member has the key, else last; left out when undefined.
		if coverageOK {
			first = first.Set("coverage", coverage)
		} else {
			kept := jsjson.Object{}
			for _, x := range first {
				if x.Key != "coverage" {
					kept = append(kept, x)
				}
			}
			first = kept
		}
		if err := line(first); err != nil {
			return err
		}
		received, _ := fld(report, "received")
		for _, v := range list(received) {
			if err := line(withKind("received", nil, v)); err != nil {
				return err
			}
		}
		authority, _ := fld(report, "authorityAtRemoval")
		if jsjson.Truthy(authority) {
			removalID, removalIDOK := fld(authority, "removalId")
			removedAt, removedAtOK := fld(authority, "removedAt")
			envs, _ := fld(authority, "environments")
			for _, e := range list(envs) {
				head := member(member(jsjson.Object{}, "removalId", removalID, removalIDOK), "removedAt", removedAt, removedAtOK)
				if err := line(withKind("authority", head, e)); err != nil {
					return err
				}
			}
			reqs, _ := fld(authority, "requirements")
			for _, q := range list(reqs) {
				head := member(jsjson.Object{}, "removalId", removalID, removalIDOK)
				if err := line(withKind("requirement", head, q)); err != nil {
					return err
				}
			}
		}
		indirect, _ := fld(report, "indirect")
		return line(withKind("indirect", nil, indirect))
	}
	// Environment names for the IDs the report holds, when the caller may
	// list them; otherwise, or for a deleted one, the ID stays.
	names := map[string]string{}
	if projects, err := api.ListProjects(bg, org); err == nil {
		items, _ := fld(projects, "items")
		for _, p := range list(items) {
			slug, slugOK := fld(p, "slug")
			envs, err := api.ListEnvironments(bg, org, jsTemplate(slug, slugOK))
			if err != nil {
				if !isAPIError(err) {
					return err
				}
				continue
			}
			envItems, _ := fld(envs, "items")
			for _, e := range list(envItems) {
				id, idOK := fld(e, "id")
				name, nameOK := fld(e, "name")
				if idOK {
					names[jsTemplate(id, true)] = sv(slug, slugOK) + " / " + sv(name, nameOK)
				}
			}
		}
	} else if !isAPIError(err) {
		return err
	}
	envName := func(id any) string {
		if id == nil || id == apiclient.Undefined || !jsjson.Truthy(id) {
			return "an unknown environment"
		}
		s := jsTemplate(id, true)
		if n, ok := names[s]; ok {
			return n
		}
		return shownValue(s)
	}
	return r.printLines(exposureLines(r, report, envName))
}

func isAPIError(err error) bool {
	var apiErr *apiclient.APIError
	return errors.As(err, &apiErr)
}

// withKind is `{ kind, ...head, ...rest }`: a NDJSON record.
func withKind(kind string, head jsjson.Object, rest any) jsjson.Object {
	out := jsjson.Object{{Key: "kind", Value: kind}}
	for _, m := range head {
		out = out.Set(m.Key, m.Value)
	}
	for _, m := range spread(rest) {
		out = out.Set(m.Key, m.Value)
	}
	return out
}

// outJSONLine is console.log(JSON.stringify(doc)): one NDJSON record, every
// string through the fail-safe (RedactValue).
func (r *Run) outJSONLine(doc jsjson.Object) error {
	redacted, err := RedactValue(doc, r.inFlight...)
	if err != nil {
		return err
	}
	return r.println(string(jsjson.Stringify(redacted)))
}

var wayWords = map[string]string{
	"revealed":  "revealed",
	"delivered": "delivered to a process",
	"export":    "read for export",
	"written":   "written by them",
}

// stateWords is members.ts's stateWords: a version's state, in words.
func stateWords(v any) string {
	servedAs, _ := fld(v, "servedAs")
	var base string
	switch servedAs {
	case "current":
		base = "still served (current)"
	case "retiring":
		until, untilOK := fld(v, "retiringUntil")
		base = "still served (retiring until " + timeOr(until, untilOK, UnrecognizedTime) + ")"
	default:
		why, whyOK := fld(v, "notServedBecause")
		key := "unknown"
		if whyOK && why != nil {
			key = sv(why, true)
		}
		base = map[string]string{
			"replaced":            "no longer served (replaced)",
			"value-deleted":       "no longer served (value deleted)",
			"environment-deleted": "no longer served (environment deleted)",
			"unknown":             "unknown here",
		}[key]
		if base == "" {
			base = "undefined"
		}
	}
	confirmation, _ := fld(v, "confirmation")
	if jsjson.Truthy(confirmation) {
		at, atOK := fld(confirmation, "confirmedAt")
		return "revoked at the provider, confirmed " + timeOr(at, atOK, UnrecognizedTime) + "; " + base
	}
	return base
}

// requirementWords is members.ts's requirementWords: a Requirement as it
// was defined at removal, in words.
func requirementWords(req any) string {
	target, _ := fld(req, "target")
	selector, selectorOK := fld(req, "selector")
	if !selectorOK || selector == nil {
		selector = jsjson.Object{}
	}
	kind, _ := fld(target, "kind")
	on := "its target"
	switch kind {
	case "tier":
		tier, tierOK := fld(target, "tier")
		on = "the " + sv(tier, tierOK) + " tier"
	case "environments":
		ids, _ := fld(target, "environmentIds")
		on = "environments " + joinStrings(list(ids), ", ")
	}
	var by []string
	for _, s := range []struct{ key, word string }{{"tags", "tags"}, {"users", "users"}, {"nodes", "nodes"}} {
		v, _ := fld(selector, s.key)
		if len(list(v)) > 0 {
			by = append(by, s.word+" "+joinStrings(list(v), ", "))
		}
	}
	tailnet, tailnetOK := fld(selector, "tailnet")
	in := "a tailnet"
	if tailnetOK && tailnet != nil {
		in = sv(tailnet, true)
	}
	words := "on " + on + ", a device in " + in
	if len(by) > 0 {
		words += " with " + strings.Join(by, " or ")
	}
	return words
}

// joinStrings is Array.prototype.join: null and undefined as "".
func joinStrings(xs []any, sep string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		if x != nil && x != apiclient.Undefined {
			parts[i] = shownValue(jsjson.String(x))
		}
	}
	return strings.Join(parts, sep)
}

// exposureLines is members.ts's exposureLines: what they received, what
// they could reach at removal, what is not covered, and what they set up.
func exposureLines(r *Run, report any, envName func(any) string) []string {
	m, _ := fld(report, "member")
	name, nameOK := fld(m, "name")
	removed, removedOK := fld(m, "removedAt")
	role, roleOK := fld(m, "role")
	state := "no role"
	if removedOK && jsjson.Truthy(removed) {
		state = "former member, removed " + timeOr(removed, true, "undefined")
	} else if roleOK && role != nil {
		state = sv(role, true)
	}
	lines := []string{"Exposure report for " + sv(name, nameOK) + " (" + state + ")."}
	coverage, _ := fld(report, "coverage")
	if complete, _ := fld(coverage, "complete"); !jsjson.Truthy(complete) {
		from, fromOK := fld(coverage, "from")
		to, toOK := fld(coverage, "to")
		lines = append(lines, "Older history is still being indexed: events from "+timeOr(from, fromOK, "?")+" to "+timeOr(to, toOK, "?")+" are not covered yet.")
	}
	lines = append(lines, "", "Received (observed in the audit log; a delivery is not proof that a copy was kept):")
	received, _ := fld(report, "received")
	if len(list(received)) == 0 {
		lines = append(lines, "  nothing")
	}
	anyUnsafe := false
	for _, v := range list(received) {
		item, itemOK := fld(v, "itemName")
		ver, verOK := fld(v, "versionId")
		owning, _ := fld(v, "owningEnvironmentId")
		lines = append(lines, "  "+sv(item, itemOK)+"  "+sv(ver, verOK)+"  in "+envName(owning)+": "+stateWords(v))
		receipts, _ := fld(v, "receipts")
		for _, rc := range list(receipts) {
			env, _ := fld(rc, "environmentId")
			through := ""
			if !jsval.StrictEqual(env, owning) {
				through = " through " + envName(env)
			}
			way, wayOK := fld(rc, "way")
			words, known := wayWords[sv(way, wayOK)]
			if !known {
				words = sv(way, wayOK)
			}
			first, firstOK := fld(rc, "firstAt")
			last, lastOK := fld(rc, "lastAt")
			when := timeOr(first, firstOK, "undefined")
			if !jsval.StrictEqual(orUndefined(first, firstOK), orUndefined(last, lastOK)) {
				when = timeOr(first, firstOK, "undefined") + " to " + timeOr(last, lastOK, "undefined")
			}
			lines = append(lines, "    "+words+through+", "+when)
		}
		hint, _ := fld(v, "rotationHint")
		served, _ := fld(v, "served")
		if jsjson.Truthy(hint) && jsjson.Truthy(served) {
			lines = append(lines, "    to rotate: "+r.Secrets.ServerMessage(jsjson.String(hint)))
		}
		confirmation, _ := fld(v, "confirmation")
		if !jsjson.Truthy(served) && !jsjson.Truthy(confirmation) {
			anyUnsafe = true
		}
	}
	if anyUnsafe {
		lines = append(lines, "  No longer served is not safe: replacing a value in Varlatch does not revoke the old credential at its provider.")
	}
	authority, _ := fld(report, "authorityAtRemoval")
	if jsjson.Truthy(authority) {
		at, atOK := fld(authority, "removedAt")
		lines = append(lines, "", "Could reach when removed ("+timeOr(at, atOK, "undefined")+"):")
		envs, _ := fld(authority, "environments")
		if len(list(envs)) == 0 {
			lines = append(lines, "  nothing")
		}
		for _, e := range list(envs) {
			conditional, _ := fld(e, "conditionalOn")
			condition := "unconditional"
			if len(list(conditional)) > 0 {
				condition = "conditional on Tailnet Requirement " + joinStrings(list(conditional), ", ")
			}
			actions, _ := fld(e, "actions")
			var names []string
			for _, a := range list(actions) {
				action, actionOK := fld(a, "action")
				names = append(names, sv(action, actionOK))
			}
			env, _ := fld(e, "environmentId")
			lines = append(lines, "  "+envName(env)+": "+strings.Join(names, ", ")+" (reading values "+condition+")")
		}
		reqs, _ := fld(authority, "requirements")
		if len(list(reqs)) > 0 {
			lines = append(lines, "  Tailnet Requirements as defined at removal:")
			for _, q := range list(reqs) {
				rid, ridOK := fld(q, "requirementId")
				lines = append(lines, "    "+sv(rid, ridOK)+": "+requirementWords(q))
			}
		}
	}
	lines = append(lines, "",
		"Not covered: what they could reach before removal and no longer could then, and values that reached a broker, an agent or a platform; those are listed below as indirect paths.")
	indirect, _ := fld(report, "indirect")
	review := reviewLines(indirect)
	if len(review) == 0 {
		lines = append(lines, "", "Indirect paths: none.")
	} else {
		lines = append(append(lines, "", "Indirect paths (what they set up; not evidence that they held a value):"), review...)
	}
	// Every line holds names, IDs and text from the server: escaped (issue #119).
	for i, l := range lines {
		lines[i] = Printable(l)
	}
	return lines
}

var changeWords = map[string]string{
	"created":             "created",
	"repointed":           "re-pointed",
	"destination_changed": "destination changed",
	"credential_replaced": "credential replaced",
}

// reviewLines is members.ts's reviewLines: what the person set up that may
// keep working without them, one line per thing; none when nothing.
func reviewLines(review any) []string {
	var lines []string
	section := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		lines = append(lines, "  "+title+":")
		for _, item := range items {
			lines = append(lines, "    "+item)
		}
	}
	changes := func(c any) string {
		var out []string
		for _, x := range list(c) {
			s := sv(x, true)
			if w, ok := changeWords[s]; ok {
				s = w
			}
			out = append(out, s)
		}
		return strings.Join(out, ", ")
	}
	s := func(x any, key string) string { v, ok := fld(x, key); return sv(v, ok) }
	truthy := func(x any, key string) bool { v, _ := fld(x, key); return jsjson.Truthy(v) }
	revokedMark := func(x any) string {
		if truthy(x, "revoked") {
			return ", revoked"
		}
		return ""
	}
	each := func(key string, f func(x any) string) []string {
		v, _ := fld(review, key)
		var out []string
		for _, x := range list(v) {
			out = append(out, f(x))
		}
		return out
	}
	section("Integrations", each("syncTargets", func(t any) string {
		c, _ := fld(t, "changes")
		return s(t, "id") + "  " + s(t, "platform") + ", " + s(t, "state") + ", environment " + s(t, "environmentId") + "  (" + changes(c) + ")"
	}))
	section("Connections", each("connections", func(c any) string {
		kind := "token"
		if k, _ := fld(c, "credentialKind"); k == "github-app" {
			kind = "GitHub App"
		}
		ch, _ := fld(c, "changes")
		return s(c, "id") + "  " + s(c, "name") + " (" + s(c, "platform") + ", " + kind + revokedMark(c) + ")  (" + changes(ch) + ")"
	}))
	section("Webhooks (each signing secret was shown to its creator)", each("webhooks", func(w any) string {
		host := "(no host)"
		if truthy(w, "host") {
			host = s(w, "host")
		}
		return s(w, "id") + "  " + host + revokedMark(w)
	}))
	section("OIDC bindings", each("oidcBindings", func(b any) string {
		return s(b, "id") + "  " + s(b, "identityName") + " from " + s(b, "issuer") + revokedMark(b)
	}))
	section("Machine credentials whose token they were shown", each("credentials", func(c any) string {
		name := "(unnamed)"
		if v, ok := fld(c, "name"); ok && v != nil {
			name = sv(v, true)
		}
		return s(c, "id") + "  " + name + " for " + s(c, "identityName") + ": " + s(c, "state")
	}))
	section("Personal environments", each("personalEnvironments", func(e any) string {
		return s(e, "id") + "  " + s(e, "name")
	}))
	return lines
}

// removalLines is members.ts's removalLines: what a removal or a leave did,
// and what is left to review.
func removalLines(removal any, name, organization string) []string {
	left, _ := fld(removal, "left")
	first := "Removed " + name + " from " + organization + "."
	if jsjson.Truthy(left) {
		first = "You left " + organization + "."
	}
	grants, _ := fld(removal, "grantsRevoked")
	groups, _ := fld(removal, "groupsLeft")
	invitations, _ := fld(removal, "invitationsRevoked")
	third := "Their sign-in and credentials are unaffected; from their next request they reach nothing in this organization."
	if jsjson.Truthy(left) {
		third = "Your sign-in and credentials are unaffected; they reach nothing in this organization from now on."
	}
	lines := []string{
		first,
		"Revoked " + plural(grants, "Grant", "Grants") + ", left " + plural(groups, "group or team", "groups and teams") + ", " +
			"revoked " + plural(invitations, "pending invitation", "pending invitations") + ".",
		third,
	}
	review, _ := fld(removal, "review")
	r := reviewLines(review)
	if len(r) == 0 {
		lines = append(lines, "Nothing they set up here needs review.")
	} else {
		lines = append(append(lines, "", "To review (the removal changed none of it; it may keep working without them):"), r...)
	}
	// Every line holds names, IDs and counts from the server: escaped (issue #119).
	for i, l := range lines {
		lines[i] = Printable(l)
	}
	return lines
}
