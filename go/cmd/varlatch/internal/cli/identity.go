// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The usage texts of these commands, as main.ts prints them.
const (
	identityRenameUsage     = "Usage: varlatch identity rename <identity-id> <new-name>"
	identityRetireUsage     = "Usage: varlatch identity retire <identity-id> [--confirm <name>]"
	identityReactivateUsage = "Usage: varlatch identity reactivate <identity-id>"
	identityUsage           = "Usage: varlatch identity <list|reach|rename|retire|reactivate>"
	credentialListUsage     = "Usage: varlatch credential list <identity-id>"
	credentialRevokeUsage   = "Usage: varlatch credential revoke <identity-id> <credential-id>"
	credentialUsage         = "Usage: varlatch credential <list|revoke|issue>"
)

// `varlatch identity` and `varlatch credential` (slice 5.7a), from main.ts,
// reach.ts and credentialIssue.ts.

// identityID is members.ts's IDENTITY_ID: idn_ and lowercase base32.
var identityID = regexp.MustCompile(`^idn_[a-z2-7]+$`)

const (
	reachCapability = "identity.reach"
	reachUsage      = "Usage: varlatch identity reach <identity-id|name> [--json] [--server <url>]"
)

// identityCommand is `varlatch identity list|reach|rename|retire|reactivate`.
func identityCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	if sub == "reach" {
		return r.identityReach()
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		api, err := lazy.get()
		if err != nil {
			return err
		}
		page, err := api.ListIdentities(bg, ctx.Organization)
		if err != nil {
			return err
		}
		if hasArg(r.Args, "--json") {
			list, err := pageItems(page, "page", "map")
			if err != nil {
				return err
			}
			identities := make([]any, len(list))
			for i, x := range list {
				o, err := pick(x, "id", "name", "kind")
				if err != nil {
					return err
				}
				disabled, disabledOK, _ := get(x, "disabled")
				seen, seenOK, _ := get(x, "lastSeenAt")
				identities[i] = append(o, jsjson.Member{Key: "retired", Value: disabledOK && jsjson.Truthy(disabled)}, jsjson.Member{Key: "lastSeenAt", Value: orNull(seen, seenOK)})
			}
			return r.printDoc(jsjson.Object{{Key: "organization", Value: ctx.Organization}, {Key: "identities", Value: identities}})
		}
		list, err := pageItems(page, "page", "")
		if err != nil {
			return err
		}
		for _, x := range list {
			id, idOK, err := get(x, "id")
			if err != nil {
				return err
			}
			name, nameOK, _ := get(x, "name")
			kind, kindOK, _ := get(x, "kind")
			disabled, disabledOK, _ := get(x, "disabled")
			seen, seenOK, _ := get(x, "lastSeenAt")
			state := "active"
			if disabledOK && jsjson.Truthy(disabled) {
				state = "retired"
			}
			line := text(id, idOK) + "  " + text(name, nameOK) + "  (" + text(kind, kindOK) + ", " + state + ", last seen " + Printable(timeOr(seen, seenOK, "never")) + ")"
			if err := r.println(line); err != nil {
				return err
			}
		}
		if len(list) == 0 {
			return r.println("(none)")
		}
		return nil
	case "rename":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(identityRenameUsage)
		}
		name, ok := positionalAt(r.Args, 2)
		if !ok {
			return UsageError("Provide the new name")
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		renamed, err := api.RenameIdentity(bg, ctx.Organization, id, name)
		if err != nil {
			return err
		}
		rid, ridOK, err := get(renamed, "id")
		if err != nil {
			return err
		}
		rname, rnameOK, _ := get(renamed, "name")
		return r.println("Identity " + text(rid, ridOK) + " renamed to " + text(rname, rnameOK) + ". Grants and credentials are unaffected; the rename is audited.")
	case "retire":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(identityRetireUsage)
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		page, err := api.ListIdentities(bg, ctx.Organization)
		if err != nil {
			return err
		}
		list, err := pageItems(page, "page", "find")
		if err != nil {
			return err
		}
		var identity any
		found := false
		for _, x := range list {
			xid, xidOK, err := get(x, "id")
			if err != nil {
				return err
			}
			if xidOK && xid == id {
				identity, found = x, true
				break
			}
		}
		if !found {
			return Fail("No such identity: "+id, ExitFailure)
		}
		iid, iidOK, _ := get(identity, "id")
		name, nameOK, _ := get(identity, "name")
		// ADR-0034: retirement revokes every credential; the name again.
		confirm, confirmOK := flagArg(r.Args, "--confirm")
		if !(confirmOK && nameOK && name == confirm || !confirmOK && !nameOK) {
			return UsageError("Retiring " + text(name, nameOK) + " revokes ALL of its credentials; re-type the name to confirm: varlatch identity retire " +
				text(iid, iidOK) + " --confirm " + text(name, nameOK))
		}
		if _, err := api.RetireIdentity(bg, ctx.Organization, raw(iid, iidOK)); err != nil {
			return err
		}
		return r.println("Identity " + text(name, nameOK) + " retired — disabled and every credential revoked. Reactivation restores no credentials.")
	case "reactivate":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(identityReactivateUsage)
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		identity, err := api.ReactivateIdentity(bg, ctx.Organization, id)
		if err != nil {
			return err
		}
		iid, iidOK, err := get(identity, "id")
		if err != nil {
			return err
		}
		return r.println("Identity " + text(iid, iidOK) + " reactivated. It has zero working credentials until you issue one.")
	}
	return UsageOnly(identityUsage)
}

// identityReach is `varlatch identity reach <identity-id|name> [--json]`
// (ADR-0054 Decision 8): read-only, conditions shown, never evaluated.
func (r *Run) identityReach() error {
	parsed, err := strictOptions("identity reach", r.Args, OptionSpec{Values: []string{"--server"}, Booleans: []string{"--json"}, Positionals: 2}, reachUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 2 {
		return UsageOnly(reachUsage)
	}
	target := parsed.Positionals[1]
	server, given := parsed.Values["--server"]
	ctx, lazy, err := r.orgContext(server, given)
	if err != nil {
		return err
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	has, version, err := r.capable(api, reachCapability)
	if err != nil {
		return err
	}
	if !has {
		return Fail("This server ("+version+") cannot show a machine's reach; that needs Varlatch 0.21.0 or later.", ExitFailure)
	}
	// An identity ID goes to the server as it is; only a name is resolved.
	id := target
	if !identityID.MatchString(target) {
		page, err := api.ListIdentities(bg, ctx.Organization)
		if err != nil {
			return err
		}
		list, err := pageItems(page, "page", "filter")
		if err != nil {
			return err
		}
		machine, err := resolveMachine(list, target)
		if err != nil {
			return err
		}
		v, ok, _ := get(machine, "id")
		id = raw(v, ok)
	}
	reach, err := api.MachineReach(bg, ctx.Organization, id)
	if err != nil {
		return err
	}
	if parsed.Has("--json") {
		doc := jsjson.Object{{Key: "organization", Value: ctx.Organization}}
		for _, m := range spread(reach) {
			doc = doc.Set(m.Key, m.Value)
		}
		return r.printDoc(doc)
	}
	for _, line := range reachLines(reach) {
		if err := r.println(line); err != nil {
			return err
		}
	}
	return nil
}

// resolveMachine is reach.ts's resolveMachine: the one machine identity
// named exactly arg.
func resolveMachine(identities []any, arg string) (any, error) {
	var named []any
	for _, x := range identities {
		kind, _ := jsval.Get(x, "kind")
		name, _ := jsval.Get(x, "name")
		if kind != "human" && name == arg {
			named = append(named, x)
		}
	}
	if len(named) == 1 {
		return named[0], nil
	}
	if len(named) > 1 {
		ids := make([]string, len(named))
		for i, x := range named {
			v, ok := jsval.Get(x, "id")
			ids[i] = jsTemplate(v, ok)
		}
		return nil, Fail("Several machines are named "+arg+"; name one by its identity ID: "+Printable(shownValue(strings.Join(ids, ", ")))+".", ExitFailure)
	}
	return nil, Fail(arg+" is not a machine identity of this organization (varlatch identity list shows them).", ExitFailure)
}

// plural is `${n} ${n === 1 ? one : many}`.
func plural(n any, one, many string) string {
	word := many
	if f, ok := n.(float64); ok && f == 1 {
		word = one
	}
	return jsTemplate(n, true) + " " + word
}

// list is a server array, or none when it is not one.
func list(v any) []any {
	l, _ := v.([]any)
	return l
}

// reachLines is reach.ts's reachLines: the identity's state, then project
// by project and environment by environment.
func reachLines(reach any) []string {
	id, _ := jsval.Get(reach, "identity")
	str := func(x any, key string) (any, bool) { return jsval.Get(x, key) }
	state, stateOK := str(id, "state")
	reason, _ := str(id, "disabledReason")
	stateText := jsTemplate(state, stateOK)
	if state == "disabled" && reason == "organization-deletion" {
		stateText = "disabled by the organization's deletion"
	}
	name, nameOK := str(id, "name")
	iid, iidOK := str(id, "id")
	kind, kindOK := str(id, "kind")
	live, _ := str(id, "liveCredentials")
	lines := []string{"Reach of " + text(name, nameOK) + " (" + text(iid, iidOK) + ", " + text(kind, kindOK) + ", " + Printable(stateText) + ", " + Printable(plural(live, "live credential", "live credentials")) + ")."}
	requirements, _ := str(reach, "requirements")
	conditions := map[string]string{}
	for _, req := range list(requirements) {
		rid, _ := str(req, "id")
		c, _ := str(req, "condition")
		if s, ok := rid.(string); ok {
			conditions[s] = jsjson.String(c)
		}
	}
	condition := func(rid any) string {
		s := jsTemplate(rid, true)
		if c, ok := conditions[s]; ok {
			return Printable(shownValue(c))
		}
		return Printable("Requirement " + shownValue(s))
	}
	actionList := func(actions any) string {
		var parts []string
		for _, a := range list(actions) {
			action, actionOK := str(a, "action")
			conds, _ := str(a, "conditions")
			if len(list(conds)) == 0 {
				parts = append(parts, text(action, actionOK))
				continue
			}
			var cs []string
			for _, c := range list(conds) {
				cs = append(cs, condition(c))
			}
			parts = append(parts, text(action, actionOK)+" ("+strings.Join(cs, " and ")+")")
		}
		return strings.Join(parts, ", ")
	}
	orgActions, _ := str(reach, "organizationActions")
	if len(list(orgActions)) > 0 {
		lines = append(lines, "", "Organization-wide: "+actionList(orgActions))
	}
	projects, _ := str(reach, "projects")
	if len(list(projects)) == 0 {
		lines = append(lines, "", "No Grant allows it anything in a project.")
	}
	for _, p := range list(projects) {
		slug, slugOK := str(p, "slug")
		pname, pnameOK := str(p, "name")
		lines = append(lines, "", text(slug, slugOK)+" ("+text(pname, pnameOK)+"):")
		actions, _ := str(p, "actions")
		if len(list(actions)) > 0 {
			lines = append(lines, "  project: "+actionList(actions))
		}
		envs, _ := str(p, "environments")
		for _, e := range list(envs) {
			ename, enameOK := str(e, "name")
			eactions, _ := str(e, "actions")
			lines = append(lines, "  "+text(ename, enameOK)+": "+actionList(eactions))
		}
	}
	if len(list(requirements)) > 0 {
		lines = append(lines, "", "Conditions are Tailnet Requirements: each must be met by the device a request comes from. They are listed, not checked against any device.")
	}
	notes, _ := str(reach, "notes")
	if len(list(notes)) > 0 {
		lines = append(lines, "")
		for _, n := range list(notes) {
			lines = append(lines, Printable(shownValue(jsjson.String(n))))
		}
	}
	return lines
}

// ---------------------------------------------------------------------------
// credential

// credentialCommand is `varlatch credential list|revoke|issue`.
func credentialCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	if sub == "issue" {
		return r.credentialIssue(r.Args[1:])
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(credentialListUsage)
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		page, err := api.ListIdentityCredentials(bg, ctx.Organization, id)
		if err != nil {
			return err
		}
		if hasArg(r.Args, "--json") {
			items, err := pageItems(page, "page", "map")
			if err != nil {
				return err
			}
			credentials := make([]any, len(items))
			for i, c := range items {
				o, err := pick(c, "id", "kind")
				if err != nil {
					return err
				}
				for _, k := range []string{"name"} {
					v, ok, _ := get(c, k)
					o = append(o, jsjson.Member{Key: k, Value: orNull(v, ok)})
				}
				created, createdOK, _ := get(c, "createdAt")
				o = member(o, "createdAt", created, createdOK)
				for _, k := range []string{"expiresAt", "revokedAt", "lastUsedAt"} {
					v, ok, _ := get(c, k)
					o = append(o, jsjson.Member{Key: k, Value: orNull(v, ok)})
				}
				credentials[i] = o
			}
			return r.printDoc(jsjson.Object{{Key: "identity", Value: id}, {Key: "credentials", Value: credentials}})
		}
		items, err := pageItems(page, "page", "")
		if err != nil {
			return err
		}
		for _, c := range items {
			cid, cidOK, err := get(c, "id")
			if err != nil {
				return err
			}
			var marks []string
			add := func(v any, ok bool, s string) {
				if ok && jsjson.Truthy(v) {
					marks = append(marks, s)
				}
			}
			kind, kindOK, _ := get(c, "kind")
			name, nameOK, _ := get(c, "name")
			created, createdOK, _ := get(c, "createdAt")
			expires, expiresOK, _ := get(c, "expiresAt")
			revoked, revokedOK, _ := get(c, "revokedAt")
			used, usedOK, _ := get(c, "lastUsedAt")
			add(kind, kindOK, sv(kind, kindOK))
			add(name, nameOK, sv(name, nameOK))
			marks = append(marks, "created "+timeOr(created, createdOK, "undefined"))
			add(expires, expiresOK, "expires "+timeOr(expires, expiresOK, "undefined"))
			add(revoked, revokedOK, "revoked "+timeOr(revoked, revokedOK, "undefined"))
			marks = append(marks, "last used "+timeOr(used, usedOK, "never"))
			if err := r.println(text(cid, cidOK) + "  (" + Printable(strings.Join(marks, ", ")) + ")"); err != nil {
				return err
			}
		}
		if len(items) == 0 {
			return r.println("(none)")
		}
		return nil
	case "revoke":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(credentialRevokeUsage)
		}
		credentialID, ok := positionalAt(r.Args, 2)
		if !ok {
			return UsageError("Provide the credential id")
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		if _, err := api.RevokeIdentityCredential(bg, ctx.Organization, id, credentialID); err != nil {
			return err
		}
		return r.println("Credential " + credentialID + " revoked. Every subsequent request with it fails.")
	}
	return UsageOnly(credentialUsage)
}

// ---------------------------------------------------------------------------
// credential issue (credentialIssue.ts)

const (
	issueCapability = "identity.credentials.issue"
	issuePrefix     = "varlatch credential issue:"
	issueUsage      = "Usage: varlatch credential issue <identity-id> --name <name> [--ttl <s>] [--max-uses <n>] --out <file> [--json]"
)

var issueOptions = OptionSpec{
	Values:       []string{"--name", "--ttl", "--max-uses", "--out", "--server"},
	Booleans:     []string{"--json"},
	OnceBooleans: true,
	Positionals:  1,
}

var wholeNumber = regexp.MustCompile(`^\d+$`)

// credentialLimit is main.ts's credentialLimit: --ttl or --max-uses, a
// whole number from 1 to max (the server's limits), or exit 64.
func credentialLimit(option, value string, given bool, max float64) (float64, bool, error) {
	if !given {
		return 0, false, nil
	}
	n, err := strconv.ParseFloat(value, 64)
	if !wholeNumber.MatchString(value) || err != nil && !errors.Is(err, strconv.ErrRange) || n < 1 || n > max {
		return 0, false, UsageError("varlatch credential issue: " + option + " takes a whole number from 1 to " + jsjson.Number(max) + ", not " + value)
	}
	return n, true, nil
}

// lifetime is securityControls.ts's lifetime: days, hours, minutes or
// seconds, whichever divides it.
func lifetime(total float64) string {
	unit := func(n float64, word string) string {
		s := jsjson.Number(n) + " " + word
		if n != 1 {
			s += "s"
		}
		return s
	}
	switch {
	case math.Mod(total, 86400) == 0:
		return unit(total/86400, "day")
	case math.Mod(total, 3600) == 0:
		return unit(total/3600, "hour")
	case math.Mod(total, 60) == 0:
		return unit(total/60, "minute")
	}
	return unit(total, "second")
}

// credentialIssue is `varlatch credential issue`: another service
// credential for an existing machine identity, its token written only to
// the --out file (a new file, 0600, created exclusively and never through
// a link), never printed (ADR-0043 Decision 2).
func (r *Run) credentialIssue(args []string) error {
	parsed, err := strictOptions("credential issue", args, issueOptions, issueUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 1 {
		return UsageOnly(issueUsage)
	}
	identity := parsed.Positionals[0]
	name, ok := parsed.Values["--name"]
	if !ok {
		return UsageErrorWithUsage("varlatch credential issue: give --name, such as the program that will use it", "\n"+issueUsage)
	}
	if n := utf16Len(name); n == 0 || n > 200 {
		return UsageError("varlatch credential issue: --name takes 1 to 200 characters")
	}
	out, ok := parsed.Values["--out"]
	if !ok || out == "" {
		return UsageErrorWithUsage("varlatch credential issue: give --out <file>; the token is written only to a new file, never to the output", "\n"+issueUsage)
	}
	ttlValue, ttlGiven := parsed.Values["--ttl"]
	ttl, hasTTL, err := credentialLimit("--ttl", ttlValue, ttlGiven, 315_360_000)
	if err != nil {
		return err
	}
	usesValue, usesGiven := parsed.Values["--max-uses"]
	maxUses, hasMaxUses, err := credentialLimit("--max-uses", usesValue, usesGiven, 1_000_000)
	if err != nil {
		return err
	}
	server, given := parsed.Values["--server"]
	ctx, lazy, err := r.orgContext(server, given && server != "")
	if err != nil {
		return err
	}
	issued, err := r.issueToFile(lazy, ctx.Organization, identity, name, ttl, hasTTL, maxUses, hasMaxUses, out)
	if err != nil {
		return err
	}
	id, idOK, _ := get(issued, "id")
	iname, inameOK, _ := get(issued, "name")
	expires, expiresOK, _ := get(issued, "expiresAt")
	uses, usesOK, _ := get(issued, "maxUses")
	if parsed.Has("--json") {
		credential := member(jsjson.Object{}, "id", id, idOK)
		credential = append(credential, jsjson.Member{Key: "kind", Value: "service"})
		credential = member(credential, "name", iname, inameOK)
		credential = member(credential, "expiresAt", expires, expiresOK)
		credential = member(credential, "maxUses", uses, usesOK)
		return r.printDoc(jsjson.Object{{Key: "identity", Value: identity}, {Key: "credential", Value: credential}, {Key: "out", Value: out}})
	}
	var limits []string
	if expiresOK && jsjson.Truthy(expires) {
		note := ""
		if !hasTTL {
			// No --ttl, yet an expiry: the Organization's credential-lifetime default (ADR-0054).
			note = " (the organization's default lifetime for machine credentials)"
		}
		limits = append(limits, "expires "+timeOr(expires, true, "undefined")+note)
	} else {
		limits = append(limits, "no expiry: revoke it when nothing uses it")
	}
	if usesOK && jsjson.Truthy(uses) {
		s := ""
		if f, isNumber := uses.(float64); !isNumber || f != 1 {
			s = "s"
		}
		limits = append(limits, Printable(jsTemplate(uses, true))+" use"+s)
	}
	if err := r.println("Issued credential " + text(id, idOK) + " (" + text(iname, inameOK) + ") for " + Printable(identity) + "; " + strings.Join(limits, ", ") + "."); err != nil {
		return err
	}
	if err := r.println("The token is in " + out + ", readable by you only, and is never shown again."); err != nil {
		return err
	}
	if r.Assisted.On {
		return r.println("The file holds a credential: do not print or read it; give its path to the program that uses it.")
	}
	return nil
}

// fileErrorCode is the code Node gives a failed file operation ("ENOENT",
// "EACCES", ...), "an error" when it has none.
func fileErrorCode(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EACCES:
			return "EACCES"
		case syscall.EPERM:
			return "EPERM"
		case syscall.EEXIST:
			return "EEXIST"
		case syscall.ENOTDIR:
			return "ENOTDIR"
		case syscall.EISDIR:
			return "EISDIR"
		case syscall.ELOOP:
			return "ELOOP"
		case syscall.ENAMETOOLONG:
			return "ENAMETOOLONG"
		case syscall.EROFS:
			return "EROFS"
		case syscall.ENOSPC:
			return "ENOSPC"
		case syscall.EIO:
			return "EIO"
		}
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "ENOENT"
	case errors.Is(err, fs.ErrPermission):
		return "EACCES"
	case errors.Is(err, fs.ErrExist):
		return "EEXIST"
	}
	return "an error"
}

// nodeDirname is Node's path.dirname for a POSIX path (its algorithm,
// byte for byte), filepath.Dir on Windows.
func nodeDirname(p string) string {
	if filepath.Separator != '/' {
		return filepath.Dir(p)
	}
	if p == "" {
		return "."
	}
	hasRoot := p[0] == '/'
	end := -1
	matchedSlash := true
	for i := len(p) - 1; i >= 1; i-- {
		if p[i] == '/' {
			if !matchedSlash {
				end = i
				break
			}
		} else {
			matchedSlash = false
		}
	}
	switch {
	case end == -1 && hasRoot:
		return "/"
	case end == -1:
		return "."
	case hasRoot && end == 1:
		return "//"
	}
	return p[:end]
}

// checkOutPath is credentialIssue.ts's checkOutPath: the file must not
// exist, its directory must.
func checkOutPath(out string) error {
	_, err := os.Lstat(out)
	if err == nil {
		return Fail(issuePrefix+" "+out+" already exists, and the command never replaces a file. Choose a new --out. Nothing was issued.", ExitFailure)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return Fail(issuePrefix+" cannot create "+out+" ("+fileErrorCode(err)+"). Nothing was issued.", ExitFailure)
	}
	abs, absErr := filepath.Abs(out)
	isDir := false
	if absErr == nil {
		if info, statErr := os.Stat(filepath.Dir(abs)); statErr == nil {
			isDir = info.IsDir()
		}
	}
	if !isDir {
		return Fail(issuePrefix+" the directory "+nodeDirname(out)+" does not exist; the command creates the file only, never its directory. Nothing was issued.", ExitFailure)
	}
	return nil
}

// issueToFile is credentialIssue.ts's issueCredentialToFile: the file is
// created before the credential is issued, so a path that cannot be
// written never leaves a live credential nobody holds; a failed write
// revokes it.
func (r *Run) issueToFile(lazy *lazyAPI, org, identity, name string, ttl float64, hasTTL bool, maxUses float64, hasMaxUses bool, out string) (any, error) {
	if err := checkOutPath(out); err != nil {
		return nil, err
	}
	api, err := lazy.get()
	if err != nil {
		return nil, err
	}
	has, version, err := r.capable(api, issueCapability)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, Fail(issuePrefix+" this server ("+version+") cannot issue a credential for an existing machine identity "+
			"(it lacks the "+issueCapability+" capability); upgrade the server. Nothing was issued.", ExitFailure)
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL|createNoFollow, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Created between the check and now: never written through.
			if checkErr := checkOutPath(out); checkErr != nil {
				return nil, checkErr
			}
		}
		return nil, Fail(issuePrefix+" cannot create "+out+" ("+fileErrorCode(err)+"). Nothing was issued.", ExitFailure)
	}
	discard := func() {
		_ = f.Close()
		_ = os.Remove(out)
	}
	if err := f.Chmod(0o600); err != nil {
		discard()
		return nil, Fail(issuePrefix+" cannot create "+out+" ("+fileErrorCode(err)+"). Nothing was issued.", ExitFailure)
	}
	body := jsjson.Object{{Key: "name", Value: name}}
	if hasTTL {
		body = append(body, jsjson.Member{Key: "ttlSeconds", Value: ttl})
	}
	if hasMaxUses {
		body = append(body, jsjson.Member{Key: "maxUses", Value: maxUses})
	}
	issued, err := api.IssueMachineCredential(bg, org, identity, body)
	if err != nil {
		discard()
		var apiErr *apiclient.APIError
		if errors.As(err, &apiErr) && apiErr.CodeIs("RESOURCE_NOT_FOUND") {
			return nil, Fail(issuePrefix+" "+org+" has no machine identity "+identity+" that can hold a service credential "+
				"(a service, workload, or broker identity that is not retired). Nothing was issued."+r.requestNote(apiErr), ExitFailure)
		}
		if errors.As(err, &apiErr) && apiErr.CodeIs("CREDENTIAL_LIFETIME_EXCEEDED") {
			raw, _ := jsval.Get(apiErr.Details, "maxTtlSeconds")
			max := jsNumber(raw)
			limit := "a shorter lifetime"
			if max == math.Trunc(max) && max > 0 && !math.IsInf(max, 0) {
				limit = "at most " + lifetime(max) + " (--ttl " + jsjson.Number(max) + ")"
			}
			return nil, Fail(issuePrefix+" "+org+" enforces credential-lifetime: a machine credential may last "+limit+". "+
				"Give a shorter --ttl, or none for the organization's default lifetime. Nothing was issued."+r.requestNote(apiErr), ExitFailure)
		}
		return nil, err
	}
	tokenValue, tokenOK, _ := get(issued, "token")
	token := jsTemplate(tokenValue, tokenOK)
	r.holdValue(token)
	r.Secrets.Remember(token)
	writeErr := func() error {
		if _, err := f.Write([]byte(token + "\n")); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		return f.Close()
	}()
	if writeErr != nil {
		discard()
		id, idOK, _ := get(issued, "id")
		shownID := text(id, idOK)
		// A credential nobody holds is revoked, so a failed write leaves nothing live.
		_, revokeErr := api.RevokeIdentityCredential(bg, org, identity, raw(id, idOK))
		message := issuePrefix + " cannot write " + out + " (" + fileErrorCode(writeErr) + "). "
		if revokeErr == nil {
			message += "Credential " + shownID + " was issued and then revoked: nothing is live."
		} else {
			message += "Credential " + shownID + " was issued, and revoking it failed: revoke it with varlatch credential revoke " + Printable(identity) + " " + shownID
		}
		return nil, Fail(message, ExitFailure)
	}
	return issued, nil
}

// jsNumber is Number(v) for a value from a server's answer.
func jsNumber(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	case nil:
		return 0
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
	}
	return math.NaN()
}
