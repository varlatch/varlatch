// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"regexp"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// The usage texts of these commands, as main.ts prints them.
const (
	tailnetRemoveUsage = "Usage: varlatch tailnet remove <requirement-id>"
	tailnetUsage       = "Usage: varlatch tailnet <require|requirements|remove>"
	auditUsage         = "Usage: varlatch audit <list|export>"
	orgCreateUsage     = "Usage: varlatch org create <slug> [name]"
	projectCreateUsage = "Usage: varlatch project create <slug> [name] [--managed]"
	projectRenameUsage = "Usage: varlatch project rename <slug> <new-name>"
	projectUsage       = "Usage: varlatch project <create|list|rename|delete>"
	envDeleteUsage     = "Usage: varlatch env-delete <name> [--confirm <name>]"
)

// Organization administration, first part (slice 5.7a of internal
// docs/design/go-cli.md): `invite`, `tailnet`, `audit list`, `org
// list/create`, `project create/list/rename`, `env-create`, `env-delete`
// here; `identity` and `credential` in identity.go; `member` in member.go.
// Ported from main.ts. A subcommand of a later slice (org
// delete/deletion/freeze/unfreeze, project delete, audit export) answers
// that it is not built yet.

var bg = context.Background()

// laterSubcommand is the refusal of a subcommand a later slice builds.
func laterSubcommand(command, slice string) error {
	return UsageError("varlatch " + command + ": not in this build of the Go CLI yet (slice " + slice + "); use the TypeScript CLI for it until then")
}

// lazyAPI is main.ts's client(ctx): the client of ctx's server, connected
// on its first request, so a command's own usage errors come first (64)
// whether or not a credential is stored.
type lazyAPI struct {
	r      *Run
	server string
	api    *apiclient.Client
}

func (l *lazyAPI) get() (*apiclient.Client, error) {
	if l.api == nil {
		api, err := l.r.connectClient(l.server)
		if err != nil {
			return nil, err
		}
		l.api = api
	}
	return l.api, nil
}

// repoContext is main.ts's `const ctx = context(args); const api =
// client(ctx)`: the repository's context, a context error as main.ts's
// catch prints it (1).
func (r *Run) repoContext() (*clientctx.Context, *lazyAPI, error) {
	cwd, err := Cwd()
	if err != nil {
		return nil, nil, err
	}
	ctx, err := r.resolveFromArgs(cwd)
	if err != nil {
		return nil, nil, contextError(err)
	}
	server, err := serverString(ctx.Server)
	if err != nil {
		return nil, nil, err
	}
	return ctx, &lazyAPI{r: r, server: server}, nil
}

// orgContext is the context of a command that needs no Environment (member,
// identity reach, credential issue): resolveContext with the environment
// "(unused)" and the --server option, when given.
func (r *Run) orgContext(server string, given bool) (*clientctx.Context, *lazyAPI, error) {
	cwd, err := Cwd()
	if err != nil {
		return nil, nil, err
	}
	options := clientctx.ResolveOptions{Cwd: cwd, Environment: "(unused)"}
	if given {
		options.Server = server
	}
	ctx, err := clientctx.ResolveContext(options, r.Env)
	if err != nil {
		return nil, nil, contextError(err)
	}
	resolved, err := serverString(ctx.Server)
	if err != nil {
		return nil, nil, err
	}
	return ctx, &lazyAPI{r: r, server: resolved}, nil
}

// positionalAt is main.ts's positional(args, i): the argument at i, or
// false when that slot is an option or an option's value.
func positionalAt(args []string, i int) (string, bool) {
	if i >= len(args) {
		return "", false
	}
	v := args[i]
	if strings.HasPrefix(v, "-") {
		return "", false
	}
	if i > 0 && strings.HasPrefix(args[i-1], "-") {
		return "", false
	}
	return v, true
}

// arg is args[i], false past the end (`args[i] ?? ...`).
func arg(args []string, i int) (string, bool) {
	if i < len(args) {
		return args[i], true
	}
	return "", false
}

// pageItems is `page.items` read for `for (const x of page.items)` (forJSON
// false) or for `page.items.map(...)`/`.filter(...)` (forJSON true): V8's
// TypeErrors when it is not there or not an array.
func pageItems(page any, name string, method string) ([]any, error) {
	items, ok, err := read(page, page != apiclient.Undefined, "items")
	if err != nil {
		return nil, err
	}
	if method != "" {
		list, isArray := items.([]any)
		if !isArray {
			if !ok || items == nil {
				return nil, typeErrorRead(items, ok, method)
			}
			return nil, &clientctx.TypeError{Message: name + ".items." + method + " is not a function"}
		}
		return list, nil
	}
	if !ok || items == nil {
		return nil, &clientctx.TypeError{Message: name + ".items is not iterable"}
	}
	return iterate(items, name+".items")
}

// get is `x.key` of a value from a server's answer: V8's TypeError when x
// is null or undefined; false for a key that is not there.
func get(x any, key string) (any, bool, error) {
	return read(x, x != apiclient.Undefined, key)
}

// text is `${v}` of a value read with get, through printable() (safe“)
// and the URL fail-safe every printed server value goes through.
func text(v any, ok bool) string {
	return Printable(shownValue(jsTemplate(v, ok)))
}

// raw is `${v}` without printable(): main.ts's lines that interpolate
// without safe“.
func raw(v any, ok bool) string { return jsTemplate(v, ok) }

// orNull is `v ?? null`.
func orNull(v any, ok bool) any {
	if !ok || v == nil || v == apiclient.Undefined {
		return nil
	}
	return v
}

// timeOr is `safeTime(v) ?? or`: or for null and undefined.
func timeOr(v any, ok bool, or string) string {
	if !ok {
		return or
	}
	s, known := SafeTime(v)
	if !known {
		return or
	}
	return s
}

// member appends key: v to o as JSON.stringify writes it: left out when v
// is undefined.
func member(o jsjson.Object, key string, v any, ok bool) jsjson.Object {
	if !ok || v == apiclient.Undefined {
		return o
	}
	return append(o, jsjson.Member{Key: key, Value: v})
}

// pick is `({ k1: x.k1, k2: x.k2, ... })` of a server's object, each key as
// JSON.stringify writes it.
func pick(x any, keys ...string) (jsjson.Object, error) {
	out := jsjson.Object{}
	for _, k := range keys {
		v, ok, err := get(x, k)
		if err != nil {
			return nil, err
		}
		out = member(out, k, v, ok)
	}
	return out, nil
}

// printableArg is printable(v) of a server's value: printable() calls
// text.replace, so anything but a string is V8's TypeError.
func printableArg(v any, ok bool) (string, error) {
	switch s := v.(type) {
	case string:
		return Printable(shownValue(s)), nil
	case nil:
		if !ok {
			return "", &clientctx.TypeError{Message: "Cannot read properties of undefined (reading 'replace')"}
		}
		return "", &clientctx.TypeError{Message: "Cannot read properties of null (reading 'replace')"}
	}
	if v == apiclient.Undefined {
		return "", &clientctx.TypeError{Message: "Cannot read properties of undefined (reading 'replace')"}
	}
	return "", &clientctx.TypeError{Message: "text.replace is not a function"}
}

// capable is `meta.capabilities.includes(capability)`, with the server's
// version as safeVersion shows it ("an older release" when it does not).
func (r *Run) capable(api *apiclient.Client, capability string) (bool, string, error) {
	meta, err := api.Meta(bg)
	if err != nil {
		return false, "", err
	}
	capabilities, capOK, err := read(meta, meta != apiclient.Undefined, "capabilities")
	if err != nil {
		return false, "", err
	}
	has, err := includes(capabilities, capOK, capability, "meta.capabilities.includes")
	if err != nil {
		return false, "", err
	}
	version, _ := jsval.Get(meta, "serverVersion")
	shown, ok := r.Secrets.SafeVersion(version)
	if !ok {
		shown = "an older release"
	}
	return has, shown, nil
}

// commandServer is main.ts's commandServer: the server of a command that
// needs no Project (org list/create, project create).
func (r *Run) commandServer() (string, error) {
	cwd, err := Cwd()
	if err != nil {
		return "", err
	}
	given, _ := flagArg(r.Args, "--server")
	resolved, err := clientctx.ResolveServer(cwd, given, r.Env)
	if err != nil {
		return "", contextError(err)
	}
	if resolved == nil {
		if clientctx.FindRepoRoot(cwd) != "" {
			return "", UsageError("Provide --server <url>, or name the server in " + clientctx.RepoConfigFile)
		}
		return "", UsageError("Provide --server <url>, or sign in with varlatch login --server <url> to remember it")
	}
	return serverString(resolved.Server)
}

// serverClient is the client org and project create build for a server
// with no repository context: the stored credential (or VARLATCH_TOKEN),
// refused as not authenticated (77) when there is none.
func (r *Run) serverClient(server string) (*apiclient.Client, error) {
	token, err := r.loadToken(server)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, Fail("Not authenticated to "+shownServer(server), ExitDenied)
	}
	if err := r.warnIfExpiring(server); err != nil {
		return nil, err
	}
	return r.newClient(apiclient.Options{
		Server:              server,
		Token:               token,
		UserAgent:           r.UserAgent(),
		OnMaintenance:       r.maintenanceNotice,
		OnCredentialExpires: r.credentialExpiryNotice(server, token),
		Env:                 r.Env,
	}), nil
}

// ---------------------------------------------------------------------------
// invite

const inviteUsage = "Usage: varlatch invite <name> [--role member|admin]"

// inviteTokenFormat is an invitation token as both servers make it:
// vlt_invite_ and 32 random bytes in base64url (go/server/auth's
// InviteToken; the TypeScript server's issueInviteGrant).
var inviteTokenFormat = regexp.MustCompile(`^vlt_invite_[A-Za-z0-9_-]{43}$`)

// InviteNotShown is invite's message when the server's answer holds no
// token it may print. It names nothing from the answer.
const InviteNotShown = "varlatch invite: the server's answer holds no invitation token in Varlatch's format, or holds a credential or value this run knows, so no link is printed. The server may have created the invitation anyway: revoke it under Pending invitations in the dashboard."

// showableInvite says whether invite may print token, the one secret it
// shows on purpose: only an invitation token in the servers' format that
// neither holds nor is part of a secret the run knows (its bearer,
// VARLATCH_TOKEN, a stored credential, a value in flight). A server that
// answers with anything else gets nothing printed (go/README.md, "`invite`
// prints only an invitation token").
func (r *Run) showableInvite(token string) bool {
	if !inviteTokenFormat.MatchString(token) {
		return false
	}
	if r.Secrets != nil {
		if r.Secrets.maskHeld(token) != token {
			return false
		}
		for _, h := range r.Secrets.held() {
			if strings.Contains(h, token) {
				return false
			}
		}
	}
	for _, v := range r.inFlight {
		if v != "" && (strings.Contains(token, v) || strings.Contains(v, token)) {
			return false
		}
	}
	return true
}

// inviteCommand is `varlatch invite <name> [--role member|admin]`: a
// one-time enrollment link, its token printed on purpose (outShowing).
func inviteCommand(r *Run) error {
	name, ok := arg(r.Args, 0)
	if !ok {
		return UsageOnly(inviteUsage)
	}
	role, ok := flagArg(r.Args, "--role")
	if !ok {
		role = "member"
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	invite, err := api.CreateInvitation(bg, ctx.Organization, name, role)
	if err != nil {
		return err
	}
	if err := r.println("Hand this one-time enrollment link to " + name + " (" + role + "):"); err != nil {
		return err
	}
	tokenValue, tokenOK, err := get(invite, "token")
	if err != nil {
		return err
	}
	token, err := printableArg(tokenValue, tokenOK)
	if err != nil {
		return err
	}
	if raw, _ := tokenValue.(string); raw != token || !r.showableInvite(token) {
		return Fail(InviteNotShown, ExitFailure)
	}
	if err := r.outShowing("  "+shownServer(lazy.server)+"/enroll#"+token+"\n", token); err != nil {
		return err
	}
	expires, expiresOK, err := get(invite, "expiresAt")
	if err != nil {
		return err
	}
	return r.println("Expires: " + timeOr(expires, expiresOK, "undefined") + ". They will create a passkey — no email involved.")
}

// ---------------------------------------------------------------------------
// tailnet

// tailnetCommand is `varlatch tailnet require|requirements|remove`.
func tailnetCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	switch sub {
	case "require":
		// The flagship convenience (ADR-0014 §9): compiles to an ordinary
		// typed Requirement.
		tier, ok := flagArg(r.Args, "--tier")
		if !ok {
			tier = "production"
		}
		tailnet, ok := flagArg(r.Args, "--tailnet")
		if !ok {
			return UsageError("Provide --tailnet <your-tailnet.ts.net>")
		}
		list := func(option string) []any {
			v, ok := flagArg(r.Args, option)
			if !ok {
				return nil
			}
			var out []any
			for _, part := range strings.Split(v, ",") {
				if part != "" {
					out = append(out, part)
				}
			}
			return out
		}
		tags, nodes, users := list("--tags"), list("--nodes"), list("--users")
		if len(tags) == 0 && len(nodes) == 0 && len(users) == 0 {
			return UsageError("Name at least one of --tags, --nodes, or --users")
		}
		selector := jsjson.Object{{Key: "tailnet", Value: tailnet}}
		for _, s := range []struct {
			key  string
			list []any
		}{{"tags", tags}, {"nodes", nodes}, {"users", users}} {
			if len(s.list) > 0 {
				selector = append(selector, jsjson.Member{Key: s.key, Value: s.list})
			}
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		created, err := api.CreateTailnetRequirement(bg, ctx.Organization, jsjson.Object{{Key: "kind", Value: "tier"}, {Key: "tier", Value: tier}}, selector)
		if err != nil {
			return err
		}
		idValue, idOK, err := get(created, "id")
		if err != nil {
			return err
		}
		id, err := printableArg(idValue, idOK)
		if err != nil {
			return err
		}
		return r.println("Tailnet Requirement " + id + ": " + tier + "-tier retrieval now requires " +
			"trusted Tailnet Context from " + tailnet + ". Requests outside it fail closed.")
	case "requirements":
		api, err := lazy.get()
		if err != nil {
			return err
		}
		page, err := api.ListRequirements(bg, ctx.Organization)
		if err != nil {
			return err
		}
		if hasArg(r.Args, "--json") {
			items, ok, err := get(page, "items")
			if err != nil {
				return err
			}
			return r.printDoc(member(jsjson.Object{{Key: "organization", Value: ctx.Organization}}, "requirements", items, ok))
		}
		list, err := pageItems(page, "page", "")
		if err != nil {
			return err
		}
		for _, req := range list {
			id, idOK, err := get(req, "id")
			if err != nil {
				return err
			}
			target, targetOK, _ := get(req, "target")
			selector, selectorOK, _ := get(req, "selector")
			// JSON.stringify of each, every string in it through the fail-safe first.
			redactedTarget, err := RedactValue(target, r.inFlight...)
			if err != nil {
				return err
			}
			redactedSelector, err := RedactValue(selector, r.inFlight...)
			if err != nil {
				return err
			}
			shownTarget := Printable(stringifyOr(redactedTarget, targetOK))
			shownSelector := Printable(stringifyOr(redactedSelector, selectorOK))
			if err := r.println(text(id, idOK) + "  " + shownTarget + "  " + shownSelector); err != nil {
				return err
			}
		}
		if len(list) == 0 {
			return r.println("(none)")
		}
		return nil
	case "remove":
		id, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(tailnetRemoveUsage)
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		if _, err := api.DeleteRequirement(bg, ctx.Organization, id); err != nil {
			return err
		}
		return r.println("Removed " + id + ". Constrained operations are unconstrained again.")
	}
	return UsageOnly(tailnetUsage)
}

// versioned is main.ts's printJson document: `{ version: 1, ...doc }`.
func versioned(doc jsjson.Object) jsjson.Object {
	out := jsjson.Object{{Key: "version", Value: statusSchemaVersion}}
	for _, m := range doc {
		out = out.Set(m.Key, m.Value)
	}
	return out
}

// printDoc is main.ts's printJson: the document with its schema version
// first, through printJSON (the fail-safe on every string).
func (r *Run) printDoc(doc jsjson.Object) error { return r.printJSON(versioned(doc)) }

// sv is `${v}` of a server's value with the URL fail-safe applied to it
// alone (MaskURLInValue), never to the line it goes into.
func sv(v any, ok bool) string { return shownValue(jsTemplate(v, ok)) }

// stringifyOr is `${JSON.stringify(v)}`: "undefined" for undefined.
func stringifyOr(v any, ok bool) string {
	if !ok || v == apiclient.Undefined {
		return "undefined"
	}
	return string(jsjson.Stringify(v))
}

// ---------------------------------------------------------------------------
// audit

// auditCommand is `varlatch audit list [--json]`; `audit export` is 5.7c.
func auditCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	if sub == "export" {
		return laterSubcommand("audit export", "5.7c")
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	if sub != "list" {
		return UsageOnly(auditUsage)
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	page, err := api.ListAuditEvents(bg, ctx.Organization, 50, "")
	if err != nil {
		return err
	}
	if hasArg(r.Args, "--json") {
		items, ok, err := get(page, "items")
		if err != nil {
			return err
		}
		return r.printDoc(member(jsjson.Object{{Key: "organization", Value: ctx.Organization}}, "events", items, ok))
	}
	list, err := pageItems(page, "page", "")
	if err != nil {
		return err
	}
	for _, e := range list {
		at, atOK, err := get(e, "occurredAt")
		if err != nil {
			return err
		}
		decision, decisionOK, _ := get(e, "decision")
		eventType, typeOK, _ := get(e, "eventType")
		actor, actorOK, _ := get(e, "actorIdentityId")
		actorText := "-"
		if actorOK && actor != nil {
			actorText = jsTemplate(actor, true)
		}
		line := Printable(timeOr(at, atOK, "undefined")) + "  " + text(decision, decisionOK) + "  " + text(eventType, typeOK) + "  actor=" + Printable(shownValue(actorText))
		if err := r.println(line); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// org

const orgUsage = "Usage: varlatch org <list|create|delete|deletion|freeze|unfreeze>"

// orgCommand is `varlatch org list|create`; delete, deletion, freeze and
// unfreeze are 5.7c.
func orgCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	switch sub {
	case "delete", "deletion", "freeze", "unfreeze":
		return laterSubcommand("org "+sub, "5.7c")
	case "list", "create":
	default:
		return UsageOnly(orgUsage)
	}
	if slug, _ := arg(r.Args, 1); sub == "create" && slug == "" {
		return UsageOnly(orgCreateUsage)
	}
	server, err := r.commandServer()
	if err != nil {
		return err
	}
	api, err := r.serverClient(server)
	if err != nil {
		return err
	}
	if sub == "list" {
		page, err := api.ListOrganizations(bg)
		if err != nil {
			return err
		}
		if hasArg(r.Args, "--json") {
			list, err := pageItems(page, "page", "map")
			if err != nil {
				return err
			}
			organizations := make([]any, len(list))
			for i, o := range list {
				if organizations[i], err = pick(o, "id", "slug", "name"); err != nil {
					return err
				}
			}
			return r.printDoc(jsjson.Object{{Key: "organizations", Value: organizations}})
		}
		list, err := pageItems(page, "page", "")
		if err != nil {
			return err
		}
		for _, o := range list {
			slug, slugOK, err := get(o, "slug")
			if err != nil {
				return err
			}
			name, nameOK, _ := get(o, "name")
			if err := r.println(text(slug, slugOK) + "  (" + text(name, nameOK) + ")"); err != nil {
				return err
			}
		}
		if len(list) == 0 {
			return r.println("(none — create one with: varlatch org create <slug> <name>)")
		}
		return nil
	}
	slug := r.Args[1]
	name, ok := positionalAt(r.Args, 2)
	if !ok {
		name = slug
	}
	org, err := api.CreateOrganization(bg, slug, name)
	if err != nil {
		return err
	}
	orgSlug, slugOK, err := get(org, "slug")
	if err != nil {
		return err
	}
	id, idOK, _ := get(org, "id")
	return r.println("Organization " + text(orgSlug, slugOK) + " created (" + text(id, idOK) + "). You are its admin.")
}

// ---------------------------------------------------------------------------
// project

// projectCommand is `varlatch project create|list|rename`; delete is 5.7c.
func projectCommand(r *Run) error {
	sub, _ := arg(r.Args, 0)
	if sub == "delete" {
		return laterSubcommand("project delete", "5.7c")
	}
	if sub == "create" {
		slug, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(projectCreateUsage)
		}
		server, err := r.commandServer()
		if err != nil {
			return err
		}
		org, ok := flagArg(r.Args, "--org")
		if !ok {
			return UsageError("Provide --org <slug>")
		}
		api, err := r.serverClient(server)
		if err != nil {
			return err
		}
		name, ok := positionalAt(r.Args, 2)
		if !ok {
			name = slug
		}
		authority := "git"
		if hasArg(r.Args, "--managed") {
			authority = "managed"
		}
		project, err := api.CreateProject(bg, org, slug, name, authority)
		if err != nil {
			return err
		}
		pslug, pslugOK, err := get(project, "slug")
		if err != nil {
			return err
		}
		ca, caOK, _ := get(project, "contractAuthority")
		if err := r.println("Project " + text(pslug, pslugOK) + " created in " + Printable(org) + " (" + text(ca, caOK) + " contract authority)."); err != nil {
			return err
		}
		return r.println("Set up a repo with: varlatch init --org " + Printable(org) + " --project " + text(pslug, pslugOK) + " --server " + Printable(shownServer(server)))
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
		page, err := api.ListProjects(bg, ctx.Organization)
		if err != nil {
			return err
		}
		if hasArg(r.Args, "--json") {
			list, err := pageItems(page, "page", "map")
			if err != nil {
				return err
			}
			projects := make([]any, len(list))
			for i, p := range list {
				if projects[i], err = pick(p, "slug", "name", "contractAuthority"); err != nil {
					return err
				}
			}
			return r.printDoc(jsjson.Object{{Key: "organization", Value: ctx.Organization}, {Key: "projects", Value: projects}})
		}
		list, err := pageItems(page, "page", "")
		if err != nil {
			return err
		}
		for _, p := range list {
			slug, slugOK, err := get(p, "slug")
			if err != nil {
				return err
			}
			name, nameOK, _ := get(p, "name")
			ca, caOK, _ := get(p, "contractAuthority")
			if err := r.println(text(slug, slugOK) + "  (" + text(name, nameOK) + ", " + text(ca, caOK) + ")"); err != nil {
				return err
			}
		}
		return nil
	case "rename":
		slug, ok := arg(r.Args, 1)
		if !ok {
			return UsageOnly(projectRenameUsage)
		}
		name, ok := positionalAt(r.Args, 2)
		if !ok {
			return UsageError("Provide the new name")
		}
		api, err := lazy.get()
		if err != nil {
			return err
		}
		renamed, err := api.RenameProject(bg, ctx.Organization, slug, name)
		if err != nil {
			return err
		}
		rslug, rslugOK, err := get(renamed, "slug")
		if err != nil {
			return err
		}
		rname, rnameOK, _ := get(renamed, "name")
		return r.println("Project " + text(rslug, rslugOK) + " renamed to " + text(rname, rnameOK) + ". Its slug, grants and contracts are unaffected; the rename is audited.")
	}
	return UsageOnly(projectUsage)
}

// ---------------------------------------------------------------------------
// env-create and env-delete

// findEnvironment is `envs.items.find((e) => e.name === name || e.id === name)`.
func findEnvironment(envs any, name string) (any, bool, error) {
	list, err := pageItems(envs, "envs", "find")
	if err != nil {
		return nil, false, err
	}
	for _, e := range list {
		n, nOK, err := get(e, "name")
		if err != nil {
			return nil, false, err
		}
		if nOK && n == name {
			return e, true, nil
		}
		id, idOK, _ := get(e, "id")
		if idOK && id == name {
			return e, true, nil
		}
	}
	return nil, false, nil
}

const envCreateUsage = "Usage: varlatch env-create <name> --tier development|staging|production [--parent <env>] [--kind personal|preview]"

// envCreateCommand is `varlatch env-create <name> (--tier <tier> | --parent
// <env> [--kind personal|preview])`.
func envCreateCommand(r *Run) error {
	name, ok := arg(r.Args, 0)
	if !ok {
		return UsageOnly(envCreateUsage)
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	body := jsjson.Object{{Key: "name", Value: name}}
	if parent, _ := flagArg(r.Args, "--parent"); parent != "" {
		api, err := lazy.get()
		if err != nil {
			return err
		}
		envs, err := api.ListEnvironments(bg, ctx.Organization, ctx.Project)
		if err != nil {
			return err
		}
		parentEnv, found, err := findEnvironment(envs, parent)
		if err != nil {
			return err
		}
		if !found {
			return Fail("No such parent environment: "+parent, ExitFailure)
		}
		id, idOK, _ := get(parentEnv, "id")
		body = member(body, "parentEnvironmentId", id, idOK)
		if kind, _ := flagArg(r.Args, "--kind"); kind != "" {
			body = append(body, jsjson.Member{Key: "kind", Value: kind})
		}
	} else {
		tier, ok := flagArg(r.Args, "--tier")
		if !ok {
			return UsageError("Root environments need --tier development|staging|production")
		}
		body = append(body, jsjson.Member{Key: "tier", Value: tier})
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	env, err := api.CreateEnvironment(bg, ctx.Organization, ctx.Project, body)
	if err != nil {
		return err
	}
	ename, enameOK, err := get(env, "name")
	if err != nil {
		return err
	}
	kind, kindOK, _ := get(env, "kind")
	tier, tierOK, _ := get(env, "tier")
	return r.println("Environment " + text(ename, enameOK) + " created (" + text(kind, kindOK) + ", tier " + text(tier, tierOK) + ").")
}

// envDeleteCommand is `varlatch env-delete <name> [--confirm <name>]`: a
// production-tier root needs its name again (ADR-0025).
func envDeleteCommand(r *Run) error {
	name, ok := arg(r.Args, 0)
	if !ok {
		return UsageOnly(envDeleteUsage)
	}
	ctx, lazy, err := r.repoContext()
	if err != nil {
		return err
	}
	api, err := lazy.get()
	if err != nil {
		return err
	}
	envs, err := api.ListEnvironments(bg, ctx.Organization, ctx.Project)
	if err != nil {
		return err
	}
	env, found, err := findEnvironment(envs, name)
	if err != nil {
		return err
	}
	if !found {
		return Fail("No such environment: "+name, ExitFailure)
	}
	ename, enameOK, _ := get(env, "name")
	tier, tierOK, _ := get(env, "tier")
	parent, parentOK, _ := get(env, "parentEnvironmentId")
	kind, kindOK, _ := get(env, "kind")
	if tierOK && tier == "production" && !(parentOK && jsjson.Truthy(parent)) {
		confirm, confirmOK := flagArg(r.Args, "--confirm")
		same := confirmOK && enameOK && ename == confirm || !confirmOK && !enameOK
		if !same {
			shown := text(ename, enameOK)
			return UsageError(shown + " is production-tier; re-type the name to confirm: varlatch env-delete " + shown + " --confirm " + shown)
		}
	}
	if _, err := api.DeleteEnvironment(bg, ctx.Organization, ctx.Project, raw(ename, enameOK)); err != nil {
		return err
	}
	return r.println("Environment " + text(ename, enameOK) + " deleted (" + text(kind, kindOK) + ", tier " + text(tier, tierOK) +
		"). The name is free for reuse; grants and mappings never transfer to a successor.")
}
