// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"math"
	"regexp"
	"strconv"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/apiclient"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// Deletion and the incident freeze (slice 5.7c of internal
// docs/design/go-cli.md): main.ts's projectDelete, orgDeletion and
// orgFreeze, with deletion.ts and freeze.ts. Each is destructive: the
// command line, the confirmation naming the target again, assisted mode's
// refusal and the server's capability are all checked before the one
// write, in the TypeScript CLI's order, and a usage error never reaches
// the server. Step-up approvals go through the client (approvals.go).

const (
	projectDeleteUsage = "Usage: varlatch project delete <slug> --confirm <slug> [--org <org>] [--server <url>]"
	orgDeleteUsage     = "Usage: varlatch org delete <slug> (--confirm <slug> [--after <days>] | --approve <request-id> | --cancel <request-id>) [--server <url>]\n" +
		"       varlatch org deletion <slug> [--json] [--server <url>]"
	freezeUsage = "Usage: varlatch org freeze <slug> --reason <text> --confirm <slug> [--server <url>]\n" +
		"       varlatch org unfreeze <slug> [--json] [--server <url>]"
)

const (
	projectDeletionCapability      = "projects.delete"
	organizationDeletionCapability = "organizations.delete"
	incidentFreezeCapability       = "organizations.incident-freeze"
	auditExportCapability          = "audit.storage-export"
)

// orgTarget is main.ts's organizationTarget: the server and organization a
// command acts on, each with whether it is known, and the --server option
// its printed commands repeat.
type orgTarget struct {
	server, organization       string
	hasServer, hasOrganization bool
	serverOption               string
}

// organizationTarget is main.ts's organizationTarget: --server or
// VARLATCH_SERVER, else the repository's; the organization given, else the
// repository's. Outside a repository the remembered default, then the only
// stored credential (ADR-0058 Decision 1). lenient: a repository whose
// context cannot be read counts as none.
func (r *Run) organizationTarget(parsed *ParsedOptions, organization string, hasOrganization, lenient bool) (*orgTarget, error) {
	cwd, err := Cwd()
	if err != nil {
		return nil, err
	}
	given, hasGiven := parsed.Value("--server")
	if !hasGiven {
		given, hasGiven = r.Env.LookupEnv("VARLATCH_SERVER")
	}
	inRepository := clientctx.FindRepoRoot(cwd) != ""
	var repo *clientctx.Context
	if (given == "" || organization == "") && inRepository {
		options := clientctx.ResolveOptions{Cwd: cwd, Environment: "(unused)"}
		if given != "" {
			options.Server = given
		}
		ctx, err := clientctx.ResolveContext(options, r.Env)
		switch {
		case err == nil:
			repo = ctx
		case !lenient:
			return nil, contextError(err)
		}
	}
	t := &orgTarget{organization: organization, hasOrganization: hasOrganization}
	switch {
	case hasGiven:
		t.server, t.hasServer = given, true
	case repo != nil:
		server, err := serverString(repo.Server)
		if err != nil {
			return nil, err
		}
		t.server, t.hasServer = server, true
	case !inRepository:
		resolved, err := clientctx.ResolveServer(cwd, "", r.Env)
		if err != nil {
			return nil, contextError(err)
		}
		if resolved != nil {
			server, err := serverString(resolved.Server)
			if err != nil {
				return nil, err
			}
			t.server, t.hasServer = server, true
		}
	}
	if !hasOrganization && repo != nil {
		t.organization, t.hasOrganization = repo.Organization, true
	}
	if given != "" {
		t.serverOption = " --server " + shellWord(shownServer(given))
	}
	return t, nil
}

// requiredTarget is main.ts's requiredTarget: organizationTarget with both
// parts required; a missing one is a wrong command line (64).
func (r *Run) requiredTarget(parsed *ParsedOptions, organization string, hasOrganization bool) (*orgTarget, error) {
	t, err := r.organizationTarget(parsed, organization, hasOrganization, false)
	if err != nil {
		return nil, err
	}
	if !t.hasServer {
		return nil, UsageError("Provide --server <url>, or run inside a configured repository")
	}
	if !t.hasOrganization {
		return nil, UsageError("Provide --org <slug>, or run inside a configured repository")
	}
	return t, nil
}

// requireCapability is main.ts's meta check before a destructive command:
// the server's version (or "an older release") in the refusal (1).
func (r *Run) requireCapability(api *apiclient.Client, capability, refusal string) (*metaCapabilities, error) {
	meta, err := r.readMeta(api)
	if err != nil {
		return nil, err
	}
	ok, err := meta.has(capability)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, Fail("This server ("+meta.version+") "+refusal, ExitFailure)
	}
	return meta, nil
}

// safeOf is safe`${x}` of a server's value: through the URL fail-safe, then
// printable().
func safeOf(x any) string { return Printable(sval(x)) }

// safeTimeOf is safe`${safeTime(x)}`: "undefined" for null and undefined.
func safeTimeOf(x any) string {
	if x == undef {
		return "undefined"
	}
	return Printable(templateTime(x))
}

// printLinesOf prints each line, as `for (const line of lines)
// console.log(line)` does, once the builder has made them all.
func (r *Run) printLinesOf(build func() []string) error {
	var lines []string
	if err := catchJS(func() { lines = build() }); err != nil {
		return err
	}
	for _, l := range lines {
		if err := r.println(l); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// project delete

// projectDelete is main.ts's projectDelete (ADR-0051): a Project is
// deleted at once, its values erased; the slug is named again with
// --confirm.
func (r *Run) projectDelete(args []string) error {
	parsed, err := strictOptions("project delete", args, OptionSpec{Values: []string{"--org", "--server", "--confirm"}, Positionals: 2}, projectDeleteUsage)
	if err != nil {
		return err
	}
	slug, ok := arg(parsed.Positionals, 1)
	if !ok {
		return UsageOnly(projectDeleteUsage)
	}
	confirm, confirmed := parsed.Value("--confirm")
	if confirmed && confirm != slug {
		return UsageErrorWithUsage("varlatch project delete: --confirm names "+confirm+", but this command deletes "+slug+"; approval for one Project never covers another.", "\n"+projectDeleteUsage)
	}
	org, hasOrg := parsed.Value("--org")
	if !confirmed {
		known, err := r.organizationTarget(parsed, org, hasOrg, true)
		if err != nil {
			return err
		}
		quoted := shellWord(slug)
		named := "<org>"
		from := ""
		if known.organization != "" {
			named = shellWord(known.organization)
			from = " from " + known.organization
		}
		command := "varlatch project delete " + quoted + " --confirm " + quoted + " --org " + named + known.serverOption
		what := "Deleting " + slug + " erases every value of its environments" + from + " at once; there is no undo"
		if r.Assisted.On {
			return Fail("varlatch project delete: "+what+". That is the human's decision. With their approval, add --confirm "+slug+". "+
				"Or the human runs, in their own terminal:\n  "+command+"\nNothing was deleted.", ExitConfig)
		}
		return UsageError(what + ". Name it again to confirm:\n  " + command + "\nNothing was deleted.")
	}
	target, err := r.requiredTarget(parsed, org, hasOrg)
	if err != nil {
		return err
	}
	api, err := (&lazyAPI{r: r, server: target.server}).get()
	if err != nil {
		return err
	}
	if _, err := r.requireCapability(api, projectDeletionCapability, "cannot delete projects; that needs Varlatch 0.20.0 or later. Nothing was deleted."); err != nil {
		return err
	}
	deleted, err := api.DeleteProject(bg, target.organization, slug)
	if err != nil {
		return err
	}
	return r.printLinesOf(func() []string { return projectDeletionLines(deleted, target.organization) })
}

// deletionLimits is deletion.ts's deletionLimits: what deletion does not
// reach (ADR-0051 Decision 10).
func deletionLimits(organization bool) []string {
	inFlight := ""
	if organization {
		inFlight = ", and one in flight when the deletion runs may still complete"
	}
	lines := []string{
		"Deletion covers this installation's live database. It does not reach:",
		"  The database's old pages and write-ahead log, its replicas and snapshots of its volume, which keep the data for a while;",
		"  requests already authorized: the server may still hold their keys or values in memory" + inFlight + ";",
		"  backups taken before it completes: they keep the data until their retention removes them, and restoring one brings it back;",
		"  values already pushed to platforms: they stay there;",
		"  values revealed, downloaded or exported: they stay wherever they were copied. Rotate them at their provider to make old copies useless.",
	}
	if organization {
		lines = append(lines, "A GitHub App stays as it is on GitHub: uninstall it or delete it there, and revoke copies of its private key. Installation tokens already issued stay valid until they expire.")
	}
	return lines
}

// projectDeletionLines is deletion.ts's projectDeletionLines.
func projectDeletionLines(result any, organization string) []string {
	slug := safeOf(at(result, "slug"))
	return append([]string{
		"Project " + slug + " deleted from " + Printable(organization) + ".",
		"Erased " + safeOf(at(result, "versionsErased")) + " value versions of " + safeOf(at(result, "values")) + " items in " + safeOf(at(result, "environments")) + " environments; " +
			"revoked " + safeOf(at(result, "capabilitiesRevoked")) + " Capabilities and " + safeOf(at(result, "targetsRevoked")) + " Sync Targets; removed " + safeOf(at(result, "teamLinksRemoved")) + " Team links.",
		"The slug " + slug + " can be used again; a new Project with it starts empty and inherits nothing tied to this one. The audit log keeps this Project's events.",
	}, deletionLimits(false)...)
}

// ---------------------------------------------------------------------------
// org delete and org deletion

// orgDeleteMode is deletion.ts's OrgDeleteMode.
type orgDeleteMode struct {
	mode       string // "schedule", "approve" or "cancel"
	afterDays  float64
	hasAfter   bool
	deletionID string
	confirmed  bool
}

var wholeDays = regexp.MustCompile(`^[0-9]+$`)

// parseOrgDeleteMode is deletion.ts's orgDeleteMode: exactly one of
// --confirm (schedule), --approve or --cancel; --after with scheduling
// only; --confirm may go with --approve, where it records the human's
// approval in assisted mode. The error is the reason, for the usage error.
func parseOrgDeleteMode(slug string, parsed *ParsedOptions) (*orgDeleteMode, error) {
	confirm, hasConfirm := parsed.Value("--confirm")
	approve, hasApprove := parsed.Value("--approve")
	cancel, hasCancel := parsed.Value("--cancel")
	after, hasAfter := parsed.Value("--after")
	if hasApprove && hasCancel {
		return nil, errors.New("--approve and --cancel cannot be combined")
	}
	if hasConfirm && confirm != slug {
		return nil, errors.New("--confirm names " + confirm + ", but this command deletes " + slug + "; approval for one Organization never covers another")
	}
	if hasCancel {
		if hasConfirm {
			return nil, errors.New("a cancel needs no --confirm")
		}
		if hasAfter {
			return nil, errors.New("--after goes with scheduling, not with --cancel")
		}
		return &orgDeleteMode{mode: "cancel", deletionID: cancel}, nil
	}
	if hasApprove {
		if hasAfter {
			return nil, errors.New("--after goes with scheduling, not with --approve")
		}
		return &orgDeleteMode{mode: "approve", deletionID: approve, confirmed: hasConfirm}, nil
	}
	if !hasAfter {
		return &orgDeleteMode{mode: "schedule"}, nil
	}
	days, _ := strconv.ParseFloat(after, 64)
	if !wholeDays.MatchString(after) || days < 1 || days > 30 {
		return nil, errors.New("--after takes a whole number of days from 1 to 30, not " + after)
	}
	return &orgDeleteMode{mode: "schedule", afterDays: days, hasAfter: true}, nil
}

// orgDeletion is main.ts's orgDeletion (ADR-0051): deleting an
// Organization is a request. Scheduling freezes it and names it again with
// --confirm; another admin approves when there were several; any admin
// cancels until it runs.
func (r *Run) orgDeletion(sub string, args []string) error {
	spec := OptionSpec{Values: []string{"--server", "--confirm", "--after", "--approve", "--cancel"}, Positionals: 2}
	if sub == "deletion" {
		spec = OptionSpec{Values: []string{"--server"}, Booleans: []string{"--json"}, Positionals: 2}
	}
	parsed, err := strictOptions("org "+sub, args, spec, orgDeleteUsage)
	if err != nil {
		return err
	}
	slug, ok := arg(parsed.Positionals, 1)
	if !ok {
		return UsageOnly(orgDeleteUsage)
	}
	var mode *orgDeleteMode
	if sub == "delete" {
		if mode, err = parseOrgDeleteMode(slug, parsed); err != nil {
			return UsageErrorWithUsage("varlatch org delete: "+err.Error()+".", "\n"+orgDeleteUsage)
		}
	}
	// The slug is always given; the configuration is read only for a missing server.
	known, err := r.organizationTarget(parsed, slug, true, true)
	if err != nil {
		return err
	}
	quoted := shellWord(slug)
	if _, confirmed := parsed.Value("--confirm"); mode != nil && mode.mode == "schedule" && !confirmed {
		after := ""
		if mode.hasAfter {
			after = " --after " + jsNum(mode.afterDays)
		}
		command := "varlatch org delete " + quoted + " --confirm " + quoted + after + known.serverOption
		what := "Deleting " + slug + " freezes it now and, after the waiting period, ends every membership, retires its machines " +
			"and destroys its key: its values become unreadable, and there is no undo"
		if r.Assisted.On {
			return Fail("varlatch org delete: "+what+". That is the human's decision. With their approval, add --confirm "+slug+". "+
				"Or the human runs, in their own terminal:\n  "+command+"\nNothing was changed.", ExitConfig)
		}
		return UsageError(what + ". Name it again to confirm:\n  " + command + "\nNothing was changed.")
	}
	if mode != nil && mode.mode == "approve" && r.Assisted.On && !mode.confirmed {
		return Fail("varlatch org delete: approving the deletion of "+slug+" lets it run; that is the human's decision. "+
			"With their approval, add --confirm "+slug+". Or the human runs, in their own terminal:\n"+
			"  varlatch org delete "+quoted+" --approve "+shellWord(mode.deletionID)+known.serverOption+"\nNothing was changed.", ExitConfig)
	}
	target, err := r.requiredTarget(parsed, slug, true)
	if err != nil {
		return err
	}
	api, err := (&lazyAPI{r: r, server: target.server}).get()
	if err != nil {
		return err
	}
	meta, err := r.requireCapability(api, organizationDeletionCapability, "cannot delete organizations; that needs Varlatch 0.20.0 or later. Nothing was changed.")
	if err != nil {
		return err
	}
	switch {
	case mode == nil:
		answer, err := api.OrganizationDeletion(bg, slug)
		if err != nil {
			return err
		}
		open, present, err := read(answer, answer != apiclient.Undefined, "deletion")
		if err != nil {
			return err
		}
		if parsed.Has("--json") {
			return r.printDoc(member(jsjson.Object{{Key: "organization", Value: slug}}, "deletion", open, present))
		}
		if !present || !jsjson.Truthy(open) {
			return r.println("No deletion of " + slug + " is scheduled.")
		}
		return r.printLinesOf(func() []string { return deletionStateLines(open, slug, nowMS()) })
	case mode.mode == "cancel":
		cancelled, err := api.CancelOrganizationDeletion(bg, slug, mode.deletionID)
		if err != nil {
			return err
		}
		return r.printLinesOf(func() []string { return cancelledLines(cancelled, slug) })
	case mode.mode == "approve":
		approved, err := api.ApproveOrganizationDeletion(bg, slug, mode.deletionID)
		if err != nil {
			return err
		}
		return r.printLinesOf(func() []string { return deletionStateLines(approved, slug, nowMS()) })
	}
	organization, err := api.GetOrganization(bg, slug)
	if err != nil {
		return err
	}
	organizationID, idOK, err := read(organization, organization != apiclient.Undefined, "id")
	if err != nil {
		return err
	}
	if !idOK {
		organizationID = undef
	}
	body := jsjson.Object{}
	if mode.hasAfter {
		body = jsjson.Object{{Key: "afterDays", Value: mode.afterDays}}
	}
	scheduled, err := api.ScheduleOrganizationDeletion(bg, slug, body)
	if err != nil {
		return err
	}
	if err := r.println("Deletion of " + slug + " scheduled."); err != nil {
		return err
	}
	if err := r.printLinesOf(func() []string { return deletionStateLines(scheduled, slug, nowMS()) }); err != nil {
		return err
	}
	if err := r.println("Machine identities and webhooks are suspended and Sync Targets paused; pending invitations were revoked. " +
		"When it runs, every membership ends, machines are retired, values are erased and the organization's key is destroyed."); err != nil {
		return err
	}
	if err := r.println(tombstoneExportLine(organizationID)); err != nil {
		return err
	}
	for _, line := range deletionLimits(true) {
		if err := r.println(line); err != nil {
			return err
		}
	}
	// ADR-0056 Decision 10: an audit export's key outlives the deletion, for
	// its final events. Said after scheduling, and never left out because
	// the state could not be read.
	if ok, err := meta.has(auditExportCapability); err != nil {
		return err
	} else if ok {
		drain := "key stays readable by this installation for up to 30 days after deletion, to deliver the final audit events. Nothing else does."
		status, err := api.GetAuditExport(bg, slug)
		if err != nil || status == nil {
			return r.println("The audit export's state could not be read. If this organization has one, its " + drain)
		}
		state := optAtValue(optAtValue(status, "export"), "state")
		if strictEq(state, "active") || strictEq(state, "draining") {
			return r.println("The audit export's " + drain)
		}
	}
	return nil
}

// optAtValue is `x?.key` outside a builder: undefined for null or
// undefined x, never a throw.
func optAtValue(x any, key string) any {
	if isNullish(x) {
		return undef
	}
	v, ok := jsval.Get(x, key)
	if !ok {
		return undef
	}
	return v
}

// deletionStateLines is deletion.ts's deletionStateLines: the open
// request, as org deletion and the other modes print it.
func deletionStateLines(deletion any, organization string, now float64) []string {
	runAfter := at(deletion, "runAfter")
	parsed, ok := jsval.DateParse(js(runAfter))
	if !ok {
		parsed = math.NaN()
	}
	due := parsed <= now
	id := at(deletion, "id")
	lines := []string{
		"Deletion " + safeOf(id) + " of " + Printable(organization) + ": scheduled " + safeTimeOf(at(deletion, "scheduledAt")) + " by " + safeOf(at(deletion, "requestedBy")) + ".",
		"It runs no earlier than " + safeTimeOf(runAfter) + ".",
	}
	switch approvedBy := at(deletion, "approvedBy"); {
	case !truthy(at(deletion, "approvalRequired")):
		lines = append(lines, "No second approval is needed: the Organization had one admin when it was scheduled.")
	case truthy(approvedBy):
		approvedAt := at(deletion, "approvedAt")
		when := UnrecognizedTime
		if !isNullish(approvedAt) {
			when = templateTime(approvedAt)
		}
		lines = append(lines, "Approved by "+safeOf(approvedBy)+" at "+Printable(when)+".")
	default:
		never := ""
		if due {
			never = ", and never runs without it"
		}
		lines = append(lines, "It waits for another admin's approval"+never+": varlatch org delete "+Printable(organization)+" --approve "+safeOf(id))
	}
	return append(lines,
		organization+" is frozen until then: changes are refused, reads still work, so a last copy can be made.",
		"Any admin can cancel it until it runs: varlatch org delete "+Printable(organization)+" --cancel "+safeOf(id),
	)
}

// cancelledLines is deletion.ts's cancelledLines.
func cancelledLines(deletion any, organization string) []string {
	return []string{
		"Deletion " + safeOf(at(deletion, "id")) + " of " + Printable(organization) + " cancelled; " + Printable(organization) + " is no longer frozen.",
		"Machine identities and webhooks it suspended are back. Sync Targets stay paused: resume them when you choose. Invitations it revoked must be issued again.",
	}
}

// tombstoneExportLine is deletion.ts's tombstoneExportLine.
func tombstoneExportLine(organizationID any) string {
	id := safeOf(organizationID)
	return "After it runs, the people who can then read " + id + "'s audit log export it with: varlatch audit export --deleted-org " + id
}

// ---------------------------------------------------------------------------
// org freeze and org unfreeze

// freezeEffects is freeze.ts's FREEZE_EFFECTS.
var freezeEffects = []string{
	"Every read and write of its members and machines is refused, values included: varlatch run, CI jobs and deploys that fetch from it fail.",
	"Still possible: reading members, identities, Grants and the audit log; revoking credentials, Grants and Capabilities; removing members; pausing Sync Targets.",
	"Sync Targets stop pushing; webhooks keep delivering the audit log.",
	"If your deploy or rollback credentials come from this organization, keep a break-glass credential outside Varlatch first.",
}

func indentedEffects() []string {
	out := make([]string, len(freezeEffects))
	for i, l := range freezeEffects {
		out[i] = "  " + l
	}
	return out
}

// freezeReason is freeze.ts's freezeReason: 1 to 200 characters after
// trimming, as the server takes it.
func freezeReason(raw string) (string, error) {
	reason := jsTrim(raw)
	if utf16Len(reason) == 0 {
		return "", errors.New("--reason is required: say why, members see it")
	}
	if utf16Len(reason) > 200 {
		return "", errors.New("--reason is at most 200 characters")
	}
	return reason, nil
}

// orgFreeze is main.ts's orgFreeze (ADR-0055): freezing names the slug
// again with --confirm (in assisted mode too: the agent prints the
// person's command); unfreezing asks for the person's approval with a
// trusted passkey, through the client, and waits for it.
func (r *Run) orgFreeze(sub string, args []string) error {
	spec := OptionSpec{Values: []string{"--server", "--reason", "--confirm"}, Positionals: 2}
	if sub == "unfreeze" {
		spec = OptionSpec{Values: []string{"--server"}, Booleans: []string{"--json"}, Positionals: 2}
	}
	parsed, err := strictOptions("org "+sub, args, spec, freezeUsage)
	if err != nil {
		return err
	}
	slug, ok := arg(parsed.Positionals, 1)
	if !ok {
		return UsageOnly(freezeUsage)
	}
	known, err := r.organizationTarget(parsed, slug, true, true)
	if err != nil {
		return err
	}
	quoted := shellWord(slug)
	reason := ""
	if sub == "freeze" {
		raw, _ := parsed.Value("--reason")
		if reason, err = freezeReason(raw); err != nil {
			return UsageErrorWithUsage("varlatch org freeze: "+err.Error()+".", "\n"+freezeUsage)
		}
		if confirm, confirmed := parsed.Value("--confirm"); !confirmed || confirm != slug {
			command := "varlatch org freeze " + quoted + " --reason " + shellWord(reason) + " --confirm " + quoted + known.serverOption
			what := "Freezing " + slug + " stops all access to it at once, reads included, until someone lifts it with a passkey approval"
			if r.Assisted.On {
				return Fail("varlatch org freeze: "+what+". That is the human's decision. With their approval, add --confirm "+slug+". "+
					"Or the human runs, in their own terminal:\n  "+command+"\nNothing was changed.", ExitConfig)
			}
			effects := ""
			for _, l := range indentedEffects() {
				effects += l + "\n"
			}
			return UsageError(what + ".\n" + effects + "Name it again to confirm:\n  " + command + "\nNothing was changed.")
		}
	}
	target, err := r.requiredTarget(parsed, slug, true)
	if err != nil {
		return err
	}
	api, err := (&lazyAPI{r: r, server: target.server}).get()
	if err != nil {
		return err
	}
	if _, err := r.requireCapability(api, incidentFreezeCapability, "has no incident freeze; upgrade the server. Nothing was changed."); err != nil {
		return err
	}
	if sub == "freeze" {
		freeze, err := api.FreezeOrganization(bg, slug, reason)
		if err != nil {
			return err
		}
		return r.printLinesOf(func() []string {
			lines := []string{Printable(slug) + " is frozen for an incident since " + safeTimeOf(at(freeze, "frozenAt")) + " [" + safeOf(at(freeze, "id")) + "]."}
			lines = append(lines, indentedEffects()...)
			return append(lines, "Lift it with your approval: varlatch org unfreeze "+slug)
		})
	}
	state, err := api.IncidentFreeze(bg, slug)
	if err != nil {
		return err
	}
	freeze, present, err := read(state, state != apiclient.Undefined, "freeze")
	if err != nil {
		return err
	}
	if !present || !jsjson.Truthy(freeze) {
		if parsed.Has("--json") {
			return r.printDoc(jsjson.Object{{Key: "organization", Value: slug}, {Key: "freeze", Value: nil}})
		}
		return r.println(slug + " is not frozen.")
	}
	if !parsed.Has("--json") {
		var lines []string
		if err := catchJS(func() { lines = r.liftConfirmationLines(state, slug) }); err != nil {
			return err
		}
		for _, l := range lines {
			if err := r.warn(l); err != nil {
				return err
			}
		}
	}
	lifted, err := api.LiftIncidentFreeze(bg, slug, js(optAtValue(freeze, "id")))
	if err != nil {
		return err
	}
	if parsed.Has("--json") {
		return r.printDoc(spreadOnto(jsjson.Object{{Key: "organization", Value: slug}}, lifted))
	}
	return r.printLinesOf(func() []string { return liftedLines(lifted, slug) })
}

// targetLine is freeze.ts's targetLine: a Sync Target the lift resumes.
func targetLine(t any) string {
	return "  " + safeOf(at(t, "projectSlug")) + "/" + safeOf(at(t, "environmentName")) + " -> " + safeOf(at(t, "platform")) + " " + safeOf(at(t, "destination")) + " [" + safeOf(at(t, "id")) + "]"
}

// liftConfirmationLines is freeze.ts's liftConfirmationLines: what the lift
// will do, printed before asking for the approval.
func (r *Run) liftConfirmationLines(state any, slug string) []string {
	freeze := at(state, "freeze")
	frozenBy := at(freeze, "frozenBy")
	reason, ok := at(freeze, "reason").(string)
	if !ok {
		throwType("text.replace is not a function")
	}
	lines := []string{
		Printable(slug) + " is frozen since " + safeTimeOf(at(freeze, "frozenAt")) + " by " + safeOf(coalesce(at(frozenBy, "name"), at(frozenBy, "id"))) + ": " + Printable(r.Secrets.ServerMessage(reason)),
		"Lifting undoes nothing done during the freeze: revoked credentials and Grants stay revoked.",
	}
	targets := at(state, "resumingTargets")
	switch {
	case targets == nil:
		lines = append(lines, "Sync Targets that were not paused or revoked resume pushing (listing them needs config.sync.manage).")
	case strictEq(length(targets), 0.0):
		lines = append(lines, "No Sync Target resumes pushing.")
	default:
		lines = append(lines, "Sync Targets that resume pushing ("+safeOf(length(targets))+"):")
		for _, t := range array(targets, "state.resumingTargets", "map") {
			lines = append(lines, targetLine(t))
		}
	}
	return lines
}

// liftedLines is freeze.ts's liftedLines.
func liftedLines(result any, slug string) []string {
	freeze := at(result, "freeze")
	liftedAt := at(freeze, "liftedAt")
	when := UnrecognizedTime
	if !isNullish(liftedAt) {
		when = templateTime(liftedAt)
	}
	lines := []string{"Freeze of " + Printable(slug) + " lifted at " + Printable(when) + " [" + safeOf(at(freeze, "id")) + "]."}
	targets := at(result, "resumingTargets")
	if targets == nil || strictEq(length(targets), 0.0) {
		return lines
	}
	lines = append(lines, "Sync Targets resuming ("+safeOf(length(targets))+"):")
	for _, t := range array(targets, "result.resumingTargets", "map") {
		lines = append(lines, targetLine(t))
	}
	return lines
}
