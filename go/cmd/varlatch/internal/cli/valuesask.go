// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/clientctx"
	"github.com/varlatch/varlatch/go/cmd/varlatch/internal/jsval"
	"github.com/varlatch/varlatch/go/lib/jsjson"
)

// `varlatch values ask`, `asked` and `ask-cancel` (ADR-0063): a link somebody
// enters one Secret's value with on Varlatch's own page, once. Nothing here
// sees the value. Go only (go/README.md, values-ask).

const (
	valuesAskUsage       = "Usage: varlatch values ask <ITEM> [--for <identity ID> | --anyone] [--replace <ITEM>] [--totp] [--description <text>] [--ttl <seconds>] [-e <environment>] [--server <url>]"
	valuesAskedUsage     = "Usage: varlatch values asked [--json] [-e <environment>] [--server <url>]"
	valuesAskCancelUsage = "Usage: varlatch values ask-cancel <link ID> [-e <environment>] [--server <url>]"
)

// entryLinkURL is a link's address, with its token.
var (
	entryLinkURL    = regexp.MustCompile(`^https?://[^\s#?]+/entry#(vlt_entry_[A-Za-z0-9_-]{43})$`)
	entryLinkID     = regexp.MustCompile(`^enl_[a-z2-7]{10,60}$`)
	entryLinkTTL    = regexp.MustCompile(`^[0-9]{1,5}$`)
	entryLinkStatus = map[string]string{"pending": "waiting", "entered": "entered", "expired": "expired", "cancelled": "cancelled"}
)

// EntryLinkNotShown is ask's message when the answer holds no link it may
// print. It names nothing from the answer.
const EntryLinkNotShown = "varlatch values ask: the server's answer holds no entry link in Varlatch's format, or holds a credential or value this run knows, so no link is printed. The server may have made one anyway: varlatch values asked lists it, and varlatch values ask-cancel ends it."

// valuesAskContext resolves where a command with options of its own works.
func (r *Run) valuesAskContext(parsed *ParsedOptions) (*clientctx.Context, *lazyClient, error) {
	var where []string
	if env, ok := parsed.Value("--environment"); ok {
		where = append(where, "--environment", env)
	}
	if server, ok := parsed.Value("--server"); ok {
		where = append(where, "--server", server)
	}
	cwd, err := Cwd()
	if err != nil {
		return nil, nil, err
	}
	ctx, err := r.resolveArgs(cwd, where)
	if err != nil {
		return nil, nil, contextError(err)
	}
	return ctx, r.client(ctx), nil
}

func (r *Run) valuesAsk() error {
	// Value-free: a value typed after the item is never repeated.
	parsed, err := valueFreeOptions("values ask", r.Args, OptionSpec{
		Values:      []string{"--environment", "--server", "--for", "--replace", "--description", "--ttl"},
		Booleans:    []string{"--anyone", "--totp"},
		Aliases:     []Alias{{"-e", "--environment"}},
		Positionals: 2,
	}, valuesAskUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 2 {
		return UsageOnly(valuesAskUsage)
	}
	item := parsed.Positionals[1]
	who, named := parsed.Value("--for")
	anyone := parsed.Has("--anyone")
	if named && anyone {
		return UsageErrorWithUsage("varlatch values ask: --for names one person and --anyone asks nobody who they are: give one of them.", "\n"+valuesAskUsage)
	}
	replace, replaces := parsed.Value("--replace")
	if replaces && replace != item {
		return UsageErrorWithUsage("varlatch values ask: --replace names "+replace+", but this command asks for "+item+"; approval for one item never covers another.", "\n"+valuesAskUsage)
	}
	body := jsjson.Object{{Key: "item", Value: item}}
	switch {
	case anyone:
		body = append(body, jsjson.Member{Key: "restrictedTo", Value: "anyone"})
	case named:
		body = append(body, jsjson.Member{Key: "restrictedTo", Value: "identity"}, jsjson.Member{Key: "identityId", Value: who})
	}
	if replaces {
		body = append(body, jsjson.Member{Key: "replace", Value: true})
	}
	if parsed.Has("--totp") {
		body = append(body, jsjson.Member{Key: "accepts", Value: "otpauth"})
	}
	if d, ok := parsed.Value("--description"); ok {
		body = append(body, jsjson.Member{Key: "description", Value: d})
	}
	if ttl, ok := parsed.Value("--ttl"); ok {
		n, err := strconv.Atoi(ttl)
		if err != nil || !entryLinkTTL.MatchString(ttl) || n < 60 || n > 3600 {
			return UsageErrorWithUsage("varlatch values ask: --ttl is 60 to 3600 seconds.", "\n"+valuesAskUsage)
		}
		body = append(body, jsjson.Member{Key: "ttlSeconds", Value: float64(n)})
	}
	if r.Assisted.On && anyone {
		return Fail("varlatch values ask: a link open to anyone lets whoever reads it enter a value of theirs, and what an assistant prints is read in more than one place. "+
			"Leave --anyone out, or ask the human to run this in their own terminal. No link was made.", ExitConfig)
	}
	ctx, api, err := r.valuesAskContext(parsed)
	if err != nil {
		return err
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	// Before a request an older server does not know.
	meta, err := c.Meta(bg)
	if err != nil {
		return err
	}
	ok, err := includesCapability(meta, "values.entry-links")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("varlatch: this server (" + r.serverVersionText(meta) + ") has no entry links. No link was made.")
	}
	environment := environmentOf(ctx)
	made, err := c.CreateEntryLink(bg, ctx.Organization, ctx.Project, environment, body)
	if err != nil {
		return err
	}
	raw, _ := stringField(made, "url")
	m := entryLinkURL.FindStringSubmatch(raw)
	if m == nil || Printable(raw) != raw || !r.showableToken(entryToken, m[1]) {
		return Fail(EntryLinkNotShown, ExitFailure)
	}
	link, _ := jsval.Get(made, "link")
	id, _ := stringField(link, "id")
	if !entryLinkID.MatchString(id) {
		return Fail(EntryLinkNotShown, ExitFailure)
	}
	expires, _ := stringField(link, "expiresAt")
	toWhom := "a member of the organization"
	switch {
	case anyone:
		toWhom = "anyone who has it"
	case named:
		toWhom = Printable(who)
	}
	if err := r.println("Send this link to whoever has the value of " + item + " (" + environment + "), for " + toWhom + ", once:"); err != nil {
		return err
	}
	if err := r.outShowing("  "+raw+"\n", m[1]); err != nil {
		return err
	}
	return r.println("Expires: " + timeOr(expires, true, "undefined") + ". Link " + id + ": varlatch values asked says when the value was entered.")
}

func (r *Run) valuesAsked() error {
	parsed, err := strictOptions("values asked", r.Args, OptionSpec{
		Values: []string{"--environment", "--server"}, Booleans: []string{"--json"}, Aliases: []Alias{{"-e", "--environment"}}, Positionals: 1,
	}, valuesAskedUsage)
	if err != nil {
		return err
	}
	ctx, api, err := r.valuesAskContext(parsed)
	if err != nil {
		return err
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	answer, err := c.ListEntryLinks(bg, ctx.Organization, ctx.Project, environmentOf(ctx))
	if err != nil {
		return err
	}
	items, err := itemsOf(answer)
	if err != nil {
		return err
	}
	if parsed.Has("--json") {
		list := make([]any, len(items))
		for i, l := range items {
			o := jsjson.Object{}
			for _, key := range []string{"id", "item", "accepts", "replace", "restrictedTo", "status", "reason", "requestedByIdentityId", "createdAt", "expiresAt", "endedAt"} {
				if v, ok := jsval.Get(l, key); ok {
					o = append(o, jsjson.Member{Key: key, Value: v})
				}
			}
			list[i] = o
		}
		return r.printJSON(jsjson.Object{{Key: "version", Value: statusSchemaVersion}, {Key: "environment", Value: ctx.Environment}, {Key: "items", Value: list}})
	}
	if len(items) == 0 {
		return r.println("No entry links in " + environmentOf(ctx) + ".")
	}
	for _, l := range items {
		id, _ := stringField(l, "id")
		item, _ := stringField(l, "item")
		status, _ := stringField(l, "status")
		said, ok := entryLinkStatus[status]
		if !ok {
			said = Printable(status)
		}
		switch reason, _ := stringField(l, "reason"); reason {
		case "value-changed":
			said += ": the value changed first"
		case "credential-ended":
			said = "ended with the credential that made it"
		}
		if err := r.println(strings.Join([]string{Printable(item), said, Printable(id)}, "  ")); err != nil {
			return err
		}
	}
	return nil
}

func (r *Run) valuesAskCancel() error {
	parsed, err := strictOptions("values ask-cancel", r.Args, OptionSpec{
		Values: []string{"--environment", "--server"}, Aliases: []Alias{{"-e", "--environment"}}, Positionals: 2,
	}, valuesAskCancelUsage)
	if err != nil {
		return err
	}
	if len(parsed.Positionals) < 2 {
		return UsageOnly(valuesAskCancelUsage)
	}
	id := parsed.Positionals[1]
	if !entryLinkID.MatchString(id) {
		// A pasted address is never repeated: its secret would be in the message.
		return UsageErrorWithUsage("varlatch values ask-cancel: give the link's ID (enl_…), as varlatch values asked lists it.", "\n"+valuesAskCancelUsage)
	}
	ctx, api, err := r.valuesAskContext(parsed)
	if err != nil {
		return err
	}
	c, err := api.get()
	if err != nil {
		return err
	}
	if _, err := c.CancelEntryLink(bg, ctx.Organization, ctx.Project, environmentOf(ctx), id); err != nil {
		return err
	}
	return r.println("Entry link " + id + " cancelled.")
}
