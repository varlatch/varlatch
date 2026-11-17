// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Installation tokens for App Connections (ADR-0047 Decision 3,
// githubmint.ts): one hour, minted per use, narrowed to what the use needs,
// never stored, handled as opaque strings. Nothing here fails on GitHub's
// answer: no answer is a check like any other.
//
//	push               the destination      secrets (environments) write, metadata read
//	destination-check  the destination      secrets (environments) read, metadata read
//	connection-check   the installation     metadata read
//	listing            the installation     metadata read

// MintUse is a use a token is minted for.
type MintUse string

const (
	UsePush             MintUse = "push"
	UseDestinationCheck MintUse = "destination-check"
	UseConnectionCheck  MintUse = "connection-check"
	UseListing          MintUse = "listing"
)

// maxMembershipPages is MAX_MEMBERSHIP_PAGES: 3,000 repositories.
const maxMembershipPages = 30

// Narrowing is narrowing: the body of the token request.
func Narrowing(use MintUse, destination vsync.Fields) jsvalue.Object {
	repo, env := destination.Get("repo"), destination.Get("environment")
	scoped := "secrets"
	if env != "" {
		scoped = "environments"
	}
	switch use {
	case UsePush:
		return jsvalue.Object{{Key: "repositories", Value: []any{repo}}, {Key: "permissions", Value: jsvalue.Object{{Key: scoped, Value: "write"}, {Key: "metadata", Value: "read"}}}}
	case UseDestinationCheck:
		return jsvalue.Object{{Key: "repositories", Value: []any{repo}}, {Key: "permissions", Value: jsvalue.Object{{Key: scoped, Value: "read"}, {Key: "metadata", Value: "read"}}}}
	}
	return jsvalue.Object{{Key: "permissions", Value: jsvalue.Object{{Key: "metadata", Value: "read"}}}}
}

// AppCredential is what an App Connection mints with: its App's
// identifiers and key, and its installation.
type AppCredential struct {
	GitHubAppID    int64
	ClientID       string
	Key            *rsa.PrivateKey
	InstallationID int64
	// Owner is the installation's account: the Connection's base identity.
	Owner string
}

// AppRemoved is APP_REMOVED.
var AppRemoved = vsync.AccessCheck{Status: vsync.StatusCredentialRejected, Where: vsync.WhereConnection,
	Message: "This Connection's GitHub App was removed from Varlatch, so Varlatch can no longer act for it."}

// Mint is mintInstallationToken: a token for use, or the check that says
// why there is none.
func Mint(ctx context.Context, c *http.Client, cred AppCredential, use MintUse, destination vsync.Fields, now time.Time) (string, *vsync.AccessCheck) {
	fail := func(ch vsync.AccessCheck) (string, *vsync.AccessCheck) { return "", &ch }
	body := jsvalue.Stringify(Narrowing(use, destination))
	a, claims, refusal, err := AppRequest(ctx, c, http.MethodPost, "/app/installations/"+itoa(cred.InstallationID)+"/access_tokens", cred.ClientID, cred.Key, now, body)
	if err != nil || a == nil {
		if refusal != nil {
			return fail(GitHubUnreachable(refusal))
		}
		return fail(vsync.AccessCheck{Status: vsync.StatusUnreachable, Where: vsync.WhereConnection,
			Message: "Varlatch could not reach api.github.com to issue a token for the App. Check that this server can reach it, then try again."})
	}
	switch {
	case a.status == http.StatusUnauthorized:
		return fail(ReadJWTRefusal(a.asResponse(), claims))
	case a.status == http.StatusNotFound:
		return fail(vsync.AccessCheck{Status: vsync.StatusCredentialRejected, Where: vsync.WhereConnection, HTTPStatus: 404,
			Message: "The GitHub App is no longer installed on " + cred.Owner + ". Install it again on GitHub, or choose another installation."})
	case a.status == http.StatusUnprocessableEntity:
		return fail(explain422(ctx, c, cred, destination, now))
	case a.status < 200 || a.status > 299:
		return fail(vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: a.status,
			Message: "GitHub refused to issue a token for the App (HTTP " + strconv.Itoa(a.status) + ")."})
	}
	v, _ := a.json()
	o, ok := v.(jsvalue.Object)
	tok, _ := o.Get("token")
	token, isStr := tok.(string)
	if !ok || !isStr || token == "" {
		return fail(NotGitHub(a.status))
	}
	return token, nil
}

// explain422 is explain422: a 422 at minting has more than one documented
// cause (a repository outside the installation or missing; a permission
// the App or the installation lacks). The repository is read with an
// installation-wide metadata token, every step GitHub's own answer; only a
// complete list rules membership out. Anything else keeps the 422
// qualified.
func explain422(ctx context.Context, c *http.Client, cred AppCredential, destination vsync.Fields, now time.Time) vsync.AccessCheck {
	repo := destination.Get("repo")
	where := cred.Owner
	if repo != "" {
		where = cred.Owner + "/" + repo
	}
	unclear := vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: 422,
		Message: "GitHub refused to issue a token for the App's installation. The App, or its installation, may lack a permission Varlatch needs."}
	if repo == "" {
		return unclear
	}
	unclear.Where = vsync.WhereDestination
	unclear.Message = "GitHub refused to issue a token for " + where + ". The repository may be outside the App's installation, or the App may lack a permission; Varlatch could not tell which."
	token, failed := Mint(ctx, c, cred, UseListing, vsync.Fields{}, now)
	if failed != nil {
		return unclear
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubAPI+"/repos/"+encodeURIComponent(cred.Owner)+"/"+encodeURIComponent(repo), nil)
	if err != nil {
		return unclear
	}
	setGitHubHeaders(req.Header)
	req.Header.Set("Authorization", "Bearer "+token)
	read, err := do(c, req)
	if err != nil {
		return unclear
	}
	v, _ := read.json()
	body, isRecord := v.(jsvalue.Object)
	if read.status == 404 && isRecord {
		if m, _ := body.Get("message"); isString(m) {
			return vsync.AccessCheck{Status: vsync.StatusNotFound, Where: vsync.WhereDestination, HTTPStatus: 422,
				Message: "The App's installation cannot see " + where + ": it is not among the installation's repositories, or does not exist. Add it in the installation's settings on GitHub."}
		}
	}
	if read.status == 200 && isRecord {
		if full, _ := body.Get("full_name"); isString(full) && strings.EqualFold(full.(string), where) {
			switch installationIncludes(ctx, c, token, where) {
			case "yes":
				return vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: 422,
					Message: "GitHub refused a token for " + where + ", though the App's installation includes it. The App, or its installation, may lack a permission Varlatch needs; an organization owner may need to approve the App's permissions on GitHub."}
			case "no":
				return vsync.AccessCheck{Status: vsync.StatusNotFound, Where: vsync.WhereDestination, HTTPStatus: 422,
					Message: where + " is not among the App installation's repositories. Add it in the installation's settings on GitHub."}
			}
		}
	}
	return unclear
}

func isString(v any) bool { _, ok := v.(string); return ok }

// installationIncludes is installationIncludes: "yes" as soon as the
// repository appears; "no" only from a complete list (every page GitHub's,
// the last one short, as many repositories as total_count says);
// "unknown" otherwise, past the page limit too.
func installationIncludes(ctx context.Context, c *http.Client, token, where string) string {
	seen := 0
	for page := 1; page <= maxMembershipPages; page++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubAPI+"/installation/repositories?per_page=100&page="+strconv.Itoa(page), nil)
		if err != nil {
			return "unknown"
		}
		setGitHubHeaders(req.Header)
		req.Header.Set("Authorization", "Bearer "+token)
		a, err := do(c, req)
		if err != nil || a.status < 200 || a.status > 299 {
			return "unknown"
		}
		v, _ := a.json()
		body, ok := v.(jsvalue.Object)
		total, _ := body.Get("total_count")
		totalN, isNum := total.(float64)
		reposV, _ := body.Get("repositories")
		repos, isArr := reposV.([]any)
		if !ok || !isNum || !isArr {
			return "unknown"
		}
		for _, r := range repos {
			ro, ok := r.(jsvalue.Object)
			full, _ := ro.Get("full_name")
			name, isStr := full.(string)
			if !ok || !isStr {
				return "unknown"
			}
			if strings.EqualFold(name, where) {
				return "yes"
			}
		}
		seen += len(repos)
		if len(repos) < 100 {
			if float64(seen) == totalN {
				return "no"
			}
			return "unknown"
		}
	}
	return "unknown"
}

// Installation is readInstallation's answer.
type Installation struct {
	Account   Account
	Suspended bool
}

// ReadInstallation is readInstallation: the App's view of one
// installation, signed as the App.
func ReadInstallation(ctx context.Context, c *http.Client, githubAppID int64, clientID string, key *rsa.PrivateKey, installationID int64, now time.Time) (*Installation, *vsync.AccessCheck) {
	fail := func(ch vsync.AccessCheck) (*Installation, *vsync.AccessCheck) { return nil, &ch }
	a, claims, refusal, err := AppRequest(ctx, c, http.MethodGet, "/app/installations/"+itoa(installationID), clientID, key, now, nil)
	if err != nil || a == nil {
		return fail(GitHubUnreachable(refusal))
	}
	switch {
	case a.status == http.StatusUnauthorized:
		return fail(ReadJWTRefusal(a.asResponse(), claims))
	case a.status == http.StatusNotFound:
		return fail(vsync.AccessCheck{Status: vsync.StatusNotFound, Where: vsync.WhereConnection, HTTPStatus: 404,
			Message: "Installation " + itoa(installationID) + " is not an installation of this GitHub App."})
	case a.status < 200 || a.status > 299:
		return fail(vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: a.status,
			Message: "GitHub refused to read the installation (HTTP " + strconv.Itoa(a.status) + ")."})
	}
	v, _ := a.json()
	body, ok := v.(jsvalue.Object)
	get := func(k string) any { x, _ := body.Get(k); return x }
	acct, acctOK := get("account").(jsvalue.Object)
	aget := func(k string) any { x, _ := acct.Get(k); return x }
	id, idOK := get("id").(float64)
	appID, appOK := get("app_id").(float64)
	login, _ := aget("login").(string)
	typ, _ := aget("type").(string)
	if !ok || !idOK || id != float64(installationID) || !appOK || appID != float64(githubAppID) || !acctOK ||
		!loginPattern.MatchString(login) || typ != "Organization" && typ != "User" {
		return fail(NotGitHub(a.status))
	}
	inst := &Installation{Account: Account{Login: login, Type: "user"}}
	if typ == "Organization" {
		inst.Account.Type = "organization"
	}
	if s, present := body.Get("suspended_at"); present && s != nil {
		inst.Suspended = true
	}
	return inst, nil
}

// CredentialFrom is appCredentialFrom: what an App Connection mints with,
// from its App's row (its key unwrapped under orgKEK); nil when the App is
// gone or removed.
func CredentialFrom(ctx context.Context, db query.DBTX, orgKEK []byte, organizationID, appRowID string, installationID int64, owner string) (*AppCredential, error) {
	r, err := query.New(db).GitHubAppForCredential(ctx, query.GitHubAppForCredentialParams{ID: appRowID, OrganizationID: organizationID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if r.RemovedAt.Valid || !r.KeyEnvelope.Valid {
		return nil, nil
	}
	pemText, err := OpenKey(orgKEK, organizationID, r.ID, r.KeyEnvelope.String)
	if err != nil {
		return nil, err
	}
	key := ParseRSAKey(pemText)
	if key == nil {
		return nil, domainerr.New("INTERNAL", "The GitHub App's stored key is not an RSA key")
	}
	return &AppCredential{GitHubAppID: r.GithubAppID, ClientID: r.ClientID, Key: key, InstallationID: installationID, Owner: owner}, nil
}
