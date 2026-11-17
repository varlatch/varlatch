// SPDX-License-Identifier: Apache-2.0

package sync

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// GitHub Actions secrets adapter. Base identity is the repository owner;
// the destination is one repository, optionally narrowed to a repository
// environment. Values are encrypted client-side with the destination's
// public key (a sealed box); GitHub never returns secret values, so this
// platform cannot verify-and-fix.

const githubAPI = "https://api.github.com"

var (
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubNamePattern  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// githubMaxPages is how many pages of 100 a repository listing reads.
const githubMaxPages = 30

var (
	githubTokenRejected = AccessCheck{Status: StatusCredentialRejected, Where: WhereConnection, HTTPStatus: 401,
		Message: "GitHub rejected the token: it is mistyped, expired, or revoked."}
	githubAppTokenRejected = AccessCheck{Status: StatusCredentialRejected, Where: WhereConnection, HTTPStatus: 401,
		Message: "GitHub refused the token Varlatch had just issued for the App's installation. The installation may have been removed or suspended; check it on GitHub, then try again."}
)

type githubActions struct{}

// GitHubActionsAdapter is githubActionsAdapter.
var GitHubActionsAdapter Adapter = githubActions{}

func (githubActions) Platform() Platform             { return GitHubActions }
func (githubActions) CredentialScopeUnit() ScopeUnit { return ScopeDestination }
func (githubActions) SupportsReadBack() bool         { return false }
func (githubActions) SupportsRedeploy() bool         { return false }

func githubHeaders(credential string) [][2]string {
	return [][2]string{
		{"Authorization", "Bearer " + credential},
		{"Accept", "application/vnd.github+json"},
		{"X-GitHub-Api-Version", "2022-11-28"},
		{"User-Agent", "varlatch-sync"},
		{"Content-Type", "application/json"},
	}
}

func githubSecretsBase(req *Request) (string, error) {
	repoPath := githubAPI + "/repos/" + req.BaseIdentity + "/" + req.Destination.Get("repo")
	if env := req.Destination.Get("environment"); env != "" {
		enc, err := encodeURIComponent(env)
		if err != nil {
			return "", err
		}
		return repoPath + "/environments/" + enc + "/secrets", nil
	}
	return repoPath + "/actions/secrets", nil
}

// rateLimited: GitHub signals its primary rate limit with a 403 as well as
// a 429.
func rateLimited(res *response) bool {
	return res.status == 429 || headerValue(res, "x-ratelimit-remaining") == "0"
}

// headerValue is Headers.get: every value of the name, joined by ", ";
// ok is false when there is none.
func headerValue(res *response, name string) string {
	v, _ := headerGet(res, name)
	return v
}

func headerGet(res *response, name string) (string, bool) {
	values := res.header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

func githubListed(owner string, count int) AccessCheck {
	return AccessCheck{Status: StatusOK, Where: WhereConnection,
		Message: "The token can see " + strconv.Itoa(count) + " repositories in " + owner + "."}
}

func githubListedInstallation(owner string, count int) AccessCheck {
	return AccessCheck{Status: StatusOK, Where: WhereConnection,
		Message: "The GitHub App's installation includes " + strconv.Itoa(count) + " repositories in " + owner + "."}
}

// notGitHub is a 200 that is not GitHub's API.
func notGitHub(where Where) AccessCheck {
	return AccessCheck{Status: StatusFailed, Where: where, HTTPStatus: 200,
		Message: "The answer from api.github.com was not GitHub's. A proxy between this server and GitHub may be in the way."}
}

func githubRefused(res *response, where Where) AccessCheck {
	status := res.status
	if rateLimited(res) {
		status = 429
	}
	return unexpected("GitHub", status, where)
}

var tokenExpiration = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]*(UTC|Z|[+-]\d{2}:?\d{2})?$`)

// ParseTokenExpiration is parseTokenExpiration: GitHub's
// GitHub-Authentication-Token-Expiration header ("2026-06-03 19:52:44
// UTC") as an ISO 8601 instant, or "" for anything else.
func ParseTokenExpiration(value string, present bool) string {
	if !present {
		return ""
	}
	m := tokenExpiration.FindStringSubmatch(whatwg.Trim(value))
	if m == nil {
		return ""
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	year, month, day, hour, minute, second := n(1), n(2), n(3), n(4), n(5), n(6)
	// Date's ISO format: days past the month's end roll over, 24:00:00 is
	// the next day, and nothing else out of range parses.
	if month < 1 || month > 12 || day < 1 || day > 31 || minute > 59 || second > 59 ||
		hour > 24 || (hour == 24 && (minute != 0 || second != 0)) {
		return ""
	}
	offset := 0
	if zone := m[7]; zone != "" && zone != "UTC" && zone != "Z" {
		digits := strings.ReplaceAll(zone[1:], ":", "")
		hh, _ := strconv.Atoi(digits[:2])
		mm, _ := strconv.Atoi(digits[2:])
		if hh > 23 || mm > 59 {
			return ""
		}
		offset = hh*60 + mm
		if zone[0] == '-' {
			offset = -offset
		}
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, 0, time.UTC).Add(-time.Duration(offset) * time.Minute)
	return isoString(t)
}

// isoString is Date.prototype.toISOString.
func isoString(t time.Time) string {
	t = t.UTC()
	y := t.Year()
	year := fmt.Sprintf("%04d", y)
	if y < 0 || y > 9999 {
		sign := "+"
		if y < 0 {
			sign, y = "-", -y
		}
		year = sign + fmt.Sprintf("%06d", y)
	}
	return fmt.Sprintf("%s-%02d-%02dT%02d:%02d:%02d.%03dZ", year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1e6)
}

func githubRequest(ctx context.Context, req *Request, method, url string, body []byte) (*response, error) {
	res, err := send(ctx, req, method, url, githubHeaders(req.Credential), body)
	if err != nil {
		return nil, err
	}
	// A minted installation token's expiry is not the Connection's
	// (ADR-0047 Decision 4).
	if req.CredentialKind != GitHubApp {
		v, ok := headerGet(res, "github-authentication-token-expiration")
		if expiresAt := ParseTokenExpiration(v, ok); expiresAt != "" && req.OnCredentialExpiry != nil {
			req.OnCredentialExpiry(expiresAt)
		}
	}
	return res, nil
}

// withExpiry runs fn with the request's expiry observed, and puts it on
// the check.
func withExpiry(req *Request, fn func(*Request) AccessCheck) AccessCheck {
	seen := ""
	r := *req
	r.OnCredentialExpiry = func(expiresAt string) {
		seen = expiresAt
		if req.OnCredentialExpiry != nil {
			req.OnCredentialExpiry(expiresAt)
		}
	}
	check := fn(&r)
	if seen != "" {
		check.CredentialExpiresAt = seen
	}
	return check
}

func (githubActions) CanonicalizeBaseIdentity(raw string) (string, error) {
	owner := strings.TrimPrefix(whatwg.Trim(raw), "@")
	if !githubOwnerPattern.MatchString(owner) {
		return "", &AdapterError{Message: "Invalid GitHub owner (user or organization login)"}
	}
	return strings.ToLower(owner), nil
}

func (githubActions) CanonicalizeDestination(raw Object) (Destination, error) {
	repo := ""
	if s, ok := raw.Value("repo").(string); ok {
		repo = whatwg.Trim(s)
	}
	if !githubRepoPattern.MatchString(repo) {
		return Destination{}, &AdapterError{Message: "Invalid GitHub repository name"}
	}
	environment, hasEnvironment := "", false
	if s, ok := raw.Value("environment").(string); ok && whatwg.Trim(s) != "" {
		environment, hasEnvironment = whatwg.Trim(s), true
	}
	if hasEnvironment && len(codeUnits(environment)) > 255 {
		return Destination{}, &AdapterError{Message: "Invalid GitHub environment name"}
	}
	fields := Fields{{"repo", strings.ToLower(repo)}}
	key := fields[0].Value
	if hasEnvironment {
		fields = append(fields, Field{"environment", environment})
		key += "#" + environment
	}
	return Destination{Fields: fields, Key: key}, nil
}

func (githubActions) ValidateName(name string, _ Fields) string {
	canonical := jsToUpper(name)
	if !githubNamePattern.MatchString(canonical) {
		return "GitHub secret names allow only letters, digits, and _, not starting with a digit"
	}
	if strings.HasPrefix(canonical, "GITHUB_") {
		return "GITHUB_-prefixed secret names are reserved"
	}
	if len(codeUnits(canonical)) > 200 {
		return "GitHub secret names are limited to 200 characters"
	}
	return ""
}

func (githubActions) CanonicalizeName(name string) string { return jsToUpper(name) }

func (githubActions) WriteValues(ctx context.Context, req *Request, items []SyncItem) ([]NameOutcome, error) {
	base, err := githubSecretsBase(req)
	if err != nil {
		return nil, err
	}
	keyRes, err := githubRequest(ctx, req, "GET", base+"/public-key", nil)
	if err != nil {
		return nil, err
	}
	if !keyRes.ok() {
		return nil, &AdapterError{
			Message:   "GitHub public key fetch failed (" + strconv.Itoa(keyRes.status) + ")",
			Retryable: keyRes.status != 401 && keyRes.status != 403 && keyRes.status != 404,
		}
	}
	parsed, err := keyRes.json()
	if err != nil {
		return nil, err
	}
	// Buffer.from(publicKey.key, "base64"): a string decodes, an array is
	// its bytes, anything else (or a null answer) is a TypeError.
	publicKey, _ := parsed.(Object)
	var recipient []byte
	switch key := publicKey.Value("key").(type) {
	case string:
		recipient = nodeBase64(key)
	case []any:
		recipient = make([]byte, len(key))
		for i, e := range key {
			if f, ok := e.(float64); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				recipient[i] = byte(int64(math.Trunc(math.Mod(f, 256))))
			}
		}
	default:
		return nil, &ScriptError{Name: "TypeError", Message: "the public key is not a string"}
	}
	keyID, hasKeyID := publicKey.Get("key_id")

	outcomes := []NameOutcome{}
	for _, item := range items {
		stop, err := req.abort(ctx)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		sealed, err := SealedBox([]byte(wellFormed(item.Value)), recipient)
		if err != nil {
			return nil, err
		}
		name, err := encodeURIComponent(item.Name)
		if err != nil {
			return nil, err
		}
		body := Object{{"encrypted_value", base64.StdEncoding.EncodeToString(sealed)}}
		if hasKeyID {
			body = append(body, Member{"key_id", keyID})
		}
		res, err := githubRequest(ctx, req, "PUT", base+"/"+name, stringify(body))
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, outcome(item.Name, res, false))
	}
	return outcomes, nil
}

// outcome is a name's outcome from its answer; absentOK counts a 404 as
// converged.
func outcome(name string, res *response, absentOK bool) NameOutcome {
	if res.ok() || (absentOK && res.status == 404) {
		return NameOutcome{Name: name, OK: true}
	}
	return NameOutcome{Name: name, Error: "HTTP " + strconv.Itoa(res.status)}
}

func (githubActions) DeleteNames(ctx context.Context, req *Request, names []string) ([]NameOutcome, error) {
	base, err := githubSecretsBase(req)
	if err != nil {
		return nil, err
	}
	outcomes := []NameOutcome{}
	for _, name := range names {
		stop, err := req.abort(ctx)
		if err != nil {
			return nil, err
		}
		if stop {
			break
		}
		enc, err := encodeURIComponent(name)
		if err != nil {
			return nil, err
		}
		res, err := githubRequest(ctx, req, "DELETE", base+"/"+enc, nil)
		if err != nil {
			return nil, err
		}
		// A 404 is converged: the name is already absent.
		outcomes = append(outcomes, outcome(name, res, true))
	}
	return outcomes, nil
}

// CheckAccess checks the owner first (a bad token is a 401 on any route),
// then, for a destination, the public-key read every push starts with.
func (githubActions) CheckAccess(ctx context.Context, req *Request) AccessCheck {
	return withExpiry(req, func(r *Request) AccessCheck { return checkGitHubAccess(ctx, r) })
}

func (githubActions) ListDestinations(ctx context.Context, req *Request) DestinationListing {
	seen := ""
	r := *req
	r.OnCredentialExpiry = func(expiresAt string) {
		seen = expiresAt
		if req.OnCredentialExpiry != nil {
			req.OnCredentialExpiry(expiresAt)
		}
	}
	listing := listGitHubRepositories(ctx, &r)
	if seen != "" {
		listing.Check.CredentialExpiresAt = seen
	}
	return listing
}

func checkGitHubAccess(ctx context.Context, req *Request) AccessCheck {
	owner := req.BaseIdentity
	repo, environment := req.Destination.Get("repo"), req.Destination.Get("environment")
	where := WhereConnection
	if req.CredentialKind == GitHubApp && repo == "" {
		return checkInstallation(ctx, req)
	}
	fail := func(err error) AccessCheck { return unreachable("api.github.com", err, where) }
	user, err := githubRequest(ctx, req, "GET", githubAPI+"/users/"+owner, nil)
	if err != nil {
		return fail(err)
	}
	if user.status == 401 {
		return githubTokenRejected
	}
	if user.status == 404 {
		return AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "GitHub has no user or organization named " + owner + "."}
	}
	if !user.ok() {
		return githubRefused(user, where)
	}
	account, _ := user.jsonBody()
	if o, isObject := account.(Object); !isObject {
		return notGitHub(where)
	} else if _, ok := o.Value("login").(string); !ok {
		return notGitHub(where)
	}
	if repo == "" {
		return AccessCheck{Status: StatusOK, Where: where, Message: "GitHub accepted the token, and " + owner + " exists."}
	}

	where = WhereDestination
	place, permission := owner+"/"+repo, "Secrets"
	if environment != "" {
		place, permission = owner+"/"+repo+" (environment "+environment+")", "Environments"
	}
	base, err := githubSecretsBase(req)
	if err != nil {
		return fail(err)
	}
	key, err := githubRequest(ctx, req, "GET", base+"/public-key", nil)
	if err != nil {
		return fail(err)
	}
	if key.ok() {
		publicKey, _ := key.jsonBody()
		o, isObject := publicKey.(Object)
		_, idOK := o.Value("key_id").(string)
		_, keyOK := o.Value("key").(string)
		if !isObject || !idOK || !keyOK {
			return notGitHub(where)
		}
		return AccessCheck{Status: StatusOK, Where: where,
			Message: "The token can read the secrets of " + place + ". The first push shows whether it may also write them."}
	}
	if key.status == 401 {
		return githubTokenRejected
	}
	if key.status == 403 && !rateLimited(key) {
		return AccessCheck{Status: StatusPermissionMissing, Where: where, HTTPStatus: 403,
			Message: "GitHub refused the token access to the secrets of " + place + ". Give it " + permission + ": Read and write, and check that the organization approved it."}
	}
	if key.status == 404 {
		if environment != "" {
			repoRes, err := githubRequest(ctx, req, "GET", githubAPI+"/repos/"+owner+"/"+repo, nil)
			if err != nil {
				return fail(err)
			}
			if repoRes.ok() {
				return AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
					Message: owner + "/" + repo + " has no environment named " + environment + ". Create it in the repository settings, or leave the field empty for repository secrets."}
			}
		}
		return AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "GitHub cannot find " + owner + "/" + repo + " with this token. Check the name, and that the token's repository access includes it."}
	}
	return githubRefused(key, where)
}

// installationPage is an installation listing's answer, when it has the
// shape GitHub gives it.
func installationPage(res *response) (total float64, repos []any, ok bool) {
	body, _ := res.jsonBody()
	o, isObject := body.(Object)
	total, totalOK := o.Value("total_count").(float64)
	repos, reposOK := o.Value("repositories").([]any)
	return total, repos, isObject && totalOK && reposOK
}

// checkInstallation is an App Connection alone (ADR-0047 Decision 4): the
// installation's own listing, one repository.
func checkInstallation(ctx context.Context, req *Request) AccessCheck {
	where := WhereConnection
	res, err := githubRequest(ctx, req, "GET", githubAPI+"/installation/repositories?per_page=1", nil)
	if err != nil {
		return unreachable("api.github.com", err, where)
	}
	if res.status == 401 {
		return githubAppTokenRejected
	}
	if !res.ok() {
		return githubRefused(res, where)
	}
	total, _, ok := installationPage(res)
	if !ok {
		return notGitHub(where)
	}
	noun := "repositories"
	if total == 1 {
		noun = "repository"
	}
	return AccessCheck{Status: StatusOK, Where: where,
		Message: "The GitHub App is installed on " + req.BaseIdentity + ", with access to " + jsNumber(total) + " " + noun + "."}
}

// repoOption is a listed repository the listing keeps: not archived, a
// name the destination takes, and the owner's.
func repoOption(repo any, owner string) (DestinationOption, bool) {
	o, ok := repo.(Object)
	if !ok {
		return DestinationOption{}, false
	}
	ownerObject, ownerOK := o.Value("owner").(Object)
	if !ownerOK || o.Value("archived") == true {
		return DestinationOption{}, false
	}
	name, _ := o.Value("name").(string)
	login := "undefined" // String(undefined)
	if v, has := ownerObject.Get("login"); has {
		login = jsString(v)
	}
	if !githubRepoPattern.MatchString(name) || whatwg.ToLower(login) != owner {
		return DestinationOption{}, false
	}
	detail := "public"
	if o.Value("private") == true {
		detail = "private"
	}
	return DestinationOption{Destination: Fields{{"repo", name}}, Label: name, Detail: detail}, true
}

// listInstallationRepositories is an App Connection's repositories
// (ADR-0047 Decision 4), from GET /installation/repositories.
func listInstallationRepositories(ctx context.Context, req *Request) DestinationListing {
	owner := req.BaseIdentity
	where := WhereConnection
	items := []DestinationOption{}
	for page := 1; ; page++ {
		if page > githubMaxPages {
			return DestinationListing{Check: githubListedInstallation(owner, len(items)), Items: items, Truncated: true}
		}
		res, err := githubRequest(ctx, req, "GET", githubAPI+"/installation/repositories?per_page=100&page="+strconv.Itoa(page), nil)
		if err != nil {
			return listingFailed(unreachable("api.github.com", err, where))
		}
		if res.status == 401 {
			return listingFailed(githubAppTokenRejected)
		}
		if !res.ok() {
			return listingFailed(githubRefused(res, where))
		}
		_, repos, ok := installationPage(res)
		if !ok {
			return listingFailed(notGitHub(where))
		}
		for _, repo := range repos {
			option, keep := repoOption(repo, owner)
			if !keep {
				continue
			}
			if len(items) == MaxDestinations {
				return DestinationListing{Check: githubListedInstallation(owner, len(items)), Items: items, Truncated: true}
			}
			items = append(items, option)
		}
		if len(repos) < 100 {
			return DestinationListing{Check: githubListedInstallation(owner, len(items)), Items: items}
		}
	}
}

// listGitHubRepositories is the repositories the token can see in the
// owner, archived ones left out.
func listGitHubRepositories(ctx context.Context, req *Request) DestinationListing {
	if req.CredentialKind == GitHubApp {
		return listInstallationRepositories(ctx, req)
	}
	owner := req.BaseIdentity
	where := WhereConnection
	fail := func(err error) DestinationListing { return listingFailed(unreachable("api.github.com", err, where)) }
	user, err := githubRequest(ctx, req, "GET", githubAPI+"/users/"+owner, nil)
	if err != nil {
		return fail(err)
	}
	if user.status == 401 {
		return listingFailed(githubTokenRejected)
	}
	if user.status == 404 {
		return listingFailed(AccessCheck{Status: StatusNotFound, Where: where, HTTPStatus: 404,
			Message: "GitHub has no user or organization named " + owner + "."})
	}
	if !user.ok() {
		return listingFailed(githubRefused(user, where))
	}
	account, _ := user.jsonBody()
	o, isObject := account.(Object)
	if _, ok := o.Value("login").(string); !isObject || !ok {
		return listingFailed(notGitHub(where))
	}
	listing := githubAPI + "/user/repos?affiliation=owner,collaborator&sort=full_name&per_page=100"
	if o.Value("type") == "Organization" {
		listing = githubAPI + "/orgs/" + owner + "/repos?type=all&sort=full_name&per_page=100"
	}
	items := []DestinationOption{}
	for page := 1; ; page++ {
		// Filtering a user's listing to one owner can skip many pages.
		if page > githubMaxPages {
			return DestinationListing{Check: githubListed(owner, len(items)), Items: items, Truncated: true}
		}
		res, err := githubRequest(ctx, req, "GET", listing+"&page="+strconv.Itoa(page), nil)
		if err != nil {
			return fail(err)
		}
		if res.status == 401 {
			return listingFailed(githubTokenRejected)
		}
		if !res.ok() {
			return listingFailed(githubRefused(res, where))
		}
		body, _ := res.jsonBody()
		repos, ok := body.([]any)
		if !ok {
			return listingFailed(notGitHub(where))
		}
		for _, repo := range repos {
			option, keep := repoOption(repo, owner)
			if !keep {
				continue
			}
			if len(items) == MaxDestinations {
				return DestinationListing{Check: githubListed(owner, len(items)), Items: items, Truncated: true}
			}
			items = append(items, option)
		}
		if len(repos) < 100 {
			return DestinationListing{Check: githubListed(owner, len(items)), Items: items}
		}
	}
}
