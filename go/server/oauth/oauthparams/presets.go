// SPDX-License-Identifier: AGPL-3.0-or-later

package oauthparams

import (
	"regexp"
	"slices"
)

// A Preset is data about one provider: where its documents are, and what
// its authorization request needs to give a refresh token. Nothing else in
// Varlatch knows a provider's name.
type Preset struct {
	Name string
	// Issuer is the provider's, for a tenant where it has tenants.
	Issuer func(tenant string) string
	// Tenant is what a tenant is written as; nil: the provider has none.
	Tenant *regexp.Regexp
	Grants []string
	// Scopes are added to the ones asked for, in an authorization code
	// grant: an ID token to know the account, a refresh token.
	Scopes   []string
	Params   []Param
	IdleDays int64
}

// Generic is the preset of any other server, by its issuer or its endpoints.
const Generic = "generic"

// Presets are the presets with a fixed issuer.
var Presets = map[string]Preset{
	"google": {
		Name:   "google",
		Issuer: func(string) string { return "https://accounts.google.com" },
		Grants: []string{AuthorizationCode},
		Scopes: []string{"openid", "email"},
		// A refresh token comes with access_type=offline, and again only when
		// the person consents again.
		Params:   []Param{{"access_type", "offline"}, {"prompt", "consent"}},
		IdleDays: 180,
	},
	"microsoft": {
		Name: "microsoft",
		// The tenant's own ID: for common, organizations and consumers the
		// issuer of a token is another one than the one asked, so none of them
		// could be checked, and whoever signs in would be whoever has any
		// Microsoft account.
		Issuer:   func(tenant string) string { return "https://login.microsoftonline.com/" + tenant + "/v2.0" },
		Tenant:   regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
		Grants:   []string{AuthorizationCode, ClientCredentials},
		Scopes:   []string{"openid", "profile", "email", "offline_access"},
		IdleDays: 90,
	},
}

// WithScopes are scopes and the preset's that they lack, the preset's first.
func (p Preset) WithScopes(scopes []string) []string {
	out := slices.Clone(p.Scopes)
	for _, s := range scopes {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
