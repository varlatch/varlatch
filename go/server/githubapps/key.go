// SPDX-License-Identifier: AGPL-3.0-or-later

package githubapps

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	vsync "github.com/varlatch/varlatch/go/lib/sync"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
	"github.com/varlatch/varlatch/go/server/write"
)

// OpenAppKey is appWithKey's decryption: the live App's private key,
// unwrapped under orgKEK.
func OpenAppKey(orgKEK []byte, a App) (*rsa.PrivateKey, error) {
	if !a.KeyEnvelope.Valid {
		return nil, noApp()
	}
	pemText, err := OpenKey(orgKEK, a.OrganizationID, a.ID, a.KeyEnvelope.String)
	if err != nil {
		return nil, err
	}
	key := ParseRSAKey(pemText)
	if key == nil {
		return nil, domainerr.New("INTERNAL", "The GitHub App's stored key is not an RSA key")
	}
	return key, nil
}

// VerifyKey is a key rotation's check of the new key (ADR-0047 Decision
// 5): GET /app signed with it, issued as the App's client id, must answer
// this App. Nil when GitHub confirmed it; an error only when the effect
// ended.
func VerifyKey(ctx context.Context, c *http.Client, a App, key *rsa.PrivateKey, now time.Time) (*vsync.AccessCheck, error) {
	fail := func(ch vsync.AccessCheck) (*vsync.AccessCheck, error) { return &ch, nil }
	ans, claims, refusal, err := AppRequest(ctx, c, http.MethodGet, "/app", a.ClientID, key, now, nil)
	if err != nil {
		return nil, err
	}
	if ans == nil {
		if derr := write.EffectAlive(ctx); derr != nil {
			return nil, derr
		}
		return fail(GitHubUnreachable(refusal))
	}
	if ans.status == http.StatusUnauthorized {
		return fail(ReadJWTRefusal(ans.asResponse(), claims))
	}
	if ans.status < 200 || ans.status > 299 {
		return fail(vsync.AccessCheck{Status: vsync.StatusFailed, Where: vsync.WhereConnection, HTTPStatus: ans.status,
			Message: "GitHub did not confirm the new key for the App " + a.Slug + " (HTTP " + itoa(int64(ans.status)) + ")."})
	}
	v, _ := ans.json()
	body, ok := v.(jsvalue.Object)
	var id any
	if ok {
		id, _ = body.Get("id")
	}
	if n, isNum := id.(float64); !ok || !isNum || n != float64(a.GitHubAppID) {
		return fail(NotGitHub(ans.status))
	}
	return nil, nil
}
