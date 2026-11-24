// SPDX-License-Identifier: AGPL-3.0-or-later

package capabilities_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/varlatch/varlatch/go/server/httpserver"
	"github.com/varlatch/varlatch/go/server/paritytest"
)

// One-time codes (ADR-0061), over HTTP, on the parity fixture's rows.

const (
	seedA    = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXQ"
	seedB    = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	uriA     = "otpauth://totp/Portal:alice%40example.com?secret=" + seedA + "&issuer=Portal"
	uriB     = "otpauth://totp/Portal:alice%40example.com?secret=" + seedB + "&issuer=Portal&algorithm=SHA512&digits=8&period=60"
	envPath  = "/v1/organizations/cap/projects/api/environments/development"
	otpItem  = "PORTAL_OTP"
	otpPlace = "header:x-otp"
)

// codeOf is RFC 6238 written again, so the server is not held to its own.
func codeOf(secret, algorithm string, digits int, period int64, at time.Time) string {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}
	h := map[string]func() hash.Hash{"SHA1": sha1.New, "SHA256": sha256.New, "SHA512": sha512.New}[algorithm]
	m := hmac.New(h, key)
	_ = binary.Write(m, binary.BigEndian, at.Unix()/period)
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 15
	n := (uint64(sum[o])&127)<<24 | uint64(sum[o+1])<<16 | uint64(sum[o+2])<<8 | uint64(sum[o+3])
	mod := uint64(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, n%mod)
}

func codeA(at time.Time) string { return codeOf(seedA, "SHA1", 6, 30, at) }

// into moves the clock forward to d after the start of a 60-second period
// (so of a 30-second one too), with the wall's seconds going on.
func (w *world) into(d time.Duration) time.Time {
	now := w.now()
	start := now.Truncate(time.Minute).Add(time.Minute)
	w.ahead.Add(int64(start.Add(d).Sub(now)))
	return w.now()
}

func (w *world) setSeed(item, uri string) answer {
	return w.call("PUT", envPath+"/values/"+item, "alice", map[string]any{"otpauth": uri})
}

// otpCapability is one for PORTAL_OTP and SECRET_A.
func (w *world) otpCapability(as string, more with) capability {
	w.t.Helper()
	b := with{"items": []string{otpItem, "SECRET_A"}, "targets": map[string]any{otpItem: []string{otpPlace}, "SECRET_A": []string{"header:authorization"}}, "ttlSeconds": 86_400}
	for k, v := range more {
		b[k] = v
	}
	return w.issue(as, b)
}

func (w *world) exerciseOTP(as string, c capability, more with) answer {
	b := with{"placements": []any{map[string]any{"item": otpItem, "target": otpPlace}}}
	for k, v := range more {
		b[k] = v
	}
	return w.exercise(as, c, b)
}

// code is the one item of an exercise's answer.
func (w *world) code(what string, a answer) map[string]any {
	w.t.Helper()
	w.want(what, a, 200, "")
	items, _ := a.body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["kind"] != "totp" {
		w.t.Fatalf("%s: %s", what, a.raw)
	}
	return items[0].(map[string]any)
}

// noSeed fails when text holds a seed, in any form it is written in.
func noSeed(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{seedA, seedB} {
		raw, _ := base32.StdEncoding.DecodeString(s)
		for _, form := range []string{s, strings.ToLower(s), string(raw), "otpauth://"} {
			if strings.Contains(text, form) {
				t.Errorf("%s holds the seed (%q)", what, form)
				return
			}
		}
	}
}

func TestAnExerciseGivesTheCode(t *testing.T) {
	w := newWorld(t)
	set := w.want("set", w.setSeed(otpItem, uriA), 200, "")
	noSeed(t, "the answer to a write", set.raw)
	if got := fmt.Sprint(set.body["totp"]); got != "map[account:alice@example.com algorithm:SHA1 digits:6 issuer:Portal periodSeconds:30]" {
		t.Errorf("written: %s", got)
	}
	w.wantEvent("value.written", "Alice", map[string]any{"itemName": otpItem}, map[string]any{"sensitive": true, "totp": true})
	c := w.otpCapability("broker", nil)
	at := w.into(10 * time.Second)
	a := w.exerciseOTP("broker", c, nil)
	got := w.code("exercise", a)
	start := at.Truncate(30 * time.Second)
	if got["value"] != codeA(at) || got["versionId"] != set.body["versionId"] || got["notBefore"] != nil || got["startsInSeconds"] != nil ||
		got["expiresAt"] != start.Add(30*time.Second).UTC().Format("2006-01-02T15:04:05.000Z") {
		t.Errorf("%v, want the code %s of %s", got, codeA(at), start)
	}
	if left := got["expiresInSeconds"].(float64); left < 17 || left > 19 {
		t.Errorf("%v seconds left, at 10 of 30", left)
	}
	noSeed(t, "an exercise", a.raw)
	if a.raw == "" || a.body["withheld"] == nil || len(a.body["withheld"].([]any)) != 0 {
		t.Errorf("%s", a.raw)
	}
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id, "agentIdentityId": w.idn("agent")},
		map[string]any{"items": otpItem + "@" + set.body["versionId"].(string), "placements": otpItem + "=" + otpPlace,
			"oneTimeCodes": otpItem + "@" + set.body["versionId"].(string) + "=" + start.UTC().Format("2006-01-02T15:04:05.000Z")})
	// Again in the same period: the same code. In the next one: another.
	if again := w.code("again", w.exerciseOTP("broker", c, nil)); again["value"] != got["value"] {
		t.Errorf("another code in one period: %v, %v", got["value"], again["value"])
	}
	w.ahead.Add(int64(30 * time.Second))
	if next := w.code("the next period", w.exerciseOTP("broker", c, nil)); next["value"] != codeA(w.now()) {
		t.Errorf("%v, want %s", next["value"], codeA(w.now()))
	}
	// With a password, in one exercise.
	both := w.want("both", w.exerciseOTP("broker", c, with{"placements": []any{
		map[string]any{"item": otpItem, "target": otpPlace}, map[string]any{"item": "SECRET_A", "target": "header:authorization"}}}), 200, "")
	items := both.body["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["value"] != "a-secret" || items[0].(map[string]any)["kind"] != nil || items[1].(map[string]any)["value"] != codeA(w.now()) {
		t.Errorf("%s", both.raw)
	}
	// The code has an event of its own, after the Secret's.
	version := set.body["versionId"].(string)
	exercised := paritytest.Rows(t, w.store, "SELECT * FROM audit_events WHERE event_type = 'capability.exercised' ORDER BY event_order DESC LIMIT 2")
	for i, want := range []string{`"items":"` + otpItem + "@" + version + `","placements":"` + otpItem + "=" + otpPlace + `","withheld":0,"runId":null,"oneTimeCodes":"` + otpItem + "@" + version,
		`,"placements":"SECRET_A=header:authorization","withheld":0,"runId":null}`} {
		if got := fmt.Sprint(exercised[i]["metadata"]); !strings.Contains(got, want) {
			t.Errorf("%s, want %s", got, want)
		}
	}
	// Neither a code nor a seed is in the audit log.
	for _, r := range paritytest.Rows(t, w.store, "SELECT * FROM audit_events WHERE event_type LIKE 'capability.%' OR event_type LIKE 'value.%'") {
		text := fmt.Sprint(r)
		noSeed(t, "the audit log", text)
		for _, code := range []string{got["value"].(string), codeA(w.now())} {
			if strings.Contains(text, code) {
				t.Errorf("the audit log holds a code: %s", text)
			}
		}
	}
}

func TestCodesOfEveryKind(t *testing.T) {
	w := newWorld(t)
	c := w.otpCapability("broker", nil)
	for _, algorithm := range []string{"SHA1", "SHA256", "SHA512"} {
		for _, digits := range []int{6, 8} {
			for _, period := range []int64{30, 60} {
				w.want("set", w.setSeed(otpItem, fmt.Sprintf("otpauth://totp/x?secret=%s&algorithm=%s&digits=%d&period=%d", seedB, algorithm, digits, period)), 200, "")
				for _, into := range []time.Duration{time.Second, 31 * time.Second} {
					at := w.into(into)
					got := w.code("exercise", w.exerciseOTP("broker", c, nil))
					if want := codeOf(seedB, algorithm, digits, period, at); got["value"] != want {
						t.Errorf("%s, %d digits, %d s: %v, want %s", algorithm, digits, period, got["value"], want)
					}
				}
			}
		}
	}
}

func TestMinValidity(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", with{"singleUse": true})
	// Too long for any code: refused, and the single use is not spent.
	long := w.want("31 seconds", w.exerciseOTP("broker", c, with{"minValiditySeconds": 31}), 422, "VALIDATION_FAILED")
	if !strings.Contains(long.raw, `"reason":"min-validity-too-long"`) || !strings.Contains(long.raw, "30 seconds") {
		t.Errorf("%s", long.raw)
	}
	w.wantEvent("capability.denied", "broker", nil, map[string]any{"reason": "min-validity-too-long", "item": otpItem})
	for _, bad := range []any{-1, 1.5, "10", 86_401} {
		w.want(fmt.Sprint("minValiditySeconds ", bad), w.exerciseOTP("broker", c, with{"minValiditySeconds": bad}), 422, "VALIDATION_FAILED")
	}
	w.want("fresh", w.exerciseOTP("broker", c, with{"fresh": "yes"}), 422, "VALIDATION_FAILED")
	at := w.into(20 * time.Second) // 10 left
	got := w.code("5 seconds", w.exerciseOTP("broker", c, with{"minValiditySeconds": 5}))
	if got["value"] != codeA(at) || got["notBefore"] != nil {
		t.Errorf("%v, want the current code", got)
	}
	w.want("used", w.exerciseOTP("broker", c, nil), 403, "PERMISSION_DENIED")
	c = w.otpCapability("broker", nil)
	at = w.into(20 * time.Second)
	next := at.Truncate(30 * time.Second).Add(30 * time.Second)
	for _, n := range []int{15, 30} {
		got := w.code("the next", w.exerciseOTP("broker", c, with{"minValiditySeconds": n}))
		if got["value"] != codeA(next) || got["notBefore"] != next.UTC().Format("2006-01-02T15:04:05.000Z") ||
			got["expiresAt"] != next.Add(30*time.Second).UTC().Format("2006-01-02T15:04:05.000Z") {
			t.Errorf("%d s: %v, want the next code, %s", n, got, codeA(next))
		}
		if s := got["startsInSeconds"].(float64); s < 8 || s > 10 {
			t.Errorf("%d s: starts in %v", n, s)
		}
		if s := got["expiresInSeconds"].(float64); s < 37 || s > 39 {
			t.Errorf("%d s: ends in %v", n, s)
		}
	}
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"minValiditySeconds": 30})
	// 0 asks for nothing; a value is not affected, whatever is asked.
	if got := w.code("0", w.exerciseOTP("broker", c, with{"minValiditySeconds": 0})); got["value"] != codeA(at) {
		t.Errorf("%v", got)
	}
	w.wantValue("a value", w.exercise("broker", c, with{"minValiditySeconds": 86_400, "fresh": true}))
}

func TestFresh(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", nil)
	at := w.into(5 * time.Second)
	start := at.Truncate(30 * time.Second)
	// A code given without asking for a fresh one counts as given.
	if got := w.code("not fresh", w.exerciseOTP("broker", c, nil)); got["value"] != codeA(start) {
		t.Fatalf("%v", got)
	}
	if got := w.code("fresh", w.exerciseOTP("broker", c, with{"fresh": true})); got["value"] != codeA(start.Add(30*time.Second)) || got["notBefore"] == nil {
		t.Fatalf("%v, want the next code", got)
	}
	w.wantEvent("capability.exercised", "broker", nil, map[string]any{"fresh": true})
	once := w.otpCapability("broker", with{"singleUse": true})
	none := w.want("both given", w.exerciseOTP("broker", once, with{"fresh": true}), 429, "RATE_LIMITED")
	e := none.body["error"].(map[string]any)["details"].(map[string]any)
	if after := e["retryAfterSeconds"].(float64); e["reason"] != "no-fresh-code" || after < 23 || after > 25 {
		t.Errorf("%s", none.raw)
	}
	w.wantEvent("capability.denied", "broker", nil, map[string]any{"reason": "no-fresh-code", "item": otpItem})
	// Whoever does not ask for a fresh one still gets the current one.
	if got := w.code("not fresh, again", w.exerciseOTP("broker", c, nil)); got["value"] != codeA(start) {
		t.Errorf("%v", got)
	}
	// What was given is kept through a restart.
	w.restart()
	w.want("after a restart", w.exerciseOTP("broker", c, with{"fresh": true}), 429, "RATE_LIMITED")
	// The next period: its code was given, so the one after it; the single
	// use refused above was not spent.
	w.ahead.Add(int64(30 * time.Second))
	if got := w.code("the next period", w.exerciseOTP("broker", once, with{"fresh": true})); got["value"] != codeA(start.Add(60*time.Second)) {
		t.Errorf("%v", got)
	}
	// Two periods on, with nothing given since: the current one.
	w.ahead.Add(int64(90 * time.Second))
	if got := w.code("later", w.exerciseOTP("broker", c, with{"fresh": true})); got["value"] != codeA(w.now()) || got["notBefore"] != nil {
		t.Errorf("%v", got)
	}
	// Another version is another seed, whose codes were not given.
	w.want("set again", w.setSeed(otpItem, uriA), 200, "")
	if got := w.code("another version", w.exerciseOTP("broker", c, with{"fresh": true})); got["notBefore"] != nil {
		t.Errorf("%v", got)
	}
	// A clock that moves back never gives a given one: refused until it has
	// caught up.
	w.ahead.Add(int64(-10 * time.Minute))
	back := w.want("the clock moved back", w.exerciseOTP("broker", c, with{"fresh": true}), 429, "RATE_LIMITED")
	if after := back.body["error"].(map[string]any)["details"].(map[string]any)["retryAfterSeconds"].(float64); after < 500 {
		t.Errorf("%s", back.raw)
	}
	w.code("not fresh, the clock moved back", w.exerciseOTP("broker", c, nil))
	// One row per seed version is kept (never pruned, so a clock excursion
	// forward and back cannot erase what was given).
	w.ahead.Add(int64(2 * time.Hour))
	w.code("two hours later", w.exerciseOTP("broker", c, nil))
	if n := w.text("SELECT count(*) FROM one_time_codes_given"); n != "2" {
		t.Errorf("%s rows kept, want 2 (one per seed version)", n)
	}
}

// A Secret whose reference does not resolve refuses the exercise, the code
// beside it included: no code is used up, whoever else got it meanwhile, and
// no event says one was given. Nor does an exercise without a fresh code
// open the Secret beside it.
func TestARefusalGivesNoCode(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	mixed := w.issue("broker", with{"singleUse": true, "items": []string{otpItem, "SECRET_MISS", "SECRET_A"},
		"targets": map[string]any{otpItem: []string{otpPlace}, "SECRET_MISS": []string{"header:x-miss"}, "SECRET_A": []string{"header:authorization"}}})
	plain := w.otpCapability("broker", nil)
	place := func(secret, target string) with {
		return with{"fresh": true, "placements": []any{map[string]any{"item": otpItem, "target": otpPlace}, map[string]any{"item": secret, "target": target}}}
	}
	given := func() string {
		return w.text("SELECT count(*) || ':' || coalesce(max(step), 0) FROM one_time_codes_given")
	}
	claims := func() string {
		return w.text("SELECT count(*) FROM audit_events WHERE event_type = 'capability.exercised' AND metadata LIKE '%" + otpItem + "%'")
	}
	refuse := func(what string) {
		t.Helper()
		g, c := given(), claims()
		if a := w.want(what, w.exercise("broker", mixed, place("SECRET_MISS", "header:x-miss")), 403, "PERMISSION_DENIED"); !strings.Contains(a.raw, `"reason":"unresolved-reference"`) {
			t.Fatalf("%s: %s", what, a.raw)
		}
		if given() != g || claims() != c {
			t.Errorf("%s: codes given %s, then %s; events that name one %s, then %s", what, g, given(), c, claims())
		}
	}
	w.into(3 * time.Second)
	refuse("before any code")
	// The current code goes to another exercise, not asked for as fresh: what
	// is refused afterwards does not give it back.
	first := w.code("not fresh", w.exerciseOTP("broker", plain, nil))
	refuse("after it was given")
	next := w.code("fresh", w.exerciseOTP("broker", plain, with{"fresh": true}))
	if next["value"] == first["value"] || next["notBefore"] == nil {
		t.Errorf("fresh gave %v after %v", next, first)
	}
	// Both given: refused before the Secret is opened, the use not spent.
	exercised := w.events("capability.exercised")
	w.want("none left", w.exercise("broker", mixed, place("SECRET_A", "header:authorization")), 429, "RATE_LIMITED")
	if n := w.events("capability.exercised"); n != exercised {
		t.Errorf("%s capability.exercised, then %s", exercised, n)
	}
	// The single use was never spent; granted, it is, once.
	w.ahead.Add(int64(time.Minute))
	if items := w.want("granted", w.exercise("broker", mixed, place("SECRET_A", "header:authorization")), 200, "").body["items"].([]any); len(items) != 2 {
		t.Errorf("%v", items)
	}
	w.want("spent", w.exercise("broker", mixed, place("SECRET_A", "header:authorization")), 403, "PERMISSION_DENIED")
	// And its code counts as given.
	if c := w.code("after it", w.exerciseOTP("broker", plain, with{"fresh": true})); c["notBefore"] == nil {
		t.Errorf("fresh gave the current code again: %v", c)
	}
}

// Codes beside a Secret, asked for as fresh at once: two are given, not the
// same, and the others refused (some after the Secret was opened) without
// their single use being spent.
func TestFreshBesideASecretUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	body := with{"fresh": true, "placements": []any{map[string]any{"item": "SECRET_A", "target": "header:authorization"}, map[string]any{"item": otpItem, "target": otpPlace}}}
	for round := range 5 {
		w.into(2 * time.Second)
		caps := make([]capability, 8)
		for i := range caps {
			caps[i] = w.otpCapability("broker", with{"singleUse": true})
		}
		answers := make([]answer, len(caps))
		var wg sync.WaitGroup
		for i := range caps {
			wg.Go(func() { answers[i] = w.exercise("broker", caps[i], body) })
		}
		wg.Wait()
		got := map[any]bool{}
		var refused []capability
		for i, a := range answers {
			switch a.status {
			case 200:
				got[a.body["items"].([]any)[1].(map[string]any)["value"]] = true
			case 429:
				refused = append(refused, caps[i])
			default:
				t.Errorf("round %d: %d %s", round, a.status, a.raw)
			}
		}
		if len(got) != 2 || len(refused) != len(caps)-2 {
			t.Fatalf("round %d: %d codes, %d refused", round, len(got), len(refused))
		}
		w.ahead.Add(int64(time.Minute))
		for _, c := range refused {
			w.want("not spent", w.exercise("broker", c, with{"placements": body["placements"]}), 200, "")
		}
	}
}

// A temporary clock jump forward and back must not erase one_time_codes_given
// and give the same code twice as fresh.
func TestClockExcursionDoesNotRepeatFreshCode(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.want("set other", w.setSeed("OTHER_OTP", uriB), 200, "")
	c := w.otpCapability("broker", nil)
	w.into(3 * time.Second)
	first := w.code("first", w.exerciseOTP("broker", c, with{"fresh": true}))["value"]
	w.ahead.Add(int64(2 * time.Hour))
	o := w.issue("broker", with{"items": []string{"OTHER_OTP"}, "targets": map[string]any{"OTHER_OTP": []string{"header:x-o"}}})
	w.want("other", w.exercise("broker", o, with{"placements": []any{map[string]any{"item": "OTHER_OTP", "target": "header:x-o"}}}), 200, "")
	w.ahead.Add(-int64(2 * time.Hour))
	second := w.code("second", w.exerciseOTP("broker", c, with{"fresh": true}))["value"]
	if first == second {
		t.Fatalf("the same code was given twice as fresh after a clock excursion: %v", first)
	}
}

// The answer carries Retry-After as the 429 the document describes does.
func TestNoFreshCodeSaysWhenToRetry(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", nil)
	w.into(5 * time.Second)
	w.exerciseOTP("broker", c, with{"fresh": true})
	w.exerciseOTP("broker", c, with{"fresh": true})
	body, _ := json.Marshal(map[string]any{"capabilitySecret": c.secret, "destination": map[string]any{"host": "api.example.com", "port": 443},
		"placements": []any{map[string]any{"item": otpItem, "target": otpPlace}}, "fresh": true})
	req := httptest.NewRequest("POST", capsPath+"/"+c.id+"/exercises", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+w.f.Tokens["broker"])
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.handler.ServeHTTP(rec, req)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || rec.Header().Get("Retry-After") > "25" {
		t.Errorf("%d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// Many at once, each for a fresh code: two are ever given in a period (the
// current one and the next), each to one; every other is refused. Without
// fresh, every one gets the current code.
func TestFreshUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	for round := range 3 {
		for _, fresh := range []bool{true, false} {
			at := w.into(3 * time.Second)
			w.ahead.Add(int64(time.Minute) * 2) // past what the round before gave
			at = at.Add(2 * time.Minute)
			var mu sync.Mutex
			codes := map[string]int{}
			refused := 0
			var wg sync.WaitGroup
			start := make(chan struct{})
			var caps []capability
			for range 12 {
				caps = append(caps, w.otpCapability("broker", with{"singleUse": true}))
			}
			for _, c := range caps {
				wg.Go(func() {
					<-start
					a := w.exerciseOTP("broker", c, with{"fresh": fresh})
					mu.Lock()
					defer mu.Unlock()
					if a.status == 429 {
						refused++
						return
					}
					codes[w.code("exercise", a)["value"].(string)]++
				})
			}
			close(start)
			wg.Wait()
			now, next := codeA(at), codeA(at.Add(30*time.Second))
			if fresh && (codes[now] != 1 || codes[next] != 1 || len(codes) != 2 || refused != 10) {
				t.Errorf("round %d, fresh: %v, %d refused", round, codes, refused)
			}
			if !fresh && (codes[now] != 12 || refused != 0) {
				t.Errorf("round %d: %v, %d refused", round, codes, refused)
			}
		}
	}
}

func TestRotatingASeed(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", nil)
	rot := func(body map[string]any) answer {
		return w.call("POST", envPath+"/values/"+otpItem+"/rotations", "alice", body)
	}
	w.want("to a value", rot(map[string]any{"value": "x"}), 422, "VALIDATION_FAILED")
	w.want("neither", rot(map[string]any{}), 422, "VALIDATION_FAILED")
	w.want("another version", rot(map[string]any{"otpauth": uriB, "expectedVersionId": "ver_x"}), 409, "VERSION_CONFLICT")
	started := w.want("rotate", rot(map[string]any{"otpauth": uriB, "graceSeconds": 600}), 201, "")
	noSeed(t, "a rotation", started.raw)
	w.wantEvent("value.rotation_started", "Alice", nil, map[string]any{"totp": true})
	w.want("twice", rot(map[string]any{"otpauth": uriA}), 409, "ROTATION_IN_PROGRESS")
	at := w.into(40 * time.Second)
	got := w.code("both", w.exerciseOTP("broker", c, nil))
	old, _ := got["retiring"].(map[string]any)
	if got["value"] != codeOf(seedB, "SHA512", 8, 60, at) || old["value"] != codeA(at) || old["expiresAt"] == got["expiresAt"] && at.Second() < 30 ||
		old["versionId"] != started.body["retiringVersionId"] {
		t.Errorf("%v", got)
	}
	// 20 left of 60, 20 of 30: the next of each, each with its own start.
	w.want("longer than the shorter period", w.exerciseOTP("broker", c, with{"minValiditySeconds": 45}), 422, "VALIDATION_FAILED")
	got = w.code("the next of each", w.exerciseOTP("broker", c, with{"minValiditySeconds": 25}))
	old, _ = got["retiring"].(map[string]any)
	if got["value"] != codeOf(seedB, "SHA512", 8, 60, at.Add(60*time.Second)) || old["value"] != codeA(at.Add(30*time.Second)) || got["notBefore"] == nil || old["notBefore"] == nil {
		t.Errorf("%v", got)
	}
	// Both are listed as rotating, and neither seed is delivered.
	listed := w.want("listed", w.call("GET", envPath+"/effective-configuration", "alice", nil), 200, "")
	if !strings.Contains(listed.raw, `"rotating":true,"totp":{"issuer":"Portal"`) {
		t.Errorf("%s", listed.raw)
	}
	// Revealed, both are.
	seen := w.want("reveal", w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{otpItem}, "totpSeeds": true}), 200, "")
	if !strings.Contains(seen.raw, seedA) || !strings.Contains(seen.raw, seedB) {
		t.Errorf("%s", seen.raw)
	}
	done := w.want("complete", w.call("POST", envPath+"/values/"+otpItem+"/rotations/complete", "alice", map[string]any{}), 200, "")
	noSeed(t, "a completion", done.raw)
	if got := w.code("completed", w.exerciseOTP("broker", c, nil)); got["retiring"] != nil || got["value"] != codeOf(seedB, "SHA512", 8, 60, w.now()) {
		t.Errorf("%v", got)
	}
	// A deadline ends it too.
	w.want("rotate back", rot(map[string]any{"otpauth": uriA, "graceSeconds": 60}), 201, "")
	w.ahead.Add(int64(2 * time.Minute))
	if got := w.code("past the deadline", w.exerciseOTP("broker", c, nil)); got["retiring"] != nil || got["value"] != codeA(w.now()) {
		t.Errorf("%v", got)
	}
}

func TestWritingASeed(t *testing.T) {
	w := newWorld(t)
	// Refused, and the answer holds nothing of what was sent.
	const mark = "QZJXQZJXQZJXQZJX"
	for what, body := range map[string]any{
		"no URI": mark, "weak": "otpauth://totp/x?secret=QZJXQZJX", "not base32": "otpauth://totp/x?secret=" + mark + "1", "hotp": "otpauth://hotp/x?secret=" + mark,
		"digits": "otpauth://totp/x?secret=" + mark + "&digits=" + mark, "the secret as the account": "otpauth://totp/" + mark + "?secret=" + mark, "not a string": []string{mark},
	} {
		for _, a := range []answer{
			w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{"otpauth": body}),
			w.call("POST", envPath+"/changes", "alice", map[string]any{"changes": []any{map[string]any{"op": "set", "item": otpItem, "otpauth": body}}}),
			w.call("POST", envPath+"/values/SECRET_A/rotations", "alice", map[string]any{"otpauth": body}),
		} {
			w.want(what, a, 422, "VALIDATION_FAILED")
			if !strings.Contains(a.err(), "otpauth: ") || strings.Contains(strings.ToUpper(a.raw), "QZJX") {
				t.Errorf("%s: %s", what, a.raw)
			}
		}
	}
	both := map[string]any{"otpauth": uriA, "value": "x"}
	w.want("both", w.call("PUT", envPath+"/values/"+otpItem, "alice", both), 422, "VALIDATION_FAILED")
	w.want("neither", w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{}), 422, "VALIDATION_FAILED")
	w.want("an item the Contract marks not sensitive", w.setSeed("PLAIN_HOST", uriA), 422, "VALIDATION_FAILED")
	w.want("a reserved name", w.setSeed("VARLATCH_RUN_CONTEXT", uriA), 422, "VALIDATION_FAILED")
	// Who may not write values may not write seeds.
	for _, as := range []string{"carol", "svc", "broker"} {
		if a := w.call("PUT", envPath+"/values/"+otpItem, as, map[string]any{"otpauth": uriA}); a.status != 403 && a.status != 404 {
			t.Errorf("%s: %s", as, a.raw)
		}
	}
	if n := w.text("SELECT count(*) FROM env_values WHERE item_name = ?", otpItem); n != "0" {
		t.Fatalf("%s rows written by refused requests", n)
	}

	// A value is not rotated to a seed; it is replaced by one.
	w.want("rotate a value to a seed", w.call("POST", envPath+"/values/SECRET_A/rotations", "alice", map[string]any{"otpauth": uriA}), 422, "VALIDATION_FAILED")
	first := w.want("set", w.setSeed(otpItem, uriA), 200, "")
	id := first.body["versionId"].(string)
	for what, a := range map[string]answer{
		"a value over a seed":                  w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{"value": uriA}),
		"a value over a seed, in a change set": w.call("POST", envPath+"/changes", "alice", map[string]any{"changes": []any{map[string]any{"op": "set", "item": otpItem, "value": "x"}, map[string]any{"op": "set", "item": "SECRET_A", "value": "x"}}}),
	} {
		w.want(what, a, 422, "VALIDATION_FAILED")
		if !strings.Contains(a.raw, `"reason":"one-time-code"`) {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
	w.wantValue("SECRET_A as it was", w.exercise("broker", w.otpCapability("broker", nil), nil))
	w.want("a stale version", w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{"otpauth": uriB, "expectedVersionId": "ver_x"}), 409, "VERSION_CONFLICT")
	second := w.want("the current version", w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{"otpauth": uriB, "expectedVersionId": id}), 200, "")
	if second.body["previousVersionId"] != id {
		t.Errorf("%s", second.raw)
	}
	// A change set sets one and deletes one, guarded by its version.
	conflict := w.want("a conflict", w.call("POST", envPath+"/changes", "alice", map[string]any{"changes": []any{map[string]any{"op": "delete", "item": otpItem, "expectedVersionId": id}}}), 409, "VERSION_CONFLICT")
	if !strings.Contains(conflict.raw, second.body["versionId"].(string)) {
		t.Errorf("%s", conflict.raw)
	}
	set := w.want("a change set", w.call("POST", envPath+"/changes", "alice", map[string]any{"changes": []any{
		map[string]any{"op": "delete", "item": otpItem, "expectedVersionId": second.body["versionId"]}, map[string]any{"op": "set", "item": "OTHER_OTP", "otpauth": uriA}}}), 200, "")
	noSeed(t, "a change set", set.raw)
	w.want("deleted", w.call("DELETE", envPath+"/values/"+otpItem, "alice", nil), 404, "RESOURCE_NOT_FOUND")
	w.want("a rotation of a deleted one", w.call("POST", envPath+"/values/"+otpItem+"/rotations", "alice", map[string]any{"otpauth": uriA}), 404, "RESOURCE_NOT_FOUND")
	w.want("delete", w.call("DELETE", envPath+"/values/OTHER_OTP", "alice", nil), 204, "")
	// Deleted, its name takes a value, and that one a seed.
	w.want("a value", w.call("PUT", envPath+"/values/"+otpItem, "alice", map[string]any{"value": "plain"}), 200, "")
	w.want("a seed over a value", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", nil)
	if got := w.code("exercise", w.exerciseOTP("broker", c, nil)); got["value"] != codeA(w.now()) {
		t.Errorf("%v", got)
	}
	// An Idempotency-Key replays the answer, and the key is another body's.
	send := func(uri string) (int, any) {
		b, _ := json.Marshal(map[string]any{"otpauth": uri})
		req := httptest.NewRequest("PUT", envPath+"/values/"+otpItem, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+w.f.Tokens["alice"])
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", "k1")
		rec := httptest.NewRecorder()
		w.handler.ServeHTTP(rec, req)
		var got map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		return rec.Code, got["versionId"]
	}
	s1, v1 := send(uriA)
	s2, v2 := send(uriA)
	if s3, _ := send(uriB); s1 != 200 || s2 != 200 || v1 != v2 || s3 != 409 {
		t.Errorf("idempotency: %d %v, %d %v, %d", s1, v1, s2, v2, s3)
	}
	for _, r := range paritytest.Rows(t, w.store, "SELECT * FROM idempotency_keys") {
		noSeed(t, "an idempotency key", fmt.Sprint(r))
	}
}

// Deleting an environment leaves no seed live in it.
func TestDeletingAnEnvironmentEndsItsSeeds(t *testing.T) {
	w := newWorld(t)
	w.want("preview", w.call("POST", "/v1/organizations/cap/projects/api/environments", "alice", map[string]any{"name": "development/pr-1", "kind": "preview", "parentEnvironmentId": w.env("development")}), 201, "")
	preview := "/v1/organizations/cap/projects/api/environments/development%2Fpr-1"
	w.want("set", w.call("PUT", preview+"/values/"+otpItem, "alice", map[string]any{"otpauth": uriA}), 200, "")
	w.want("delete", w.call("DELETE", preview, "alice", nil), 204, "")
	if n := w.text("SELECT count(*) FROM env_values v JOIN environments e ON e.id = v.environment_id WHERE e.name = 'development/pr-1' AND v.current_version_id IS NOT NULL"); n != "0" {
		t.Errorf("%s seeds live", n)
	}
}

// A derived environment inherits its parent's seed, overrides a parent's seed
// with a value or another seed, and overrides a parent's value with a seed.
func TestInheritedSeeds(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.want("preview", w.call("POST", "/v1/organizations/cap/projects/api/environments", "alice", map[string]any{"name": "development/pr-1", "kind": "preview", "parentEnvironmentId": w.env("development")}), 201, "")
	preview := "/v1/organizations/cap/projects/api/environments/development%2Fpr-1"
	listed := func(name string) map[string]any {
		t.Helper()
		var found map[string]any
		for _, i := range w.want("listed", w.call("GET", preview+"/effective-configuration?include=values", "alice", nil), 200, "").body["items"].([]any) {
			if m := i.(map[string]any); m["name"] == name {
				if found != nil {
					t.Fatalf("duplicate item %s in effective-configuration: %v and %v", name, found, m)
				}
				found = m
			}
		}
		if found == nil {
			t.Fatalf("%s not listed", name)
		}
		return found
	}
	if m := listed(otpItem); m["source"] != "parent" || m["totp"] == nil || m["value"] != nil || m["sensitive"] != true {
		t.Errorf("inherited: %v", m)
	}
	// Parent's seed under a child's value: the child's value wins and hides
	// the parent's seed completely (no duplicate item, no seed disclosed).
	w.want("a value", w.call("PUT", preview+"/values/"+otpItem, "alice", map[string]any{"value": "child"}), 200, "")
	if m := listed(otpItem); m["source"] != "self" || m["totp"] != nil {
		t.Errorf("overridden by a value: %v", m)
	}
	all := w.want("disclosed", w.call("POST", preview+"/disclosures", "alice", map[string]any{"scope": "all-authorized-secrets"}), 200, "")
	noSeed(t, "a disclosure", all.raw)
	if !strings.Contains(all.raw, `"value":"child"`) {
		t.Errorf("%s", all.raw)
	}
	seedDisc := w.want("disclose totpSeeds", w.call("POST", preview+"/disclosures", "alice", map[string]any{"items": []string{otpItem}, "totpSeeds": true}), 200, "")
	noSeed(t, "disclose totpSeeds on child value", seedDisc.raw)
	// Child's seed over a parent's value (SECRET_A = "a-secret" in parent):
	// the child's seed wins and hides the parent's value completely.
	w.want("child seed over parent value", w.call("PUT", preview+"/values/SECRET_A", "alice", map[string]any{"otpauth": uriA}), 200, "")
	if m := listed("SECRET_A"); m["source"] != "self" || m["totp"] == nil || m["value"] != nil {
		t.Errorf("child seed over parent value: %v", m)
	}
	discChildSeed := w.want("disclose child seed", w.call("POST", preview+"/disclosures", "alice", map[string]any{"items": []string{"SECRET_A"}}), 200, "")
	if strings.Contains(discChildSeed.raw, "a-secret") || !strings.Contains(discChildSeed.raw, `"withheld":["SECRET_A"]`) {
		t.Errorf("parent value leaked under child seed: %s", discChildSeed.raw)
	}
	previewCap := w.want("issue on preview", w.call("POST", preview+"/capabilities", "broker", w.issueBody(nil)), 201, "")
	exChild := w.want("exercise child seed", w.call("POST", preview+"/capabilities/"+previewCap.body["id"].(string)+"/exercises", "broker", map[string]any{
		"capabilitySecret": previewCap.body["secret"].(string),
		"destination":      map[string]any{"host": "api.example.com", "port": 443},
		"placements":       []any{map[string]any{"item": "SECRET_A", "target": "header:authorization"}},
	}), 200, "")
	if strings.Contains(exChild.raw, "a-secret") || !strings.Contains(exChild.raw, `"kind":"totp"`) {
		t.Errorf("exercise returned parent value instead of child seed code: %s", exChild.raw)
	}
	w.want("delete", w.call("DELETE", preview+"/values/"+otpItem, "alice", nil), 204, "")
	w.want("a seed", w.call("PUT", preview+"/values/"+otpItem, "alice", map[string]any{"otpauth": uriB}), 200, "")
	if m := listed(otpItem); m["source"] != "self" || m["totp"].(map[string]any)["digits"] != 8.0 {
		t.Errorf("overridden by a seed: %v", m)
	}
	// A seed whose parameters this server does not know hides the parent's
	// item all the same.
	w.exec(`UPDATE value_versions SET payload = json_set(payload, '$.totp.period', 45) WHERE id = (SELECT v.current_version_id FROM env_values v JOIN environments e ON e.id = v.environment_id WHERE e.name = 'development/pr-1' AND v.item_name = ?)`, otpItem)
	for _, i := range w.want("listed", w.call("GET", preview+"/effective-configuration", "alice", nil), 200, "").body["items"].([]any) {
		if m := i.(map[string]any); m["name"] == otpItem {
			t.Errorf("a seed of unknown parameters is listed: %v", m)
		}
	}
}

// Every other way a value leaves: none delivers the seed, and each says why
// it has no value.
func TestNoOtherPathDeliversASeed(t *testing.T) {
	w := newWorld(t)
	var log syncBuffer
	w.stop()
	w.log = &log
	w.start()
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.want("a Secret that refers to it", w.call("PUT", envPath+"/values/SECRET_USES", "alice", map[string]any{"value": "code ${" + otpItem + "}"}), 200, "")
	w.want("a value that refers to it", w.call("PUT", envPath+"/values/PLAIN_URL", "alice", map[string]any{"value": "https://x.example/${" + otpItem + "}"}), 200, "")

	item := func(a answer) map[string]any {
		t.Helper()
		for _, i := range a.body["items"].([]any) {
			if m := i.(map[string]any); m["name"] == otpItem {
				return m
			}
		}
		return nil
	}
	for _, include := range []string{"", "?include=metadata", "?include=values", "?include=values&purpose=export"} {
		a := w.want("effective configuration", w.call("GET", envPath+"/effective-configuration"+include, "alice", nil), 200, "")
		noSeed(t, "the effective configuration"+include, a.raw)
		if m := item(a); m == nil || m["value"] != nil || m["sensitive"] != true || m["rawValue"] != nil || m["totp"].(map[string]any)["issuer"] != "Portal" {
			t.Errorf("effective configuration%s: %v", include, m)
		}
		if strings.Contains(a.raw, codeA(w.now())) {
			t.Errorf("the effective configuration%s holds a code", include)
		}
	}
	for _, body := range []map[string]any{
		{"scope": "all-authorized-secrets"}, {"scope": "all-authorized-secrets", "purpose": "export"}, {"scope": "all-authorized-secrets", "purpose": "scan"},
		{"items": []string{otpItem}}, {"items": []string{otpItem, "SECRET_A"}, "purpose": "export"}, {"items": []string{otpItem}, "purpose": "scan"},
		{"items": []string{otpItem}, "totpSeeds": false},
	} {
		a := w.want("disclose", w.call("POST", envPath+"/disclosures", "alice", body), 200, "")
		noSeed(t, fmt.Sprintf("the disclosure %v", body), a.raw)
		if item(a) != nil {
			t.Errorf("%v: disclosed", body)
		}
		if body["items"] != nil && !slices.Contains(a.body["withheld"].([]any), any(otpItem)) {
			t.Errorf("%v: withheld %v", body, a.body["withheld"])
		}
	}
	for _, mode := range []string{"strict", "preflight"} {
		a := w.want(mode, w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": mode}), 200, "")
		noSeed(t, "a retrieval", a.raw)
		if m := item(a); m == nil || m["value"] != nil || m["totp"] == nil {
			t.Errorf("%s: %v", mode, m)
		}
		says := strings.Contains(a.raw, `{"name":"PORTAL_OTP","reason":"one-time-code","requires":"secret.use"}`)
		if says != (mode == "strict") {
			t.Errorf("%s: withheld says %v: %s", mode, says, a.raw)
		}
		if !strings.Contains(a.raw, `{"name":"SECRET_USES","references":["PORTAL_OTP"]}`) || mode == "strict" && !strings.Contains(a.raw, `"code ${PORTAL_OTP}"`) {
			t.Errorf("%s: a reference to it: %s", mode, a.raw)
		}
		if v := a.body["validation"].(map[string]any); fmt.Sprint(v["unresolved"]) == "[]" || fmt.Sprint(v["notEvaluated"]) != "[]" {
			t.Errorf("%s: %v", mode, v)
		}
	}
	valid := w.want("validate", w.call("POST", envPath+"/validate", "alice", map[string]any{}), 200, "")
	noSeed(t, "a validation", valid.raw)
	found := w.want("search", w.call("GET", "/v1/organizations/cap/config-items?q=portal", "alice", nil), 200, "")
	if !strings.Contains(found.raw, otpItem) {
		t.Errorf("not found by its name: %s", found.raw)
	}
	// A reference at exercise: refused, whether the Capability names the
	// item or not.
	for _, items := range [][]string{{"SECRET_USES"}, {"SECRET_USES", otpItem}} {
		targets := map[string]any{}
		for _, i := range items {
			targets[i] = []string{"header:x-" + strings.ToLower(strings.ReplaceAll(i, "_", "-"))}
		}
		c := w.issue("broker", with{"items": items, "targets": targets})
		a := w.want("a reference", w.exercise("broker", c, with{"placements": []any{map[string]any{"item": "SECRET_USES", "target": "header:x-secret-uses"}}}), 403, "PERMISSION_DENIED")
		if !strings.Contains(a.raw, `"cause":"one-time-code"`) {
			t.Errorf("%s", a.raw)
		}
		noSeed(t, "a refused exercise", a.raw)
	}
	// Opened by name, it is, by who may reveal Secrets, and audited.
	before := w.events("secret.disclosed")
	seen := w.want("reveal", w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{otpItem, "SECRET_A"}, "totpSeeds": true}), 200, "")
	if m := item(seen); m == nil || m["value"] != uriA+"&algorithm=SHA1&digits=6&period=30" && m["value"] != strings.Replace(uriA, "%40", "@", 1)+"&algorithm=SHA1&digits=6&period=30" || m["totp"] == nil {
		t.Errorf("%s", seen.raw)
	}
	if w.events("secret.disclosed") == before {
		t.Error("not audited")
	}
	w.wantEvent("secret.disclosed", "Alice", nil, map[string]any{"mode": "requested", "totpSeeds": 1})
	for _, body := range []map[string]any{{"scope": "all-authorized-secrets", "totpSeeds": true}, {"items": []string{otpItem}, "purpose": "export", "totpSeeds": true},
		{"items": []string{otpItem}, "purpose": "scan", "totpSeeds": true}, {"items": []string{otpItem}, "totpSeeds": "yes"}} {
		a := w.want(fmt.Sprint(body), w.call("POST", envPath+"/disclosures", "alice", body), 422, "VALIDATION_FAILED")
		noSeed(t, "a refusal", a.raw)
	}
	// Who holds no secret.reveal here may not reveal it: the same right as any
	// Secret's, which using it (the Agent's) does not give.
	for _, as := range []string{"broker", "agent", "carol", "svc"} {
		a := w.call("POST", envPath+"/disclosures", as, map[string]any{"items": []string{otpItem}, "totpSeeds": true})
		if a.status < 400 {
			t.Errorf("%s reveals it: %s", as, a.raw)
		}
		noSeed(t, as+"'s disclosure", a.raw)
	}
	// Neither the log nor the audit log (its API and its rows) has it.
	noSeed(t, "the log", log.String())
	for _, path := range []string{"/v1/organizations/cap/audit-events", "/v1/organizations/cap/audit-events/export"} {
		noSeed(t, path, w.want(path, w.call("GET", path, "alice", nil), 200, "").raw)
	}
	for _, r := range paritytest.Rows(t, w.store, "SELECT * FROM audit_events") {
		noSeed(t, "the audit log", fmt.Sprint(r))
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Every GET and POST there is, asked by an Organization Admin and by the
// Broker: none answers with the seed, but the disclosure that asks for it.
func TestNoOperationAnswersWithASeed(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	c := w.otpCapability("broker", nil)
	w.check = false // synthetic bodies
	param := regexp.MustCompile(`\{[^}]+\}`)
	names := map[string]string{"{org}": "cap", "{project}": "api", "{environment}": "development", "{identity}": w.idn("broker"), "{item}": otpItem, "{capability}": c.id}
	tried := 0
	for _, as := range []string{"alice", "broker"} {
		for _, pattern := range httpserver.BuiltOperations {
			method, route, _ := strings.Cut(pattern, " ")
			if method != http.MethodGet && method != http.MethodPost || strings.Contains(route, "/organizations/{org}/deletion") || strings.Contains(route, "incident") {
				continue
			}
			path := param.ReplaceAllStringFunc(route, func(p string) string {
				if v, ok := names[p]; ok {
					return v
				}
				return "x"
			})
			for _, body := range []any{nil, map[string]any{"scope": "all-authorized-secrets", "mode": "strict", "items": []string{otpItem}}} {
				if method == http.MethodGet && body != nil {
					continue
				}
				a := w.call(method, path, as, body)
				noSeed(t, as+": "+pattern, a.raw)
				tried++
			}
		}
	}
	if tried < 200 {
		t.Errorf("%d requests", tried)
	}
}

// What an older varlatchd, and the TypeScript server, read: their queries,
// word for word. The item has no value there.
func TestAnOlderServerReadsNoSeed(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.want("rotate", w.call("POST", envPath+"/values/"+otpItem+"/rotations", "alice", map[string]any{"otpauth": uriB}), 201, "")
	env := w.env("development")
	for what, q := range map[string]string{
		"resolveItems":   "SELECT count(*) FROM env_values WHERE environment_id = ? AND deleted_at IS NULL AND current_version_id IS NOT NULL AND item_name = '" + otpItem + "'",
		"the search":     "SELECT count(*) FROM env_values WHERE environment_id IN (?) AND deleted_at IS NULL AND current_version_id IS NOT NULL AND item_name = '" + otpItem + "'",
		"deleteValue":    "SELECT count(*) FROM env_values WHERE environment_id = ? AND item_name = '" + otpItem + "' AND deleted_at IS NULL",
		"beginRotation":  "SELECT count(*) FROM env_values WHERE environment_id = ? AND item_name = '" + otpItem + "' AND deleted_at IS NULL",
		"applyChangeSet": "SELECT count(*) FROM env_values WHERE environment_id = ? AND item_name = '" + otpItem + "' AND deleted_at IS NULL AND current_version_id IS NOT NULL",
	} {
		if n := w.text(q, env); n != "0" {
			t.Errorf("%s finds it", what)
		}
	}
	// A value written there takes the name; back here it is that value.
	w.exec("UPDATE env_values SET current_version_id = (SELECT current_version_id FROM env_values WHERE item_name = 'SECRET_B' AND environment_id = ?1), deleted_at = NULL, retiring_version_id = NULL, rotation_deadline = NULL WHERE environment_id = ?1 AND item_name = ?2", env, otpItem)
	a := w.want("listed", w.call("GET", envPath+"/effective-configuration", "alice", nil), 200, "")
	for _, i := range a.body["items"].([]any) {
		if m := i.(map[string]any); m["name"] == otpItem && m["totp"] != nil {
			t.Errorf("%v", m)
		}
	}
}

// Rows changed by hand: a seed is never opened as a value, and a seed whose
// readable part was changed gives no code.
func TestTamperedSeedsFailClosed(t *testing.T) {
	w := newWorld(t)
	c := w.otpCapability("broker", nil)
	row := func(set string) {
		t.Helper()
		w.exec("UPDATE value_versions SET "+set+" WHERE id = (SELECT current_version_id FROM env_values WHERE item_name = ? AND environment_id = ?)", otpItem, w.env("development"))
	}
	for what, set := range map[string]string{
		"another issuer":   "payload = json_set(payload, '$.totp.issuer', 'Bank')",
		"a longer period":  "payload = json_set(payload, '$.totp.period', 60)",
		"another version":  "payload = (SELECT payload FROM value_versions WHERE id = (SELECT current_version_id FROM env_values WHERE item_name = 'SECRET_B'))",
		"unknown":          "payload = json_set(payload, '$.totp.period', 1)",
		"its own payload?": "payload = json_set(payload, '$.ciphertext', 'AAAA')",
	} {
		w.want("set", w.setSeed(otpItem, uriA), 200, "")
		row(set)
		a := w.exerciseOTP("broker", c, nil)
		if a.status == 200 && len(a.body["items"].([]any)) != 0 {
			t.Errorf("%s: %s", what, a.raw)
		}
		noSeed(t, what, a.raw)
		if strings.Contains(a.raw, codeA(w.now())) {
			t.Errorf("%s: a code: %s", what, a.raw)
		}
		w.exec("UPDATE env_values SET deleted_at = 1, current_version_id = NULL WHERE item_name = ?", otpItem)
	}
	// The row as a value's: no path opens the seed, each fails instead.
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.exec("UPDATE env_values SET deleted_at = NULL WHERE item_name = ?", otpItem)
	for what, a := range map[string]answer{
		"disclosed":    w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{otpItem}}),
		"all":          w.call("POST", envPath+"/disclosures", "alice", map[string]any{"scope": "all-authorized-secrets"}),
		"strict":       w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "strict"}),
		"exercised":    w.exerciseOTP("broker", c, nil),
		"reveal":       w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{otpItem}, "totpSeeds": true}),
		"as no secret": w.call("GET", envPath+"/effective-configuration?include=values", "alice", nil),
	} {
		noSeed(t, what, a.raw)
		if a.status == 200 && what != "as no secret" {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
}

// Nor when the mark itself is taken off and the row made live: what opens
// as a value is no seed.
func TestASeedStrippedOfItsMarkOpensAsNoSeed(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.exec("UPDATE value_versions SET payload = json_remove(payload, '$.totp') WHERE id = (SELECT current_version_id FROM env_values WHERE item_name = ?)", otpItem)
	if a := w.exerciseOTP("broker", w.otpCapability("broker", nil), nil); a.status == 200 && len(a.body["items"].([]any)) != 0 {
		t.Errorf("a seed without its mark: %s", a.raw)
	}
	w.exec("UPDATE env_values SET deleted_at = NULL WHERE item_name = ?", otpItem)
	for what, a := range map[string]answer{
		"disclosed": w.call("POST", envPath+"/disclosures", "alice", map[string]any{"items": []string{otpItem}, "totpSeeds": true}),
		"all":       w.call("POST", envPath+"/disclosures", "alice", map[string]any{"scope": "all-authorized-secrets"}),
		"strict":    w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "strict"}),
		"exercised": w.exerciseOTP("broker", w.otpCapability("broker", nil), nil),
	} {
		w.want(what, a, 200, "")
		noSeed(t, what, a.raw)
		if !strings.Contains(a.raw, "ciphertext") {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
}

// The Contract: an item it later marks not sensitive, or of another type.
func TestASeedAndTheContract(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	activate := func(item map[string]any) {
		t.Helper()
		pushed := w.call("POST", "/v1/organizations/cap/projects/api/contract/revisions", "alice", map[string]any{
			"contract": map[string]any{"schemaVersion": 1, "semanticsVersion": 3, "items": []any{item}}, "provenance": map[string]any{"source": "api"}})
		if pushed.status >= 300 {
			t.Fatalf("%s", pushed.raw)
		}
		w.want("activate", w.call("POST", "/v1/organizations/cap/projects/api/contract/revisions/"+pushed.body["id"].(string)+"/activate", "alice", map[string]any{}), 200, "")
	}
	for _, sensitive := range []bool{true, false} {
		activate(map[string]any{"name": otpItem, "type": "string", "required": map[string]any{"kind": "always"}, "sensitive": sensitive})
		// include=values delivers what is not sensitive: not this.
		a := w.want("read", w.call("GET", envPath+"/effective-configuration?include=values", "alice", nil), 200, "")
		noSeed(t, "a seed the Contract marks not sensitive", a.raw)
		v := w.want("validate", w.call("POST", envPath+"/validate", "alice", map[string]any{}), 200, "")
		if fmt.Sprint(v.body["missing"], v.body["invalid"], v.body["notEvaluated"]) != "[] [] []" {
			t.Errorf("required and held: %s", v.raw)
		}
		s := w.want("strict", w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "strict"}), 200, "")
		noSeed(t, "a strict retrieval", s.raw)
		if fmt.Sprint(s.body["validation"].(map[string]any)["valid"]) != "true" {
			t.Errorf("%s", s.raw)
		}
	}
	activate(map[string]any{"name": otpItem, "type": "url", "required": map[string]any{"kind": "never"}, "sensitive": true})
	for what, a := range map[string]answer{
		"validate": w.call("POST", envPath+"/validate", "alice", map[string]any{}),
		"strict":   w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "preflight"}),
	} {
		v := a.body
		if what == "strict" {
			v = a.body["validation"].(map[string]any)
		}
		if !strings.Contains(fmt.Sprint(v["invalid"]), otpItem) {
			t.Errorf("%s: %s", what, a.raw)
		}
	}
}

// For another Broker, with an exercise-only credential of a run, once
// (ADR-0060): the code is given once, and nothing else is.
func TestADelegatedCodeGivenOnce(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.grant("svc", "development")
	w.want("bind", w.bind("broker", with{"exerciseOnly": true, "runIdClaim": "job"}), 201, "")
	machine := w.exchanged(w.token(map[string]any{"job": "run-1"}))
	body := with{"brokerIdentityId": w.idn("broker"), "singleUse": true, "runId": "run-1"}
	c := w.otpCapability("svc", body)
	w.want("the issuer", w.exerciseOTP("svc", c, nil), 404, "RESOURCE_NOT_FOUND")
	w.want("another run's", w.exerciseOTP(machine, w.otpCapability("svc", with{"brokerIdentityId": w.idn("broker"), "runId": "run-2"}), nil), 404, "RESOURCE_NOT_FOUND")
	w.want("a disclosure", w.call("POST", envPath+"/disclosures", machine, map[string]any{"items": []string{otpItem}, "totpSeeds": true}), 403, "PERMISSION_DENIED")
	if got := w.code("the machine", w.exerciseOTP(machine, c, with{"fresh": true})); got["value"] != codeA(w.now()) {
		t.Errorf("%v", got)
	}
	w.wantEvent("capability.exercised", "broker", map[string]any{"capabilityId": c.id}, map[string]any{"issuedByIdentityId": w.idn("svc"), "singleUse": true, "fresh": true, "runId": "run-1"})
	w.want("twice", w.exerciseOTP(machine, c, nil), 403, "PERMISSION_DENIED")
	// The Agent's Grant is what decides, as for any Secret.
	w.want("an Agent without a Grant", w.exerciseOTP("broker", w.otpCapability("broker", with{"agentIdentityId": w.idn("nogrant")}), nil), 403, "PERMISSION_DENIED")
	// Retrieval before: a state manifest lists it by its version.
	pre := w.want("preflight", w.call("POST", envPath+"/retrievals", "alice", map[string]any{"mode": "preflight"}), 200, "")
	issued := w.want("with a precondition", w.call("POST", capsPath, "broker", w.issueBody(with{"items": []string{otpItem}, "targets": map[string]any{otpItem: []string{otpPlace}},
		"precondition": map[string]any{"projectId": w.project(), "environmentId": w.env("development"), "stateDigest": pre.body["stateDigest"], "stateDigests": pre.body["stateDigests"]}})), 201, "")
	if !strings.Contains(issued.raw, `{"name":"PORTAL_OTP","present":true,"authorized":true}`) {
		t.Errorf("%s", issued.raw)
	}
	w.want("another seed", w.setSeed(otpItem, uriB), 200, "")
	w.want("the state changed", w.call("POST", capsPath, "broker", w.issueBody(with{"items": []string{otpItem}, "targets": map[string]any{otpItem: []string{otpPlace}},
		"precondition": map[string]any{"projectId": w.project(), "environmentId": w.env("development"), "stateDigest": pre.body["stateDigest"], "stateDigests": pre.body["stateDigests"]}})), 409, "STATE_CHANGED")
}

// What a member received is reported as still served: a seed's row has a
// deletion time, and is live.
func TestARevealedSeedIsReportedAsServed(t *testing.T) {
	w := newWorld(t)
	w.want("set", w.setSeed(otpItem, uriA), 200, "")
	w.want("reveal", w.call("POST", envPath+"/disclosures", "bob", map[string]any{"items": []string{otpItem}, "totpSeeds": true}), 200, "")
	report := func() string {
		t.Helper()
		a := w.want("report", w.call("GET", "/v1/organizations/cap/members/"+w.idn("bob")+"/exposure", "alice", nil), 200, "")
		i := strings.Index(a.raw, `{"itemName":"`+otpItem)
		if i < 0 {
			t.Fatalf("%s", a.raw)
		}
		return a.raw[i:]
	}
	if got := report(); !strings.Contains(got, `"servedAs":"current"`) || strings.Contains(got, "value-deleted") {
		t.Errorf("%s", got)
	}
	w.want("another seed", w.setSeed(otpItem, uriB), 200, "")
	if got := report(); !strings.Contains(got, `"notServedBecause":"replaced"`) {
		t.Errorf("%s", got)
	}
	w.want("delete", w.call("DELETE", envPath+"/values/"+otpItem, "alice", nil), 204, "")
	if got := report(); !strings.Contains(got, `"notServedBecause":"value-deleted"`) {
		t.Errorf("%s", got)
	}
}
