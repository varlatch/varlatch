// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/varlatch/varlatch/go/lib/targets"
)

const machine = "idn_4iryusqsiqavj5y6z57obhc4cm"

func TestParsePlace(t *testing.T) {
	for raw, want := range map[string]string{
		// Hosts, as they always were, the ones named web and app included.
		"api.example.com": "api.example.com:443", "*.example.com:8443": "*.example.com:8443", "[::1]:80": "[::1]:80", "web:443": "web:443", "app:8080": "app:8080", "10.0.0.1": "10.0.0.1:443",
		// Pages.
		"web:https://portal.example.com":                "web:https://portal.example.com:443/",
		"web:https://portal.example.com/":               "web:https://portal.example.com:443/",
		"web:https://portal.example.com/*":              "web:https://portal.example.com:443/",
		"web:https://portal.example.com*":               "",
		"web:https://Portal.Example.COM./Login/":        "web:https://portal.example.com:443/Login",
		"web:https://portal.example.com/login/*":        "web:https://portal.example.com:443/login",
		"web:https://portal.example.com:8443/a/b":       "web:https://portal.example.com:8443/a/b",
		"web:http://127.0.0.1:8080/x":                   "web:http://127.0.0.1:8080/x",
		"web:http://intranet":                           "web:http://intranet:80/",
		"web:https://[2001:DB8:0:0::1]/":                "web:https://[2001:db8::1]:443/",
		"web:https://*.example.com/login":               "web:https://*.example.com:443/login",
		"web:https://m\u00fcnchen.example/":             "web:https://xn--mnchen-3ya.example:443/",
		"web:https://\uff45xample.com/":                 "web:https://example.com:443/",
		"web:https://example.com/%7euser/%c3%a9/\u00e9": "web:https://example.com:443/~user/%C3%A9/%C3%A9",
		" web:https://example.com/ ":                    "web:https://example.com:443/",
		// Applications.
		"app:SAP Logon@" + machine:       "app:SAP Logon@" + machine,
		"app:com.example.crm@" + machine: "app:com.example.crm@" + machine,
		"app:Cafe\u0301@" + machine:      "app:Caf\u00e9@" + machine,
		// None of these.
		"web:https://": "", "web:https:///login": "", "web:ftp://example.com/": "", "web:HTTPS://example.com/": "", "web:example.com": "", "WEB:https://example.com": "", "web://example.com": "",
		"web:https://user@example.com/": "", "web:https://user:pass@example.com/": "", "web:https://example.com:0/": "", "web:https://example.com:65536/": "", "web:https://example.com:/": "", "web:https://example.com:443:443/": "",
		"web:https://example.com/a?b=c": "", "web:https://example.com/a#b": "", "web:https://example.com/a/../b": "", "web:https://example.com/./a": "", "web:https://example.com/%2e%2e/a": "", "web:https://example.com/a%2fb": "",
		"web:https://example.com/a%5Cb": "", "web:https://example.com/a\\b": "", "web:https://example.com\\evil.com/": "", "web:https://example.com/a b": "", "web:https://example.com/a%zz": "", "web:https://example.com/a%": "",
		"web:https://example.com//a": "", "web:https://example.com/a//": "", "web:https://example.com/a//*": "", "web:https://example.com/a//b": "", "web:https://example.com/lo*": "", "web:https://example.com/*/a": "", "web:https://*/": "", "web:https://*.com/": "", "web:https://*.": "", "web:https://a.*.com/": "",
		"web:https://*.10.0.0.1/": "", "web:https://example..com/": "", "web:https://.example.com/": "", "web:https://exa mple.com/": "", "web:https://%65xample.com/": "", "web:https://example.com/a,b": "", "web:https://example.com/a;b": "",
		"web:https://[::1%25en0]/": "", "web:https://[10.0.0.1]/": "", "web:https://[::1]x/": "", "web:https://::1/": "", "web:https://example.com/a%00": "", "web:https://example.com/a%252e%252e/": "", "web:https://example.com/" + strings.Repeat("a", 600): "",
		"web:https://example.com/" + strings.Repeat("\u00e9", 120): "", "web:https://example.com/..;/a": "", "web:https://example.com/..%3b/a": "", "web:https://example.com/\x80": "",
		"app:x@": "", "app:@" + machine: "", "app:x@idn_short": "", "app:x@ORG": "", "app:a@b@" + machine: "", "app:*@" + machine: "", "app: x@" + machine: "", "app:x @" + machine: "", "app:a,b@" + machine: "", "app:a;b@" + machine: "",
		"app:a/b@" + machine: "", "app:a\tb@" + machine: "", "app:a\u202eb@" + machine: "", "app:a\u200bb@" + machine: "", "app:a\u00a0b@" + machine: "", "app:" + strings.Repeat("x", 101) + "@" + machine: "", "app:x@" + strings.ToUpper(machine): "",
		"app:a\ufe0fb@" + machine: "", "app:\xff@" + machine: "", "pipe:x": "", "process:x@" + machine: "",
	} {
		p, ok := ParsePlace(raw)
		if ok != (want != "") || ok && p.String() != want {
			t.Errorf("ParsePlace(%q) = %q, %v; want %q", raw, p, ok, want)
			continue
		}
		if !ok {
			continue
		}
		// Canonical: read again it is the same.
		if again, ok := ParsePlace(want); !ok || again != p {
			t.Errorf("%q read again is %+v, %v; want %+v", want, again, ok, p)
		}
	}
}

func match(t *testing.T, r Reported, selectors ...string) (string, bool) {
	t.Helper()
	var places []Place
	for _, s := range selectors {
		p, ok := ParsePlace(s)
		if !ok {
			t.Fatalf("no selector: %q", s)
		}
		places = append(places, p)
	}
	p, ok := r.Read(machine).Match(places)
	return p.String(), ok
}

func TestPagesMatch(t *testing.T) {
	const login, host, sub = "web:https://portal.example.com/login", "web:https://portal.example.com/", "web:https://*.example.com/"
	for _, c := range []struct {
		url      string
		selector string
		want     bool
	}{
		{"https://portal.example.com/login", login, true},
		{"https://portal.example.com/login/", login, true},
		{"https://portal.example.com/login/step2?user=a#b", login, true},
		{"HTTPS://PORTAL.EXAMPLE.COM:443/login", login, true},
		{"https://portal.example.com./login", login, true},
		{"https://portal.example.com/%6Cogin", login, true},
		{"https://portal.example.com", host, true},
		{"https://portal.example.com?x", host, true},
		{"https://portal.example.com/anything/at/all", host, true},
		{"https://\uff50ortal.example.com/login", login, true},
		{"https://a.example.com/", sub, true},
		{"https://a.b.example.com/", sub, true},
		{"https://m\u00fcnchen.example/x", "web:https://xn--mnchen-3ya.example/", true},
		{"https://[2001:db8::1]/", "web:https://[2001:DB8:0::1]", true},
		{"https://portal.example.com/a%20b", "web:https://portal.example.com/a%20b", true},
		{"https://portal.example.com/caf\u00e9", "web:https://portal.example.com/caf%c3%a9", true},

		{"https://portal.example.com/loginx", login, false},
		{"https://portal.example.com/Login", login, false},
		{"https://portal.example.com/", login, false},
		{"https://portal.example.com/login;jsessionid=1", login, false},
		{"https://portal.example.com/x/../login", login, false},
		{"https://portal.example.com/login/../admin", login, false},
		{"https://portal.example.com/login/%2e%2e/admin", login, false},
		{"https://portal.example.com/login/.%2E/admin", login, false},
		{"https://portal.example.com/login/..;/admin", login, false},
		{"https://portal.example.com/login/..%3Bx/admin", login, false},
		{"https://portal.example.com/login%2Fadmin", login, false},
		{"https://portal.example.com/login/..%2fadmin", login, false},
		{"https://portal.example.com/login/..%5cadmin", login, false},
		{"https://portal.example.com/login/%252e%252e/admin", login, false},
		{"https://portal.example.com/login/%25252e", login, false},
		{"https://portal.example.com/login\\..\\admin", login, false},
		{"https://portal.example.com/login%00", login, false},
		{"https://portal.example.com/login\n", login, false},
		{"https://portal.example.com/login%", login, false},
		{"https://portal.example.com/login%2", login, false},
		{"https://portal.example.com/login/%+1", login, false},
		{"https://portal.example.com//login", login, false},
		{"http://portal.example.com/login", login, false},
		{"http://portal.example.com:443/login", login, false},
		{"https://portal.example.com:8443/login", login, false},
		{"https://portal.example.com:80/login", login, false},
		{"https://portal.example.com:443x/login", login, false},
		{"https://portal.example.com:/login", login, false},
		{"https://portal.example.com.evil.com/login", login, false},
		{"https://evilportal.example.com/login", login, false},
		{"https://portal.example.com@evil.com/login", login, false},
		{"https://user@portal.example.com/login", login, false},
		{"https://portal.example.com%2eevil.com/login", login, false},
		{"https://portal.example.com\\@evil.com/login", login, false},
		{"https://portal.example.com\\.evil.com/login", login, false},
		{"https:/portal.example.com/login", login, false},
		{"https:portal.example.com/login", login, false},
		{"//portal.example.com/login", login, false},
		{"portal.example.com/login", login, false},
		{" https://portal.example.com/login", login, false},
		{"ht\ntps://portal.example.com/login", login, false},
		{"https://port\tal.example.com/login", login, false},
		{"https://port\u00adal.example.com/login", login, false},
		{"https://portal\u200b.example.com/login", login, false},
		{"https://portal\u3002example\u3002com/x", login, false},
		{"https://p\u043ertal.example.com/login", login, false},
		{"javascript://portal.example.com/login", login, false},
		{"blob:https://portal.example.com/login", login, false},
		{"view-source:https://portal.example.com/login", login, false},
		{"data:text/html,https://portal.example.com/login", login, false},
		{"file:///portal.example.com/login", login, false},
		{"about:blank", login, false},
		{"", login, false},
		{"https://", login, false},
		{"https:///login", login, false},
		{"https://example.com/", sub, false},
		{"https://example.com./", sub, false},
		{"https://.example.com/", sub, false},
		{"https://notexample.com/", sub, false},
		{"https://a.example.com.evil.com/", sub, false},
		{"https://[::ffff:10.0.0.1]/", "web:https://10.0.0.1/", false},
		// What is bounded is what is kept (TestPageBounds).
		{"https://portal.example.com/login?" + strings.Repeat("x", MaxReported), login, true},
		{"https://portal.example.com/login/" + strings.Repeat("x", MaxReported), login, false},
		{"https://portal.example.com/login\xff", login, false},
		// A host and an application are no page.
		{"https://portal.example.com/login", "portal.example.com", false},
		{"https://portal.example.com/login", "app:portal@" + machine, false},
	} {
		if _, got := match(t, Reported{Kind: PlaceWeb, URL: c.url}, c.selector); got != c.want {
			t.Errorf("%q against %s: %v", c.url, c.selector, got)
		}
	}
	// A port other than the scheme's says so on both sides.
	if _, ok := match(t, Reported{Kind: PlaceWeb, URL: "http://intranet:8080/x"}, "web:http://intranet:8080"); !ok {
		t.Error("a port")
	}
	// A frame: it and the page around it, each by some selector.
	frame := Reported{Kind: PlaceWeb, URL: "https://login.example.com/frame", Top: "https://portal.example.com/app"}
	if _, ok := match(t, frame, "web:https://login.example.com/"); ok {
		t.Error("a frame in a page that is not named")
	}
	if _, ok := match(t, frame, "web:https://portal.example.com/"); ok {
		t.Error("a frame that is not named")
	}
	if s, ok := match(t, frame, "web:https://portal.example.com/", "web:https://login.example.com/"); !ok || s != "web:https://login.example.com:443/" {
		t.Errorf("both named: %s, %v", s, ok)
	}
	frame.Top = "about:srcdoc"
	if r := frame.Read(machine); r.Top != "web:unreadable" || len(r.Hosts()) != 0 {
		t.Errorf("%+v", r)
	}
	if _, ok := match(t, frame, "web:https://login.example.com/"); ok {
		t.Error("a page around it that cannot be read")
	}
}

func TestApplicationsMatch(t *testing.T) {
	crm := "app:CRM Client@" + machine
	for name, want := range map[string]bool{"CRM Client": true, "crm client": false, "CRM Client ": false, "CRM  Client": false, "CRM Client@" + machine: false, "CRM": false, "": false, "*": false,
		"CRM\u00a0Client": false, "CRM Client\u200b": false, "\u0421RM Client": false} {
		if _, got := match(t, Reported{Kind: PlaceApp, App: name}, crm); got != want {
			t.Errorf("%q: %v", name, got)
		}
	}
	if _, ok := match(t, Reported{Kind: PlaceApp, App: "Cafe\u0301"}, "app:Caf\u00e9@"+machine); !ok {
		t.Error("another spelling of the same name")
	}
	// On the Broker's own machine, whatever the selector says.
	other := "idn_53coswbcrvqzhsvjkyuawmnd7q"
	p, _ := ParsePlace("app:CRM Client@" + other)
	if _, ok := (Reported{Kind: PlaceApp, App: "CRM Client"}).Read(machine).Match([]Place{p}); ok {
		t.Error("another machine's")
	}
	if _, ok := (Reported{Kind: PlaceApp, App: "CRM Client"}).Read(other).Match([]Place{p}); !ok {
		t.Error("that machine's own")
	}
	// A page or a host is no application.
	for _, r := range []Reported{{Kind: PlaceWeb, URL: "https://CRM Client"}, {Kind: PlaceHost, Host: Destination{"CRM Client", 443}}} {
		if _, ok := match(t, r, crm); ok {
			t.Errorf("%+v", r)
		}
	}
}

// What the audit log says of a page: its path, and nothing that came with a
// query, a fragment, credentials or a path parameter, encoded or not.
func TestWhatIsRecordedOfAPage(t *testing.T) {
	const at = "web:https://portal.example.com:443"
	for raw, want := range map[string]string{
		"https://portal.example.com":                                         at + "/",
		"https://portal.example.com/a/b":                                     at + "/a/b",
		"https://portal.example.com/a/b?made=up":                             at + "/a/b",
		"https://portal.example.com?made=up":                                 at + "/",
		"https://portal.example.com/a#made-up":                               at + "/a",
		"https://portal.example.com#made-up?made=up":                         at + "/",
		"https://portal.example.com/a;jsessionid=madeup":                     at + "/a;\u2026",
		"https://portal.example.com/a;jsessionid=madeup/b;x=madeup":          at + "/a;\u2026/b;\u2026",
		"https://portal.example.com/a%3bsid=madeup/b":                        at + "/a;\u2026/b",
		"https://portal.example.com/a%3Fmade=up/b":                           at + "/a\u2026",
		"https://portal.example.com/a%23made=up":                             at + "/a\u2026",
		"https://portal.example.com/a;x=madeup%3Fy=madeup":                   at + "/a;\u2026",
		"https://u:madeup@portal.example.com/a":                              "web:unreadable",
		"https://madeup@portal.example.com/a":                                "web:unreadable",
		"https://u%3Amadeup%40portal.example.com/a":                          "web:unreadable",
		"https://portal.example.com\\madeup/a":                               "web:unreadable",
		"https://portal.example.com/a%253Fmadeup":                            "web:unreadable",
		"https://portal.example.com;madeup/a":                                "web:unreadable",
		"https://portal.example.com&x=madeup":                                "web:unreadable",
		"data:text/html,madeup":                                              "web:unreadable",
		"madeup":                                                             "web:unreadable",
		"https://portal.example.com/" + strings.Repeat("x", 300):             at + "/" + strings.Repeat("x", 199) + "\u2026",
		"https://portal.example.com/" + strings.Repeat("x", 197) + "%C3%A9":  at + "/" + strings.Repeat("x", 197) + "\u2026",
		"https://portal.example.com/" + strings.Repeat("x", 196) + ";madeup": at + "/" + strings.Repeat("x", 196) + ";\u2026",
	} {
		for what, got := range map[string]string{
			"url": Reported{Kind: PlaceWeb, URL: raw}.Read(machine).Text,
			"top": Reported{Kind: PlaceWeb, URL: "https://x.example/", Top: raw}.Read(machine).Top,
		} {
			if what == "top" && raw == "" {
				continue
			}
			if got != want {
				t.Errorf("%s %q is recorded as %q, want %q", what, raw, got, want)
			}
			if strings.Contains(got, "madeup") || strings.Contains(got, "made=up") || !utf8.ValidString(got) {
				t.Errorf("%s %q is recorded as %q", what, raw, got)
			}
		}
	}
}

// A host matches as it always did, and no page selector is one of a host's.
func TestHostsMatch(t *testing.T) {
	for _, c := range []struct {
		host string
		port int
		sel  string
		want bool
	}{{"api.example.com", 443, "api.example.com", true}, {"API.example.com.", 443, "api.example.com", true}, {"x.example.com", 443, "*.example.com", true}, {"example.com", 443, "*.example.com", false},
		{"api.example.com", 80, "api.example.com", false}, {"portal.example.com", 443, "web:https://portal.example.com/", false}, {"CRM", 443, "app:CRM@" + machine, false}} {
		if _, got := match(t, Reported{Kind: PlaceHost, Host: Destination{c.host, c.port}}, c.sel); got != c.want {
			t.Errorf("%s:%d against %s: %v", c.host, c.port, c.sel, got)
		}
	}
	// What an earlier server makes of the new selectors: none.
	for _, s := range []string{"web:https://portal.example.com:443/", "web:http://127.0.0.1:80/x", "web:https://*.example.com:443/", "app:CRM@" + machine, "app:a:1@" + machine, "web:https://[::1]:443/"} {
		if sel, ok := ParseDestinationSelector(s); ok {
			t.Errorf("%q is the host selector %v", s, sel)
		}
	}
}

func TestTakes(t *testing.T) {
	for _, c := range []struct {
		place string
		kinds string
	}{{PlaceHost, "header query json form pipe"}, {PlaceWeb, "field"}, {PlaceApp, "field pipe"}} {
		for _, k := range []string{"header", "query", "json", "form", targets.KindPipe, targets.KindField} {
			if want := strings.Contains(" "+c.kinds+" ", " "+k+" "); Takes(c.place, k) != want {
				t.Errorf("%s takes %s: %v", c.place, k, !want)
			}
		}
	}
}

// Whatever matches a selector, another parser of URLs agrees about: the
// scheme, the host, the port, and a path that is the selector's or under it
// after every dot segment is resolved, however often it is decoded.
func FuzzPageMatch(f *testing.F) {
	selectors := []string{"web:https://portal.example.com/login", "web:https://*.example.com/", "web:http://127.0.0.1:8080/a/b", "web:https://xn--mnchen-3ya.example/%C3%A9"}
	for i, s := range []string{"https://portal.example.com/login/x?y#z", "https://a.example.com:443/", "http://127.0.0.1:8080/a/b/", "https://m\u00fcnchen.example/\u00e9",
		"https://portal.example.com/login/%2e%2e/", "https://portal.example.com\\@evil.com/login", "https://user:p@portal.example.com/login", "https://portal.example.com:00443/login", "https://[::1]/", "https://portal.example.com./login",
		"https://portal.example.com/login/..;/x", "https://x.example.com%2f.evil/", "https://portal\u3002example.com/login", "https://portal.example.com/login/%25%32%65"} {
		f.Add(s, i%len(selectors))
	}
	f.Fuzz(func(t *testing.T, raw string, n int) {
		if n < 0 {
			n = -(n + 1)
		}
		p, ok := ParsePlace(selectors[n%len(selectors)])
		if !ok {
			t.Fatal("the selector")
		}
		g, ok := ParsePage(raw)
		if !ok {
			return
		}
		// A page is its own spelling.
		full := g.Scheme + "://" + DestinationSelector{Host: g.Host, Port: g.Port}.String() + g.Path
		if again, ok := ParsePage(full); len(full) <= MaxReported && (!ok || again != g) {
			t.Fatalf("%q read again: %+v, then %+v, %v", raw, g, again, ok)
		}
		if said := g.String(); strings.Contains(g.Host, "@") || strings.ContainsAny(said, "?# \t\r\n\\") || !utf8.ValidString(said) ||
			strings.Contains(said, "%3F") || strings.Contains(said, "%23") || strings.Contains(strings.ReplaceAll(said, ";\u2026", ""), ";") {
			t.Fatalf("%q is recorded as %q", raw, g.String())
		}
		if !p.holds(g) {
			return
		}
		u, err := url.Parse(strings.ToLower(raw[:strings.Index(raw, "://")]) + raw[strings.Index(raw, "://"):])
		if err != nil {
			return // stricter than this parser
		}
		if u.User != nil || u.Scheme != p.Scheme {
			t.Fatalf("%q matches %s: %+v", raw, p, u)
		}
		host, ok := CanonicalizeHost(u.Hostname())
		if !ok || !p.Net.Wildcard && host != p.Net.Host || p.Net.Wildcard && !strings.HasSuffix(host, "."+p.Net.Host) {
			t.Fatalf("%q matches %s: host %q", raw, p, u.Hostname())
		}
		path := u.EscapedPath()
		for range 3 {
			decoded, err := url.PathUnescape(path)
			if err != nil {
				break
			}
			resolved := (&url.URL{Scheme: "x", Host: "x", Path: "/"}).ResolveReference(&url.URL{Path: strings.ReplaceAll(decoded, "\\\\", "/")}).Path
			want, _ := url.PathUnescape(p.Path)
			if p.Path != "/" && resolved != want && !strings.HasPrefix(resolved, want+"/") {
				t.Fatalf("%q matches %s and is %q after decoding", raw, p, resolved)
			}
			if decoded == path {
				break
			}
			path = decoded
		}
	})
}

// Any selector read is canonical, names no credentials, query or dot segment,
// and is no host selector of an earlier server unless it is one here.
func FuzzPlace(f *testing.F) {
	for _, s := range []string{"api.example.com", "*.example.com:8443", "[::1]:80", "web:443", "web:https://portal.example.com/login/*", "web:http://*.example.com:80/%7ea", "app:CRM Client@" + machine, "app:8080", "web:https://user@x/", "web:https://x/../y", "app:a@b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, ok := ParsePlace(raw)
		if !ok {
			return
		}
		s := p.String()
		// A host's is as it always was ("*.0" is one that reads as none again).
		again, ok := ParsePlace(s)
		if p.Kind != PlaceHost && (!ok || again != p) {
			t.Fatalf("%q: %q, then %q, %v", raw, s, again, ok)
		}
		_, host := ParseDestinationSelector(raw)
		if host != (p.Kind == PlaceHost) {
			t.Fatalf("%q is a %s, and a host selector: %v", raw, p.Kind, host)
		}
		if _, old := ParseDestinationSelector(s); old && p.Kind != PlaceHost {
			t.Fatalf("%q: the earlier server reads %q: %v", raw, s, old)
		}
		if p.Kind != PlaceHost && (strings.ContainsAny(s, ",;?#\n\t") || len(s) > MaxSelector) {
			t.Fatalf("%q: %q", raw, s)
		}
		if p.Kind == PlaceWeb && strings.Contains(s, "@") && !strings.Contains(p.Path, "@") {
			t.Fatalf("%q: %q", raw, s)
		}
	})
}

// What is bounded of a reported page is what is kept of it: a long query or
// fragment goes, unread, and a long path is refused.
func TestPageBounds(t *testing.T) {
	const page = "https://portal.example.com/login"
	for _, tail := range []string{"?" + strings.Repeat("x", MaxReported), "#" + strings.Repeat("x", MaxReported), "?a=\xff"} {
		if g, ok := ParsePage(page + tail); !ok || g.Path != "/login" {
			t.Errorf("%.40q: %+v, %v", page+tail, g, ok)
		}
	}
	if _, ok := ParsePage(page + "/" + strings.Repeat("x", MaxReported)); ok {
		t.Error("a long path is read")
	}
	if _, ok := ParsePage(page + "/\xff"); ok {
		t.Error("a path that is not UTF-8 is read")
	}
}
