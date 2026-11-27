// SPDX-License-Identifier: AGPL-3.0-or-later

package authz

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/varlatch/varlatch/go/lib/targets"
	"github.com/varlatch/varlatch/go/lib/whatwg"
)

// Destinations of a Capability beside host and port (ADR-0064), for a Broker
// that types a value instead of sending it:
//
//   - web:<scheme>://<host>[:<port>][/<path>]: a page in a browser. The host
//     is exact or *.suffix (subdomains, never the apex, never an IP); the
//     path is a prefix of whole segments; no path is every page of the host.
//   - app:<name>@<identity>: a desktop application on the machine of the
//     Broker of that identity.
//
// Varlatch compares what the Broker reports. The machine of an app: place is
// the authenticated Broker, so that part is not reported but known; the page
// and the application's name are the Broker's word. Everything that cannot
// be read, or could be read two ways, matches nothing.

// Kinds of destination.
const (
	PlaceHost = "host"
	PlaceWeb  = "web"
	PlaceApp  = "app"
)

// MaxSelector and MaxReported bound a selector and a reported URL, in bytes.
const (
	MaxSelector = 512
	MaxReported = 4096
	// MaxAppName is in code points.
	MaxAppName = 100
)

// Place is a Capability's destination selector, of any kind.
type Place struct {
	Kind string
	// Net is the host and port, of a host or a page.
	Net DestinationSelector
	// Scheme and Path are a page's: Path is "/" or a normalized path without
	// a trailing slash.
	Scheme, Path string
	// App and Machine are a desktop application's.
	App, Machine string
}

var (
	identityID = regexp.MustCompile(`^idn_[a-z2-7]{26}$`)
	// pageHost is a name there is, or an IPv4 address: a "*", and what a host
	// could carry in a query's place (";x=y"), is none.
	pageHost = regexp.MustCompile(`^[a-z0-9._-]+$`)
	// encodedTwice is a percent sign, encoded, before what it would encode: for
	// a server that decodes twice.
	encodedTwice = regexp.MustCompile(`%25[0-9A-Fa-f]{2}`)
	// What String leaves out: path parameters, and what follows an encoded
	// "?" or "#"; and half a percent-encoding at the end.
	pathParameter = regexp.MustCompile(`(?:;|%3B)[^/]*`)
	encodedMark   = regexp.MustCompile(`%3F|%23`)
	halfEncoded   = regexp.MustCompile(`%[0-9A-F]?$`)
	// schemes' ports.
	schemePort = map[string]int{"https": 443, "http": 80}
)

// ParsePlace reads a destination selector. What is no web: or app: selector
// is read as it always was (ParseDestinationSelector): "web:443" and
// "app:8080" are hosts named web and app.
func ParsePlace(raw string) (Place, bool) {
	input := whatwg.Trim(raw)
	switch {
	case strings.HasPrefix(input, "web:http://"), strings.HasPrefix(input, "web:https://"):
		return parseWeb(strings.TrimPrefix(input, "web:"))
	case strings.HasPrefix(input, "app:") && strings.Contains(input, "@"):
		return parseApp(strings.TrimPrefix(input, "app:"))
	}
	sel, ok := ParseDestinationSelector(raw)
	return Place{Kind: PlaceHost, Net: sel}, ok
}

// String is the selector in its canonical form.
func (p Place) String() string {
	switch p.Kind {
	case PlaceWeb:
		return "web:" + p.Scheme + "://" + p.Net.String() + p.Path
	case PlaceApp:
		return "app:" + p.App + "@" + p.Machine
	}
	return p.Net.String()
}

func parseWeb(raw string) (Place, bool) {
	// Commas separate selectors in the audit log, and a query or a fragment
	// is never compared: neither is part of a selector.
	if len(raw) > MaxSelector || strings.ContainsAny(raw, ",;?#") {
		return Place{}, false
	}
	// "/*" at the end says what a path says without it. A path is whole
	// segments: "/log*" is none.
	if strings.HasSuffix(raw, "*") && !strings.HasSuffix(raw, "/*") {
		return Place{}, false
	}
	raw = strings.TrimSuffix(raw, "*")
	scheme, rest, _ := strings.Cut(raw, "://")
	authority, path := rest, "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	wildcard := false
	if s, ok := strings.CutPrefix(authority, "*."); ok {
		wildcard, authority = true, s
	}
	host, port, ok := splitAuthority(authority, scheme)
	if !ok || strings.Contains(path, "*") {
		return Place{}, false
	}
	if wildcard && (whatwg.IsIP(host) != 0 || !strings.Contains(host, ".")) {
		// Never all of a top-level domain.
		return Place{}, false
	}
	if path, ok = normalizePath(path); !ok || strings.Contains(path, "//") {
		return Place{}, false
	}
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	p := Place{Kind: PlaceWeb, Scheme: scheme, Path: path, Net: DestinationSelector{Host: host, Wildcard: wildcard, Port: port}}
	return p, len(p.String()) <= MaxSelector
}

// splitAuthority is a URL's host, canonical, and its port: never credentials.
func splitAuthority(authority, scheme string) (string, int, bool) {
	port, known := schemePort[scheme]
	if !known || authority == "" || strings.ContainsAny(authority, "@%\\") {
		return "", 0, false
	}
	host := authority
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", 0, false
		}
		ip, err := netip.ParseAddr(authority[1:end])
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return "", 0, false
		}
		// One spelling, whoever writes it.
		host = ip.String()
		if rest := authority[end+1:]; rest != "" {
			p, ok := parsePort(strings.TrimPrefix(rest, ":"))
			if !ok || rest[0] != ':' {
				return "", 0, false
			}
			port = p
		}
		return host, port, true
	}
	if i := strings.IndexByte(authority, ':'); i >= 0 {
		p, ok := parsePort(authority[i+1:])
		if !ok {
			return "", 0, false
		}
		host, port = authority[:i], p
	}
	if strings.Contains(host, ":") {
		return "", 0, false
	}
	host, ok := CanonicalizeHost(host)
	if !ok || !pageHost.MatchString(host) {
		return "", 0, false
	}
	return host, port, true
}

const hexDigits = "0123456789ABCDEF"

// normalizePath is a URL's path in one spelling: UTF-8 percent-encoded,
// percent-encodings upper-case, and none where the character needs none. A
// path that could name another place to another reader is refused: a dot
// segment, an encoded slash or backslash or control character (once or
// more), a raw backslash, space or control character, a percent sign that
// encodes nothing.
func normalizePath(path string) (string, bool) {
	if !strings.HasPrefix(path, "/") || !utf8.ValidString(path) {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		switch {
		case c == '%':
			if i+2 >= len(path) {
				return "", false
			}
			n, err := strconv.ParseUint(path[i+1:i+3], 16, 8)
			if err != nil || path[i+1] == '+' || path[i+1] == '-' {
				return "", false
			}
			d := byte(n)
			if d < 0x20 || d == 0x7f || d == '/' || d == '\\' {
				return "", false
			}
			if unreserved(d) {
				b.WriteByte(d)
			} else {
				b.WriteByte('%')
				b.WriteByte(hexDigits[d>>4])
				b.WriteByte(hexDigits[d&15])
			}
			i += 2
		case c <= 0x20 || c == 0x7f || c == '\\':
			return "", false
		case c >= 0x80 || strings.IndexByte("\"<>`{}|^", c) >= 0:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&15])
		default:
			b.WriteByte(c)
		}
	}
	out := b.String()
	if encodedTwice.MatchString(out) {
		return "", false
	}
	for _, segment := range strings.Split(out, "/") {
		// A path parameter does not make ".." anything else to some servers.
		name, _, _ := strings.Cut(strings.ReplaceAll(segment, "%3B", ";"), ";")
		if name == "." || name == ".." {
			return "", false
		}
	}
	return out, true
}

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// Page is a page's address as it is compared: no credentials, query or
// fragment.
type Page struct {
	Scheme, Host string
	Port         int
	Path         string
}

// ParsePage reads the address a Broker reports, as a browser shows it. The
// query and the fragment go first, unread: what is bounded is what is kept.
func ParsePage(raw string) (Page, bool) {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) > MaxReported || !utf8.ValidString(raw) {
		return Page{}, false
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	scheme = asciiLower(scheme)
	if !ok || schemePort[scheme] == 0 {
		return Page{}, false
	}
	authority, path := rest, "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		authority, path = rest[:i], rest[i:]
	}
	for _, r := range authority {
		if r <= 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return Page{}, false
		}
	}
	host, port, ok := splitAuthority(authority, scheme)
	if !ok {
		return Page{}, false
	}
	if path, ok = normalizePath(path); !ok {
		return Page{}, false
	}
	return Page{scheme, host, port, path}, true
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Net is where the page is.
func (p Page) Net() Destination { return Destination{Host: p.Host, Port: p.Port} }

// String is the page as the audit log has it: its path shortened, and
// without what a path can carry in a query's place. A path parameter
// (";jsessionid=…") goes, and so does all that follows a query's or a
// fragment's mark that was encoded.
func (p Page) String() string {
	path := p.Path
	if i := encodedMark.FindStringIndex(path); i != nil {
		path = path[:i[0]] + "…"
	}
	path = pathParameter.ReplaceAllString(path, ";…")
	if len(path) > 200 {
		path = path[:200]
		// Not half of a character, nor of an encoded one.
		for !utf8.ValidString(path) {
			path = path[:len(path)-1]
		}
		path = halfEncoded.ReplaceAllString(path, "") + "…"
	}
	return p.Scheme + "://" + DestinationSelector{Host: p.Host, Port: p.Port}.String() + path
}

// holds is whether the selector names the page.
func (p Place) holds(g Page) bool {
	if p.Kind != PlaceWeb || p.Scheme != g.Scheme || !p.Net.Matches(g.Net()) {
		return false
	}
	return p.Path == "/" || g.Path == p.Path || strings.HasPrefix(g.Path, p.Path+"/")
}

func parseApp(raw string) (Place, bool) {
	at := strings.LastIndexByte(raw, '@')
	name, machine := raw[:at], raw[at+1:]
	app, ok := AppName(name)
	if !ok || !identityID.MatchString(machine) || len(raw) > MaxSelector {
		return Place{}, false
	}
	return Place{Kind: PlaceApp, App: app, Machine: machine}, true
}

// AppName is a desktop application's name as it is compared: NFC, exactly. A
// name with a character that shows as nothing or as another place (a control,
// format or blank one, @, *, or what separates entries in the audit log) is
// none.
func AppName(raw string) (string, bool) {
	if !utf8.ValidString(raw) {
		return "", false
	}
	name := norm.NFC.String(raw)
	if n := utf8.RuneCountInString(name); n == 0 || n > MaxAppName || strings.TrimSpace(name) != name || strings.ContainsAny(name, "@*,;=\\/") || !targets.Plain(name) {
		return "", false
	}
	return name, true
}

// Takes is whether a value may be put at a target of this kind there: a part
// of a request goes to a host, a field is of a page or an application, and a
// document over a pipe goes to a process, which is an application or talks to
// a host.
func Takes(place, target string) bool {
	switch target {
	case targets.KindField:
		return place == PlaceWeb || place == PlaceApp
	case targets.KindPipe:
		return place == PlaceHost || place == PlaceApp
	}
	return place == PlaceHost
}

// Reported is where a Broker says it puts a value.
type Reported struct {
	Kind string
	// Host is a host and port.
	Host Destination
	// URL is the address of the page that holds the field, and Top of the
	// page around it, when that is another one ("": none).
	URL, Top string
	// App is the application's name. The title of its window is no part of a
	// report: titles hold what people look at, and are recorded nowhere.
	App string
}

// Reading is a reported destination, read: what is compared, and what the
// audit log says of it.
type Reading struct {
	Kind string
	host Destination
	// pages are the page and, when it is another, the page around it; none
	// when either could not be read.
	pages  []Page
	app    string
	broker string
	// Text is the destination in the audit log, and Top the page around it.
	Text, Top string
}

// Read reads a reported destination of broker.
func (r Reported) Read(broker string) Reading {
	out := Reading{Kind: r.Kind, broker: broker}
	switch r.Kind {
	case PlaceWeb:
		out.Text = "web:unreadable"
		page, ok := ParsePage(r.URL)
		if !ok {
			return out
		}
		out.Text, out.pages = "web:"+page.String(), []Page{page}
		if r.Top != "" {
			top, ok := ParsePage(r.Top)
			if !ok {
				out.Top, out.pages = "web:unreadable", nil
				return out
			}
			out.Top, out.pages = "web:"+top.String(), append(out.pages, top)
		}
	case PlaceApp:
		out.Text = "app:unreadable@" + broker
		if app, ok := AppName(r.App); ok {
			out.app, out.Text = app, "app:"+app+"@"+broker
		}
	default:
		out.Kind, out.host = PlaceHost, r.Host
		out.Text = r.Host.Host + ":" + strconv.Itoa(r.Host.Port)
	}
	return out
}

// Hosts are the hosts and ports it goes to: none for an application, nor
// where a page of it is not https. A host and port in a list of hosts are
// what TLS is spoken to.
func (r Reading) Hosts() []Destination {
	if r.Kind == PlaceHost {
		return []Destination{r.host}
	}
	var out []Destination
	for _, p := range r.pages {
		if p.Scheme != "https" {
			return nil
		}
		out = append(out, p.Net())
	}
	return out
}

// Host is the hosts of a selector, and whether it is of hosts, as those of
// Reading are: no application and no page that is not https.
func (p Place) Host() (DestinationSelector, bool) {
	return p.Net, p.Kind == PlaceHost || p.Kind == PlaceWeb && p.Scheme == "https"
}

// Match is the selector that names the destination, and whether one does: of
// a page in a frame, both it and the page around it have to be named.
func (r Reading) Match(places []Place) (Place, bool) {
	first := func(holds func(Place) bool) (Place, bool) {
		for _, p := range places {
			if holds(p) {
				return p, true
			}
		}
		return Place{}, false
	}
	switch r.Kind {
	case PlaceHost:
		return first(func(p Place) bool { return p.Kind == PlaceHost && p.Net.Matches(r.host) })
	case PlaceApp:
		return first(func(p Place) bool {
			return p.Kind == PlaceApp && r.app != "" && p.App == r.app && p.Machine == r.broker
		})
	case PlaceWeb:
		var found Place
		for i, g := range r.pages {
			p, ok := first(func(p Place) bool { return p.holds(g) })
			if !ok {
				return Place{}, false
			}
			if i == 0 {
				found = p
			}
		}
		return found, len(r.pages) > 0
	}
	return Place{}, false
}
