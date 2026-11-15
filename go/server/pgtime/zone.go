// SPDX-License-Identifier: AGPL-3.0-or-later AND PostgreSQL
//
// Zones as PostgreSQL 17 reads them for timestamp input: pg_tzset and
// pg_open_tzfile (src/timezone/pgtz.c), and tzload, tzparse,
// pg_next_dst_boundary and pg_interpret_timezone_abbrev
// (src/timezone/localtime.c, PostgreSQL's copy of the IANA tz code, which
// is in the public domain), ported to Go. A name is looked up, ignoring
// case, in a tz database directory, as a server built
// --with-system-tzdata reads it; a name no file holds is read as a POSIX
// TZ string.
//
// Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
// (LICENSE-PostgreSQL)

package pgtime

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	tzMaxTimes  = 2000
	tzMaxTypes  = 256
	tzMaxChars  = 50
	tzMaxLeaps  = 50
	tzStrlenMax = 255
	maxPgPath   = 1024
	// charsSize is sizeof state.chars: BIGGEST(TZ_MAX_CHARS + 1, 4,
	// 2 * (TZ_STRLEN_MAX + 1)).
	charsSize = 2 * (tzStrlenMax + 1)
	// tzHeadSize is sizeof(struct tzhead).
	tzHeadSize = 44
	// inputBufferSize is sizeof(union input_buffer) on a 64-bit server:
	// 2 * sizeof(struct tzhead) + 2 * sizeof(struct state) + 4 *
	// TZ_MAX_TIMES; a tz file is read up to this many bytes.
	inputBufferSize = 2*tzHeadSize + 2*23440 + 4*tzMaxTimes

	yearsPerRepeat = 400
	avgSecsPerYear = 31556952
	secsPerRepeat  = yearsPerRepeat * avgSecsPerYear
	epochYear      = 1970
	secsPerHour    = 3600
	secsPerDay     = 86400
	daysPerNYear   = 365
	daysPerLYear   = 366
	timeTMin       = -1 << 63
	timeTMax       = 1<<63 - 1
)

// tzDefRuleString is TZDEFRULESTRING: the rules a POSIX TZ string with a
// daylight-saving name and no rules gets (US rules).
const tzDefRuleString = ",M3.2.0,M11.1.0"

type ttinfo struct {
	utoff           int32
	isdst           bool
	desigidx        int
	ttisstd, ttisut bool
}

type lsinfo struct {
	trans int64
	corr  int64
}

// state is struct state.
type state struct {
	leapcnt, timecnt, typecnt, charcnt int
	goback, goahead                    bool
	ats                                [tzMaxTimes]int64
	types                              [tzMaxTimes]uint8
	ttis                               [tzMaxTypes]ttinfo
	chars                              [charsSize]byte
	lsis                               [tzMaxLeaps]lsinfo
}

// cstr is the NUL-terminated string at b's start.
func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// Zones is a tz database directory and the zones read from it, cached by
// name as a server session caches them.
type Zones struct {
	dir   string
	mu    sync.Mutex
	cache map[string]*state
}

// NewZones reads zones from dir.
func NewZones(dir string) *Zones {
	return &Zones{dir: dir, cache: map[string]*state{}}
}

// System is the host's tz database, where PostgreSQL's packages built
// --with-system-tzdata read theirs.
var System = NewZones("/usr/share/zoneinfo")

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// tzset is pg_tzset: the zone a name means, nil for none.
func (z *Zones) tzset(name string) *state {
	if len(name) > tzStrlenMax {
		return nil
	}
	up := upper(name)
	z.mu.Lock()
	sp, ok := z.cache[up]
	z.mu.Unlock()
	if ok {
		return sp
	}
	sp = new(state)
	if up == "GMT" {
		if !tzparse(up, sp, true) {
			return nil
		}
	} else if !z.tzload(up, sp) {
		*sp = state{}
		if up[0] == ':' || !tzparse(up, sp, false) {
			return nil
		}
	}
	z.mu.Lock()
	z.cache[up] = sp
	z.mu.Unlock()
	return sp
}

// openTZFile is pg_open_tzfile with a canonical name wanted: each level of
// the name found in its directory ignoring case, never a hidden entry.
func (z *Zones) openTZFile(name string) ([]byte, bool) {
	if len(z.dir)+1+len(name) >= maxPgPath {
		return nil, false
	}
	full := z.dir
	for _, part := range strings.Split(name, "/") {
		entries, err := os.ReadDir(full)
		if err != nil {
			return nil, false
		}
		found := ""
		for _, e := range entries {
			n := e.Name()
			if n[0] != '.' && equalFoldASCII(n, part) {
				found = n
				break
			}
		}
		if found == "" {
			return nil, false
		}
		full = filepath.Join(full, found)
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	// One read of up to the input buffer's size, as tzloadbody's read().
	buf := make([]byte, inputBufferSize)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, false
	}
	return buf[:n], true
}

// equalFoldASCII is pg_strncasecmp's equality for names of one length.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

func detzcode(b []byte) int32 {
	return int32(uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]))
}

func detzcode64(b []byte) int64 {
	var r uint64
	for i := 0; i < 8; i++ {
		r = r<<8 | uint64(b[i])
	}
	return int64(r)
}

// tzload is tzload with doextend: a compiled tz file into sp; false when
// there is none, or it is not one.
func (z *Zones) tzload(name string, sp *state) bool {
	if name != "" && name[0] == ':' {
		name = name[1:]
	}
	data, ok := z.openTZFile(name)
	if !ok {
		return false
	}
	return tzloadbody(data, sp)
}

func tzloadbody(buf []byte, sp *state) bool {
	sp.goback, sp.goahead = false, false
	nread := len(buf)
	if nread < tzHeadSize {
		return false
	}
	at := func(i int) byte {
		if i < len(buf) {
			return buf[i]
		}
		return 0
	}
	for stored := 4; stored <= 8; stored *= 2 {
		if len(buf) < tzHeadSize {
			return false
		}
		ttisstdcnt := int(detzcode(buf[24:]))
		ttisutcnt := int(detzcode(buf[20:]))
		leapcnt := int(detzcode(buf[28:]))
		timecnt := int(detzcode(buf[32:]))
		typecnt := int(detzcode(buf[36:]))
		charcnt := int(detzcode(buf[40:]))
		version := buf[4]
		var prevtr int64
		var prevcorr int64
		p := tzHeadSize
		if !(0 <= leapcnt && leapcnt < tzMaxLeaps && 0 <= typecnt && typecnt < tzMaxTypes &&
			0 <= timecnt && timecnt < tzMaxTimes && 0 <= charcnt && charcnt < tzMaxChars &&
			(ttisstdcnt == typecnt || ttisstdcnt == 0) && (ttisutcnt == typecnt || ttisutcnt == 0)) {
			return false
		}
		if nread < tzHeadSize+timecnt*stored+timecnt+typecnt*6+charcnt+leapcnt*(stored+4)+ttisstdcnt+ttisutcnt {
			return false
		}
		sp.leapcnt, sp.timecnt, sp.typecnt, sp.charcnt = leapcnt, timecnt, typecnt, charcnt

		// Transitions; one at the same time as the one before replaces it.
		keep := make([]bool, sp.timecnt)
		n := 0
		for i := 0; i < sp.timecnt; i++ {
			var t int64
			if stored == 4 {
				t = int64(detzcode(buf[p:]))
			} else {
				t = detzcode64(buf[p:])
			}
			keep[i] = true
			if n > 0 && t <= sp.ats[n-1] {
				if t < sp.ats[n-1] {
					return false
				}
				keep[i-1] = false
				n--
			}
			sp.ats[n] = t
			n++
			p += stored
		}
		n = 0
		for i := 0; i < sp.timecnt; i++ {
			typ := at(p)
			p++
			if sp.typecnt <= int(typ) {
				return false
			}
			if keep[i] {
				sp.types[n] = typ
				n++
			}
		}
		sp.timecnt = n
		for i := 0; i < sp.typecnt; i++ {
			t := &sp.ttis[i]
			t.utoff = detzcode(buf[p:])
			p += 4
			isdst := at(p)
			p++
			if !(isdst < 2) {
				return false
			}
			t.isdst = isdst == 1
			desig := at(p)
			p++
			if !(int(desig) < sp.charcnt) {
				return false
			}
			t.desigidx = int(desig)
		}
		i := 0
		for ; i < sp.charcnt; i++ {
			sp.chars[i] = at(p)
			p++
		}
		sp.chars[i] = 0

		n = 0
		for i := 0; i < sp.leapcnt; i++ {
			var tr int64
			if stored == 4 {
				tr = int64(detzcode(buf[p:]))
			} else {
				tr = detzcode64(buf[p:])
			}
			corr := int64(detzcode(buf[p+stored:]))
			p += stored + 4
			if tr < 0 {
				return false
			}
			if tr-prevtr < 28*secsPerDay-1 || (corr != prevcorr-1 && corr != prevcorr+1) {
				return false
			}
			prevtr, prevcorr = tr, corr
			sp.lsis[n] = lsinfo{trans: tr, corr: corr}
			n++
		}
		sp.leapcnt = n

		for i := 0; i < sp.typecnt; i++ {
			if ttisstdcnt == 0 {
				sp.ttis[i].ttisstd = false
			} else {
				if c := at(p); c > 1 {
					return false
				}
				sp.ttis[i].ttisstd = at(p) == 1
				p++
			}
		}
		for i := 0; i < sp.typecnt; i++ {
			if ttisutcnt == 0 {
				sp.ttis[i].ttisut = false
			} else {
				if c := at(p); c > 1 {
					return false
				}
				sp.ttis[i].ttisut = at(p) == 1
				p++
			}
		}
		if version == 0 {
			break
		}
		nread -= p
		buf = buf[p:]
	}
	if nread > 2 && buf[0] == '\n' && buf[nread-1] == '\n' && sp.typecnt+2 <= tzMaxTypes {
		ts := new(state)
		if tzparse(cstr(buf[1:nread-1]), ts, false) {
			gotabbr := 0
			charcnt := sp.charcnt
			for i := 0; i < ts.typecnt; i++ {
				tsabbr := cstr(ts.chars[ts.ttis[i].desigidx:])
				j := 0
				for ; j < charcnt; j++ {
					if cstr(sp.chars[j:]) == tsabbr {
						ts.ttis[i].desigidx = j
						gotabbr++
						break
					}
				}
				if !(j < charcnt) {
					if j+len(tsabbr) < tzMaxChars {
						copy(sp.chars[j:], tsabbr)
						sp.chars[j+len(tsabbr)] = 0
						charcnt = j + len(tsabbr) + 1
						ts.ttis[i].desigidx = j
						gotabbr++
					}
				}
			}
			if gotabbr == ts.typecnt {
				sp.charcnt = charcnt
				for 1 < sp.timecnt && sp.types[sp.timecnt-1] == sp.types[sp.timecnt-2] {
					sp.timecnt--
				}
				i := 0
				for ; i < ts.timecnt; i++ {
					if sp.timecnt == 0 || sp.ats[sp.timecnt-1] < ts.ats[i]+leapcorr(sp, ts.ats[i]) {
						break
					}
				}
				for i < ts.timecnt && sp.timecnt < tzMaxTimes {
					sp.ats[sp.timecnt] = ts.ats[i] + leapcorr(sp, ts.ats[i])
					sp.types[sp.timecnt] = uint8(sp.typecnt + int(ts.types[i]))
					sp.timecnt++
					i++
				}
				for i := 0; i < ts.typecnt; i++ {
					sp.ttis[sp.typecnt] = ts.ttis[i]
					sp.typecnt++
				}
			}
		}
	}
	if sp.typecnt == 0 {
		return false
	}
	if sp.timecnt > 1 {
		for i := 1; i < sp.timecnt; i++ {
			if typesequiv(sp, int(sp.types[i]), int(sp.types[0])) && sp.ats[i]-sp.ats[0] == secsPerRepeat {
				sp.goback = true
				break
			}
		}
		for i := sp.timecnt - 2; i >= 0; i-- {
			if typesequiv(sp, int(sp.types[sp.timecnt-1]), int(sp.types[i])) && sp.ats[sp.timecnt-1]-sp.ats[i] == secsPerRepeat {
				sp.goahead = true
				break
			}
		}
	}
	return true
}

func typesequiv(sp *state, a, b int) bool {
	if a < 0 || a >= sp.typecnt || b < 0 || b >= sp.typecnt {
		return false
	}
	ap, bp := sp.ttis[a], sp.ttis[b]
	return ap.utoff == bp.utoff && ap.isdst == bp.isdst && ap.ttisstd == bp.ttisstd && ap.ttisut == bp.ttisut &&
		cstr(sp.chars[ap.desigidx:]) == cstr(sp.chars[bp.desigidx:])
}

func leapcorr(sp *state, t int64) int64 {
	for i := sp.leapcnt - 1; i >= 0; i-- {
		if t >= sp.lsis[i].trans {
			return sp.lsis[i].corr
		}
	}
	return 0
}

var monLengths = [2][12]int{
	{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
	{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31},
}

var yearLengths = [2]int{daysPerNYear, daysPerLYear}

func isleapI(y int) int {
	if y%4 == 0 && (y%100 != 0 || y%400 == 0) {
		return 1
	}
	return 0
}

func tzDigit(c byte) bool { return c >= '0' && c <= '9' }

// getzname scans a zone abbreviation; it returns the index just past it.
func getzname(s string, i int) int {
	for i < len(s) {
		c := s[i]
		if c == 0 || tzDigit(c) || c == ',' || c == '-' || c == '+' {
			break
		}
		i++
	}
	return i
}

func getqzname(s string, i int, delim byte) int {
	for i < len(s) && s[i] != 0 && s[i] != delim {
		i++
	}
	return i
}

func ch(s string, i int) byte {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return 0
}

// getnum is getnum: -1 for no number or one out of [min, max].
func getnum(s string, i int, num *int, min, max int) int {
	if i < 0 || !tzDigit(ch(s, i)) {
		return -1
	}
	n := 0
	for {
		n = n*10 + int(s[i]-'0')
		if n > max {
			return -1
		}
		i++
		if !tzDigit(ch(s, i)) {
			break
		}
	}
	if n < min {
		return -1
	}
	*num = n
	return i
}

func getsecs(s string, i int, secs *int32) int {
	var num int
	if i = getnum(s, i, &num, 0, 24*7-1); i < 0 {
		return -1
	}
	*secs = int32(num) * secsPerHour
	if ch(s, i) == ':' {
		if i = getnum(s, i+1, &num, 0, 59); i < 0 {
			return -1
		}
		*secs += int32(num) * 60
		if ch(s, i) == ':' {
			if i = getnum(s, i+1, &num, 0, 60); i < 0 {
				return -1
			}
			*secs += int32(num)
		}
	}
	return i
}

func getoffset(s string, i int, offset *int32) int {
	neg := false
	switch ch(s, i) {
	case '-':
		neg = true
		i++
	case '+':
		i++
	}
	if i = getsecs(s, i, offset); i < 0 {
		return -1
	}
	if neg {
		*offset = -*offset
	}
	return i
}

const (
	julianDay = iota
	dayOfYear
	monthNthDayOfWeek
)

type rule struct {
	typ            int
	day, week, mon int
	time           int32
}

func getrule(s string, i int, r *rule) int {
	switch c := ch(s, i); {
	case c == 'J':
		r.typ = julianDay
		i = getnum(s, i+1, &r.day, 1, daysPerNYear)
	case c == 'M':
		r.typ = monthNthDayOfWeek
		if i = getnum(s, i+1, &r.mon, 1, 12); i < 0 {
			return -1
		}
		if ch(s, i) != '.' {
			return -1
		}
		if i = getnum(s, i+1, &r.week, 1, 5); i < 0 {
			return -1
		}
		if ch(s, i) != '.' {
			return -1
		}
		i = getnum(s, i+1, &r.day, 0, 6)
	case tzDigit(c):
		r.typ = dayOfYear
		i = getnum(s, i, &r.day, 0, daysPerLYear-1)
	default:
		return -1
	}
	if i < 0 {
		return -1
	}
	if ch(s, i) == '/' {
		i = getoffset(s, i+1, &r.time)
	} else {
		r.time = 2 * secsPerHour
	}
	return i
}

func transtime(year int, r *rule, offset int32) int32 {
	leap := isleapI(year)
	var value int32
	switch r.typ {
	case julianDay:
		value = int32(r.day-1) * secsPerDay
		if leap == 1 && r.day >= 60 {
			value += secsPerDay
		}
	case dayOfYear:
		value = int32(r.day) * secsPerDay
	case monthNthDayOfWeek:
		m1 := (r.mon+9)%12 + 1
		yy0 := year
		if r.mon <= 2 {
			yy0 = year - 1
		}
		yy1 := yy0 / 100
		yy2 := yy0 % 100
		dow := ((26*m1-2)/10 + 1 + yy2 + yy2/4 + yy1/4 - 2*yy1) % 7
		if dow < 0 {
			dow += 7
		}
		d := r.day - dow
		if d < 0 {
			d += 7
		}
		for i := 1; i < r.week; i++ {
			if d+7 >= monLengths[leap][r.mon-1] {
				break
			}
			d += 7
		}
		value = int32(d) * secsPerDay
		for i := 0; i < r.mon-1; i++ {
			value += int32(monLengths[leap][i]) * secsPerDay
		}
	}
	return value + r.time + offset
}

// incrementOverflowTime is increment_overflow_time: true when *tp + j
// would overflow, else adds it.
func incrementOverflowTime(tp *int64, j int64) bool {
	if j < 0 {
		if !(timeTMin-j <= *tp) {
			return true
		}
	} else if !(*tp <= timeTMax-j) {
		return true
	}
	*tp += j
	return false
}

// tzparse is tzparse: a POSIX TZ string into sp.
func tzparse(name string, sp *state, lastditch bool) bool {
	var stdname, dstname string
	var stdlen, dstlen int
	var stdoffset, dstoffset int32
	i := 0
	if lastditch {
		stdname = name
		stdlen = len(cstr([]byte(name)))
		i = stdlen
		stdoffset = 0
	} else {
		if ch(name, i) == '<' {
			i++
			start := i
			i = getqzname(name, i, '>')
			if ch(name, i) != '>' {
				return false
			}
			stdname, stdlen = name[start:i], i-start
			i++
		} else {
			start := i
			i = getzname(name, i)
			stdname, stdlen = name[start:i], i-start
		}
		if ch(name, i) == 0 {
			return false
		}
		if i = getoffset(name, i, &stdoffset); i < 0 {
			return false
		}
	}
	charcnt := stdlen + 1
	if charsSize < charcnt {
		return false
	}
	sp.goback, sp.goahead = false, false
	sp.leapcnt = 0

	if ch(name, i) != 0 {
		if ch(name, i) == '<' {
			i++
			start := i
			i = getqzname(name, i, '>')
			if ch(name, i) != '>' {
				return false
			}
			dstname, dstlen = name[start:i], i-start
			i++
		} else {
			start := i
			i = getzname(name, i)
			dstname, dstlen = name[start:i], i-start
		}
		if dstlen == 0 {
			return false
		}
		charcnt += dstlen + 1
		if charsSize < charcnt {
			return false
		}
		if c := ch(name, i); c != 0 && c != ',' && c != ';' {
			if i = getoffset(name, i, &dstoffset); i < 0 {
				return false
			}
		} else {
			dstoffset = stdoffset - secsPerHour
		}
		rules, j := name, i
		if ch(name, i) == 0 {
			rules, j = tzDefRuleString, 0
		}
		if c := ch(rules, j); c != ',' && c != ';' {
			// The rest names no rules (PostgreSQL never loads posixrules).
			return false
		}
		var start, end rule
		j++
		if j = getrule(rules, j, &start); j < 0 {
			return false
		}
		if ch(rules, j) != ',' {
			return false
		}
		j++
		if j = getrule(rules, j, &end); j < 0 {
			return false
		}
		if ch(rules, j) != 0 {
			return false
		}
		sp.typecnt = 2
		sp.ttis[0] = ttinfo{utoff: -stdoffset}
		sp.ttis[1] = ttinfo{utoff: -dstoffset, isdst: true, desigidx: stdlen + 1}
		timecnt := 0
		var janfirst int64
		var janoffset int64
		yearbeg := epochYear
		for {
			yearsecs := int64(yearLengths[isleapI(yearbeg-1)] * secsPerDay)
			yearbeg--
			if incrementOverflowTime(&janfirst, -yearsecs) {
				janoffset = -yearsecs
				break
			}
			if !(epochYear-yearsPerRepeat/2 < yearbeg) {
				break
			}
		}
		yearlim := yearbeg + yearsPerRepeat + 1
		year := yearbeg
		for ; year < yearlim; year++ {
			starttime := transtime(year, &start, stdoffset)
			endtime := transtime(year, &end, dstoffset)
			yearsecs := int32(yearLengths[isleapI(year)] * secsPerDay)
			reversed := endtime < starttime
			if reversed {
				starttime, endtime = endtime, starttime
			}
			if reversed || (starttime < endtime && endtime-starttime < yearsecs+(stdoffset-dstoffset)) {
				if tzMaxTimes-2 < timecnt {
					break
				}
				sp.ats[timecnt] = janfirst
				if !incrementOverflowTime(&sp.ats[timecnt], janoffset+int64(starttime)) {
					if reversed {
						sp.types[timecnt] = 0
					} else {
						sp.types[timecnt] = 1
					}
					timecnt++
				}
				sp.ats[timecnt] = janfirst
				if !incrementOverflowTime(&sp.ats[timecnt], janoffset+int64(endtime)) {
					if reversed {
						sp.types[timecnt] = 1
					} else {
						sp.types[timecnt] = 0
					}
					timecnt++
					yearlim = year + yearsPerRepeat + 1
				}
			}
			if incrementOverflowTime(&janfirst, janoffset+int64(yearsecs)) {
				break
			}
			janoffset = 0
		}
		sp.timecnt = timecnt
		if timecnt == 0 {
			sp.ttis[0] = sp.ttis[1]
			sp.typecnt = 1
		} else if yearsPerRepeat < year-yearbeg {
			sp.goback, sp.goahead = true, true
		}
	} else {
		dstlen = 0
		sp.typecnt = 1
		sp.timecnt = 0
		sp.ttis[0] = ttinfo{utoff: -stdoffset}
	}
	sp.charcnt = charcnt
	copy(sp.chars[:], stdname[:stdlen])
	sp.chars[stdlen] = 0
	if dstlen != 0 {
		copy(sp.chars[stdlen+1:], dstname[:dstlen])
		sp.chars[stdlen+1+dstlen] = 0
	}
	return true
}

// nextDSTBoundary is pg_next_dst_boundary: 1 with the state before and
// after the next transition after t, 0 with the state at t when none
// follows, -1 on failure.
func nextDSTBoundary(t int64, sp *state) (res int, beforeOff int64, beforeDST bool, boundary int64, afterOff int64, afterDST bool) {
	lowestStandard := func() ttinfo {
		i := 0
		for sp.ttis[i].isdst {
			i++
			if i >= sp.typecnt {
				i = 0
				break
			}
		}
		return sp.ttis[i]
	}
	if sp.timecnt == 0 {
		tt := lowestStandard()
		return 0, int64(tt.utoff), tt.isdst, 0, 0, false
	}
	first, last := sp.ats[0], sp.ats[sp.timecnt-1]
	if (sp.goback && t < first) || (sp.goahead && t > last) {
		newt := t
		var seconds int64
		if t < first {
			seconds = first - t
		} else {
			seconds = t - last
		}
		seconds--
		tcycles := seconds / yearsPerRepeat / avgSecsPerYear
		tcycles++
		seconds = tcycles * yearsPerRepeat * avgSecsPerYear
		if t < first {
			newt += seconds
		} else {
			newt -= seconds
		}
		if newt < first || newt > last {
			return -1, 0, false, 0, 0, false
		}
		res, bo, bd, b, ao, ad := nextDSTBoundary(newt, sp)
		if t < first {
			b -= seconds
		} else {
			b += seconds
		}
		return res, bo, bd, b, ao, ad
	}
	if t >= last {
		tt := sp.ttis[sp.types[sp.timecnt-1]]
		return 0, int64(tt.utoff), tt.isdst, 0, 0, false
	}
	if t < first {
		tt := lowestStandard()
		after := sp.ttis[sp.types[0]]
		return 1, int64(tt.utoff), tt.isdst, first, int64(after.utoff), after.isdst
	}
	lo, hi := 1, sp.timecnt-1
	for lo < hi {
		mid := (lo + hi) >> 1
		if t < sp.ats[mid] {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	before, after := sp.ttis[sp.types[lo-1]], sp.ttis[sp.types[lo]]
	return 1, int64(before.utoff), before.isdst, sp.ats[lo], int64(after.utoff), after.isdst
}

// interpretAbbrev is pg_interpret_timezone_abbrev: the offset an
// (uppercase) abbreviation had in the zone at or most recently before t,
// else first after it; false when the zone never used it.
func interpretAbbrev(abbrev string, t int64, sp *state) (int64, bool) {
	abbrind := 0
	for abbrind < sp.charcnt {
		if cstr(sp.chars[abbrind:]) == abbrev {
			break
		}
		for sp.chars[abbrind] != 0 {
			abbrind++
		}
		abbrind++
	}
	if abbrind >= sp.charcnt {
		return 0, false
	}
	lo, hi := 0, sp.timecnt
	for lo < hi {
		mid := (lo + hi) >> 1
		if t < sp.ats[mid] {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	for i := lo - 1; i >= 0; i-- {
		if tt := sp.ttis[sp.types[i]]; tt.desigidx == abbrind {
			return int64(tt.utoff), true
		}
	}
	for i := lo; i < sp.timecnt; i++ {
		if tt := sp.ttis[sp.types[i]]; tt.desigidx == abbrind {
			return int64(tt.utoff), true
		}
	}
	return 0, false
}
