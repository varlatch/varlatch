#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The corpus of timestamptz-vectors.json: inputs for PostgreSQL's
timestamptz input in every family it reads (date only; ISO with and
without T, fractions and offsets; epoch, infinity, now, today, tomorrow,
yesterday, allballs; every Default abbreviation; zone names; POSIX zone
strings; textual months; Julian days; run-together forms; text it refuses)
and seeded fuzz from their pieces.

To rewrite the vectors, with src/timezone/tznames/Default of the
PostgreSQL release and a postgres:17 container (TimeZone UTC) named PG:

  python3 gen-vectors.py Default > corpus.json
  docker cp corpus.json PG:/tmp/corpus.json; docker cp probe.sql PG:/tmp/probe.sql
  docker exec PG psql -U postgres -q -f /tmp/probe.sql > timestamptz-vectors.json

and copy the server's /usr/share/zoneinfo files for the zones the corpus
names into zoneinfo/ (README there).
"""
import json, random, re, sys
random.seed(43)
out = []
def add(*xs): out.extend(xs)
# ISO forms
dates = ["2026-01-02","2024-02-29","2023-02-29","2026-13-01","2026-00-10","2026-12-31","1999-12-31","2000-01-01","0001-01-01","9999-12-31","294276-12-31","294277-01-01","10000-01-01","1970-01-01","1-01-01","99-01-02","69-01-02","70-01-02","00-01-01","2026-1-2","2026-01-32","2026-04-31","2026/01/02","01/02/2026","1/2/26","2026.01.02","20260102","260102","2026.002","2026.366","2024.366","1999.008"]
times = ["","00:00:00","04:05:06","04:05:06.789","04:05:06.7891234","04:05:06.9999995","04:05:06.0000005","04:05:06.0000015","24:00:00","24:00:01","23:59:60","23:59:60.5","23:60:00","25:00:00","04:05","04:05.5","4:5:6","04:05:06.","040506","0405","040506.789","04:05:06.5e3","12:00 am","12:00 pm","01:00 pm","13:00 pm","12:30:00 AM","11:59:59.999999 PM","allballs"]
zones = ["","Z","z","+00","-00","+02","-08","+0530","-0330","+05:30","-03:30:15","+5","+15","+16","-15:59","+14:60","+1:2:3","+023","+12345","UTC","utc","GMT","EST","PST","PDT","CET","CEST","MSK","IST","JST","AEST","NZDT","EST DST","PST dst","dst","MET DST","America/New_York","america/new_york","AMERICA/NEW_YORK","Europe/Brussels","Europe/Moscow","Asia/Kolkata","Asia/Calcutta","US/Eastern","Etc/GMT+5","Etc/GMT-14","Australia/Lord_Howe","Africa/Casablanca","Europe/Dublin","Pacific/Apia","Pacific/Kiritimati","Asia/Tehran","Factory","posixrules","localtime","Europe","Europe/","Europe//Paris","../etc/passwd","EST5EDT","CST6CDT","XYZ5","xyz+3","abc-5:30","ABC5XYZ","abc5xyz4","ABC5XYZ,M3.2.0,M11.1.0","GMT+5","utc-3","Japan","NoSuch/Zone","Mars/Olympus"]
for d in dates:
    add(d)
for d in random.sample(dates, 12):
    for t in times:
        add((d+" "+t).strip(), (d+"T"+t).strip() if t else d)
for z in zones:
    for d in ["2026-01-02 04:05:06","2026-07-02 04:05:06","2026-03-08 02:30:00","2026-11-01 01:30:00","2026-03-29 02:30:00","2026-10-25 02:30:00","1850-06-01 12:00:00","2100-06-01 12:00:00","3000-06-01 12:00:00","1890-01-01 00:00:00"]:
        add((d+" "+z).strip())
    add(("2026-01-02T04:05:06"+z) if z[:1] in "+-Zz" else "2026-01-02T04:05:06 "+z)
# abbreviations, every one in Default
abbrevs = re.findall(r'^([A-Z][A-Z0-9]*)\s', open(sys.argv[1]).read(), re.M)
for a in abbrevs:
    add("2026-01-02 04:05:06 "+a, "1980-07-01 12:00 "+a.lower(), "1890-07-01 12:00 "+a)
# specials
for s in ["epoch","EPOCH","infinity","+infinity","-infinity","Infinity","inf","-inf","now","NOW","today","tomorrow","yesterday","today 12:00","tomorrow 23:59:59.5","yesterday allballs","today +02","now +02","now pm","now bc","epoch bc","epoch pm","infinity monday","-infinity at","today today","epoch 5","2026-01-02 now","now 2026-01-02","today EST","today America/New_York","zulu","current","invalid","allballs","2026-01-02 allballs","2026-01-02 zulu"]:
    add(s, " "+s+" ")
# textual months and other formats
for s in ["January 8, 1999","Jan 8 1999","8 Jan 1999","8-Jan-1999","Jan-08-1999","1999-Jan-08","08-Jan-99","Jan-08-99","99-Jan-08","January 8 99 BC","Jan 8 2000 BC","Jan 8 0 BC","Sept 3 2026","sept 3 2026","Sep 31 2026","Feb 29 2023","feb 29 2024","Fri Feb 7 1997 15:23:27","Fri Feb 7 15:23:27 1997 PST","Feb 7 152327 1997","Feb 7 152327-08 1997","Mon Jan 01 2026","1997 Feb 7","on Jan 8 1999 at 04:05","J2451187","J 2451187","j2451187.5","julian 2451187","J2451187-07","J2451187 04:05","jd 0","J-1","J2147483647","20011225T040506.789-07","20011225 T 040506","20011225T040506","2001-12-25T04","2001-12-25 T 04:05:06","2001-12-25 T04:05:06","T04:05:06","y2001m12d25","2001-12-25 h04","2001-12-25 4 pm","2001-12-25 16:00 pm","2001-12-25 ad","2001-12-25 bc","0000-01-01","-2001-01-01","2001-12-25 04:05:06 +02 +03","2001-12-25 990000","2001-12-25 993000","2001-12-25 1260","2001-12-25 04::05","2001-12-25 04:","2001-12-25 :04","12.5","2001-12-25 12.5","2001-12-25 .5","2001-12-25 04:05:06 .5","5874897-12-31","5874898-01-01","4713-11-24 BC","4714-11-23 BC","4714-11-24 BC","4714-11-24 00:00:00+00 BC","294276-12-31 23:59:59.999999","294276-12-31 23:59:59.999999+00","294276-12-31 23:59:59.999999-01","294277-01-01 00:00:00+01","2026-01-02 04:05:06 +99","2026-01-02 04:05:06 -15:59:59","2026-01-02 04:05:06+0","2026-01-02 04:05:06.123456789","2026-01-02 04:05:06,123","2026-01-02_04:05:06","2026-01-02 04.05.06","2026-01-02 4h","2026-01-02 tuesday","tuesday 2026-01-02","2026-01-02 monday","2026-01-02 xyz","2026-01-02 garbage","not a time","","   ","-","+","1","12","123","1234","12345","123456","1234567","12345678","123456789","99999999999999999999","2026-01-02 04:05:06 99999999999","2026-99999999999-01","2026-01-02 99999999999:00","2026-01-02 04:99999999999:00","é2026-01-02","2026-01-02 ünicode","2026-01-02\t04:05:06","2026-01-02\n04:05:06","2026-01-02\x0b04:05:06","2026-01-02\x0104:05","2026-01-02 04:05:06 ∞","2026-01-02 (04:05:06)","[2026-01-02]","2026-01-02!!!","2026--01--02","2026-01-02-","2026-01-02 - 04:05","2026-01-02 + 04:05","2026-01-02 +04:05","2026-01-02 + 04","2026-01-02 - foo","2026-01-02 -foo","2026-01-02 +infinity","2026-01-02 infinity",'x'*130,"2026-01-02 "+"a"*120,"2026-01-02 "+"1 "*30,"1 1 1"]:
    add(s)
# 2-digit and order heuristics
for s in ["1/2/3","01/02/03","1-2-3","2026-1-2-3","1.2.3","12/25/2026","25/12/2026","2026/25/12","26/1/2","1999-12-31 23:59:59.9999995","1999-12-31 24:00:00","2000-01-01 00:00:00.0000005"]:
    add(s)
# fuzz from token pieces
pieces = ["2026","01","1","12","31","-","/",".",":"," ","T","t","Z","+","-05","+05:30","jan","feb","dec","pm","am","bc","ad","epoch","now","today","est","pst","msk","utc","j","y","m","d","h","mm","s","dow","doy","dst","at","on","x","abc","5","2026-01-02","04:05:06",".5","99","24","60","allballs","infinity","America/New_York","europe/brussels","EST5EDT","xyz5"]
for _ in range(2500):
    n = random.randint(1,7)
    add("".join(random.choice(pieces) for _ in range(n)))
# random ISO with fractions/offsets
for _ in range(400):
    y = random.choice([random.randint(1,9999), random.randint(1960,2100)])
    s = "%04d-%02d-%02d%s%02d:%02d:%02d" % (y, random.randint(1,12), random.randint(1,28), random.choice([" ","T","t"]), random.randint(0,23), random.randint(0,59), random.randint(0,59))
    if random.random()<0.6: s += "." + "".join(random.choice("0123456789") for _ in range(random.randint(1,9)))
    s += random.choice(["","Z","+00","+00:00","-07","+05:45","+0530"," UTC"," EST"," CEST"," America/New_York"," Asia/Kolkata"])
    add(s)
seen=set(); res=[]
for s in out:
    if s not in seen and "\x00" not in s:
        seen.add(s); res.append(s)
json.dump(res, sys.stdout, ensure_ascii=False)
