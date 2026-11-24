// SPDX-License-Identifier: AGPL-3.0-or-later

package values

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/varlatch/varlatch/go/lib/contract"
	"github.com/varlatch/varlatch/go/lib/envelope"
	"github.com/varlatch/varlatch/go/lib/storage"
	"github.com/varlatch/varlatch/go/lib/totp"
	"github.com/varlatch/varlatch/go/server/audit"
	"github.com/varlatch/varlatch/go/server/db/query"
	"github.com/varlatch/varlatch/go/server/domainerr"
	"github.com/varlatch/varlatch/go/server/jsvalue"
)

// Seeds of one-time codes (ADR-0061): a Secret whose use gives a code, not
// its value.
//
// A seed is a value version like any other, in columns an older server also
// has, and three things make it one:
//
//   - what is sealed as its value is another envelope (envelope.EncryptSeed),
//     sealed for a seed's purpose: opened as a value, whoever does it, it is
//     no seed. The outer one is a value's so that the TypeScript export, which
//     opens every stored version and refuses as a whole when one does not
//     open, keeps working after a reverse migration;
//   - the payload, beside the outer envelope's members, has a member totp:
//     what people may read (whose code it is, and how codes are made). The
//     seed opens only with these, as they were sealed;
//   - its row in env_values has a deleted_at and a current version, which
//     nothing else leaves. An older varlatchd, and the TypeScript server
//     after a reverse migration, read such a row as deleted: there the item
//     has no value, in every path. And so does every query here that does
//     not ask for seeds.
//
// A retrieval keeps seeds apart (State.Codes): the paths that deliver values
// never see one. decrypt and OpenForSync refuse a version that says it is a
// seed, whatever row led to it. Only an exercise (its code) and a disclosure
// that asks for seeds (the seed) open one.

// errSeed is a seed where a value was to be opened: never reached, and
// nothing is delivered if it is.
var errSeed = errors.New("values: a seed of one-time codes is not opened as a value")

// seedParams is the payload's member totp; ok is false for a value. The
// text is looked at first: an envelope's base64 holds no quote, so only a
// seed's payload is parsed twice. A member totp of another shape is a seed
// too, whose parameters are none's.
func seedParams(payload string) (p totp.Params, ok bool) {
	if !strings.Contains(payload, `"totp"`) {
		return totp.Params{}, false
	}
	var v struct {
		TOTP *totp.Params `json:"totp"`
	}
	if err := json.Unmarshal([]byte(payload), &v); err != nil {
		return totp.Params{}, true
	}
	if v.TOTP == nil {
		return totp.Params{}, false
	}
	return *v.TOTP, true
}

// seedItem is a seed as a retrieval resolves it; ok is false for one whose
// parameters this server does not know (a later release's, after a
// rollback): its name then has no value here, as on a server without seeds.
func seedItem(r query.SeedsOfEnvironmentRow, source string, now int64) (_ Item, ok bool) {
	var p totp.Params
	if json.Unmarshal([]byte(r.Params), &p) != nil || p.Check() != nil {
		return Item{}, false
	}
	it := Item{Name: r.ItemName, Sensitive: true, Source: source, ValueRowID: r.ID, VersionID: r.CurrentVersionID.String, Code: &p}
	if r.RetiringVersionID.Valid && r.RotationDeadline.Valid && r.RotationDeadline.Int64 > now {
		it.RetiringVersionID = r.RetiringVersionID.String
	}
	return it, true
}

// ParamsJS is a seed's readable part, as answers carry it.
func ParamsJS(p totp.Params) jsvalue.Object {
	return jsvalue.Object{{Key: "issuer", Value: p.Issuer}, {Key: "account", Value: p.Account}, {Key: "algorithm", Value: p.Algorithm},
		{Key: "digits", Value: p.Digits}, {Key: "periodSeconds", Value: p.Period}}
}

// withCode adds a seed's readable part to an item of a listing.
func withCode(o jsvalue.Object, it Item) jsvalue.Object {
	if it.Code != nil {
		o = append(o, jsvalue.Member{Key: "totp", Value: ParamsJS(*it.Code)})
	}
	return o
}

// ParseSeed reads an otpauth:// URI; its error (VALIDATION_FAILED) never
// holds any of it.
func ParseSeed(uri string) (totp.Seed, error) {
	s, err := totp.Parse(uri)
	if err != nil {
		return totp.Seed{}, domainerr.New("VALIDATION_FAILED", "otpauth: "+err.Error())
	}
	return s, nil
}

// insertSeed writes a new version of a value row, the seed sealed, its
// payload saying it is one.
func insertSeed(ctx context.Context, q *query.Queries, orgKEK []byte, organizationID, valueID, versionID string, seed totp.Seed, previous sql.NullString, actor string, at int64) error {
	params, err := json.Marshal(seed.Params)
	if err != nil {
		return err
	}
	plain := []byte(seed.URI())
	defer clear(plain)
	sealed, err := envelope.EncryptSeed(orgKEK, organizationID, valueID, versionID, string(params), plain)
	if err != nil {
		return err
	}
	// The envelope's own encoding has no such member: both are one object.
	env, err := json.Marshal(sealed.Payload)
	if err != nil {
		return err
	}
	payload := string(env[:len(env)-1]) + `,"totp":` + string(params) + "}"
	dek, err := json.Marshal(sealed.WrappedDEK)
	if err != nil {
		return err
	}
	return q.InsertValueVersion(ctx, query.InsertValueVersionParams{
		ID: versionID, ValueID: valueID, Payload: sql.NullString{String: payload, Valid: true},
		WrappedDek: sql.NullString{String: string(dek), Valid: true}, PreviousVersionID: previous,
		CreatedBy: sql.NullString{String: actor, Valid: true}, CreatedAt: at,
	})
}

// openSeeds opens exactly these versions, seeds captured by a retrieval
// whose audit event was committed. The readable part is part of what a seed
// is sealed with, in the order its members are written here (jsonb, which a
// migration goes through, keeps no order): a changed one opens nothing.
func (s *Service) openSeeds(st *State, versionIDs []string) (map[string]totp.Seed, error) {
	kek, err := s.orgKEK(st)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	out := make(map[string]totp.Seed, len(versionIDs))
	for _, v := range versionIDs {
		c, ok := st.ciphertext[v]
		if !ok || !c.seed {
			return nil, domainerr.New("INTERNAL", "A seed was not captured in the retrieval snapshot")
		}
		params, err := json.Marshal(c.params)
		if err != nil {
			return nil, err
		}
		plain, err := envelope.DecryptSeed(kek, st.Org.ID, c.valueRowID, v, string(params), envelope.EncryptedValue{Payload: c.payload, WrappedDEK: c.wrappedDEK})
		if err != nil {
			return nil, err
		}
		seed, err := totp.Parse(string(plain))
		clear(plain)
		if err != nil || seed.Params != c.params {
			return nil, errors.New("values: the seed " + v + " is not what its row says it is")
		}
		out[v] = seed
	}
	return out, nil
}

// codeWanted is a seed's version an exercise gives a code of, with its
// parameters.
type codeWanted struct {
	item      Item
	versionID string
	params    totp.Params
}

// codesWanted are the versions behind the selected seeds: each one's, and
// the one a rotation retires.
func codesWanted(st *State, selected []Item) ([]codeWanted, error) {
	var out []codeWanted
	for _, it := range selected {
		for _, v := range []string{it.VersionID, it.RetiringVersionID} {
			if v == "" {
				continue
			}
			c := st.ciphertext[v]
			if !c.seed || c.params.Check() != nil {
				return nil, errors.New("values: the version " + v + " is no seed of one-time codes")
			}
			out = append(out, codeWanted{it, v, c.params})
		}
	}
	return out, nil
}

// notFresh is an exercise that asks for a code not given before while the
// next step's, or a later one's, was.
type notFresh struct {
	item  string
	after time.Duration
}

func (*notFresh) Error() string { return "values: no fresh one-time code yet" }

// codeProblem is the Contract's verdict on an item whose value here is a
// seed: a code is text of digits, so it fits a string and nothing narrower.
// No seed is opened for it.
func codeProblem(it contract.Item) string {
	if it.Type == "string" {
		return ""
	}
	return "holds the seed of a one-time code, which fits the type string only"
}

// MaxMinValiditySeconds bounds minValiditySeconds: a day.
const MaxMinValiditySeconds = 86_400

// giveCodes decides, in the exercise's own job at its time, which step's
// code each version gives, and records it. The step is the current one, or
// the next one:
//
//   - when the current one ends in less than minValidity;
//   - when fresh, and the current one's code or a later one was given
//     before: the newest given is all that is kept.
//
// The next one's code is given with its start, so nobody waits here: whoever
// asked does. When fresh and the next one's was given too (or a later one's), *notFresh: only
// these two are ever given, since a code is a secret for as long as it can
// still be used. The newest step given is kept as long as its seed's
// version (one row each): the clock may move back, however far, and a step
// recorded that this clock has not reached yet counts as given. Without
// record it only tells whether there is a code to give now.
func giveCodes(ctx context.Context, tx *storage.Tx, wanted []codeWanted, minValidity time.Duration, fresh bool, now time.Time, record bool) (map[string]int64, jsvalue.Object, error) {
	q := query.New(tx)
	steps := make(map[string]int64, len(wanted))
	given := make([]string, 0, len(wanted))
	for _, w := range wanted {
		current := w.params.Step(now)
		step := current
		if _, end := w.params.Window(step); end.Sub(now) < minValidity {
			step++
		}
		if fresh {
			before, err := q.OneTimeCodeGiven(ctx, w.versionID)
			if err != nil {
				return nil, nil, err
			}
			if len(before) > 0 && before[0] >= step {
				step = before[0] + 1
			}
			if step > current+1 {
				// The earliest moment step is the one after the current one.
				start, _ := w.params.Window(step - 1)
				return nil, nil, &notFresh{item: w.item.Name, after: start.Sub(now)}
			}
		}
		start, _ := w.params.Window(step)
		if record {
			if err := q.GiveOneTimeCode(ctx, query.GiveOneTimeCodeParams{VersionID: w.versionID, Step: step}); err != nil {
				return nil, nil, err
			}
		}
		steps[w.versionID] = step
		given = append(given, w.item.Name+"@"+w.versionID+"="+audit.ISOTime(start.UnixMicro()))
	}
	md := jsvalue.Object{{Key: "oneTimeCodes", Value: strings.Join(given, ",")}}
	if minValidity > 0 {
		md = append(md, jsvalue.Member{Key: "minValiditySeconds", Value: int64(minValidity / time.Second)})
	}
	if fresh {
		md = append(md, jsvalue.Member{Key: "fresh", Value: true})
	}
	return steps, md, nil
}

// codeJS is a code as an exercise answers it: the code, when its step
// starts (only while it has not) and ends, and the same as seconds from this
// answer, for a machine whose clock is not the server's.
func codeJS(seed totp.Seed, step int64, now time.Time) jsvalue.Object {
	start, end := seed.Window(step)
	o := jsvalue.Object{{Key: "value", Value: seed.Code(step)}}
	if wait := start.Sub(now); wait > 0 {
		o = append(o, jsvalue.Member{Key: "notBefore", Value: audit.ISOTime(start.UnixMicro())},
			jsvalue.Member{Key: "startsInSeconds", Value: int64((wait + time.Second - 1) / time.Second)})
	}
	return append(o, jsvalue.Member{Key: "expiresAt", Value: audit.ISOTime(end.UnixMicro())},
		jsvalue.Member{Key: "expiresInSeconds", Value: max(0, int64(end.Sub(now)/time.Second))})
}

// tooLong names the first wanted seed whose codes never last as long as
// asked, "" when every one's do.
func tooLong(wanted []codeWanted, minValiditySeconds int64) string {
	for _, w := range wanted {
		if minValiditySeconds > w.params.Period {
			return w.item.Name
		}
	}
	return ""
}

func seconds(n int64) string {
	if n == 1 {
		return "1 second"
	}
	return strconv.FormatInt(n, 10) + " seconds"
}
