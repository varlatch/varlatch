#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Gate G11 on the Go server's live updates (ADR-0059 Decision 4): its
 * server-sent events at GET /auth/events, read the way the dashboard reads
 * them, as raw streams.
 *
 *   - no signal crosses organizations: a stream carries the changeSignals
 *     of its person's organizations and that person's identitySignal, and
 *     nothing else, whatever the request asks;
 *   - revocation and removal close streams: signing out, revoking the
 *     session's credential, and removal from an organization each end the
 *     stream, with the reason, and leave other streams open;
 *   - a slow client is cut off alone: a client that stops reading is
 *     disconnected while another receives every signal.
 *
 * The fourth G11 check, that the reconnect refresh covers a missed signal,
 * is the dashboard's (apps/web/scripts/e2e-realtime-degraded.mjs).
 *
 * go-server checks: they need the target's go-server capability, whose
 * fixtures write the organizations, people, sessions and audit events the
 * streams need while the /v1 writes that make them are not built yet
 * (ADR-0059 step 4). The fixtures commit from another process, which
 * varlatchd publishes within its poll interval (one second).
 *
 *   realtime-events.mjs <origin>      (run by scripts/conformance/run.mjs)
 */
import { connect } from "node:net";
import { randomBytes } from "node:crypto";
import { reporter, targetOp } from "../suite-kit.mjs";

const [origin] = process.argv.slice(2);
if (!origin) {
  console.error("Usage: realtime-events.mjs <origin>");
  process.exit(64);
}
const { check, error, finish } = reporter();
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const fixture = (...args) => JSON.parse(targetOp("go-server", ["fixture", ...args]));
const SIGNAL_KEYS = { change: ["organizationId", "lastEventId", "occurredAt", "domains"], identity: ["lastEventId", "occurredAt", "domains"] };

/** The cookie names the server uses (the __Host- prefix with an https public URL). */
async function cookieNames() {
  const r = await fetch(`${origin}/auth/session`);
  await r.arrayBuffer();
  const set = r.headers.getSetCookie().find((c) => /varlatch_csrf=/.test(c)) ?? "";
  const csrf = set.split("=")[0] || "varlatch_csrf";
  return { csrf, session: csrf.replace("varlatch_csrf", "varlatch_session") };
}

/** A browser session: its token as a cookie, a CSRF token, and its POSTs. */
async function browser(names, token) {
  const csrf = randomBytes(32).toString("base64url");
  const cookie = `${names.session}=${token}; ${names.csrf}=${csrf}`;
  return {
    cookie,
    post: (path) =>
      fetch(`${origin}${path}`, { method: "POST", headers: { Cookie: cookie, Origin: origin, "Varlatch-CSRF": csrf } }).then(async (r) => ({
        status: r.status,
        body: await r.text(),
      })),
  };
}

/** One stream, read as EventSource would: its events, and whether it ended. */
function stream(cookie, query = "") {
  const s = { events: [], status: 0, ended: false, waiters: [] };
  const wake = () => {
    for (const w of [...s.waiters]) w();
  };
  const abort = new AbortController();
  s.abort = () => abort.abort();
  s.done = (async () => {
    try {
      const r = await fetch(`${origin}/auth/events${query}`, { headers: { Cookie: cookie, Accept: "text/event-stream" }, signal: abort.signal });
      s.status = r.status;
      if (r.status !== 200) {
        s.body = await r.text();
        return;
      }
      const decoder = new TextDecoder();
      let buffer = "";
      for await (const chunk of r.body) {
        buffer += decoder.decode(chunk, { stream: true });
        let at;
        while ((at = buffer.indexOf("\n\n")) >= 0) {
          const block = buffer.slice(0, at);
          buffer = buffer.slice(at + 2);
          let name = "message";
          const data = [];
          for (const line of block.split("\n")) {
            if (line.startsWith("event: ")) name = line.slice(7);
            else if (line.startsWith("data: ")) data.push(line.slice(6));
            else if (line.startsWith("id:")) s.ids = true;
          }
          if (data.length > 0) s.events.push({ name, data: JSON.parse(data.join("\n")) });
          wake();
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") s.error = String(err);
    } finally {
      s.ended = true;
      wake();
    }
  })();
  /** Waits until pred holds of the events so far (or the stream ends). */
  s.until = (pred, ms = 10_000) =>
    new Promise((resolve) => {
      const test = () => {
        if (pred(s.events) || s.ended) {
          clearTimeout(timer);
          s.waiters = s.waiters.filter((w) => w !== test);
          resolve(pred(s.events));
        }
      };
      const timer = setTimeout(() => {
        s.waiters = s.waiters.filter((w) => w !== test);
        resolve(pred(s.events));
      }, ms);
      s.waiters.push(test);
      test();
    });
  s.endedWithin = async (ms) => {
    await Promise.race([s.done, sleep(ms)]);
    return s.ended;
  };
  return s;
}

const changesOf = (events, org) => events.filter((e) => e.name === "change" && (org === undefined || e.data.organizationId === org));
const identities = (events) => events.filter((e) => e.name === "identity");
const closeOf = (events) => events.find((e) => e.name === "close")?.data.reason ?? null;
const keysOk = (events) =>
  events.every((e) => !(e.name in SIGNAL_KEYS) || JSON.stringify(Object.keys(e.data)) === JSON.stringify(SIGNAL_KEYS[e.name]));

const open = [];
try {
  const names = await cookieNames();
  const world = fixture("world", `g11-${randomBytes(3).toString("hex")}`);
  const { a, b } = world.organizations;
  const { alice, bob, carol } = world.identities;
  const session = (identity) => fixture("session", identity);
  const opened = async (cookie, query) => {
    const s = stream(cookie, query);
    open.push(s);
    if (!(await s.until((ev) => ev.some((e) => e.name === "ready")))) throw new Error(`a stream did not open (${s.status} ${s.body ?? s.error ?? ""})`);
    return s;
  };

  // ---- No signal crosses organizations.
  {
    const A = await opened((await browser(names, session(alice).token)).cookie);
    // Asking for another organization, or another identity, changes nothing.
    const A2 = await opened((await browser(names, session(alice).token)).cookie, `?organizationId=${b}&identityId=${bob}`);
    const B = await opened((await browser(names, session(bob).token)).cookie);
    const C = await opened((await browser(names, session(carol).token)).cookie);
    fixture("events", b, bob, "3");
    fixture("events", "-", bob, "2");
    const bReached = await B.until((ev) => changesOf(ev, b).length > 0 && identities(ev).length > 0);
    fixture("events", a, alice, "1");
    const aReached = await A.until((ev) => changesOf(ev, a).length > 0);
    await A2.until((ev) => changesOf(ev, a).length > 0);
    await C.until((ev) => changesOf(ev, a).length > 0 && changesOf(ev, b).length > 0);
    // Publication is in commit order: once org a's signal arrived, every
    // earlier one was sent too.
    const leaks = [
      ...[A, A2].flatMap((s) => [...changesOf(s.events).filter((e) => e.data.organizationId !== a), ...identities(s.events)]),
      ...changesOf(B.events).filter((e) => e.data.organizationId !== b),
      ...identities(C.events),
    ];
    const carolBoth = changesOf(C.events, a).length > 0 && changesOf(C.events, b).length > 0;
    const shapes = [A, A2, B, C].every((s) => keysOk(s.events) && !s.ids);
    check(
      "realtime-events.no-signal-crosses-organizations",
      "no signal crosses organizations: a stream carries only its person's organizations' changeSignals and its own identitySignal, metadata only",
      bReached && aReached && carolBoth && leaks.length === 0 && shapes,
      `bob's signals ${bReached}, alice's ${aReached}, carol both ${carolBoth}, shapes ${shapes}, leaked ${JSON.stringify(leaks.slice(0, 3))}`,
    );
    for (const s of [A, A2, B, C]) s.abort();
  }

  // ---- Revocation and removal close streams.
  {
    const out = [];
    // Signing out.
    const signedOut = await browser(names, session(alice).token);
    const S1 = await opened(signedOut.cookie);
    const kept = await opened((await browser(names, session(alice).token)).cookie);
    const signOut = await signedOut.post("/auth/sign-out");
    const s1Ended = await S1.endedWithin(10_000);
    out.push(`sign-out ${signOut.status}: ended ${s1Ended}, reason ${closeOf(S1.events)}`);
    const afterSignOut = stream(signedOut.cookie);
    if (!(await afterSignOut.endedWithin(10_000))) afterSignOut.abort();
    out.push(`a new stream after sign-out: ${afterSignOut.status}`);

    // Revoking the session's credential: its dashboard bearer.
    const revokedSession = await browser(names, session(alice).token);
    const S2 = await opened(revokedSession.cookie);
    const minted = await revokedSession.post("/auth/varlatch-token");
    const bearer = minted.status === 200 ? JSON.parse(minted.body).token : null;
    const me = bearer ? await fetch(`${origin}/v1/me`, { headers: { Authorization: `Bearer ${bearer}` } }).then((r) => r.json()) : null;
    const credentialId = me?.credential?.id;
    const revoke = credentialId
      ? await fetch(`${origin}/v1/me/credentials/${credentialId}`, { method: "DELETE", headers: { Authorization: `Bearer ${bearer}` } }).then((r) => r.status)
      : 0;
    const s2Ended = await S2.endedWithin(10_000);
    out.push(`revocation ${revoke}: ended ${s2Ended}, reason ${closeOf(S2.events)}`);
    // From 0.50.2 revoking a browser's credential ends its session too, so
    // that browser cannot open a stream again (401). G6 runs these suites
    // against the previous release as well, which keeps the stream open, so
    // this is reported, not checked; the Go server's tests check it.
    const afterRevoke = stream(revokedSession.cookie);
    if (!(await afterRevoke.endedWithin(5_000))) afterRevoke.abort();
    out.push(`a new stream after revocation: ${afterRevoke.status}`);

    // Removal from organization b: carol's stream says so, then closes; bob's stays.
    const carolStream = await opened((await browser(names, session(carol).token)).cookie);
    const bobStream = await opened((await browser(names, session(bob).token)).cookie);
    fixture("remove-member", b, carol);
    const carolEnded = await carolStream.endedWithin(10_000);
    const told = identities(carolStream.events).some((e) => e.data.domains.includes("membership"));
    const bobSaw = await bobStream.until((ev) => changesOf(ev, b).some((e) => e.data.domains.includes("membership")));
    out.push(`removal: ended ${carolEnded}, told ${told}, reason ${closeOf(carolStream.events)}, bob saw it ${bobSaw}, bob still open ${!bobStream.ended}`);
    // Reconnected, carol hears from a only.
    const carolAgain = await opened((await browser(names, session(carol).token)).cookie);
    fixture("events", b, bob, "1");
    fixture("events", a, alice, "1");
    await carolAgain.until((ev) => changesOf(ev, a).length > 0);
    const stillB = changesOf(carolAgain.events, b).length;
    out.push(`after removal carol hears org b ${stillB} times`);

    check(
      "realtime-events.revocation-and-removal-close-streams",
      "revocation and removal close streams: sign-out, a revoked session credential and removal from an organization end the stream with the reason, and other streams stay open",
      signOut.status === 204 && s1Ended && closeOf(S1.events) === "session-ended" && afterSignOut.status === 401 &&
        revoke === 204 && s2Ended && ["credential-revoked", "session-ended"].includes(closeOf(S2.events)) &&
        carolEnded && told && closeOf(carolStream.events) === "membership-removed" && bobSaw && !bobStream.ended &&
        stillB === 0 && !kept.ended,
      out.join("; "),
    );
    for (const s of [kept, bobStream, carolAgain]) s.abort();
  }

  // ---- A slow client is cut off alone.
  //
  // Round by round: one commit of events in many organizations, then a
  // wait until the fast stream has each organization's signal for that
  // commit (its last event id), so the rounds never run together and no
  // sleep decides anything. The slow client never reads; once its socket
  // is full the server can write nothing more to it, and its bounded
  // buffer of publications (or a write's deadline) ends its stream. The
  // server's request log says when: a stream's request is logged once it
  // ended. The protocol guarantees that end and that the fast stream keeps
  // receiving, not after how many rounds, so the rounds are bounded only
  // generously.
  {
    const many = fixture("orgs", alice, "150").organizations;
    const slowSession = session(alice);
    const fast = await opened((await browser(names, session(alice).token)).cookie);
    const endedStreams = () =>
      targetOp("request-log")
        .split("\n")
        .filter(Boolean)
        .map((l) => JSON.parse(l))
        .filter((r) => r.method === "GET" && r.path === "/auth/events").length;
    const before = endedStreams();
    // The slow client: a socket that sends its request and never reads.
    const url = new URL(origin);
    const socket = connect({ host: url.hostname, port: Number(url.port) });
    await new Promise((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    socket.pause();
    socket.write(`GET /auth/events HTTP/1.1\r\nHost: ${url.host}\r\nCookie: ${names.session}=${slowSession.token}\r\nAccept: text/event-stream\r\n\r\n`);
    const MAX_ROUNDS = 60;
    let rounds = 0;
    let acknowledged = 0;
    let cut = false;
    while (!cut && rounds < MAX_ROUNDS) {
      rounds++;
      const { events } = fixture("events", many.join(","), "-", "20");
      // Each organization's 20 events, in order: its last is the signal's.
      const last = new Map(many.map((org, i) => [org, events[i * 20 + 19]]));
      const got = await fast.until(
        (ev) => [...last].every(([org, id]) => changesOf(ev, org).some((e) => e.data.lastEventId === id)),
        30_000,
      );
      if (!got || fast.ended) break;
      acknowledged++;
      cut = endedStreams() > before;
    }
    // What the slow client was sent before its cut, then the end of its
    // socket (no close event: nothing more is written to a client that
    // does not read).
    let text = "";
    const slowEnded = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 15_000);
      socket.on("data", (d) => (text += d.toString("utf8")));
      socket.on("end", () => (clearTimeout(timer), resolve(true)));
      socket.on("close", () => (clearTimeout(timer), resolve(true)));
      socket.on("error", () => (clearTimeout(timer), resolve(true)));
      socket.resume();
    });
    const slowReceived = (text.match(/^event: change$/gm) ?? []).length;
    // It was a stream (not a refusal) before it was cut.
    const slowOpened = /^HTTP\/1\.1 200 /.test(text) && text.includes("event: ready");
    // The fast stream still receives after the cut.
    const { events: after } = fixture("events", many[0], "-", "1");
    const stillLive = await fast.until((ev) => changesOf(ev, many[0]).some((e) => e.data.lastEventId === after[0]), 30_000);
    const fresh = await opened((await browser(names, session(alice).token)).cookie);
    check(
      "realtime-events.slow-client-cut-off-alone",
      "a slow client is cut off without affecting others: a stream that is not read is disconnected, another receives every signal",
      cut && slowOpened && slowEnded && acknowledged === rounds && stillLive && !fast.ended && fresh.events.some((e) => e.name === "ready"),
      `slow client opened ${slowOpened}, cut ${cut} after ${rounds} rounds (it had been sent ${slowReceived} signals), its socket ended ${slowEnded}; ` +
        `the other stream had every signal of ${acknowledged} of ${rounds} rounds and one after the cut ${stillLive}, still open ${!fast.ended}`,
    );
    socket.destroy();
    for (const s of [fast, fresh]) s.abort();
  }
} catch (err) {
  error(`realtime events: ${String(err?.stack ?? err).slice(0, 500)}`);
} finally {
  for (const s of open) s.abort();
}
finish();
