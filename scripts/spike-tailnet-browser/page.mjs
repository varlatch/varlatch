// SPDX-License-Identifier: Apache-2.0
// The S5 test page: what a dashboard would do, a cross-origin fetch with an
// Authorization header (so a preflight), credentials omitted, with an abort.
// Each fetch goes once without and once with the Private Network Access
// header requested from the probe (?pna=0, ?pna=1). The bearer is a dummy.
//
// Results land on window.__spike. With a run ID, every fetch carries it and
// the page posts its completed results to `report` on its own origin: what
// the browser itself saw, including whether it read the JSON and which probe
// entry the answer names, so a judge never has to infer completion from the
// server side alone.

export function pageHtml(endpoint, abortMs = 4000, { run = null, report = null, query = "" } = {}) {
  const config = JSON.stringify({ endpoint, abortMs, run, report, query });
  return `<!doctype html>
<meta charset="utf-8">
<title>tailnet browser spike</title>
<pre id="out">running…</pre>
<script>
const { endpoint, abortMs, run, report, query } = ${config};
window.__spike = [];
(async () => {
  for (const pna of ["0", "1"]) {
    const t0 = performance.now();
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), abortMs);
    const url = endpoint + "/probe?pna=" + pna + (run ? "&run=" + encodeURIComponent(run) : "") + query;
    try {
      const res = await fetch(url, {
        headers: { Authorization: "Bearer spike-dummy-not-a-credential" },
        credentials: "omit",
        signal: ctl.signal,
      });
      let body = null;
      let json = false;
      try {
        body = await res.json();
        json = true;
      } catch {}
      window.__spike.push({ pna, ok: res.ok, status: res.status, json, id: body && body.id, whois: body && body.whois, ms: Math.round(performance.now() - t0) });
    } catch (err) {
      window.__spike.push({ pna, ok: false, json: false, error: String(err), ms: Math.round(performance.now() - t0) });
    } finally {
      clearTimeout(timer);
    }
  }
  if (run && report) {
    try {
      const sent = await fetch(report, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run, results: window.__spike, userAgent: navigator.userAgent }),
      });
      window.__spikeReported = sent.status === 204;
    } catch (err) {
      window.__spikeReported = false;
    }
  }
  document.getElementById("out").textContent =
    JSON.stringify(window.__spike, null, 2) + (run && report ? "\\nreported: " + window.__spikeReported : "");
  window.__spikeDone = true;
})();
</script>
`;
}
