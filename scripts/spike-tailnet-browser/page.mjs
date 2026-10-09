// SPDX-License-Identifier: Apache-2.0
// The S5 test page: what a dashboard would do, a cross-origin fetch with an
// Authorization header (so a preflight), credentials omitted, with an abort.
// Each fetch goes once without and once with the Private Network Access
// header requested from the probe (?pna=0, ?pna=1). Results land on
// window.__spike for the harness to read; the bearer is a dummy.

export function pageHtml(endpoint, abortMs = 4000) {
  const config = JSON.stringify({ endpoint, abortMs });
  return `<!doctype html>
<meta charset="utf-8">
<title>tailnet browser spike</title>
<pre id="out">running…</pre>
<script>
const { endpoint, abortMs } = ${config};
window.__spike = [];
(async () => {
  for (const pna of ["0", "1"]) {
    const t0 = performance.now();
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), abortMs);
    try {
      const res = await fetch(endpoint + "/probe?pna=" + pna, {
        headers: { Authorization: "Bearer spike-dummy-not-a-credential" },
        credentials: "omit",
        signal: ctl.signal,
      });
      const body = await res.json().catch(() => null);
      window.__spike.push({ pna, ok: res.ok, status: res.status, ms: Math.round(performance.now() - t0), whois: body && body.whois });
    } catch (err) {
      window.__spike.push({ pna, ok: false, error: String(err), ms: Math.round(performance.now() - t0) });
    } finally {
      clearTimeout(timer);
    }
  }
  document.getElementById("out").textContent = JSON.stringify(window.__spike, null, 2);
  window.__spikeDone = true;
})();
</script>
`;
}
