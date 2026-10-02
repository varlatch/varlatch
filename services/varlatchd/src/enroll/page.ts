// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Passkey enrollment and sign-in page served by varlatchd at /enroll: the
 * one-time invite/recovery link target and the CLI browser hand-off. It is
 * self-contained (inline CSS and script, system fonts); the brand image comes
 * from the dashboard origin when available.
 *
 * Contract with the e2e scripts: the buttons keep ids `enroll` and `signin`,
 * the name field keeps id `name`, and every outcome is rendered inside
 * `#status` with the phrases "Authenticated as <identity>", "API credential",
 * the credential itself, "terminal" for the CLI hand-off, and "failed".
 */
export const ENROLL_HTML = /* html */ `<!doctype html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Varlatch · passkey</title>
  <script>
    (function () {
      var saved = localStorage.getItem("varlatch-theme");
      var light = saved === "light" || ((!saved || saved === "system") && matchMedia("(prefers-color-scheme: light)").matches);
      document.documentElement.dataset.theme = light ? "light" : "dark";
    })();
  </script>
  <style>
    :root { --bg:#0d0f14; --raised:#151821; --inset:#0a0c10; --border:#262b38; --text:#e6e8ee; --muted:#8b91a3; --accent:#7bd88f; --accent-fg:#07140b; --deny:#ff5c74; --warn:#e8b339; color-scheme: dark; }
    [data-theme="light"] { --bg:#f6f7f9; --raised:#fff; --inset:#eef0f4; --border:#dde1e8; --text:#16181f; --muted:#5d6373; --accent:#1a7f37; --accent-fg:#fff; --deny:#d1244a; --warn:#9a6700; color-scheme: light; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; background: var(--bg); color: var(--text);
      font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; -webkit-font-smoothing: antialiased; }
    body::before { content: ""; position: fixed; inset: 0; pointer-events: none;
      background-image: radial-gradient(circle at 1px 1px, color-mix(in srgb, var(--muted) 16%, transparent) 1px, transparent 0); background-size: 22px 22px;
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%); }
    .card { position: relative; width: 100%; max-width: 460px; background: var(--raised); border: 1px solid var(--border); border-radius: 16px; padding: 32px; box-shadow: 0 18px 48px -12px rgb(0 0 0 / .45); }
    .brand { display: flex; align-items: center; justify-content: center; gap: 10px; font-size: 18px; font-weight: 650; }
    .brand img { width: 34px; height: 34px; border-radius: 22%; }
    .steps { display: flex; align-items: flex-start; justify-content: center; gap: 0; margin: 22px 0 6px; }
    .step { display: flex; flex-direction: column; align-items: center; gap: 6px; width: 92px; font-size: 12px; color: var(--muted); }
    .dot { width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; border: 1px solid var(--border); font-size: 12px; font-weight: 600; background: var(--inset); color: var(--muted); }
    .step.done .dot, .step.current .dot { background: var(--accent); border-color: var(--accent); color: var(--accent-fg); }
    .step.current { color: var(--text); font-weight: 600; }
    .bar { flex: 1; height: 1px; max-width: 48px; margin-top: 13px; background: var(--border); }
    .bar.done { background: var(--accent); }
    h1 { margin: 18px 0 4px; text-align: center; font-size: 22px; letter-spacing: -0.01em; }
    p.lead { margin: 0 0 20px; text-align: center; color: var(--muted); }
    label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
    input { width: 100%; height: 38px; padding: 0 12px; border-radius: 8px; border: 1px solid var(--border); background: var(--inset); color: var(--text); font: inherit; }
    input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); }
    button, a.button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; height: 40px; padding: 0 16px; border-radius: 8px; font: inherit; font-weight: 600; cursor: pointer; text-decoration: none; border: 1px solid transparent; }
    .primary { width: 100%; background: var(--accent); color: var(--accent-fg); margin-top: 16px; }
    .primary:hover { filter: brightness(1.06); }
    .secondary { background: var(--raised); color: var(--text); border-color: var(--border); }
    .secondary:hover { background: var(--inset); }
    .small { height: 30px; padding: 0 10px; font-size: 12.5px; font-weight: 500; }
    .muted { color: var(--muted); }
    #status { margin-top: 14px; min-height: 20px; font-size: 13px; color: var(--muted); text-align: center; white-space: pre-wrap; }
    #status.result { text-align: left; color: var(--text); white-space: normal; }
    #status .fail { color: var(--deny); }
    .section-title { font-weight: 600; margin: 18px 0 8px; }
    .code { display: flex; align-items: center; gap: 8px; padding: 10px 10px 10px 14px; border: 1px solid var(--border); border-radius: 8px; background: var(--inset); font: 12.5px/1.5 ui-monospace, "SF Mono", Menlo, monospace; }
    .code > span { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .token { filter: blur(5px); user-select: none; }
    .row { display: flex; align-items: center; gap: 10px; margin-top: 12px; font-size: 13px; color: var(--muted); }
    .row .grow { flex: 1; }
    .foot { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border); text-align: center; font-size: 12.5px; color: var(--muted); }
    .who { margin-top: 6px; font-size: 12px; color: var(--muted); text-align: center; }
    [hidden] { display: none !important; }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand"><img src="/brand/varlatch-app-icon.png" alt="" onerror="this.remove()" />Varlatch</div>
    <div class="steps" id="steps" hidden>
      <div class="step current" id="step-1"><span class="dot">1</span>Name</div>
      <span class="bar" id="bar-1"></span>
      <div class="step" id="step-2"><span class="dot">2</span>Passkey</div>
      <span class="bar" id="bar-2"></span>
      <div class="step" id="step-3"><span class="dot">3</span>Ready</div>
    </div>
    <h1 id="title">Sign in to Varlatch</h1>
    <p class="lead" id="lead">No passwords exist here. Your passkey lives on your device or security key.</p>
    <div id="mode-enroll" hidden>
      <label for="name">Your name</label>
      <input id="name" value="" placeholder="How others will see you" autocomplete="name" />
    </div>
    <button id="enroll" class="primary" hidden>Create passkey</button>
    <button id="signin" class="primary">Continue with passkey</button>
    <div id="status" aria-live="polite"></div>
  </main>
  <script src="/enroll.js"></script>
  <script>
    const token = location.hash.slice(1);
    const callback = new URLSearchParams(location.search).get("callback");
    const status = document.getElementById("status");
    const el = (tag, attrs, children) => {
      const node = document.createElement(tag);
      for (const [k, v] of Object.entries(attrs || {})) { if (k === "text") node.textContent = v; else node.setAttribute(k, v); }
      for (const c of children || []) node.append(c);
      return node;
    };
    const show = (msg, failed) => {
      status.className = "";
      status.replaceChildren(failed ? el("span", { class: "fail", text: msg }) : document.createTextNode(msg));
    };
    const setStep = (n) => {
      for (let i = 1; i <= 3; i++) {
        const s = document.getElementById("step-" + i);
        s.className = "step" + (i < n ? " done" : i === n ? " current" : "");
        s.querySelector(".dot").textContent = i < n ? "\\u2713" : String(i);
      }
      document.getElementById("bar-1").className = "bar" + (n > 1 ? " done" : "");
      document.getElementById("bar-2").className = "bar" + (n > 2 ? " done" : "");
    };
    const copyButton = (value, label) => {
      const b = el("button", { class: "secondary small", type: "button", text: label });
      b.onclick = async () => { try { await navigator.clipboard.writeText(value); b.textContent = "Copied"; setTimeout(() => (b.textContent = label), 1500); } catch {} };
      return b;
    };
    const hideForm = () => {
      for (const id of ["mode-enroll", "enroll", "signin"]) document.getElementById(id).hidden = true;
    };
    const showResult = async (r) => {
      if (callback) {
        // CLI browser hand-off (ADR-0017): deliver the short-lived bearer to
        // the local loopback listener the CLI opened, then stop.
        try {
          const u = new URL(callback);
          if (u.hostname !== "127.0.0.1" && u.hostname !== "localhost") throw new Error("bad callback");
          // targetAddressSpace satisfies Chrome's Local Network Access checks
          // for the page -> 127.0.0.1 hand-off.
          await fetch(callback, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: r.token, identityId: r.identityId }), targetAddressSpace: "loopback" });
          hideForm();
          document.getElementById("title").textContent = "You're signed in";
          document.getElementById("lead").textContent = "Return to your terminal: the CLI has received its credential. You can close this tab.";
          show("Authenticated as " + r.identityId + ". Return to your terminal; the CLI has received its credential.");
          return;
        } catch (e) { show("Could not reach the CLI callback: " + e.message + " (failed)", true); return; }
      }
      hideForm();
      if (token) setStep(3);
      document.getElementById("title").textContent = token ? "You're in" : "Signed in";
      document.getElementById("lead").textContent = token ? "Your passkey is saved on this device." : "Your passkey worked.";
      const login = "varlatch login --server " + location.origin;
      const expires = new Date(r.expiresAt);
      const tokenSpan = el("span", { class: "token", text: r.token, title: "Hidden: use Copy" });
      const countdown = el("span", { class: "grow" });
      const tick = () => {
        const s = Math.max(0, Math.round((expires.getTime() - Date.now()) / 1000));
        countdown.textContent = s > 0 ? "Expires in " + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0") + " (" + r.expiresAt + ")" : "Expired: " + r.expiresAt;
      };
      tick();
      setInterval(tick, 1000);
      status.className = "result";
      status.replaceChildren(
        el("div", { class: "section-title", text: "Sign in from your terminal" }),
        el("div", { class: "code" }, [el("span", { text: login }), document.createTextNode(" "), copyButton(login, "Copy")]),
        el("div", { class: "section-title", text: "Short-lived API credential (for varlatch login)" }),
        // The space keeps the credential a separate word in #status text.
        el("div", { class: "code" }, [tokenSpan, document.createTextNode(" "), copyButton(r.token, "Copy credential")]),
        el("div", { class: "row" }, [countdown]),
        el("a", { class: "button primary", href: "/", text: "Open the dashboard" }),
        el("div", { class: "who", text: "Authenticated as " + r.identityId }),
        el("div", { class: "foot", text: token ? "Add a second passkey later under Account, Security, so losing this device never locks you out." : "This credential works only for a few minutes; varlatch login exchanges it." }),
      );
    };
    if (token) {
      document.getElementById("steps").hidden = false;
      document.getElementById("mode-enroll").hidden = false;
      document.getElementById("enroll").hidden = false;
      document.getElementById("signin").hidden = true;
      document.getElementById("title").textContent = "Set up your passkey";
      document.getElementById("lead").textContent = "This one-time link enrolls a passkey for this installation. No password is ever created.";
      document.getElementById("name").focus();
    }
    document.getElementById("enroll").onclick = async () => {
      try {
        setStep(2);
        show("Waiting for your authenticator…");
        showResult(await window.varlatch.enroll(token, document.getElementById("name").value || "Passkey"));
      } catch (err) { setStep(1); show("Enrollment failed: " + err.message, true); }
    };
    document.getElementById("signin").onclick = async () => {
      try {
        show("Waiting for your authenticator…");
        showResult(await window.varlatch.signIn());
      } catch (err) { show("Sign-in failed: " + err.message, true); }
    };
  </script>
</body>
</html>`;
