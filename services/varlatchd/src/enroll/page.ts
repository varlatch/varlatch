// SPDX-License-Identifier: AGPL-3.0-or-later
/** Interim enrollment/sign-in page served by varlatchd until apps/web lands. */
export const ENROLL_HTML = /* html */ `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Varlatch — passkey enrollment</title>
  <style>
    body { font: 16px/1.5 system-ui, sans-serif; max-width: 34rem; margin: 4rem auto; padding: 0 1rem; color: #1a1a2e; }
    button { font: inherit; padding: .6rem 1.2rem; border-radius: .5rem; border: 1px solid #1a1a2e; background: #1a1a2e; color: #fff; cursor: pointer; }
    button.secondary { background: #fff; color: #1a1a2e; }
    #status { margin-top: 1rem; white-space: pre-wrap; }
    code { background: #f0f0f5; padding: .1rem .3rem; border-radius: .3rem; word-break: break-all; }
  </style>
</head>
<body>
  <h1>Varlatch</h1>
  <p id="mode-enroll" hidden>
    Enroll a passkey for this installation. This consumes your one-time setup token.
    <label>Display name <input id="name" value="" placeholder="Your name" /></label>
  </p>
  <p>
    <button id="enroll" hidden>Create passkey</button>
    <button id="signin" class="secondary">Sign in with passkey</button>
  </p>
  <div id="status"></div>
  <script src="/enroll.js"></script>
  <script>
    const token = location.hash.slice(1);
    const callback = new URLSearchParams(location.search).get("callback");
    const status = document.getElementById("status");
    const show = (msg) => { status.textContent = msg; };
    const showResult = async (r) => {
      if (callback) {
        // CLI browser-handoff (ADR-0017): deliver the short-lived bearer to
        // the local loopback listener the CLI opened, then stop.
        try {
          const u = new URL(callback);
          if (u.hostname !== "127.0.0.1" && u.hostname !== "localhost") throw new Error("bad callback");
          // targetAddressSpace satisfies Chrome's Local Network Access checks
          // for the page -> 127.0.0.1 hand-off.
          await fetch(callback, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ token: r.token, identityId: r.identityId }), targetAddressSpace: "loopback" });
          show("Authenticated as " + r.identityId + ".\\nReturn to your terminal — the CLI has received its credential.");
          return;
        } catch (e) { show("Could not reach the CLI callback: " + e.message); return; }
      }
      show("Authenticated as " + r.identityId + "\\n\\nShort-lived API credential (for varlatch login):\\n" + r.token + "\\n\\nExpires: " + r.expiresAt);
    };
    if (token) {
      document.getElementById("mode-enroll").hidden = false;
      document.getElementById("enroll").hidden = false;
    }
    document.getElementById("enroll").onclick = async () => {
      try {
        show("Waiting for your authenticator…");
        showResult(await window.varlatch.enroll(token, document.getElementById("name").value || "Passkey"));
      } catch (err) { show("Enrollment failed: " + err.message); }
    };
    document.getElementById("signin").onclick = async () => {
      try {
        show("Waiting for your authenticator…");
        showResult(await window.varlatch.signIn());
      } catch (err) { show("Sign-in failed: " + err.message); }
    };
  </script>
</body>
</html>`;
