// SPDX-License-Identifier: AGPL-3.0-or-later
// The enrollment page's client on varlatchd's own browser session
// (ADR-0059 Decision 6; the TypeScript server's page runs Better Auth's
// client instead, services/varlatchd/src/enroll/client.ts). It gives the
// page the same two calls, each answering the bearer the page shows or
// hands to the CLI: enroll(token, name) registers a passkey with a setup
// grant, signIn() signs in with a discoverable passkey. Plain browser
// JavaScript, no dependencies: WebAuthn's options and responses are
// converted between base64url JSON and ArrayBuffers here.
(function () {
  "use strict";

  var b64 = {
    toBuffer: function (s) {
      var pad = s.replace(/-/g, "+").replace(/_/g, "/");
      while (pad.length % 4) pad += "=";
      var bin = atob(pad);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out.buffer;
    },
    fromBuffer: function (buf) {
      var bytes = new Uint8Array(buf);
      var bin = "";
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    },
  };

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { id: b64.toBuffer(d.id), type: d.type };
      if (d.transports) out.transports = d.transports;
      return out;
    });
  }

  var csrf = null;
  function csrfToken() {
    if (csrf) return Promise.resolve(csrf);
    return fetch("/auth/session", { credentials: "include", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (!r.ok) throw new Error("session check failed: " + r.status);
        return r.json();
      })
      .then(function (body) {
        csrf = body.csrfToken;
        return csrf;
      });
  }

  function post(path, body) {
    return csrfToken().then(function (token) {
      return fetch(path, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json", Accept: "application/json", "Varlatch-CSRF": token },
        body: JSON.stringify(body || {}),
      });
    }).then(function (r) {
      if (r.status === 204) return null;
      return r.json().then(function (json) {
        if (!r.ok) {
          var err = new Error((json && json.error && json.error.message) || path + " failed: " + r.status);
          err.code = json && json.error && json.error.code;
          throw err;
        }
        return json;
      }, function () {
        throw new Error(path + " failed: " + r.status);
      });
    });
  }

  function exchange() {
    return post("/auth/varlatch-token").catch(function (err) {
      throw new Error("token exchange failed: " + err.message);
    });
  }

  function attestationJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: b64.fromBuffer(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: b64.fromBuffer(r.clientDataJSON),
        attestationObject: b64.fromBuffer(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
      },
    };
  }

  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: b64.fromBuffer(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: {
        clientDataJSON: b64.fromBuffer(r.clientDataJSON),
        authenticatorData: b64.fromBuffer(r.authenticatorData),
        signature: b64.fromBuffer(r.signature),
        userHandle: r.userHandle ? b64.fromBuffer(r.userHandle) : undefined,
      },
    };
  }

  function enroll(token, name) {
    return post("/auth/passkey/registration/options", { token: token })
      .then(function (body) {
        var o = body.publicKey;
        return navigator.credentials.create({
          publicKey: {
            challenge: b64.toBuffer(o.challenge),
            rp: o.rp,
            user: { id: b64.toBuffer(o.user.id), name: o.user.name, displayName: o.user.displayName },
            pubKeyCredParams: o.pubKeyCredParams,
            timeout: o.timeout,
            attestation: o.attestation,
            excludeCredentials: descriptors(o.excludeCredentials),
            authenticatorSelection: o.authenticatorSelection,
            extensions: o.extensions,
          },
        });
      })
      .then(function (cred) {
        if (!cred) throw new Error("enrollment failed");
        return post("/auth/passkey/registration", { response: attestationJSON(cred), name: name || undefined });
      })
      .then(exchange);
  }

  function signIn() {
    return post("/auth/passkey/sign-in/options")
      .then(function (body) {
        var o = body.publicKey;
        return navigator.credentials.get({
          publicKey: {
            challenge: b64.toBuffer(o.challenge),
            timeout: o.timeout,
            rpId: o.rpId,
            allowCredentials: descriptors(o.allowCredentials),
            userVerification: o.userVerification,
          },
        });
      })
      .then(function (cred) {
        if (!cred) throw new Error("sign-in failed");
        return post("/auth/passkey/sign-in", { response: assertionJSON(cred) }).catch(function (err) {
          // A passkey whose server row is gone (e.g. the database was
          // reset): signal the browser to forget it, where supported.
          if (err.code === "PASSKEY_NOT_FOUND") {
            try {
              if (PublicKeyCredential.signalUnknownCredential) {
                PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId: cred.id });
              }
            } catch (e) {
              // Best-effort.
            }
            throw new Error(
              "this passkey is no longer registered with the server (it may have been reset). " +
                "It was removed from your authenticator where supported; use another passkey or re-enroll.",
            );
          }
          throw err;
        });
      })
      .then(exchange);
  }

  window.varlatch = { enroll: enroll, signIn: signIn };
})();
