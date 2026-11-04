// Passkeys: the browser half. WebAuthn wants binary where the server sends
// base64url, so this converts both ways, and otherwise only carries the
// ceremony between the browser and the webmail.
(function () {
  "use strict";

  var toBytes = function (s) {
    var b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    var out = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return out.buffer;
  };
  var toText = function (buf) {
    var bytes = new Uint8Array(buf), b = "";
    for (var i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
    return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  var post = function (url, headers, body) {
    return fetch(url, { method: "POST", credentials: "same-origin", headers: headers, body: body }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || "Something went wrong.");
        return data;
      });
    });
  };
  var plain = function (err) {
    // The browser's own errors are written for developers. Dismissing the
    // prompt is the common one, and it isn't a problem.
    if (err && err.name === "NotAllowedError") return "";
    if (err && err.name === "InvalidStateError") return "This device already has a passkey for this account.";
    if (err && err.name && err.name !== "Error") return "Your browser couldn't use a passkey here.";
    return (err && err.message) || "Something went wrong.";
  };

  var supported = window.PublicKeyCredential && window.isSecureContext;

  // ---- sign-in -----------------------------------------------------------
  var signIn = document.querySelector("[data-passkey-signin]");
  if (signIn && supported) {
    var token = signIn.getAttribute("data-token");
    var problem = document.querySelector("[data-passkey-problem]");
    signIn.hidden = false;
    signIn.addEventListener("click", function () {
      signIn.disabled = true;
      if (problem) problem.hidden = true;
      var json = { "Content-Type": "application/json" };
      post("/login/passkey/begin", json, JSON.stringify({ token: token })).then(function (begun) {
        var options = begun.options.publicKey;
        options.challenge = toBytes(options.challenge);
        (options.allowCredentials || []).forEach(function (c) { c.id = toBytes(c.id); });
        return navigator.credentials.get({ publicKey: options }).then(function (cred) {
          return post("/login/passkey/finish", json, JSON.stringify({
            token: token, challenge: begun.challenge,
            response: {
              id: cred.id, rawId: toText(cred.rawId), type: cred.type,
              response: {
                clientDataJSON: toText(cred.response.clientDataJSON),
                authenticatorData: toText(cred.response.authenticatorData),
                signature: toText(cred.response.signature),
                userHandle: cred.response.userHandle ? toText(cred.response.userHandle) : ""
              }
            }
          }));
        });
      }).then(function (done) {
        location.href = done.next;
      }).catch(function (err) {
        signIn.disabled = false;
        var text = plain(err);
        if (problem && text) { problem.textContent = text; problem.hidden = false; }
      });
    });
  }

  // ---- settings ----------------------------------------------------------
  var form = document.querySelector("[data-passkey-add]");
  if (form && supported) {
    var unsupported = document.querySelector("[data-passkey-unsupported]");
    if (unsupported) unsupported.hidden = true;
    form.hidden = false;
    var note = form.querySelector("[data-passkey-problem]");
    var csrf = document.body.getAttribute("data-csrf");
    var encoded = { "Content-Type": "application/x-www-form-urlencoded" };
    var body = function (fields) {
      fields.csrf = csrf;
      return new URLSearchParams(fields).toString();
    };
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      note.hidden = true;
      var name = form.elements.name.value, password = form.elements.password.value;
      post("/settings/passkeys/begin", encoded, body({ password: password })).then(function (begun) {
        var options = begun.options.publicKey;
        options.challenge = toBytes(options.challenge);
        options.user.id = toBytes(options.user.id);
        (options.excludeCredentials || []).forEach(function (c) { c.id = toBytes(c.id); });
        return navigator.credentials.create({ publicKey: options }).then(function (cred) {
          return post("/settings/passkeys/finish", encoded, body({
            name: name, challenge: begun.challenge,
            response: JSON.stringify({
              id: cred.id, rawId: toText(cred.rawId), type: cred.type,
              response: {
                clientDataJSON: toText(cred.response.clientDataJSON),
                attestationObject: toText(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : []
              }
            })
          }));
        });
      }).then(function (done) {
        location.href = done.next;
      }).catch(function (err) {
        var text = plain(err);
        if (text) { note.textContent = text; note.hidden = false; }
      });
    });
  }
}());
