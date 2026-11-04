// PGP on the page: everything that isn't crypto. The crypto and the unlocked key
// stay in pgp-worker.js. A decrypted message only ever goes into the page as
// text: it came from outside, and nothing here renders it.
(function () {
  "use strict";
  var doc = document;
  var csrf = doc.body.getAttribute("data-csrf");
  var workerURL = doc.body.getAttribute("data-pgp-worker");
  var owner = doc.body.getAttribute("data-pgp-owner");
  var $ = function (sel, ctx) { return (ctx || doc).querySelector(sel); };
  if (!workerURL || !window.Worker) return;

  var port = null, nextID = 1, waiting = {};
  function connect() {
    if (port) return port;
    if (window.SharedWorker) {
      port = new SharedWorker(workerURL, { name: "elemta-pgp" }).port;
      port.start();
    } else {
      port = new Worker(workerURL);
    }
    port.onmessage = function (event) {
      var m = event.data, w = waiting[m.id];
      delete waiting[m.id];
      if (!w) return;
      if (m.error) w.reject(new Error(m.error)); else w.resolve(m.result);
    };
    return port;
  }
  function call(action, fields) {
    var id = nextID++, message = fields || {};
    message.id = id;
    message.action = action;
    message.owner = owner;
    return new Promise(function (resolve, reject) {
      waiting[id] = { resolve: resolve, reject: reject };
      connect().postMessage(message);
    });
  }
  function api(url, fields) {
    var opts = { credentials: "same-origin", headers: { "X-CSRF-Token": csrf } };
    if (fields) {
      opts.method = "POST";
      opts.body = new URLSearchParams(fields);
    }
    return fetch(url, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (!r.ok) throw new Error(data.error || "Something went wrong.");
        return data;
      });
    });
  }
  function show(el, text) { el.textContent = text; el.hidden = !text; }

  function grouped(fingerprint) { return (fingerprint.match(/.{1,4}/g) || []).join(" "); }

  // Asks for the passphrase in the given form if the key isn't open yet.
  function ensureUnlocked(passphrase) {
    return call("status").then(function (st) {
      if (st.unlocked) return st;
      return api("/api/pgp/key").then(function (key) {
        if (!key.private_key) throw new Error("You don't have a key yet. Create one in Settings, Security.");
        return call("unlock", { privateKey: key.private_key, passphrase: passphrase || "" });
      }).catch(function (err) {
        throw /passphrase|Incorrect|decrypt/i.test(err.message) ? new Error("That passphrase isn't right.") : err;
      });
    });
  }

  // Lock on the way out, rather than leaving the key open for the next person.
  // The page waits for it: a message sent while leaving can be lost with the
  // page. It waits briefly, because nothing here may stop someone signing out.
  doc.addEventListener("submit", function (event) {
    var out = event.target;
    if (!out.matches || !out.matches('form[action="/logout"]')) return;
    event.preventDefault();
    var leave = function () { HTMLFormElement.prototype.submit.call(out); };
    Promise.race([call("lock"), new Promise(function (r) { setTimeout(r, 800); })]).then(leave, leave);
  }, true);

  // ---- settings ----------------------------------------------------------
  var card = $("[data-pgp-settings]");
  if (card) {
    var problem = $("[data-pgp-problem]", card);
    var fail = function (err) { show(problem, err.message); };
    var download = function (name, text) {
      var a = doc.createElement("a");
      a.href = URL.createObjectURL(new Blob([text], { type: "application/pgp-keys" }));
      a.download = name;
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    };
    var save = function (pair, password) {
      return api("/api/pgp/key", { public_key: pair.publicKey, private_key: pair.privateKey, password: password }).then(function () {
        location.href = "/settings/security?n=pgp-key-saved#pgp";
      });
    };
    var checkPassphrase = function (form) {
      if (form.elements.passphrase.value.length < 12) throw new Error("Use a passphrase of at least 12 characters.");
      if (form.elements.passphrase.value !== form.elements.confirm.value) throw new Error("The two passphrases don't match.");
    };
    var create = $("[data-pgp-create]", card);
    if (create) create.addEventListener("submit", function (event) {
      event.preventDefault();
      show(problem, "");
      try { checkPassphrase(create); } catch (err) { fail(err); return; }
      var button = $("button[type=submit]", create);
      button.disabled = true;
      call("generate", { name: create.getAttribute("data-name"), email: create.getAttribute("data-email"), passphrase: create.elements.passphrase.value })
        .then(function (pair) { return save(pair, create.elements.password.value); })
        .catch(function (err) { button.disabled = false; fail(err); });
    });
    var importing = $("[data-pgp-import]", card);
    if (importing) importing.addEventListener("submit", function (event) {
      event.preventDefault();
      show(problem, "");
      try { checkPassphrase(importing); } catch (err) { fail(err); return; }
      call("importKey", { armored: importing.elements.armored.value, oldPassphrase: importing.elements.old.value, passphrase: importing.elements.passphrase.value })
        .then(function (pair) { return save(pair, importing.elements.password.value); })
        .catch(fail);
    });
    var exportPublic = $("[data-pgp-export-public]", card), exportPrivate = $("[data-pgp-export-private]", card);
    if (exportPublic) exportPublic.addEventListener("click", function () {
      api("/api/pgp/key").then(function (k) { download("public-key.asc", k.public_key); }).catch(fail);
    });
    if (exportPrivate) exportPrivate.addEventListener("click", function () {
      api("/api/pgp/key").then(function (k) { download("private-key.asc", k.private_key); }).catch(fail);
    });
    var remove = $("[data-pgp-remove]", card);
    if (remove) remove.addEventListener("submit", function (event) {
      event.preventDefault();
      show(problem, "");
      api("/api/pgp/key/delete", { password: remove.elements.password.value }).then(function () {
        return call("lock");
      }).then(function () { location.href = "/settings/security?n=pgp-key-removed#pgp"; }).catch(fail);
    });
  }

  // ---- reading -----------------------------------------------------------
  // A small MIME reader, for what comes out of a message. It finds the first
  // text part and the protected subject, and names any attachments.
  function bytesToText(bytes) { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
  function latin(bytes) { var s = ""; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return s; }
  function toBytes(s) { var b = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 255; return b; }
  function splitPart(raw) {
    var m = /\r?\n\r?\n/.exec(raw);
    if (!m) return { headers: {}, body: raw };
    var headers = {};
    raw.slice(0, m.index).replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/).forEach(function (line) {
      var at = line.indexOf(":");
      if (at > 0) headers[line.slice(0, at).trim().toLowerCase()] = line.slice(at + 1).trim();
    });
    return { headers: headers, body: raw.slice(m.index + m[0].length) };
  }
  function bodyBytes(part) {
    var cte = (part.headers["content-transfer-encoding"] || "").toLowerCase();
    if (cte === "base64") {
      try { return toBytes(atob(part.body.replace(/\s+/g, ""))); } catch (err) { return toBytes(part.body); }
    }
    if (cte === "quoted-printable") {
      return toBytes(part.body.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, function (_, h) { return String.fromCharCode(parseInt(h, 16)); }));
    }
    return toBytes(part.body);
  }
  function partName(part) {
    var text = (part.headers["content-disposition"] || "") + ";" + (part.headers["content-type"] || "");
    var encoded = /filename\*=(?:UTF-8|utf-8)''([^;]+)/.exec(text);
    if (encoded) { try { return decodeURIComponent(encoded[1]); } catch (err) { /* below */ } }
    var plain = /(?:file)?name="?([^";]+)"?/i.exec(text);
    return plain ? plain[1] : "";
  }
  function readMime(raw, out, depth) {
    var part = splitPart(raw), type = (part.headers["content-type"] || "text/plain").toLowerCase();
    if (part.headers.subject && !out.subject) out.subject = part.headers.subject;
    var boundary = /boundary="?([^";]+)"?/i.exec(part.headers["content-type"] || "");
    if (type.indexOf("multipart/") === 0 && boundary && depth < 8) {
      part.body.split("--" + boundary[1]).slice(1).forEach(function (piece) {
        if (piece.indexOf("--") !== 0) readMime(piece.replace(/^\r?\n/, "").replace(/\r?\n$/, ""), out, depth + 1);
      });
      return;
    }
    var name = partName(part);
    if (/attachment/i.test(part.headers["content-disposition"] || "") || name) {
      out.attachments.push({ name: name || "attachment", data: bodyBytes(part) });
      return;
    }
    if (type.indexOf("text/plain") === 0 && !out.text) { out.text = bytesToText(bodyBytes(part)); return; }
    if (type.indexOf("text/html") === 0 && !out.html) { out.html = bytesToText(bodyBytes(part)); }
  }
  function plainFromHTML(html) {
    // DOMParser builds an inert document: nothing in it runs or loads.
    return new DOMParser().parseFromString(html, "text/html").body.textContent || "";
  }

  function replyKey(folder, uid) { return "pgp-reply:" + folder + ":" + uid; }

  // ---- signed mail -------------------------------------------------------
  // The reading pane replaces the message without loading a page, so this runs
  // again for each one. Decrypted attachments would otherwise stay in memory
  // until the tab closed.
  var attachmentURLs = [];
  function readMessage() {
    attachmentURLs.splice(0).forEach(function (url) { URL.revokeObjectURL(url); });
    var signed = $("[data-pgp-verify]");
    if (signed) {
      var from = signed.getAttribute("data-sender");
      api("/api/pgp/lookup", { addresses: from }).catch(function () { return []; }).then(function (found) {
        if (!found.length) { show(signed, "Signed, but no key was found for " + from + ", so it can't be checked."); return null; }
        var request = { senderKeys: found.map(function (k) { return k.public_key; }) };
        var clear = $("[data-pgp-cleartext]");
        if (clear) {
          request.cleartext = clear.value;
        } else {
          request.content = toBytes(atob(signed.getAttribute("data-content")));
          request.signature = $("[data-pgp-detached]").value;
        }
        return call("verify", request).then(function (out) {
          show(signed, out.verified ? "Signed by " + from + ". The signature checks out." :
            "The signature doesn't match. This message may have been changed, or it isn't from " + from + ".");
          signed.classList.toggle("problem", !out.verified);
        });
      }).catch(function () { show(signed, "Signed, but the signature couldn't be read."); });
    }

    var reading = $("[data-pgp-message]");
    if (reading) {
      var unlockForm = $("[data-pgp-unlock]", reading), note = $("[data-pgp-problem]", reading);
      var output = $("[data-pgp-text]", reading), banner = $("[data-pgp-signature]", reading);
      var armored = $("[data-pgp-armor]", reading).value, sender = reading.getAttribute("data-sender");
      var open = function () {
        return api("/api/pgp/lookup", { addresses: sender }).catch(function () { return []; }).then(function (found) {
          return call("decrypt", { message: armored, senderKeys: found.map(function (k) { return k.public_key; }) }).then(function (result) {
            // The reading pane may have moved on, and the subject below is outside
            // this message's element: it would land on the next message.
            if (!reading.isConnected) return;
            var mime = { attachments: [] };
            readMime(latin(result.data), mime, 0);
            var text = mime.text || (mime.html ? plainFromHTML(mime.html) : bytesToText(result.data));
            output.textContent = text;
            output.hidden = false;
            unlockForm.hidden = true;
            if (mime.subject) { var subject = $("[data-message-subject]"); if (subject) subject.textContent = mime.subject; }
            var state = result.verified ? "Encrypted and signed by " + sender + "." :
              result.signed ? "Encrypted. The signature couldn't be checked, so the sender isn't confirmed." : "Encrypted, but not signed.";
            show(banner, state);
            // Saved, never opened: the type is forced so the browser can't render
            // a file from a stranger in this page's origin.
            var list = $("[data-pgp-attachments]", reading);
            mime.attachments.forEach(function (file) {
              var item = doc.createElement("li"), a = doc.createElement("a");
              a.className = "attachment";
              a.href = URL.createObjectURL(new Blob([file.data], { type: "application/octet-stream" }));
              attachmentURLs.push(a.href);
              a.download = file.name;
              a.textContent = file.name;
              item.appendChild(a);
              list.appendChild(item);
            });
            list.hidden = !mime.attachments.length;
            // The reply is written in this browser, so its quote stays here too.
            try {
              sessionStorage.setItem(replyKey(reading.getAttribute("data-folder"), reading.getAttribute("data-uid")),
                JSON.stringify({ subject: mime.subject || "", text: text, sender: sender }));
            } catch (err) { /* then the reply just has no quote */ }
          });
        });
      };
      call("status").then(function (st) {
        if (st.unlocked) { open().catch(function () { show(note, "This message wasn't encrypted to your key."); unlockForm.hidden = true; }); return; }
        unlockForm.hidden = false;
      });
      unlockForm.addEventListener("submit", function (event) {
        event.preventDefault();
        show(note, "");
        ensureUnlocked(unlockForm.elements.passphrase.value).then(function () {
          unlockForm.elements.passphrase.value = "";
          return open().catch(function () { throw new Error("This message wasn't encrypted to your key."); });
        }).catch(function (err) { show(note, err.message); });
      });
    }
  }
  readMessage();
  doc.addEventListener("elemta:reader", readMessage);

  // ---- compose -----------------------------------------------------------
  var toggle = $("[data-pgp-toggle]");
  if (toggle) {
    var form = toggle.closest("form"), status = $("[data-pgp-status]"), passRow = $("[data-pgp-passphrase]");
    var saveButton = $('button[name="op"][value="save"]', form), attach = $("#attachments");
    // Encoded twice, files nearly double on their way into the message.
    var maxFiles = 15 * 1048576;
    var refresh = function () {
      var on = toggle.checked;
      // A draft is stored on the server, in the clear. An encrypted message has
      // no draft, rather than a copy nobody meant to keep there.
      if (saveButton) saveButton.disabled = on;
      show(status, on ? "Sent encrypted and signed, attachments too, to you as well. Drafts are off for this message." : "");
      if (on) call("status").then(function (st) { passRow.hidden = st.unlocked; });
      else passRow.hidden = true;
    };
    toggle.addEventListener("change", refresh);
    // A reply to encrypted mail stays encrypted unless someone decides otherwise,
    // and its quote comes from this browser, because the server can't read it.
    var original = form.elements.orig_uid ? replyKey(form.elements.orig_f.value, form.elements.orig_uid.value) : "";
    var stash = null;
    try {
      stash = original ? JSON.parse(sessionStorage.getItem(original) || "null") : null;
      if (stash) sessionStorage.removeItem(original);
    } catch (err) { stash = null; }
    if (stash || toggle.hasAttribute("data-pgp-original")) toggle.checked = true;
    if (stash) {
      var forwarding = form.elements.mode.value === "forward";
      if (stash.subject) form.elements.subject.value = (forwarding ? "Fwd: " : "Re: ") + stash.subject.replace(/^(Re|Fwd): /i, "");
      var quote = (forwarding ? "---------- Forwarded message ----------\nFrom: " + stash.sender + "\n\n" + stash.text :
        stash.sender + " wrote:\n" + stash.text.split(/\r?\n/).map(function (l) { return "> " + l; }).join("\n"));
      form.elements.body.value = "\n\n" + quote;
      var box = $("[data-editor]");
      if (box) box.innerText = "\n\n" + quote;
    }
    refresh();
    var fileText = function (file) {
      return new Promise(function (resolve, reject) {
        var r = new FileReader();
        r.onerror = function () { reject(new Error("Couldn't read " + file.name + ".")); };
        r.onload = function () {
          resolve('Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename*=UTF-8\'\'' +
            encodeURIComponent(file.name).replace(/'/g, "%27") + "\r\n\r\n" + r.result.split(",")[1].replace(/.{1,76}/g, "$&\r\n"));
        };
        r.readAsDataURL(file);
      });
    };
    // Everything is built here and sealed as one, so the server sees no file
    // names or sizes beyond the message's own length.
    var buildMime = function (subject, text) {
      var files = attach ? Array.prototype.slice.call(attach.files) : [];
      var total = files.reduce(function (n, f) { return n + f.size; }, 0);
      if (total > maxFiles) return Promise.reject(new Error("Encrypted attachments can total " + Math.round(maxFiles / 1048576) + " MB."));
      var subjectLine = "Subject: " + subject.replace(/[\r\n]+/g, " ") + "\r\n";
      var textPart = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n";
      var body = text.replace(/\r?\n/g, "\r\n");
      if (!files.length) {
        return Promise.resolve('Content-Type: text/plain; charset=utf-8; protected-headers="v1"\r\nContent-Transfer-Encoding: 8bit\r\n' + subjectLine + "\r\n" + body);
      }
      var boundary = "elemta-" + crypto.getRandomValues(new Uint32Array(4)).join("");
      return Promise.all(files.map(fileText)).then(function (parts) {
        var out = 'Content-Type: multipart/mixed; boundary="' + boundary + '"; protected-headers="v1"\r\n' + subjectLine + "\r\n--" + boundary + "\r\n" + textPart + "\r\n" + body + "\r\n";
        parts.forEach(function (p) { out += "--" + boundary + "\r\n" + p; });
        return out + "--" + boundary + "--\r\n";
      });
    };
    var recipients = function () {
      return ["to", "cc", "bcc"].map(function (n) { return form.elements[n] ? form.elements[n].value : ""; }).join(",")
        .split(/[,;]/).map(function (s) { var m = /<([^>]+)>/.exec(s); return (m ? m[1] : s).trim(); }).filter(Boolean);
    };
    var bodyText = function () {
      var editor = $("[data-editor]"), wrap = $("[data-editor-wrap]");
      return editor && wrap && !wrap.hidden ? editor.innerText : form.elements.body.value;
    };
    form.addEventListener("submit", function (event) {
      var button = event.submitter;
      if (!toggle.checked || !button || button.value !== "send") return;
      event.preventDefault();
      event.stopImmediatePropagation();
      show(status, "Encrypting…");
      var addresses = recipients(), subject = form.elements.subject.value;
      button.disabled = true;
      ensureUnlocked(form.elements.pgp_passphrase.value).then(function () {
        return api("/api/pgp/lookup", { addresses: addresses.join("\n") });
      }).then(function (found) {
        var have = {};
        found.forEach(function (k) { have[k.address.toLowerCase()] = k; });
        var missing = addresses.filter(function (a) { return !have[a.toLowerCase()]; });
        if (!addresses.length) throw new Error("Add a recipient.");
        if (missing.length) throw new Error("No PGP key found for " + missing.join(", ") + ". Send without encryption, or ask them for their key.");
        var changed = found.filter(function (k) { return k.status === "changed"; });
        if (changed.length && !window.confirm("The key for " + changed.map(function (k) { return k.address; }).join(", ") +
            " has changed since you last wrote to them. That can be a new device, or someone intercepting your mail. Send anyway?\n\nNew key: " + changed.map(function (k) { return grouped(k.fingerprint); }).join("\n"))) {
          throw new Error("Not sent. Check the new key with them first.");
        }
        return buildMime(subject, bodyText()).then(function (protectedPart) {
          return call("encrypt", { text: protectedPart, recipientKeys: found.map(function (k) { return k.public_key; }) });
        }).then(function (out) {
          var data = new FormData(form);
          // Nothing readable leaves this page.
          ["body", "html", "attachments"].forEach(function (n) { data.delete(n); });
          data.set("subject", "...");
          data.set("format", "text");
          data.set("op", "send");
          data.delete("pgp_passphrase");
          data.set("pgp_message", out.message);
          return fetch(form.action, { method: "POST", body: data, credentials: "same-origin" }).then(function (r) {
            if (!r.ok) throw new Error("The message couldn't be sent. Nothing was lost: try again.");
            return Promise.all(found.map(function (k) {
              return api("/api/pgp/pin", { address: k.address, fingerprint: k.fingerprint }).catch(function () {});
            })).then(function () { location.href = r.url; });
          });
        });
      }).catch(function (err) {
        button.disabled = false;
        show(status, err.message);
      });
    }, true);
  }
}());
