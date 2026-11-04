// PGP in the browser, in a shared worker. Keeping the crypto here means the
// unlocked key is never in a page's memory, so a bug in a page can't simply read
// it. The passphrase never leaves this browser, and the server only ever sees
// the key locked.
//
// The webmail is ordinary pages, and a worker dies with the last page using it,
// which with one tab is every click. So that reading mail doesn't ask for the
// passphrase each time, an unlocked key is kept in IndexedDB, sealed under an
// AES key the browser won't let anyone export. It belongs to one account, and
// goes on sign-out or after half an hour unused.
"use strict";
importScripts("openpgp.min.js");

var IDLE = 30 * 60 * 1000;
var unlocked = null, unlockedOwner = "", idleTimer = null;

// The strongest setting of the standard protection, which every OpenPGP program
// can read. Argon2 would be stronger, but Thunderbird can't import it.
var config = { s2kIterationCountByte: 255 };

function store(mode, run) {
  return new Promise(function (resolve, reject) {
    var open = indexedDB.open("elemta-pgp", 1);
    open.onupgradeneeded = function () { open.result.createObjectStore("session"); };
    open.onerror = function () { reject(open.error); };
    open.onsuccess = function () {
      var request = run(open.result.transaction("session", mode).objectStore("session"));
      request.onsuccess = function () { open.result.close(); resolve(request.result); };
      request.onerror = function () { open.result.close(); reject(request.error); };
    };
  });
}

function forget() {
  unlocked = null;
  unlockedOwner = "";
  clearTimeout(idleTimer);
  return store("readwrite", function (s) { return s.delete("key"); }).catch(function () {});
}

function touch() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(forget, IDLE);
  store("readwrite", function (s) { return s.get("key"); }).then(function (saved) {
    if (saved) { saved.expires = Date.now() + IDLE; return store("readwrite", function (s) { return s.put(saved, "key"); }); }
  }).catch(function () {});
}

// keep seals the unlocked key. Failing to is no harm: the passphrase is asked for
// again, on the next page.
function keep(owner) {
  var iv = crypto.getRandomValues(new Uint8Array(12));
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]).then(function (wrap) {
    return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, wrap, new TextEncoder().encode(unlocked.armor())).then(function (data) {
      var saved = { wrap: wrap, iv: iv, data: data, owner: owner, expires: Date.now() + IDLE };
      return store("readwrite", function (s) { return s.put(saved, "key"); });
    });
  }).catch(function () {});
}

function restore(owner) {
  if (unlocked && unlockedOwner === owner) return Promise.resolve();
  if (unlocked) { unlocked = null; unlockedOwner = ""; }
  return store("readonly", function (s) { return s.get("key"); }).then(function (saved) {
    if (!saved) return;
    if (saved.expires < Date.now() || saved.owner !== owner) return forget();
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: saved.iv }, saved.wrap, saved.data).then(function (plain) {
      return openpgp.readPrivateKey({ armoredKey: new TextDecoder().decode(plain) });
    }).then(function (key) {
      unlocked = key;
      unlockedOwner = owner;
      touch();
    });
  }).catch(function () {});
}

function keysFrom(armored) {
  return Promise.all((armored || []).map(function (k) { return openpgp.readKey({ armoredKey: k }); }));
}

var actions = {
  status: function () {
    return { unlocked: !!unlocked, fingerprint: unlocked ? unlocked.getFingerprint().toUpperCase() : "" };
  },
  lock: function () { return forget().then(function () { return {}; }); },
  generate: function (m) {
    return openpgp.generateKey({
      // The classic Curve25519 format. The library's newer "curve25519" type
      // uses RFC 9580 algorithms that GnuPG 2.4 can't read, so its users could
      // neither decrypt this mail nor write to us.
      type: "ecc", curve: "curve25519Legacy", userIDs: [{ name: m.name, email: m.email }], passphrase: m.passphrase, format: "armored", config: config
    }).then(function (pair) {
      return openpgp.readKey({ armoredKey: pair.publicKey }).then(function (key) {
        return { publicKey: pair.publicKey, privateKey: pair.privateKey, fingerprint: key.getFingerprint().toUpperCase() };
      });
    });
  },
  // A key from elsewhere comes back locked with the new passphrase, unlocked
  // with the old one first if it has one.
  importKey: function (m) {
    return openpgp.readPrivateKey({ armoredKey: m.armored }).then(function (key) {
      var open = key.isDecrypted() ? Promise.resolve(key) : openpgp.decryptKey({ privateKey: key, passphrase: m.oldPassphrase });
      return open.then(function (plain) {
        return openpgp.encryptKey({ privateKey: plain, passphrase: m.passphrase, config: config }).then(function (locked) {
          return { publicKey: locked.toPublic().armor(), privateKey: locked.armor(), fingerprint: locked.getFingerprint().toUpperCase() };
        });
      });
    });
  },
  unlock: function (m) {
    return openpgp.readPrivateKey({ armoredKey: m.privateKey }).then(function (key) {
      return openpgp.decryptKey({ privateKey: key, passphrase: m.passphrase });
    }).then(function (key) {
      unlocked = key;
      unlockedOwner = m.owner;
      touch();
      return keep(m.owner).then(actions.status);
    });
  },
  decrypt: function (m) {
    if (!unlocked) return Promise.reject(new Error("locked"));
    touch();
    return Promise.all([openpgp.readMessage({ armoredMessage: m.message }), keysFrom(m.senderKeys)]).then(function (got) {
      return openpgp.decrypt({ message: got[0], decryptionKeys: unlocked, verificationKeys: got[1], format: "binary" });
    }).then(function (out) {
      return Promise.all(out.signatures.map(function (s) {
        return s.verified.then(function () { return true; }, function () { return false; });
      })).then(function (checks) {
        return { data: out.data, signed: checks.length > 0, verified: checks.length > 0 && checks.every(Boolean) };
      });
    });
  },
  // A signature needs no private key, so this works with the key locked.
  verify: function (m) {
    return keysFrom(m.senderKeys).then(function (keys) {
      if (m.cleartext) {
        return openpgp.readCleartextMessage({ cleartextMessage: m.cleartext }).then(function (message) {
          return openpgp.verify({ message: message, verificationKeys: keys });
        });
      }
      return Promise.all([openpgp.createMessage({ binary: m.content }), openpgp.readSignature({ armoredSignature: m.signature })]).then(function (got) {
        return openpgp.verify({ message: got[0], signature: got[1], verificationKeys: keys });
      });
    }).then(function (out) {
      return Promise.all(out.signatures.map(function (s) {
        return s.verified.then(function () { return true; }, function () { return false; });
      }));
    }).then(function (checks) {
      return { verified: checks.length > 0 && checks.every(Boolean) };
    });
  },
  // To every recipient and to the sender, so Sent stays readable.
  encrypt: function (m) {
    if (!unlocked) return Promise.reject(new Error("locked"));
    touch();
    return Promise.all([keysFrom(m.recipientKeys), openpgp.createMessage({ text: m.text })]).then(function (got) {
      return openpgp.encrypt({ message: got[1], encryptionKeys: got[0].concat([unlocked.toPublic()]), signingKeys: unlocked, format: "armored" });
    }).then(function (armored) { return { message: armored }; });
  }
};

function serve(port) {
  port.onmessage = function (event) {
    var m = event.data, run = actions[m.action];
    Promise.resolve().then(function () {
      if (!run) throw new Error("unknown action");
      return m.action === "lock" || m.action === "unlock" ? null : restore(m.owner);
    }).then(function () {
      return run(m);
    }).then(function (result) {
      port.postMessage({ id: m.id, result: result });
    }).catch(function (err) {
      port.postMessage({ id: m.id, error: String(err && err.message || err) });
    });
  };
}

// As a shared worker, or a plain one where a browser has no shared workers, which
// costs only asking for the passphrase on each page.
if (typeof SharedWorkerGlobalScope !== "undefined" && self instanceof SharedWorkerGlobalScope) {
  self.onconnect = function (event) { serve(event.ports[0]); };
} else {
  serve(self);
}
