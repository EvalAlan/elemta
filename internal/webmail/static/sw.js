// Elemta Mail's service worker. It only shows notifications pushed by the
// mail server (new mail, event reminders) and opens the right page when
// one is clicked. It caches nothing: every page still comes from the
// server, so nothing of anyone's mail is kept here.
"use strict";

self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (event) { event.waitUntil(self.clients.claim()); });

self.addEventListener("push", function (event) {
  var d = {};
  try { d = event.data ? event.data.json() : {}; } catch (err) { d = {}; }
  var options = {
    body: d.body || "",
    tag: d.tag || "elemta",
    // A newer message to the same tag (more mail) alerts again rather
    // than replacing the old one silently.
    renotify: !!d.tag,
    requireInteraction: !!d.require,
    icon: "/static/icon-192.png",
    badge: "/static/badge-96.png",
    data: { url: d.url || "/mail" }
  };
  event.waitUntil(self.registration.showNotification(d.title || "Elemta Mail", options));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = new URL((event.notification.data || {}).url || "/mail", self.location.origin);
  // Only ever this site's own pages.
  if (target.origin !== self.location.origin) target = new URL("/mail", self.location.origin);
  event.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(function (windows) {
    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      if (new URL(w.url).origin === target.origin && "focus" in w) {
        return w.focus().then(function (focused) {
          var c = focused || w;
          return c.navigate ? c.navigate(target.href) : null;
        });
      }
    }
    return self.clients.openWindow(target.href);
  }));
});
