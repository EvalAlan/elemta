// Elemta Webmail progressive enhancement.
//
// Every page works without this file: forms post, links navigate. The
// script adds what plain HTML can't do well: keyboard shortcuts, select-all,
// confirmations, an unsaved-changes guard, address autocomplete, live unread
// counts and time zone detection. It loads under a CSP of script-src 'self',
// so it uses no inline handlers, eval or string timers.
(function () {
  "use strict";

  var doc = document;
  var root = doc.documentElement;
  root.classList.add("js");
  var body = doc.body;
  var csrf = body.getAttribute("data-csrf") || "";

  function $(sel, ctx) { return (ctx || doc).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || doc).querySelectorAll(sel)); }

  function post(url, data) {
    var form = new URLSearchParams(data);
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString()
    });
  }

  // ---- confirmations -------------------------------------------------------
  // A button or link with a non-empty data-confirm asks first.
  doc.addEventListener("click", function (e) {
    var el = e.target.closest("[data-confirm]");
    if (!el) return;
    var msg = el.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);

  // ---- bulk selection ------------------------------------------------------
  var bulk = $("#bulk");
  if (bulk) {
    var boxes = function () { return $$('input[name="uid"]', bulk); };
    var all = $("[data-select-all]", bulk);
    var sync = function () {
      var n = boxes().filter(function (b) { return b.checked; }).length;
      bulk.classList.toggle("has-selection", n > 0);
      if (all) {
        all.checked = n > 0 && n === boxes().length;
        all.indeterminate = n > 0 && n < boxes().length;
      }
      $$(".row-wrap", bulk).forEach(function (row) {
        var b = $('input[name="uid"]', row);
        row.classList.toggle("checked", !!(b && b.checked));
      });
    };
    bulk.addEventListener("change", function (e) {
      if (e.target === all) {
        boxes().forEach(function (b) { b.checked = all.checked; });
      }
      sync();
    });
    // Moving from the dropdown shouldn't need a second click.
    var dest = $("#bulk-dest");
    if (dest) {
      dest.addEventListener("change", function () {
        if (!dest.value) return;
        var btn = $('button[value="move"]', bulk);
        if (btn) btn.click();
      });
    }
    sync();
  }

  // ---- unsaved changes ---------------------------------------------------
  $$("form[data-unsaved-warning]").forEach(function (form) {
    var dirty = false;
    form.addEventListener("input", function () { dirty = true; });
    form.addEventListener("change", function () { dirty = true; });
    form.addEventListener("submit", function () { dirty = false; });
    window.addEventListener("beforeunload", function (e) {
      if (dirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    });
    $$("[data-discard]", form).forEach(function (a) {
      a.addEventListener("click", function (e) {
        if (dirty && !window.confirm("Discard this message?")) {
          e.preventDefault();
          return;
        }
        dirty = false;
      });
    });
  });

  // ---- compose -----------------------------------------------------------
  var bodyField = $("textarea[data-cursor-top]");
  if (bodyField) {
    bodyField.focus();
    bodyField.setSelectionRange(0, 0);
    bodyField.scrollTop = 0;
  } else if ($("form.compose")) {
    var to = $("#to");
    if (to && !to.value) to.focus();
  }
  // Ctrl+Enter or Cmd+Enter sends.
  var sendBtn = $("[data-submit-key]");
  if (sendBtn) {
    sendBtn.form.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        sendBtn.click();
      }
    });
  }

  // ---- address autocomplete ----------------------------------------------
  var addressFields = $$("input[data-addresses]");
  if (addressFields.length) {
    var suggestions = null;
    var load = function () {
      if (suggestions) return Promise.resolve(suggestions);
      return fetch("/api/addresses", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : []; })
        .then(function (list) { suggestions = list; return list; })
        .catch(function () { suggestions = []; return []; });
    };
    addressFields.forEach(function (input) { attachAutocomplete(input, load); });
  }

  function attachAutocomplete(input, load) {
    var box = doc.createElement("ul");
    box.className = "suggest";
    box.setAttribute("role", "listbox");
    box.hidden = true;
    input.setAttribute("aria-autocomplete", "list");
    input.parentNode.appendChild(box);
    var items = [];
    var active = -1;

    var current = function () {
      var v = input.value;
      var i = Math.max(v.lastIndexOf(","), v.lastIndexOf(";"));
      return { head: i >= 0 ? v.slice(0, i + 1) + " " : "", term: v.slice(i + 1).trim() };
    };
    var close = function () { box.hidden = true; active = -1; };
    var choose = function (i) {
      var c = current();
      input.value = c.head + items[i].value + ", ";
      close();
      input.focus();
    };
    var render = function () {
      box.textContent = "";
      items.forEach(function (s, i) {
        var li = doc.createElement("li");
        li.setAttribute("role", "option");
        li.textContent = s.label;
        if (s.group) li.className = "group";
        if (i === active) li.setAttribute("aria-selected", "true");
        li.addEventListener("mousedown", function (e) { e.preventDefault(); choose(i); });
        box.appendChild(li);
      });
      box.hidden = items.length === 0;
    };
    input.addEventListener("input", function () {
      var term = current().term.toLowerCase();
      if (term.length < 1) { close(); return; }
      load().then(function (list) {
        items = list.filter(function (s) { return s.label.toLowerCase().indexOf(term) >= 0; }).slice(0, 8);
        active = items.length ? 0 : -1;
        render();
      });
    });
    input.addEventListener("keydown", function (e) {
      if (box.hidden) return;
      if (e.key === "ArrowDown") { active = (active + 1) % items.length; render(); e.preventDefault(); }
      else if (e.key === "ArrowUp") { active = (active - 1 + items.length) % items.length; render(); e.preventDefault(); }
      else if ((e.key === "Enter" || e.key === "Tab") && active >= 0) { choose(active); e.preventDefault(); }
      else if (e.key === "Escape") { close(); }
    });
    input.addEventListener("blur", function () { setTimeout(close, 150); });
  }

  // ---- time zone ---------------------------------------------------------
  if (body.hasAttribute("data-detect-tz") && window.Intl) {
    try {
      var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) {
        post("/settings/timezone", { timezone: tz }).then(function (r) {
          // Times on this page were drawn in the default zone; redraw once.
          if (r.status === 204 && !sessionStorage.getItem("tz-reloaded")) {
            sessionStorage.setItem("tz-reloaded", "1");
            location.reload();
          }
        });
      }
    } catch (err) { /* private mode or an old browser: keep the default */ }
  }

  // ---- live unread counts ------------------------------------------------
  var baseTitle = doc.title.replace(/^\(\d+\) /, "");
  function refreshCounts() {
    if (doc.hidden) return;
    fetch("/api/counts", { credentials: "same-origin" })
      .then(function (r) {
        if (r.status === 401) { location.href = "/login"; return null; }
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (!data) return;
        $$("a.folder[data-folder]").forEach(function (a) {
          var name = a.getAttribute("data-folder");
          var span = $(".count", a);
          if (!span || !(name in data.unread)) return;
          var n = data.unread[name];
          var hidden = span.classList.contains("hidden-role");
          span.textContent = n > 0 && !hidden ? String(n) : "";
          span.classList.toggle("hidden", !(n > 0) || hidden);
        });
        var inbox = data.unread.INBOX || 0;
        doc.title = (inbox > 0 ? "(" + inbox + ") " : "") + baseTitle;
      })
      .catch(function () {});
  }
  if ($("a.folder[data-folder]")) {
    setInterval(refreshCounts, 60000);
    doc.addEventListener("visibilitychange", function () { if (!doc.hidden) refreshCounts(); });
  }

  // ---- keyboard shortcuts ------------------------------------------------
  var help = $("#shortcuts");
  function toggleHelp(show) {
    if (!help) return;
    help.hidden = show === undefined ? !help.hidden : !show;
    if (!help.hidden) {
      var close = $("[data-close]", help);
      if (close) close.focus();
    }
  }
  if (help) {
    help.addEventListener("click", function (e) {
      if (e.target === help || e.target.hasAttribute("data-close")) toggleHelp(false);
    });
  }

  function clickKey(k) {
    var el = $('[data-key="' + k + '"]');
    if (!el) return false;
    el.click();
    return true;
  }

  // In the list without an open message, j/k move a cursor over the rows.
  var cursor = -1;
  function rows() { return $$(".messages .row"); }
  function moveCursor(delta) {
    var r = rows();
    if (!r.length) return;
    cursor = Math.max(0, Math.min(r.length - 1, cursor + delta));
    r.forEach(function (row, i) { row.parentNode.classList.toggle("cursor", i === cursor); });
    r[cursor].focus();
  }

  var pendingG = false;
  doc.addEventListener("keydown", function (e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target;
    if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) {
      if (e.key === "Escape") t.blur();
      return;
    }
    if (help && !help.hidden) {
      if (e.key === "Escape" || e.key === "?") toggleHelp(false);
      return;
    }
    var k = e.key;
    if (pendingG) {
      pendingG = false;
      var dest = { i: "/mail?f=INBOX", c: "/calendar", t: "/tasks", k: "/contacts", s: "/settings" }[k];
      if (dest) { location.href = dest; e.preventDefault(); }
      return;
    }
    var open = $(".reader .toolbar");
    switch (k) {
      case "?": toggleHelp(true); break;
      case "g": pendingG = true; setTimeout(function () { pendingG = false; }, 1500); break;
      case "c": location.href = body.getAttribute("data-app") === "calendar" ? "/calendar/event?new=1" : "/compose"; break;
      case "/": var q = $("#q"); if (q) q.focus(); break;
      case "j": if (!clickKey("j") && !open) moveCursor(1); break;
      case "k": if (!clickKey("k") && !open) moveCursor(-1); break;
      case "Enter":
        if (cursor >= 0 && rows()[cursor]) rows()[cursor].click(); else return;
        break;
      case "x":
        var r = rows()[cursor];
        var box = r ? $('input[name="uid"]', r.parentNode) : null;
        if (box) { box.checked = !box.checked; box.dispatchEvent(new Event("change", { bubbles: true })); }
        break;
      case "u": case "r": case "a": case "f": case "s": case "e": case "#":
        if (!clickKey(k)) return;
        break;
      default: return;
    }
    e.preventDefault();
  });

  // ---- calendar ----------------------------------------------------------
  // Picking a start time moves the end time with it, keeping the duration.
  var start = $("#ev-start-time"), end = $("#ev-end-time");
  var startDate = $("#ev-start-date"), endDate = $("#ev-end-date");
  if (start && end) {
    var mins = function (v) { var p = v.split(":"); return p.length === 2 ? (+p[0]) * 60 + (+p[1]) : NaN; };
    var fmt = function (m) { m = ((m % 1440) + 1440) % 1440; var h = Math.floor(m / 60), n = m % 60; return (h < 10 ? "0" : "") + h + ":" + (n < 10 ? "0" : "") + n; };
    var dur = mins(end.value) - mins(start.value);
    start.addEventListener("change", function () {
      if (!isNaN(dur) && !isNaN(mins(start.value))) end.value = fmt(mins(start.value) + dur);
    });
    end.addEventListener("change", function () { dur = mins(end.value) - mins(start.value); });
  }
  if (startDate && endDate) {
    startDate.addEventListener("change", function () {
      if (!endDate.value || endDate.value < startDate.value) endDate.value = startDate.value;
    });
  }
  var allDay = $("#ev-allday");
  if (allDay) {
    var syncAllDay = function () { $$(".time-field").forEach(function (f) { f.hidden = allDay.checked; }); };
    allDay.addEventListener("change", syncAllDay);
    syncAllDay();
  }
  var repeat = $("#ev-repeat");
  if (repeat) {
    var syncRepeat = function () { $$(".repeat-detail").forEach(function (f) { f.hidden = !repeat.value; }); };
    repeat.addEventListener("change", syncRepeat);
    syncRepeat();
  }
  // Scroll the week and day grids to the working day.
  var grid = $(".time-grid[data-scroll-hour]");
  if (grid) {
    var slot = $('[data-hour="' + grid.getAttribute("data-scroll-hour") + '"]', grid);
    if (slot) grid.scrollTop = slot.offsetTop - 8;
  }
})();
