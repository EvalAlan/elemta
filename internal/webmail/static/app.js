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

  // ---- calendar and contact import -----------------------------------------
  // The import shows as a link (see .js .import in the stylesheet); choosing
  // a file is the confirmation, so it submits straight away.
  doc.addEventListener("change", function (e) {
    var input = e.target;
    if (!input.matches || !input.matches(".import input[type=file]")) return;
    if (input.files && input.files.length) input.form.submit();
  });

  // ---- holiday countries ---------------------------------------------------
  // Choosing a country adds its chip at once, and a chip's × removes it,
  // without submitting the form: the change is kept with Save changes.
  $$("[data-country-picker]").forEach(function (picker) {
    var list = $(".country-chips", picker);
    var none = $(".country-none", picker);
    var select = $("select", picker);
    var max = parseInt(picker.getAttribute("data-max"), 10) || 12;
    function refresh() {
      var n = list.children.length;
      none.hidden = n > 0;
      select.disabled = n >= max;
      select.options[0].textContent = n >= max ? "Limit reached" : "Add a country…";
    }
    function option(code) {
      return Array.prototype.find.call(select.options, function (o) { return o.value === code; });
    }
    select.addEventListener("change", function () {
      var o = select.options[select.selectedIndex];
      if (!o || !o.value || o.disabled) return;
      var li = doc.createElement("li");
      li.className = "country-chip";
      var input = doc.createElement("input");
      input.type = "hidden"; input.name = "holiday_extra_countries"; input.value = o.value;
      var label = doc.createElement("span");
      label.textContent = o.textContent;
      var btn = doc.createElement("button");
      btn.type = "submit"; btn.name = "holiday_extra_remove"; btn.value = o.value; btn.title = "Remove " + o.textContent;
      btn.innerHTML = '<span aria-hidden="true">×</span><span class="visually-hidden"></span>';
      btn.lastChild.textContent = "Remove " + o.textContent;
      li.append(input, label, btn);
      list.appendChild(li);
      o.disabled = true;
      select.value = "";
      refresh();
      btn.focus();
    });
    list.addEventListener("click", function (e) {
      var btn = e.target.closest("button[name=holiday_extra_remove]");
      if (!btn) return;
      e.preventDefault();
      var o = option(btn.value);
      if (o) o.disabled = false;
      btn.closest("li").remove();
      refresh();
      select.focus();
    });
    refresh();
  });

  // ---- theme ---------------------------------------------------------------
  // The toggle flips whichever theme is showing, including one that came
  // from the device's setting, applies it at once and saves it in the
  // background. Without script the button's form posts and reloads.
  var toggle = $("[data-theme-toggle]");
  if (toggle) {
    toggle.addEventListener("click", function (e) {
      e.preventDefault();
      var current = root.getAttribute("data-theme") ||
        (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      var next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      toggle.value = next === "dark" ? "light" : "dark";
      post("/settings/theme", { theme: next });
    });
  }

  // ---- appearance preview --------------------------------------------------
  // Settings' theme and colour scheme repaint the page as they're chosen, so
  // a scheme can be seen before it's saved. Nothing is stored until the form
  // is submitted; leaving the page shows the saved choice again.
  [["#palette", "data-palette"], ["#theme", "data-theme"]].forEach(function (pair) {
    var select = $(pair[0]);
    if (!select || !select.form || select.form.id !== "general") return;
    select.addEventListener("change", function () {
      if (select.value) root.setAttribute(pair[1], select.value);
      else root.removeAttribute(pair[1]);
    });
  });

  // ---- menus -------------------------------------------------------------
  // Menus are <details>, so they open without script; this closes them on
  // a click elsewhere or Escape, as menus are expected to behave.
  doc.addEventListener("click", function (e) {
    $$("details.menu[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });
  doc.addEventListener("keydown", function (e) {
    if (e.key === "Escape") $$("details.menu[open]").forEach(function (d) { d.removeAttribute("open"); });
  });

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
  var editor = $("[data-editor]");
  var plainMode = false;
  try { plainMode = localStorage.getItem("compose-format") === "plain"; } catch (err) { /* blocked storage */ }
  if (editor && !plainMode) {
    startRich(false);
  }
  var bodyField = $("textarea[data-cursor-top]");
  if (editor && !editor.closest("[hidden]") && bodyField) {
    editor.focus();
    placeCaretAtStart(editor);
  } else if (bodyField) {
    bodyField.focus();
    bodyField.setSelectionRange(0, 0);
    bodyField.scrollTop = 0;
  } else if ($("form.compose")) {
    var to = $("#to");
    if (to && !to.value) to.focus();
  }

  function placeCaretAtStart(el) {
    var range = doc.createRange();
    range.setStart(el, 0);
    range.collapse(true);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    el.scrollTop = 0;
  }

  // textToHTML mirrors the server's: escaped text, line breaks, and "> "
  // quoted lines as blockquotes.
  function textToHTML(text) {
    var out = "", depth = 0;
    text.replace(/\r\n/g, "\n").split("\n").forEach(function (line) {
      var d = 0;
      while (line.charAt(0) === ">") { d++; line = line.replace(/^> ?/, ""); }
      while (depth < d) { out += "<blockquote>"; depth++; }
      while (depth > d) { out += "</blockquote>"; depth--; }
      var div = doc.createElement("div");
      div.textContent = line;
      out += div.innerHTML + "<br>";
    });
    while (depth-- > 0) out += "</blockquote>";
    return out;
  }

  // htmlToText renders the editor as plain text for the text/plain part:
  // block elements become lines, quotes get "> ", list items get bullets
  // and links keep their address.
  function htmlToText(node) {
    var out = [];
    var line = "";
    function flush(prefix) { out.push(prefix + line); line = ""; }
    function walk(n, prefix) {
      if (n.nodeType === 3) { line += n.nodeValue.replace(/\s+/g, " "); return; }
      if (n.nodeType !== 1) return;
      var tag = n.tagName;
      if (tag === "BR") { flush(prefix); return; }
      var block = /^(P|DIV|LI|BLOCKQUOTE|H1|H2|H3|PRE|UL|OL|HR)$/.test(tag);
      if (block && line) flush(prefix);
      var p = tag === "BLOCKQUOTE" ? prefix + "> " : prefix;
      if (tag === "LI") line += (n.parentNode && n.parentNode.tagName === "OL" ? (Array.prototype.indexOf.call(n.parentNode.children, n) + 1) + ". " : "• ");
      if (tag === "HR") { line = "----------"; flush(prefix); return; }
      Array.prototype.forEach.call(n.childNodes, function (c) { walk(c, p); });
      if (tag === "A" && n.getAttribute("href") && n.textContent !== n.getAttribute("href")) line += " <" + n.getAttribute("href") + ">";
      if (block && line) flush(p);
    }
    walk(node, "");
    if (line) flush("");
    return out.join("\n").replace(/\n{3,}/g, "\n\n");
  }

  function startRich(fromPlain) {
    var wrap = $("[data-editor-wrap]"), ta = $("#body");
    if (!wrap || !ta) return;
    if (fromPlain || !editor.innerHTML.trim()) editor.innerHTML = textToHTML(ta.value);
    wrap.hidden = false;
    ta.hidden = true;
    ta.removeAttribute("required");
    $("[data-format]").value = "html";
    var r = $("[data-to-rich-wrap]");
    if (r) r.hidden = true;
  }
  function startPlain() {
    var wrap = $("[data-editor-wrap]"), ta = $("#body");
    ta.value = htmlToText(editor);
    wrap.hidden = true;
    ta.hidden = false;
    $("[data-format]").value = "text";
    var r = $("[data-to-rich-wrap]");
    if (r) r.hidden = false;
  }
  if (editor) {
    var form = editor.closest("form");
    if (plainMode) { var rw = $("[data-to-rich-wrap]"); if (rw) rw.hidden = false; }
    form.addEventListener("submit", function () {
      if ($("[data-format]").value === "html") {
        $("[data-html]").value = editor.innerHTML;
        $("#body").value = htmlToText(editor);
      }
    });
    // The selection is saved whenever it changes inside the editor, so
    // controls that take focus (the colour pickers, the selects) can put
    // it back before they act.
    var savedRange = null;
    doc.addEventListener("selectionchange", function () {
      var sel = window.getSelection();
      if (sel.rangeCount && editor.contains(sel.getRangeAt(0).commonAncestorContainer)) savedRange = sel.getRangeAt(0).cloneRange();
    });
    function restoreSelection() {
      editor.focus();
      if (savedRange) {
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(savedRange);
      }
    }
    function exec(cmd, arg) {
      restoreSelection();
      doc.execCommand(cmd, false, arg === undefined ? null : arg);
      editor.dispatchEvent(new Event("input", { bubbles: true }));
    }
    // Colours and highlights as CSS spans, which every client renders;
    // the compose sanitiser keeps only the style properties it allows.
    try { doc.execCommand("styleWithCSS", false, true); } catch (err) { /* old browser */ }

    $$(".editor-toolbar [data-cmd]").forEach(function (b) {
      b.addEventListener("mousedown", function (e) { e.preventDefault(); }); // keep the selection
      b.addEventListener("click", function () {
        var cmd = b.getAttribute("data-cmd"), arg = b.getAttribute("data-arg");
        if (cmd === "createLink") {
          arg = window.prompt("Link address (https://…)", "https://");
          if (!arg || !/^(https?:\/\/|mailto:)/i.test(arg)) return;
        }
        exec(cmd, arg || undefined);
      });
    });
    var blockSel = $("[data-block]"), fontSel = $("[data-font]"), sizeSel = $("[data-size]");
    if (blockSel) blockSel.addEventListener("change", function () { exec("formatBlock", "<" + blockSel.value + ">"); blockSel.value = "p"; });
    if (fontSel) fontSel.addEventListener("change", function () { if (fontSel.value) exec("fontName", fontSel.value); fontSel.value = ""; });
    if (sizeSel) sizeSel.addEventListener("change", function () { if (sizeSel.value) exec("fontSize", sizeSel.value); sizeSel.value = ""; });
    $$("[data-color]").forEach(function (inp) {
      inp.addEventListener("input", function () {
        var cmd = inp.getAttribute("data-color");
        restoreSelection();
        if (!doc.execCommand(cmd, false, inp.value) && cmd === "hiliteColor") doc.execCommand("backColor", false, inp.value);
        editor.dispatchEvent(new Event("input", { bubbles: true }));
      });
    });

    // ---- pictures ----
    // Pictures are embedded as data: URIs while editing; the server turns
    // them into inline attachments (cid:) when the message is sent. Large
    // photos are scaled down first, so a phone picture doesn't make a
    // 10 MB message.
    var MAX_SIDE = 2000, MAX_BYTES = 1500000;
    function readImage(file) {
      return new Promise(function (resolve, reject) {
        var r = new FileReader();
        r.onerror = reject;
        r.onload = function () {
          var url = r.result;
          if (file.size <= MAX_BYTES || file.type === "image/gif") { resolve(url); return; }
          var img = new Image();
          img.onerror = function () { resolve(url); };
          img.onload = function () {
            var scale = Math.min(1, MAX_SIDE / Math.max(img.naturalWidth, img.naturalHeight));
            var c = doc.createElement("canvas");
            c.width = Math.round(img.naturalWidth * scale);
            c.height = Math.round(img.naturalHeight * scale);
            c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
            resolve(c.toDataURL(file.type === "image/png" && file.size < 4 * MAX_BYTES ? "image/png" : "image/jpeg", 0.85));
          };
          img.src = url;
        };
        r.readAsDataURL(file);
      });
    }
    function insertImages(files) {
      files = Array.prototype.filter.call(files, function (f) { return /^image\//.test(f.type); });
      return Promise.all(files.map(readImage)).then(function (urls) {
        urls.forEach(function (u) {
          var div = doc.createElement("div");
          var img = doc.createElement("img");
          img.src = u;
          img.alt = "";
          div.appendChild(img);
          exec("insertHTML", div.innerHTML + "<br>");
        });
      });
    }
    var imageInput = $("[data-image-input]");
    var imageBtn = $("[data-insert-image]");
    if (imageBtn && imageInput) {
      imageBtn.addEventListener("mousedown", function (e) { e.preventDefault(); });
      imageBtn.addEventListener("click", function () { imageInput.click(); });
      imageInput.addEventListener("change", function () { insertImages(imageInput.files); imageInput.value = ""; });
    }
    // Files dropped on the editor: pictures go into the text, anything
    // else is added to the message's attachments.
    editor.addEventListener("dragover", function (e) { if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types, "Files") >= 0) e.preventDefault(); });
    editor.addEventListener("drop", function (e) {
      var files = e.dataTransfer && e.dataTransfer.files;
      if (!files || !files.length) return;
      e.preventDefault();
      var others = Array.prototype.filter.call(files, function (f) { return !/^image\//.test(f.type); });
      insertImages(files);
      var att = $("#attachments");
      if (others.length && att && window.DataTransfer) {
        var dt = new DataTransfer();
        Array.prototype.forEach.call(att.files, function (f) { dt.items.add(f); });
        others.forEach(function (f) { dt.items.add(f); });
        att.files = dt.files;
        att.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });

    // Clicking a picture offers sizes and removal.
    var imageBar = $("[data-image-bar]"), activeImg = null;
    editor.addEventListener("click", function (e) {
      activeImg = e.target.tagName === "IMG" ? e.target : null;
      if (imageBar) imageBar.hidden = !activeImg;
    });
    $$("[data-img-size]").forEach(function (b) {
      b.addEventListener("click", function () {
        if (!activeImg) return;
        var v = b.getAttribute("data-img-size");
        if (v === "0") activeImg.removeAttribute("width"); else activeImg.setAttribute("width", v + "%");
        editor.dispatchEvent(new Event("input", { bubbles: true }));
      });
    });
    var imgRemove = $("[data-img-remove]");
    if (imgRemove) imgRemove.addEventListener("click", function () {
      if (activeImg) { activeImg.remove(); activeImg = null; imageBar.hidden = true; editor.dispatchEvent(new Event("input", { bubbles: true })); }
    });

    var tableBtn = $("[data-insert-table]");
    if (tableBtn) {
      tableBtn.addEventListener("mousedown", function (e) { e.preventDefault(); });
      tableBtn.addEventListener("click", function () {
        var spec = window.prompt("Table size (columns × rows)", "3 x 3");
        var m = spec && spec.match(/(\d+)\s*[x×*,]\s*(\d+)/i);
        if (!m) return;
        var cols = Math.min(+m[1], 12), rows = Math.min(+m[2], 50), html = '<table border="1" cellpadding="6" cellspacing="0">';
        for (var r = 0; r < rows; r++) {
          html += "<tr>";
          for (var c = 0; c < cols; c++) html += "<td><br></td>";
          html += "</tr>";
        }
        exec("insertHTML", html + "</table><br>");
      });
    }

    var toPlain = $("[data-to-plain]");
    if (toPlain) toPlain.addEventListener("click", function () {
      if (editor.querySelector("b,strong,i,em,u,s,ul,ol,a,h1,h2,h3") && !window.confirm("Switch to plain text? Formatting will be removed.")) return;
      startPlain();
      try { localStorage.setItem("compose-format", "plain"); } catch (err) { /* blocked storage */ }
    });
    var toRich = $("[data-to-rich]");
    if (toRich) toRich.addEventListener("click", function () {
      startRich(true);
      try { localStorage.removeItem("compose-format"); } catch (err) { /* blocked storage */ }
      editor.focus();
    });
    // Paste keeps formatting from other apps (documents, web pages, other
    // mail) after cleaning it down to what the compose sanitiser allows,
    // so what the user sees is what will be sent. Pasted pictures (a
    // screenshot, an image copied from a page) are embedded. Ctrl+Shift+V
    // pastes plain text, as everywhere else.
    var ALLOWED = /^(P|BR|DIV|SPAN|B|STRONG|I|EM|U|S|STRIKE|SUB|SUP|UL|OL|LI|BLOCKQUOTE|PRE|CODE|H1|H2|H3|H4|HR|TABLE|THEAD|TBODY|TR|TD|TH|A|IMG|FONT)$/;
    var STYLES = ["color", "background-color", "font-family", "font-size", "font-weight", "font-style", "text-decoration", "text-align", "margin-left", "padding-left"];
    function cleanNode(node) {
      Array.prototype.slice.call(node.childNodes).forEach(function (n) {
        if (n.nodeType === 8) { n.remove(); return; }
        if (n.nodeType !== 1) return;
        if (/^(SCRIPT|STYLE|META|LINK|TITLE|HEAD|IFRAME|OBJECT|EMBED|svg|SVG|FORM|INPUT|BUTTON|SELECT|TEXTAREA)$/.test(n.tagName)) { n.remove(); return; }
        cleanNode(n);
        if (!ALLOWED.test(n.tagName)) {
          while (n.firstChild) n.parentNode.insertBefore(n.firstChild, n);
          n.remove();
          return;
        }
        var keep = {};
        STYLES.forEach(function (p) { var v = n.style.getPropertyValue(p); if (v && !/url\(/i.test(v)) keep[p] = v; });
        Array.prototype.slice.call(n.attributes).forEach(function (a) {
          var name = a.name.toLowerCase();
          var ok = (name === "href" && n.tagName === "A" && /^(https?:|mailto:)/i.test(a.value)) ||
            (name === "src" && n.tagName === "IMG" && /^data:image\//i.test(a.value)) ||
            (/^(align|colspan|rowspan|border|cellpadding|cellspacing|width|alt|color|face|size)$/.test(name));
          if (!ok) n.removeAttribute(a.name);
        });
        Object.keys(keep).forEach(function (p) { n.style.setProperty(p, keep[p]); });
        if (n.tagName === "IMG" && !n.getAttribute("src")) n.remove();
      });
    }
    var plainPaste = false;
    editor.addEventListener("keydown", function (e) { plainPaste = e.shiftKey && (e.ctrlKey || e.metaKey) && (e.key === "V" || e.key === "v"); });
    editor.addEventListener("paste", function (e) {
      var cd = e.clipboardData || window.clipboardData;
      if (!cd) return;
      var images = Array.prototype.filter.call(cd.files || [], function (f) { return /^image\//.test(f.type); });
      var html = cd.getData("text/html"), text = cd.getData("text/plain");
      e.preventDefault();
      if (images.length && !text) { insertImages(images); return; }
      if (html && !plainPaste) {
        var parsed = new DOMParser().parseFromString(html, "text/html");
        cleanNode(parsed.body);
        exec("insertHTML", parsed.body.innerHTML);
        return;
      }
      if (text) exec("insertHTML", textToHTML(text).replace(/<br>$/, ""));
      else if (images.length) insertImages(images);
    });
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

  // ---- rooms on the event form ----------------------------------------------
  // A room is a guest, so it goes in the guest list, where availability and
  // invitations already work.
  var roomPicker = $("[data-room-picker]");
  if (roomPicker) {
    roomPicker.addEventListener("change", function () {
      var field = $("#ev-guests"), address = roomPicker.value;
      roomPicker.value = "";
      if (!field || !address || field.value.indexOf(address) >= 0) return;
      field.value = field.value.trim() ? field.value.replace(/[,\s]*$/, "") + ", " + address : address;
      field.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }

  // ---- availability on the event form --------------------------------------
  // Guests' busy times for the chosen day, from the free/busy they publish.
  // Hidden until there is someone to show, and if the server has none.
  var avail = $("[data-freebusy]");
  if (avail) {
    var fbLabel = $("[data-freebusy-label]");
    var guests = $("#ev-guests"), startDate = $("#ev-start-date"), startTime = $("#ev-start-time"), endTime = $("#ev-end-time"), endDate = $("#ev-end-date"), allDay = $("#ev-allday");
    var fbTimer = null, fbSeq = 0;
    var minutesOf = function (v) { var p = (v || "").split(":"); return p.length < 2 ? null : Number(p[0]) * 60 + Number(p[1]); };
    var hide = function () { avail.hidden = true; if (fbLabel) fbLabel.hidden = true; };
    var fbRender = function (data) {
      avail.textContent = "";
      if (!data || !data.people || data.people.length < 2) { hide(); return; }
      var slotFrom = allDay && allDay.checked ? 0 : minutesOf(startTime && startTime.value);
      var slotTo = allDay && allDay.checked ? data.minutes : minutesOf(endTime && endTime.value);
      if (endDate && endDate.value && startDate && endDate.value !== startDate.value) slotTo = data.minutes;
      if (slotFrom === null) slotFrom = 9 * 60;
      if (slotTo === null || slotTo <= slotFrom) slotTo = Math.min(data.minutes, slotFrom + 60);
      // Working hours, widened to take in the proposed time.
      var from = Math.min(7 * 60, Math.floor(slotFrom / 60) * 60), to = Math.max(20 * 60, Math.ceil(slotTo / 60) * 60);
      var pct = function (m) { return ((Math.max(from, Math.min(to, m)) - from) / (to - from) * 100) + "%"; };
      var hours = doc.createElement("div"); hours.className = "fb-hours";
      for (var h = from; h <= to; h += 120) { var s = doc.createElement("span"); s.style.left = pct(h); s.textContent = String(h / 60).padStart(2, "0") + ":00"; hours.appendChild(s); }
      var head = doc.createElement("div"); head.className = "fb-row"; head.appendChild(doc.createElement("span")); head.appendChild(hours); avail.appendChild(head);
      var conflicts = [];
      data.people.forEach(function (p, i) {
        var row = doc.createElement("div"); row.className = "fb-row";
        var who = doc.createElement("span"); who.className = "fb-who"; who.textContent = i === 0 ? "You" : p.address; who.title = p.address; row.appendChild(who);
        if (!p.known) {
          var u = doc.createElement("span"); u.className = "fb-unknown"; u.textContent = "No availability shared"; row.appendChild(u);
        } else {
          var track = doc.createElement("div"); track.className = "fb-track";
          p.busy.forEach(function (b) {
            if (b.to <= from || b.from >= to) return;
            var d = doc.createElement("span"); d.className = "fb-busy" + (b.tentative ? " tentative" : "");
            d.style.left = pct(b.from); d.style.width = "calc(" + pct(b.to) + " - " + pct(b.from) + ")";
            track.appendChild(d);
          });
          var slot = doc.createElement("span"); slot.className = "fb-slot"; slot.style.left = pct(slotFrom); slot.style.width = "calc(" + pct(slotTo) + " - " + pct(slotFrom) + ")";
          track.appendChild(slot);
          row.appendChild(track);
          if (i > 0 && p.busy.some(function (b) { return !b.tentative && b.from < slotTo && b.to > slotFrom; })) conflicts.push(p.address);
        }
        avail.appendChild(row);
      });
      var sum = doc.createElement("p"); sum.className = "fb-summary" + (conflicts.length ? " conflict" : "");
      sum.textContent = conflicts.length ? "Busy at this time: " + conflicts.join(", ") : "No conflicts with the guests who share their availability.";
      avail.appendChild(sum);
      avail.hidden = false; if (fbLabel) fbLabel.hidden = false;
    };
    var fbLoad = function () {
      if (!startDate || !startDate.value || !guests.value.trim()) { hide(); return; }
      var seq = ++fbSeq;
      fetch("/api/freebusy?date=" + encodeURIComponent(startDate.value) + "&attendees=" + encodeURIComponent(guests.value), { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) { if (seq === fbSeq) fbRender(data); })
        .catch(hide);
    };
    var fbSoon = function () { clearTimeout(fbTimer); fbTimer = setTimeout(fbLoad, 400); };
    [guests, startDate, startTime, endTime, endDate, allDay].forEach(function (el) { if (el) el.addEventListener("change", fbSoon); });
    guests.addEventListener("input", fbSoon);
    fbLoad();
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

  // ---- new mail ----------------------------------------------------------
  // IDLE events trigger counts and list refreshes; polling covers servers
  // or proxies that cannot keep the event stream open.
  var baseTitle = doc.title.replace(/^\(\d+\) /, "");
  var knownTotals = {};
  $$("a.folder[data-folder]").forEach(function (a) {
    knownTotals[a.getAttribute("data-folder")] = +a.getAttribute("data-total") || 0;
  });
  var listEl = function () { return $("ol.messages"); };

  function rowSummaries(ol) {
    var out = {};
    $$("li[data-uid]", ol).forEach(function (li) {
      out[li.getAttribute("data-uid")] = {
        unread: li.classList.contains("unread"),
        from: ($(".from", li) || {}).textContent || "",
        subject: ($(".subject", li) || {}).textContent || ""
      };
    });
    return out;
  }

  function busy() {
    return !!($("#bulk.has-selection") || $("details.menu[open]") || ctxMenuOpen() ||
      new URLSearchParams(location.search).get("page") > 1);
  }
  function ctxMenuOpen() { return !!$(".ctx-menu"); }

  function showNewMailPill() {
    if ($(".new-mail-pill")) return;
    var b = doc.createElement("button");
    b.type = "button";
    b.className = "new-mail-pill";
    b.textContent = "New mail · Show";
    b.addEventListener("click", function () { location.reload(); });
    var head = $(".list-head");
    if (head) head.insertAdjacentElement("afterend", b);
  }

  function notifyNew(added) {
    if (!doc.hidden || !window.Notification || Notification.permission !== "granted" || !added.length) return;
    try {
      if (added.length === 1) {
        var n = new Notification(added[0].from.trim() || "New mail", { body: added[0].subject.trim(), tag: "elemta-new-mail" });
        n.onclick = function () { window.focus(); };
      } else {
        new Notification(added.length + " new messages", { body: added.slice(0, 3).map(function (m) { return m.from.trim() + ": " + m.subject.trim(); }).join("\n"), tag: "elemta-new-mail" });
      }
    } catch (err) { /* some browsers only notify from a service worker */ }
  }

  function refreshList() {
    var old = listEl();
    if (!old) return;
    if (busy()) { showNewMailPill(); return; }
    var before = rowSummaries(old);
    fetch(location.href, { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (!html) return;
        var fresh = new DOMParser().parseFromString(html, "text/html");
        var next = $("ol.messages", fresh);
        if (!next || busy() || !listEl()) { if (next) showNewMailPill(); return; }
        var after = rowSummaries(next);
        var added = [];
        $$("li[data-uid]", next).forEach(function (li) {
          var id = li.getAttribute("data-uid");
          if (!before[id]) {
            li.classList.add("new-arrival");
            if (after[id].unread) added.push(after[id]);
          }
        });
        listEl().replaceWith(doc.importNode(next, true));
        var count = $(".list-head .mono", fresh), cur = $(".list-head .mono");
        if (count && cur) cur.textContent = count.textContent;
        notifyNew(added);
      })
      .catch(function () {});
  }

  // ---- new-mail sound --------------------------------------------------------
  // Generated here, so there are no audio files to serve and the CSP needs no
  // media source. Each note is [frequency, start, length, peak, partials], where
  // partials are overtones as [multiple, level]; a bell is mostly overtones.
  var BELL = [[2.76, 0.4], [5.4, 0.2]], WOOD = [[3.9, 0.25]];
  var TONES = {
    chime: [[659.25, 0, 0.5, 0.2], [987.77, 0.13, 0.7, 0.2]],
    bell: [[880, 0, 1.3, 0.2, BELL]],
    ping: [[1318.51, 0, 0.3, 0.16]],
    marimba: [[523.25, 0, 0.35, 0.24, WOOD], [659.25, 0.1, 0.35, 0.24, WOOD], [783.99, 0.2, 0.5, 0.24, WOOD]],
    drop: [[1046.5, 0, 0.16, 0.18], [523.25, 0.1, 0.4, 0.2]]
  };
  var audio = null;
  function audioContext() {
    var Ctx = window.AudioContext || window.webkitAudioContext;
    if (!audio && Ctx) audio = new Ctx();
    return audio;
  }
  function playTone(name) {
    var notes = TONES[name], ctx = audioContext();
    if (!notes || !ctx) return;
    if (ctx.state === "suspended") ctx.resume();
    notes.forEach(function (n) {
      [[1, 1]].concat(n[4] || []).forEach(function (p) {
        var at = ctx.currentTime + n[1], osc = ctx.createOscillator(), gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.value = n[0] * p[0];
        gain.gain.setValueAtTime(0.0001, at);
        gain.gain.exponentialRampToValueAtTime(n[3] * p[1], at + 0.01);
        gain.gain.exponentialRampToValueAtTime(0.0001, at + n[2] / p[0]);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(at);
        osc.stop(at + n[2] / p[0] + 0.02);
      });
    });
  }
  var mailSound = doc.body.getAttribute("data-mail-sound");
  // A browser only lets a page make sound once someone has used that page, and
  // a tab left open and untouched must not save it all up for later.
  if (mailSound || body.getAttribute("data-reminder-sound")) {
    ["pointerdown", "keydown"].forEach(function (kind) {
      doc.addEventListener(kind, function unlock() {
        doc.removeEventListener(kind, unlock, true);
        var ctx = audioContext();
        if (ctx && ctx.state === "suspended") ctx.resume();
      }, true);
    });
  }
  // Every open tab hears about the same message, and only one should ring.
  function chime() {
    if (audio && audio.state !== "running") { try { audio.resume(); } catch (err) { /* no sound, then */ } }
    try {
      var now = Date.now(), last = Number(localStorage.getItem("elemta-mail-sound")) || 0;
      if (now - last < 3000) return;
      localStorage.setItem("elemta-mail-sound", String(now));
    } catch (err) { /* private windows: every tab rings */ }
    playTone(mailSound);
  }
  var preview = $("[data-sound-preview]");
  if (preview) {
    preview.addEventListener("click", function () {
      var choice = $("#mail_sound");
      if (choice) playTone(choice.value);
    });
  }

  var checkingMail = false, pendingMailCheck = false, knownInbox = null;
  function checkMail() {
    if (checkingMail) { pendingMailCheck = true; return; }
    checkingMail = true;
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
        var ol = listEl(), folder = ol && ol.getAttribute("data-folder");
        var totals = data.total || {};
        // New mail adds a message and an unread one. Marking something unread
        // adds no message, and reading one while another arrives adds neither
        // count on its own, so both have to rise. The first check only learns
        // where things stand.
        var inboxTotal = totals.INBOX;
        if (mailSound && knownInbox && inboxTotal > knownInbox.total && inbox > knownInbox.unread) chime();
        if (inboxTotal !== undefined) knownInbox = { total: inboxTotal, unread: inbox };
        if (folder && folder in totals && folder in knownTotals && totals[folder] > knownTotals[folder]) refreshList();
        Object.keys(totals).forEach(function (k) { knownTotals[k] = totals[k]; });
      })
      .catch(function () {})
      .then(function () {
        checkingMail = false;
        if (pendingMailCheck) { pendingMailCheck = false; checkMail(); }
      });
  }
  // With a sound on, pages without a mail list watch too: the point is hearing
  // about mail while doing something else.
  if ($("a.folder[data-folder]") || mailSound) {
    var mailTimer = null, stream = null;
    function fallback() {
      if (!mailTimer) mailTimer = setInterval(checkMail, 60000);
    }
    if (window.EventSource) {
      var currentList = listEl();
      var watchedFolder = currentList ? currentList.getAttribute("data-folder") : "INBOX";
      function connectMail() {
        stream = new EventSource("/api/events?folder=" + encodeURIComponent(watchedFolder || "INBOX"));
        stream.addEventListener("ready", function () { clearInterval(mailTimer); mailTimer = null; checkMail(); });
        stream.addEventListener("mail", checkMail);
        stream.addEventListener("unavailable", function () { stream.close(); fallback(); });
        stream.addEventListener("signedout", function () { stream.close(); location.href = "/login"; });
        stream.onerror = fallback;
      }
      connectMail();
      // The stream watches the open folder. Reading another one, only this
      // notices the inbox.
      if (mailSound && watchedFolder && watchedFolder !== "INBOX") setInterval(checkMail, 60000);
      window.addEventListener("pagehide", function () { stream.close(); });
      window.addEventListener("pageshow", function (event) { if (event.persisted) connectMail(); });
    } else { fallback(); }
    doc.addEventListener("visibilitychange", function () { if (!doc.hidden) checkMail(); });
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

  // ---- refresh -----------------------------------------------------------
  // The refresh link reloads the list (which also checks the server for new
  // mail); the spin shows it was pressed while the page loads.
  $$("[data-refresh]").forEach(function (a) {
    a.addEventListener("click", function () { a.classList.add("spinning"); });
  });

  // ---- message frame -----------------------------------------------------
  // The message body is a sandboxed, script-free frame on our origin. It's
  // sized to its content here, so a long message scrolls with the page
  // instead of inside a box; images that load later resize it again.
  // Conversation cards load their message when first opened.
  // Expanding a card is reading that message, as opening it is. The frame
  // only peeks, so a conversation read card by card stayed unread in the list
  // however much of it had been read.
  function readCard(card) {
    var folder = card.getAttribute("data-unread-folder"), uid = card.getAttribute("data-unread-uid");
    if (!folder || !uid || !csrf) return;
    card.removeAttribute("data-unread-folder");
    card.removeAttribute("data-unread-uid");
    // Manual, so the action's redirect isn't fetched: it would render the
    // whole mail page only to be thrown away.
    fetch("/mail/action", {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ f: folder, uid: uid, op: "read" }).toString()
    }).then(function (r) {
      if (!r.ok && r.type !== "opaqueredirect") throw new Error("not marked");
      var dot = $(".unread-dot", card);
      if (dot) dot.remove();
      refreshRows();
      checkMail();
    }).catch(function () {
      card.setAttribute("data-unread-folder", folder);
      card.setAttribute("data-unread-uid", uid);
    });
  }

  // refreshRows brings the list's read state and links up to date without
  // replacing it, for a change made from the reader.
  function refreshRows() {
    if (!listEl()) return;
    fetch(location.href, { credentials: "same-origin" })
      .then(function (r) { return r.ok && !r.redirected ? r.text() : null; })
      .then(function (html) { if (html) syncRows(new DOMParser().parseFromString(html, "text/html")); })
      .catch(function () {});
  }

  function setUpFrames(scope) {
    $$("details.thread-card", scope).forEach(function (card) {
      card.addEventListener("toggle", function () {
        var f = $("iframe[data-src]", card);
        if (card.open && f && !f.getAttribute("src")) f.setAttribute("src", f.getAttribute("data-src"));
        if (card.open) readCard(card);
      });
    });
    $$("iframe[data-autosize]", scope).forEach(function (frame) {
      var fit = function () {
        try {
          var d = frame.contentDocument;
          if (!d || !d.documentElement) return;
          // The body's height is the content's; the document's is never less
          // than the frame, so measuring it could only ever grow the frame.
          var b = d.body || d.documentElement;
          var cs = frame.contentWindow.getComputedStyle(b);
          var h = b.getBoundingClientRect().height + parseFloat(cs.marginTop || 0) + parseFloat(cs.marginBottom || 0);
          frame.style.height = Math.ceil(Math.max(120, h, b.scrollHeight)) + 2 + "px";
          // Sized to fit, the frame needs no scrollbar of its own.
          d.documentElement.style.overflowY = "hidden";
        } catch (err) { /* not same-origin (an old cached page): keep the fixed height */ }
      };
      frame.addEventListener("load", function () {
        frame.classList.add("autosized");
        fit();
        try {
          if (window.ResizeObserver) new ResizeObserver(fit).observe(frame.contentDocument.body || frame.contentDocument.documentElement);
          Array.prototype.forEach.call(frame.contentDocument.images, function (img) { img.addEventListener("load", fit); });
        } catch (err) { /* see above */ }
      });
      // A frame added by the reading pane is still about:blank here, and sizing
      // that would squash it to the minimum until the message arrives.
      if (frame.contentDocument && frame.contentDocument.readyState === "complete" && frame.contentDocument.URL !== "about:blank") fit();
    });
  }
  setUpFrames(doc);

  // ---- reading pane ------------------------------------------------------
  // Opening a message from the list replaces only the reader. A full page load
  // repainted the whole app on every click and lost the list's scroll position,
  // so a message opened from further down threw the reader's user back to the
  // top of the list. The server's page is still the only source: this fetches
  // what the link would have loaded, and anything unexpected falls back to
  // following the link, so a dead session reaches the sign-in page as it always
  // did.
  var opening = 0;

  function revealSelected() {
    var row = $(".messages .selected"), list = row && row.closest(".list-scroll");
    // Only where the list is its own scroller: elsewhere this would move the page.
    if (list && window.getComputedStyle(list).overflowY !== "visible") row.scrollIntoView({ block: "nearest" });
  }

  // The rows stay, because they hold the user's ticks and the list's scroll
  // position. Only what opening a message changes is copied across.
  function syncRows(fresh) {
    $$("li[data-uid]", listEl()).forEach(function (li) {
      var next = $('li[data-uid="' + li.getAttribute("data-uid") + '"]', fresh);
      var selected = !!next && next.classList.contains("selected");
      li.classList.toggle("selected", selected);
      var link = $("a.row", li);
      if (link) {
        if (selected) link.setAttribute("aria-current", "true"); else link.removeAttribute("aria-current");
      }
      if (next) {
        li.classList.toggle("unread", next.classList.contains("unread"));
        li.toggleAttribute("data-seen", next.hasAttribute("data-seen"));
        // A conversation row opens its oldest unread message, so reading
        // one moves its link on to the next. Left as it was, the row kept
        // reopening the message just read, and the last unread one in a
        // conversation could never be reached from the list.
        ["data-open", "data-latest", "data-count"].forEach(function (name) {
          if (next.hasAttribute(name)) li.setAttribute(name, next.getAttribute(name));
        });
        var nextLink = $("a.row", next);
        if (link && nextLink) {
          link.setAttribute("href", nextLink.getAttribute("href"));
          // The contents only, so a row the keyboard is on keeps focus.
          link.replaceChildren.apply(link, Array.prototype.map.call(nextLink.childNodes, function (n) { return doc.importNode(n, true); }));
        }
      }
    });
  }

  function showMessage(url, remember) {
    var token = ++opening;
    fetch(url, { credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok || r.redirected) throw new Error("not a message page");
        return r.text();
      })
      .then(function (html) {
        if (token !== opening) return;
        var fresh = new DOMParser().parseFromString(html, "text/html");
        var next = $(".reader", fresh), panes = $(".panes", fresh), reader = $(".reader");
        if (!next || !panes || !reader || !listEl()) throw new Error("not a message page");
        var added = doc.importNode(next, true);
        reader.replaceWith(added);
        $(".panes").classList.toggle("has-message", panes.classList.contains("has-message"));
        syncRows(fresh);
        if (remember) history.pushState(null, "", url);
        baseTitle = fresh.title.replace(/^\(\d+\) /, "");
        doc.title = fresh.title;
        // In the single-pane layouts the page scrolls, not the reader.
        window.scrollTo(0, 0);
        revealSelected();
        setUpFrames(added);
        doc.dispatchEvent(new CustomEvent("elemta:reader"));
        checkMail();
      })
      .catch(function () { if (token === opening) location.href = url; });
  }

  doc.addEventListener("click", function (e) {
    if (e.defaultPrevented || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target.closest('.messages a.row, .reader a[data-key="j"], .reader a[data-key="k"]');
    if (!a || !listEl()) return;
    e.preventDefault();
    showMessage(a.href, true);
  });
  // Only the reader's own history entries land here; the rest are other pages.
  if (listEl()) {
    window.addEventListener("popstate", function () { showMessage(location.href, false); });
    revealSelected();
  }

  // ---- print -------------------------------------------------------------
  if (body.hasAttribute("data-print")) {
    window.addEventListener("load", function () { window.print(); });
  }

  // ---- reminders ---------------------------------------------------------
  // The server lists the reminders due in the next two hours and keeps each
  // listed until its event starts. At its time a reminder shows in every open
  // tab as a card in the corner, flashes the title of a tab in the background
  // and, in one tab only, plays the reminder sound and shows a desktop
  // notification. Dismissing or snoozing it in one tab does the same in the
  // others. That state lives in localStorage, so a reload or a new tab
  // doesn't bring back a dismissed reminder or ring again for one that rang.
  var reminderSound = body.getAttribute("data-reminder-sound") || "";
  var REMINDERS = "elemta-reminders", SNOOZE_MS = 5 * 60 * 1000, BELL_MARK = "🔔 ";
  var timers = {}, cards = {}, known = {}, memState = {}, flashTimer = null, ticker = null;

  // Each entry is {d: dismissed, s: snoozed until, rang: the due time it
  // last rang for, t: when it last changed}, all times in milliseconds.
  function readState() {
    try {
      var raw = localStorage.getItem(REMINDERS);
      if (raw !== null) return JSON.parse(raw) || {};
    } catch (err) { /* blocked or corrupt: fall back to this tab's copy */ }
    return memState;
  }
  function writeState(key, change) {
    var st = readState(), now = Date.now();
    Object.keys(st).forEach(function (k) { if (now - (st[k].t || 0) > 2 * 86400000) delete st[k]; });
    var e = st[key] || {};
    Object.keys(change).forEach(function (k) { e[k] = change[k]; });
    e.t = now;
    st[key] = e;
    memState = st;
    try { localStorage.setItem(REMINDERS, JSON.stringify(st)); } catch (err) { /* this tab only, then */ }
  }
  // When the reminder should next show, or null once it's dismissed.
  function dueAt(r) {
    var e = readState()[r.key] || {};
    if (e.d) return null;
    return Math.max(e.s || 0, r.at * 1000);
  }

  function toastStack() {
    var st = $(".toast-stack");
    if (!st) {
      st = doc.createElement("div");
      st.className = "toast-stack";
      st.setAttribute("role", "status");
      st.setAttribute("aria-live", "polite");
      body.appendChild(st);
    }
    return st;
  }

  function startsIn(r) {
    if (r.allday) return "";
    var m = Math.round((r.start * 1000 - Date.now()) / 60000);
    if (m >= 60) return "Starts in " + Math.floor(m / 60) + " h" + (m % 60 ? " " + (m % 60) + " min" : "");
    if (m > 0) return "Starts in " + m + " min";
    if (m === 0) return "Starting now";
    return "Started " + (-m) + " min ago";
  }
  function tick() {
    Object.keys(cards).forEach(function (k) {
      var c = cards[k], line = $(".reminder-countdown", c.el);
      if (line) line.textContent = startsIn(c.r);
    });
  }

  // While a reminder is up and the tab isn't in view, the tab's title
  // flashes a bell. A prefix rather than a saved title, so the unread count
  // the mail page writes into the title carries on working underneath.
  function flashTitle() {
    if (flashTimer || !doc.hidden) return;
    flashTimer = setInterval(function () {
      doc.title = doc.title.indexOf(BELL_MARK) === 0 ? doc.title.slice(BELL_MARK.length) : BELL_MARK + doc.title;
    }, 1000);
  }
  function stopFlash() {
    clearInterval(flashTimer);
    flashTimer = null;
    if (doc.title.indexOf(BELL_MARK) === 0) doc.title = doc.title.slice(BELL_MARK.length);
  }
  doc.addEventListener("visibilitychange", function () {
    if (!doc.hidden) stopFlash(); else if (Object.keys(cards).length) flashTitle();
  });

  function dropCard(key) {
    var c = cards[key];
    if (!c) return;
    c.el.remove();
    delete cards[key];
    if (!Object.keys(cards).length) { stopFlash(); clearInterval(ticker); ticker = null; }
  }

  // tone overrides the saved sound, for trying one out from Settings.
  function showReminder(r, at, tone) {
    if (cards[r.key]) return;
    var t = doc.createElement("div");
    t.className = "toast reminder";
    t.setAttribute("role", "alert");
    var a = doc.createElement("a");
    a.href = r.url;
    a.textContent = r.title;
    var p = doc.createElement("span");
    p.className = "small muted";
    p.textContent = r.when + (r.where ? " · " + r.where : "");
    var cd = doc.createElement("span");
    cd.className = "small reminder-countdown";
    var actions = doc.createElement("div");
    actions.className = "reminder-actions";
    var button = function (label, run) {
      var b = doc.createElement("button");
      b.className = "button small-button";
      b.type = "button";
      b.textContent = label;
      b.addEventListener("click", run);
      actions.appendChild(b);
    };
    button("Snooze 5 min", function () { snoozeReminder(r.key); });
    button("Dismiss", function () { dismissReminder(r.key); });
    t.append(a, p, cd, actions);
    toastStack().appendChild(t);
    cards[r.key] = { el: t, r: r };
    tick();
    if (!ticker) ticker = setInterval(tick, 30000);
    flashTitle();

    // Every tab shows the card, but only the first to get here rings and
    // notifies, and only once each time the reminder comes due.
    if ((readState()[r.key] || {}).rang === at) return;
    writeState(r.key, { rang: at });
    var sound = tone === undefined ? reminderSound : tone;
    if (sound) {
      if (audio && audio.state !== "running") { try { audio.resume(); } catch (err) { /* no sound, then */ } }
      playTone(sound);
    }
    if (window.Notification && Notification.permission === "granted") {
      try {
        // requireInteraction: a reminder that slips away after a few seconds,
        // unseen, is no reminder.
        var n = new Notification(r.title, { body: r.when + (r.where ? " · " + r.where : ""), tag: r.key, requireInteraction: true });
        n.onclick = function () { window.focus(); location.href = r.url; };
      } catch (err) { /* some browsers only allow notifications from a service worker */ }
    }
  }

  function schedule(r) {
    known[r.key] = r;
    clearTimeout(timers[r.key]);
    delete timers[r.key];
    var at = dueAt(r);
    if (at === null) { dropCard(r.key); return; }
    var wait = at - Date.now();
    if (wait <= 0) { showReminder(r, at); return; }
    dropCard(r.key); // snoozed in another tab
    timers[r.key] = setTimeout(function () { showReminder(r, at); }, wait);
  }
  function snoozeReminder(key) {
    writeState(key, { s: Date.now() + SNOOZE_MS });
    dropCard(key);
    if (known[key]) schedule(known[key]);
  }
  function dismissReminder(key) {
    writeState(key, { d: 1 });
    clearTimeout(timers[key]);
    dropCard(key);
  }
  // Another tab dismissed or snoozed something.
  window.addEventListener("storage", function (e) {
    if (e.key !== REMINDERS) return;
    Object.keys(known).forEach(function (k) { schedule(known[k]); });
    Object.keys(cards).forEach(function (k) {
      var st = readState()[k] || {};
      if (!known[k] && (st.d || st.s > Date.now())) dropCard(k);
    });
  });

  function loadReminders() {
    fetch("/api/reminders", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : []; })
      .then(function (list) { list.forEach(schedule); })
      .catch(function () {});
  }
  if (csrf) {
    loadReminders();
    setInterval(loadReminders, 10 * 60 * 1000);
  }
  // Settings: show what a reminder looks and sounds like, with the tone
  // picked but not yet saved.
  var tryReminder = $("[data-reminder-test]");
  if (tryReminder) {
    tryReminder.addEventListener("click", function () {
      var now = Date.now(), choice = $("#reminder_sound");
      var r = { key: "try-" + now, at: now / 1000, start: now / 1000 + 15 * 60, title: "Example reminder",
        when: "In 15 minutes", where: "This is how a reminder looks", url: "/calendar" };
      known[r.key] = r;
      showReminder(r, now, choice && choice.value !== "none" ? choice.value : "");
    });
  }

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
  // ---- context menus -----------------------------------------------------
  // Right-click (or the Menu key, or Shift+F10) on a message, folder,
  // event, contact or task opens a menu of what can be done to it. Every
  // item uses the page's own actions and forms. Holding Shift, or right-clicking
  // where nothing has a menu, keeps the browser's own menu.
  var ctxMenu = null;

  function submitPost(action, fields) {
    var f = doc.createElement("form");
    f.method = "post";
    f.action = action;
    f.hidden = true;
    var add = function (k, v) {
      var i = doc.createElement("input");
      i.type = "hidden"; i.name = k; i.value = v;
      f.appendChild(i);
    };
    add("csrf", csrf);
    Object.keys(fields).forEach(function (k) {
      var v = fields[k];
      if (Array.isArray(v)) v.forEach(function (x) { add(k, x); }); else add(k, v);
    });
    body.appendChild(f);
    f.submit();
  }

  function closeCtx() {
    if (ctxMenu) { ctxMenu.remove(); ctxMenu = null; }
  }

  // openCtx shows items at (x, y). An item is {label, run, danger, sub}
  // or "-" for a separator; sub is a function returning more items.
  function openCtx(items, x, y, title) {
    closeCtx();
    var m = doc.createElement("div");
    m.className = "ctx-menu";
    m.setAttribute("role", "menu");
    if (title) m.setAttribute("aria-label", title);
    var render = function (list) {
      m.textContent = "";
      list.forEach(function (it) {
        if (it === "-") {
          var hr = doc.createElement("div");
          hr.className = "ctx-sep";
          hr.setAttribute("role", "separator");
          m.appendChild(hr);
          return;
        }
        var b = doc.createElement("button");
        b.type = "button";
        b.className = "ctx-item" + (it.danger ? " danger" : "") + (it.sub ? " has-sub" : "");
        b.setAttribute("role", "menuitem");
        b.textContent = it.label + (it.sub ? " ›" : "");
        b.addEventListener("click", function (e) {
          e.stopPropagation();
          if (it.sub) { render(it.sub()); focusFirst(); return; }
          closeCtx();
          it.run();
        });
        m.appendChild(b);
      });
    };
    var focusFirst = function () { var f = $(".ctx-item", m); if (f) f.focus(); };
    render(items);
    body.appendChild(m);
    var r = m.getBoundingClientRect();
    m.style.left = Math.max(4, Math.min(x, window.innerWidth - r.width - 4)) + "px";
    m.style.top = Math.max(4, Math.min(y, window.innerHeight - r.height - 4)) + "px";
    ctxMenu = m;
    focusFirst();
    m.addEventListener("keydown", function (e) {
      var all = $$(".ctx-item", m), i = all.indexOf(doc.activeElement);
      if (e.key === "ArrowDown") { all[(i + 1) % all.length].focus(); e.preventDefault(); }
      else if (e.key === "ArrowUp") { all[(i - 1 + all.length) % all.length].focus(); e.preventDefault(); }
      else if (e.key === "Escape") { closeCtx(); e.preventDefault(); }
      e.stopPropagation();
    });
  }

  doc.addEventListener("click", function (e) { if (ctxMenu && !ctxMenu.contains(e.target)) closeCtx(); });
  window.addEventListener("scroll", closeCtx, true);
  window.addEventListener("resize", closeCtx);

  function folderTargets(exclude) {
    return $$("a.folder[data-folder]").map(function (a) { return a.getAttribute("data-folder"); })
      .filter(function (n) { return n !== exclude; });
  }

  function messageMenu(row) {
    var list = row.closest("ol.messages");
    var folder = list.getAttribute("data-folder"), role = list.getAttribute("data-role");
    var back = list.getAttribute("data-back");
    var box = $('input[name="uid"]', row);
    // Acting on a selected row acts on the whole selection, as in a
    // desktop client; acting on an unselected one acts on it alone.
    var uids = [row.getAttribute("data-uid")];
    if (box && box.checked) {
      uids = $$('ol.messages input[name="uid"]:checked').map(function (b) { return b.value; });
    }
    // A conversation's row holds all its UIDs, which the bulk actions want.
    // Reply, print and the like work on one message: its latest.
    var one = uids.length === 1, uid = row.getAttribute("data-latest") || uids[0];
    var act = function (op, extra) {
      var f = { f: folder, uid: uids, op: op, back: back };
      Object.keys(extra || {}).forEach(function (k) { f[k] = extra[k]; });
      return function () { submitPost("/mail/action", f); };
    };
    var compose = function (mode) { return function () { location.href = "/compose?" + new URLSearchParams({ mode: mode, f: folder, uid: uid }); }; };
    var items = [];
    if (one) {
      items.push({ label: "Open", run: function () { location.href = row.getAttribute("data-open"); } });
      if (role === "drafts") {
        items.push({ label: "Edit draft", run: compose("draft") });
      } else {
        items.push({ label: "Reply", run: compose("reply") }, { label: "Reply all", run: compose("replyall") }, { label: "Forward", run: compose("forward") });
      }
      items.push("-");
    }
    var seen = one ? row.hasAttribute("data-seen") : false;
    var flagged = one ? row.hasAttribute("data-flagged") : false;
    items.push(seen ? { label: "Mark unread", run: act("unread") } : { label: one ? "Mark read" : "Mark read (" + uids.length + ")", run: act("read") });
    if (!one) items.push({ label: "Mark unread", run: act("unread") });
    items.push(flagged ? { label: "Unflag", run: act("unflag") } : { label: "Flag", run: act("flag") });
    if (!one) items.push({ label: "Unflag", run: act("unflag") });
    items.push({ label: "Tag…", run: function () {
      var t = window.prompt("Tag" + (one ? "" : " " + uids.length + " messages") + " as:");
      if (t) act("tag", { tag: t.trim() })();
    } });
    items.push("-");
    items.push({ label: "Move to", sub: function () {
      return folderTargets(folder).map(function (n) { return { label: n, run: act("move", { dest: n }) }; });
    } });
    if (role !== "archive") items.push({ label: "Archive", run: act("archive") });
    items.push(role === "quarantine" ? { label: "Release to Inbox", run: act("notjunk") } :
      role === "junk" ? { label: "Not junk", run: act("notjunk") } : { label: "Report junk", run: act("junk") });
    items.push({ label: role === "trash" ? "Delete for good" : "Delete", danger: true, run: function () {
      if (role === "trash" && !window.confirm("Delete " + (one ? "this message" : uids.length + " messages") + " for good?")) return;
      act("delete")();
    } });
    if (one) {
      items.push("-");
      var from = row.getAttribute("data-from");
      if (from) items.push({ label: "Filter mail like this…", run: function () { location.href = "/filters?" + new URLSearchParams({ "new": "1", from: from }); } });
      items.push({ label: "View original", run: function () { window.open("/mail/source?" + new URLSearchParams({ f: folder, uid: uid }), "_blank", "noopener"); } });
      items.push({ label: "Print", run: function () { window.open("/mail/print?" + new URLSearchParams({ f: folder, uid: uid }), "_blank", "noopener"); } });
    }
    return items;
  }

  function folderMenu(a) {
    var name = a.getAttribute("data-folder"), role = a.getAttribute("data-role"), display = a.getAttribute("data-display");
    var items = [
      { label: "Open", run: function () { location.href = a.href; } },
      { label: "Mark all read", run: function () { submitPost("/mail/action", { f: name, op: "readall", back: location.pathname === "/mail" ? location.pathname + location.search : "/mail?f=" + encodeURIComponent(name) }); } },
      "-",
      { label: "New folder inside…", run: function () {
        var n = window.prompt("Name of the new folder inside " + display + ":");
        if (n) submitPost("/folders", { op: "create", name: n.trim(), parent: name });
      } }
    ];
    if (!role) {
      items.push({ label: "Rename…", run: function () {
        var n = window.prompt("Rename " + display + " to:", display);
        if (n && n.trim() !== display) submitPost("/folders", { op: "rename", folder: name, name: n.trim() });
      } });
      items.push({ label: "Delete folder", danger: true, run: function () {
        if (window.confirm("Delete the folder " + name + " and every message in it?")) submitPost("/folders", { op: "delete", folder: name });
      } });
    }
    if (!a.hasAttribute("data-retention-disabled") && (!role || role === "trash" || role === "junk" || role === "sent")) {
      items.push({ label: "Set retention…", run: function () {
        fetch("/folders/retention?" + new URLSearchParams({ folder: name })).then(function (response) {
          if (!response.ok) throw new Error("Couldn't read this folder's retention setting.");
          return response.json();
        }).then(function (setting) {
          var typed = window.prompt("Delete messages in " + display + " after how many days? Enter 0 to keep them until you delete them.", String(setting.days));
          if (typed === null) return;
          typed = typed.trim();
          if (!/^\d+$/.test(typed) || Number(typed) > 36500) { window.alert("Enter 0 to 36500 days."); return; }
          submitPost("/folders/retention", { folder: name, days: typed, back: location.pathname + location.search });
        }).catch(function (error) { window.alert(error.message); });
      } });
    }
    if (role === "trash" || role === "junk") {
      items.push("-", { label: "Empty " + display, danger: true, run: function () {
        if (window.confirm("Delete every message in " + display + " for good? This can't be undone.")) submitPost("/mail/action", { f: name, op: "empty", back: "/mail?f=" + encodeURIComponent(name) });
      } });
    }
    return items;
  }

  function eventMenu(a) {
    var uid = a.getAttribute("data-uid"), occ = a.getAttribute("data-occ");
    var owner = a.getAttribute("data-owner");
    var sharedFields = owner ? { owner: owner } : {};
    var q = function (extra) { return "/calendar/event?" + new URLSearchParams(Object.assign({ uid: uid, occ: occ }, sharedFields, extra || {})); };
    var items = [{ label: "Open", run: function () { location.href = a.href; } }];
    if (a.hasAttribute("data-readonly")) return items;
    items.push({ label: "Edit", run: function () { location.href = q({ edit: "1" }); } });
    if (!owner) items.push({ label: "Download .ics", run: function () { location.href = "/calendar/export?" + new URLSearchParams({ uid: uid }); } });
    items.push("-");
    if (a.hasAttribute("data-recurring")) {
      items.push({ label: "Delete this occurrence", danger: true, run: function () {
        if (window.confirm("Delete only this occurrence?")) submitPost("/calendar/event", { owner: owner || "", op: "delete-occurrence", uid: uid, occ: occ });
      } });
    }
    items.push({ label: a.hasAttribute("data-recurring") ? "Delete series" : "Delete", danger: true, run: function () {
      if (window.confirm(a.hasAttribute("data-recurring") ? "Delete every occurrence of this event?" : "Delete this event?")) submitPost("/calendar/event", { owner: owner || "", op: "delete", uid: uid, notify: "1" });
    } });
    return items;
  }

  function contactMenu(a) {
    var id = a.getAttribute("data-id"), email = a.getAttribute("data-email"), name = a.getAttribute("data-name"), group = a.getAttribute("data-group");
    var items = [{ label: "Open", run: function () { location.href = a.href; } }];
    if (email) {
      items.push({ label: "Write email", run: function () { location.href = "/compose?" + new URLSearchParams({ to: name ? name + " <" + email + ">" : email }); } });
      items.push({ label: "Find emails", run: function () { location.href = "/mail?" + new URLSearchParams({ f: "INBOX", q: "from:" + email }); } });
    }
    items.push({ label: "Edit", run: function () { location.href = "/contacts?" + new URLSearchParams({ id: id, g: group, edit: "1" }); } });
    items.push("-", { label: "Delete", danger: true, run: function () {
      if (window.confirm("Delete " + (name || email) + " from your contacts?")) submitPost("/contacts", { op: "delete", id: id, g: group });
    } });
    return items;
  }

  function taskMenu(li) {
    var id = li.getAttribute("data-id"), list = li.getAttribute("data-list"), show = li.getAttribute("data-show");
    return [
      { label: "Open", run: function () { location.href = li.getAttribute("data-open"); } },
      { label: li.hasAttribute("data-done") ? "Mark not done" : "Mark done", run: function () { submitPost("/tasks", { op: "toggle", id: id, list_filter: list, show: show }); } },
      "-",
      { label: "Delete", danger: true, run: function () {
        if (window.confirm("Delete this task?")) submitPost("/tasks", { op: "delete", id: id, list_filter: list, show: show });
      } }
    ];
  }

  function menuFor(el) {
    var t = el.closest("[data-ctx]");
    if (!t) return null;
    switch (t.getAttribute("data-ctx")) {
      case "message": return { items: messageMenu(t), title: "Message actions", el: t };
      case "folder": return { items: folderMenu(t), title: "Folder actions", el: t };
      case "event": return { items: eventMenu(t), title: "Event actions", el: t };
      case "contact": return { items: contactMenu(t), title: "Contact actions", el: t };
      case "task": return { items: taskMenu(t), title: "Task actions", el: t };
    }
    return null;
  }

  doc.addEventListener("contextmenu", function (e) {
    if (e.shiftKey || !csrf) return;
    var m = menuFor(e.target);
    if (!m) { closeCtx(); return; }
    e.preventDefault();
    openCtx(m.items, e.clientX, e.clientY, m.title);
  });
  // The keyboard way in: the Menu key or Shift+F10 on a focused item.
  doc.addEventListener("keydown", function (e) {
    if (!(e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey))) return;
    var m = menuFor(doc.activeElement || body);
    if (!m) return;
    e.preventDefault();
    var r = m.el.getBoundingClientRect();
    openCtx(m.items, r.left + 16, r.top + r.height / 2, m.title);
  });

  // ---- event bubble --------------------------------------------------------
  // A click on an event shows its details in a bubble beside it, so checking
  // where or when something is doesn't cost leaving the calendar. A double
  // click, or a click with a modifier, opens the full event page as before.
  // The bubble is the event page's own card, fetched and lifted out the way
  // the reading pane is: what it shows, including what a shared private event
  // hides, is decided by the server once and can't drift from the page.
  var peek = null, peekToken = 0;
  var EVENT = 'a[data-ctx="event"]';

  function closePeek(refocus) {
    peekToken++;
    if (!peek) return;
    var from = peek.from;
    peek.el.remove();
    if (peek.onclose) peek.onclose();
    peek = null;
    if (refocus && from.isConnected) from.focus();
  }

  // Beside the event if there's room on either side, otherwise below or
  // above it (a month cell on a phone has no side to spare).
  function placePeek() {
    var r = peek.from.getBoundingClientRect(), el = peek.el, p = el.getBoundingClientRect();
    var w = doc.documentElement.clientWidth, h = window.innerHeight, gap = 8, edge = 8;
    var clamp = function (v, lo, hi) { return Math.max(lo, Math.min(v, hi)); };
    var left, top;
    if (r.right + gap + p.width <= w - edge) left = r.right + gap;
    else if (r.left - gap - p.width >= edge) left = r.left - gap - p.width;
    if (left !== undefined) {
      top = clamp(r.top, edge, h - p.height - edge);
    } else {
      left = clamp(r.left, edge, w - p.width - edge);
      if (r.bottom + gap + p.height <= h - edge) top = r.bottom + gap;
      else if (r.top - gap - p.height >= edge) top = r.top - gap - p.height;
      else top = clamp(r.bottom + gap, edge, h - p.height - edge);
    }
    el.style.left = Math.max(edge, left) + "px";
    el.style.top = Math.max(edge, top) + "px";
  }

  function openPeek(a) {
    closePeek(false);
    var token = peekToken;
    var el = doc.createElement("div");
    el.className = "event-peek";
    el.setAttribute("role", "dialog");
    el.tabIndex = -1;
    var name = (a.getAttribute("title") || a.textContent).trim();
    el.setAttribute("aria-label", name);
    var close = doc.createElement("button");
    close.type = "button";
    close.className = "peek-close";
    close.setAttribute("aria-label", "Close");
    close.textContent = "×";
    close.addEventListener("click", function () { closePeek(true); });
    // Shown straight away, so a slow server still answers the click.
    var loading = doc.createElement("p");
    loading.className = "muted small peek-loading";
    loading.textContent = "Loading " + name + "…";
    el.append(close, loading);
    el.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { closePeek(true); e.preventDefault(); }
      // Keys typed here are for the bubble, not the calendar's shortcuts.
      e.stopPropagation();
    });
    body.appendChild(el);
    peek = { el: el, from: a };
    placePeek();

    fetch(a.href, { credentials: "same-origin" })
      .then(function (r) {
        if (!r.ok || r.redirected) throw new Error("not an event page");
        return r.text();
      })
      .then(function (html) {
        if (token !== peekToken) return;
        var fresh = new DOMParser().parseFromString(html, "text/html");
        var card = $(".event-view", fresh), bar = $('.toolbar[aria-label="Event actions"]', fresh);
        if (!card) throw new Error("not an event page");
        var actions = doc.createElement("div");
        actions.className = "peek-actions";
        var open = doc.createElement("a");
        open.className = "button";
        open.href = a.href;
        open.textContent = "Open";
        actions.appendChild(open);
        // The page's own Edit, Delete and Hide buttons: their forms carry
        // the CSRF token and their data-confirm prompts work anywhere.
        if (bar) Array.prototype.forEach.call(bar.children, function (n) { actions.appendChild(doc.importNode(n, true)); });
        loading.replaceWith(doc.importNode(card, true), actions);
        placePeek();
        el.focus();
      })
      .catch(function () {
        // Signed out, gone or the server failed: the full page says which.
        if (token === peekToken) location.href = a.href;
      });
  }

  doc.addEventListener("click", function (e) {
    var a = e.target.closest(EVENT);
    if (peek && !peek.el.contains(e.target) && a !== peek.from) closePeek(false);
    if (!a || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    // The second click of a double click: the dblclick that follows opens it.
    if (e.detail > 1) return;
    if (peek && peek.from === a) closePeek(false); else openPeek(a);
  });
  doc.addEventListener("dblclick", function (e) {
    var a = e.target.closest(EVENT);
    if (!a || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    closePeek(false);
    location.href = a.href;
  });
  // A double click would otherwise select the event's text as it leaves.
  doc.addEventListener("mousedown", function (e) {
    if (e.detail > 1 && e.target.closest(EVENT)) e.preventDefault();
  });
  doc.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && peek) closePeek(true);
  });
  doc.addEventListener("contextmenu", function () { closePeek(false); });
  // The bubble is placed against the event; once that moves, it points at
  // nothing. Scrolling inside the bubble itself is fine.
  window.addEventListener("scroll", function (e) { if (peek && !peek.el.contains(e.target)) closePeek(false); }, true);
  window.addEventListener("resize", function () { closePeek(false); });

  // ---- quick add ------------------------------------------------------------
  // A click on an empty hour, or an empty part of a day, asks for a title in
  // a bubble there instead of leaving for the full form; More options takes
  // what was typed to the form. The bubble and its closing rules are the
  // event bubble's.
  function ymdAdd(ymd, days) {
    var p = ymd.split("-"), d = new Date(Date.UTC(+p[0], p[1] - 1, +p[2] + days));
    return d.toISOString().slice(0, 10);
  }
  function ymdDiff(from, to) {
    var a = from.split("-"), b = to.split("-");
    return Math.round((Date.UTC(+b[0], b[1] - 1, +b[2]) - Date.UTC(+a[0], a[1] - 1, +a[2])) / 86400000);
  }
  function hhmm(mins) {
    var h = Math.floor(mins / 60), m = mins % 60;
    return (h < 10 ? "0" : "") + h + ":" + (m < 10 ? "0" : "") + m;
  }
  function dayLabel(ymd) {
    var p = ymd.split("-");
    return new Date(+p[0], p[1] - 1, +p[2]).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  }

  // hour is -1 for an all-day event. when is how the slot names its time.
  function quickAdd(anchor, date, hour, when) {
    closePeek(false);
    var el = doc.createElement("div");
    el.className = "event-peek event-quick-add";
    el.setAttribute("role", "dialog");
    el.setAttribute("aria-label", "New event");
    var close = doc.createElement("button");
    close.type = "button";
    close.className = "peek-close";
    close.setAttribute("aria-label", "Close");
    close.textContent = "×";
    close.addEventListener("click", function () { closePeek(true); });
    var form = doc.createElement("form");
    form.className = "event-quick-add-form";
    var title = doc.createElement("input");
    title.type = "text";
    title.name = "summary";
    title.maxLength = 500;
    title.placeholder = "Add a title";
    title.setAttribute("aria-label", "Title");
    var whenLine = doc.createElement("p");
    whenLine.className = "muted small";
    whenLine.textContent = dayLabel(date) + " · " + (hour < 0 ? "All day" : when);
    var problem = doc.createElement("p");
    problem.className = "small event-quick-add-problem";
    problem.hidden = true;
    var actions = doc.createElement("div");
    actions.className = "peek-actions";
    var save = doc.createElement("button");
    save.type = "submit";
    save.className = "button primary";
    save.textContent = "Save";
    var more = doc.createElement("a");
    more.className = "button";
    more.textContent = "More options";
    var full = function () {
      var q = { new: "1", date: date };
      if (hour < 0) q.allday = "1"; else q.hour = String(hour);
      if (title.value.trim()) q.title = title.value.trim();
      return "/calendar/event?" + new URLSearchParams(q);
    };
    more.href = full();
    title.addEventListener("input", function () { more.href = full(); });
    actions.append(save, more);
    form.append(title, whenLine, problem, actions);
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      save.disabled = true;
      var f = { op: "save", summary: title.value.trim(), start_date: date, end_date: date,
        reminder: "15", busy: "busy", ends: "never", interval: "1" };
      if (hour < 0) {
        f.allday = "1";
      } else {
        f.start_time = hhmm(hour * 60);
        // An hour long; one starting at 23:00 ends at midnight, the next day.
        if (hour === 23) { f.end_date = ymdAdd(date, 1); f.end_time = "00:00"; } else f.end_time = hhmm(hour * 60 + 60);
      }
      post("/calendar/event", f).then(function (r) {
        if (!r.ok) throw new Error("not saved");
        location.reload();
      }).catch(function () {
        save.disabled = false;
        problem.textContent = "The event couldn't be saved. Try More options.";
        problem.hidden = false;
      });
    });
    el.append(close, form);
    el.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { closePeek(true); e.preventDefault(); }
      e.stopPropagation();
    });
    body.appendChild(el);
    anchor.classList.add("picked");
    peek = { el: el, from: anchor, onclose: function () { anchor.classList.remove("picked"); } };
    placePeek();
    title.focus();
  }

  doc.addEventListener("click", function (e) {
    if (!csrf || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    var slot = e.target.closest(".daycol .slot");
    if (slot) {
      var col = slot.closest(".daycol[data-date]");
      if (!col) return;
      e.preventDefault();
      var hour = +slot.getAttribute("data-hour");
      var next = slot.nextElementSibling && slot.nextElementSibling.matches(".slot") ? slot.nextElementSibling : null;
      var label = function (s) { return (s.getAttribute("aria-label") || "").replace(/^New event at /, ""); };
      quickAdd(slot, col.getAttribute("data-date"), hour, label(slot) + (next ? " – " + label(next) : ""));
      return;
    }
    // The empty part of a month day, or of a day in the week's all-day row.
    var cell = e.target.closest(".month .day[data-date], .allday-row .cell[data-date]");
    if (cell && !e.target.closest("a, button")) {
      e.preventDefault();
      quickAdd(cell, cell.getAttribute("data-date"), -1, "");
    }
  });

  // ---- drag events to move or resize ----------------------------------------
  // With a mouse, an event can be dragged to another time or day, and a
  // timed event's bottom edge dragged to change when it ends. Touch keeps
  // scrolling and uses the form instead: a drag there is a scroll. Nothing
  // moves until the pointer has travelled a few pixels, so a click or a
  // double click still opens the bubble or the event.
  var drag = null, swallowClick = false;
  $$(".daycol .ev[data-ctx=\"event\"]:not([data-readonly])").forEach(function (a) {
    var h = doc.createElement("span");
    h.className = "ev-resize";
    h.setAttribute("aria-hidden", "true");
    a.appendChild(h);
  });
  // A link drags its address natively, and once the browser starts that it
  // cancels the pointer events this needs, so it's turned off up front.
  // The hour slots are links too, and once the dragged event lets the
  // pointer through, a native drag would start from the slot beneath it.
  $$(".daycol " + EVENT + ", .month " + EVENT + ", .allday-row " + EVENT + ", .daycol .slot").forEach(function (a) { a.draggable = false; });
  doc.addEventListener("dragstart", function (e) {
    if (drag || (e.target.closest && e.target.closest(EVENT))) e.preventDefault();
  });

  function timeText(mins, like) {
    var h = Math.floor(mins / 60) % 24, m = mins % 60, mm = (m < 10 ? "0" : "") + m;
    if (/[ap]m/i.test(like)) return ((h + 11) % 12 + 1) + ":" + mm + (h < 12 ? " AM" : " PM");
    return (h < 10 ? "0" : "") + h + ":" + mm;
  }

  doc.addEventListener("pointerdown", function (e) {
    if (e.pointerType === "touch" || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || !csrf) return;
    var a = e.target.closest(EVENT);
    if (!a || a.hasAttribute("data-readonly") || !a.closest(".daycol, .month .day, .allday-row .cell")) return;
    drag = { a: a, x0: e.clientX, y0: e.clientY, started: false, resize: e.target.classList.contains("ev-resize"),
      grid: !!a.closest(".daycol"), home: a.parentElement, next: a.nextSibling };
  });

  function beginDrag(d) {
    d.started = true;
    closePeek(false);
    var a = d.a;
    a.classList.add("dragging");
    body.classList.add("cal-dragging");
    if (d.grid) {
      var col = a.parentElement, r = a.getBoundingClientRect();
      d.qh = col.getBoundingClientRect().height / 96;
      d.q = Math.round(a.offsetTop / d.qh);
      d.len = Math.max(1, Math.round(r.height / d.qh));
      d.grab = d.y0 - r.top;
      d.label = $(".t", a) ? $(".t", a).textContent : "";
      // Out of its lane, full width, placed by pixels while it moves.
      a.style.left = "2px"; a.style.right = "2px"; a.style.width = "auto";
      a.style.top = d.q * d.qh + "px"; a.style.height = d.len * d.qh + "px";
    } else {
      d.from = d.home.getAttribute("data-date");
    }
  }

  function dragTo(d, x, y) {
    var a = d.a, under = doc.elementFromPoint(x, y);
    if (d.grid) {
      var col = under && under.closest(".daycol[data-date]");
      if (col && col !== a.parentElement && !d.resize) col.appendChild(a);
      var top = a.parentElement.getBoundingClientRect().top;
      if (d.resize) {
        d.len = Math.max(1, Math.min(96 - d.q, Math.round((y - top) / d.qh) - d.q));
        a.style.height = d.len * d.qh + "px";
      } else {
        d.q = Math.max(0, Math.min(96 - d.len, Math.round((y - d.grab - top) / d.qh)));
        a.style.top = d.q * d.qh + "px";
      }
      var t = $(".t", a);
      if (t) t.textContent = timeText(d.q * 15, d.label) + (d.resize ? " – " + timeText((d.q + d.len) * 15, d.label) : "");
    } else {
      var cell = under && under.closest(".month .day[data-date], .allday-row .cell[data-date]");
      if (cell && cell !== a.parentElement) cell.insertBefore(a, $(".more", cell));
    }
  }

  function undoDrag(d) {
    var a = d.a;
    a.classList.remove("dragging");
    body.classList.remove("cal-dragging");
    d.home.insertBefore(a, d.next && d.next.parentNode === d.home ? d.next : null);
    // Property by property: the CSP refuses a style attribute set whole.
    ["left", "right", "width", "top", "height"].forEach(function (k) { a.style[k] = ""; });
    if (d.grid && $(".t", a)) $(".t", a).textContent = d.label;
  }

  function dropDrag(d) {
    var a = d.a;
    a.classList.remove("dragging");
    body.classList.remove("cal-dragging");
    var f = { op: "move", uid: a.getAttribute("data-uid"), occ: a.getAttribute("data-occ"), owner: a.getAttribute("data-owner") || "" };
    if (d.grid) {
      var date = a.parentElement.getAttribute("data-date");
      f.start_date = date;
      f.start_time = hhmm(d.q * 15);
      if (d.resize) {
        var end = (d.q + d.len) * 15;
        f.end_date = end >= 1440 ? ymdAdd(date, 1) : date;
        f.end_time = hhmm(end % 1440);
      }
      if (!d.resize && d.home === a.parentElement && f.start_time === a.getAttribute("data-time")) { undoDrag(d); return; }
    } else {
      var shift = ymdDiff(d.from, a.parentElement.getAttribute("data-date"));
      if (!shift) { undoDrag(d); return; }
      f.start_date = ymdAdd(a.getAttribute("data-day"), shift);
      if (!a.hasAttribute("data-allday")) f.start_time = a.getAttribute("data-time");
    }
    if (a.hasAttribute("data-recurring") && !window.confirm("This event repeats. Move only this occurrence?")) { undoDrag(d); return; }
    if (a.hasAttribute("data-guests") && !window.confirm("Move this meeting? Its guests will be sent the new time.")) { undoDrag(d); return; }
    post("/calendar/event", f).then(function (r) {
      if (r.status === 204) { location.reload(); return; }
      return r.text().then(function (msg) {
        window.alert(msg || "The event couldn't be moved.");
        if (r.ok) location.reload(); else undoDrag(d);
      });
    }).catch(function () {
      window.alert("The event couldn't be moved. Check your connection and try again.");
      undoDrag(d);
    });
  }

  doc.addEventListener("pointermove", function (e) {
    var d = drag;
    if (!d) return;
    if (!d.started) {
      if (Math.abs(e.clientX - d.x0) + Math.abs(e.clientY - d.y0) < 5) return;
      beginDrag(d);
    }
    e.preventDefault();
    dragTo(d, e.clientX, e.clientY);
  });
  doc.addEventListener("pointerup", function () {
    var d = drag;
    drag = null;
    if (!d || !d.started) return;
    // The click this release makes isn't a click on the event.
    swallowClick = true;
    setTimeout(function () { swallowClick = false; }, 400);
    dropDrag(d);
  });
  doc.addEventListener("pointercancel", function () { if (drag && drag.started) undoDrag(drag); drag = null; });
  doc.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && drag && drag.started) { undoDrag(drag); drag = null; e.preventDefault(); }
  });
  doc.addEventListener("click", function (e) {
    if (!swallowClick) return;
    swallowClick = false;
    e.preventDefault();
    e.stopPropagation();
  }, true);

  // ---- drag messages onto a folder -----------------------------------------
  // A message row dragged onto a folder in the sidebar moves there, with the
  // other ticked rows if it was one of them. It posts the bulk Move, so the
  // page comes back with the usual notice.
  var DRAG_TYPE = "application/x-elemta-messages";
  doc.addEventListener("dragstart", function (e) {
    var li = e.target.closest && e.target.closest(".messages li[data-uid]");
    if (!li || !e.dataTransfer) return;
    var list = li.closest("ol.messages"), box = $("input[name=uid]", li), uids;
    if (box && box.checked) {
      uids = $$("input[name=uid]:checked", list).map(function (i) { return i.value; });
    } else {
      uids = [li.getAttribute("data-uid")];
    }
    e.dataTransfer.setData(DRAG_TYPE, JSON.stringify({ folder: list.getAttribute("data-folder"), uids: uids, back: list.getAttribute("data-back") }));
    e.dataTransfer.effectAllowed = "move";
    var n = uids.join(",").split(",").length;
    var ghost = doc.createElement("div");
    ghost.className = "drag-ghost";
    ghost.textContent = n === 1 ? "1 message" : n + " messages";
    body.appendChild(ghost);
    e.dataTransfer.setDragImage(ghost, 10, 10);
    setTimeout(function () { ghost.remove(); }, 0);
  });
  function folderTarget(e) {
    if (!e.dataTransfer || Array.prototype.indexOf.call(e.dataTransfer.types, DRAG_TYPE) < 0) return null;
    return e.target.closest && e.target.closest("a.folder[data-folder]");
  }
  doc.addEventListener("dragover", function (e) {
    var f = folderTarget(e);
    if (!f) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    $$("a.folder.drop-target").forEach(function (x) { if (x !== f) x.classList.remove("drop-target"); });
    f.classList.add("drop-target");
  });
  doc.addEventListener("dragleave", function (e) {
    var f = folderTarget(e);
    if (f && !f.contains(e.relatedTarget)) f.classList.remove("drop-target");
  });
  doc.addEventListener("drop", function (e) {
    var f = folderTarget(e);
    if (!f) return;
    e.preventDefault();
    f.classList.remove("drop-target");
    var m;
    try { m = JSON.parse(e.dataTransfer.getData(DRAG_TYPE)); } catch (err) { return; }
    var dest = f.getAttribute("data-folder");
    if (!m || !m.uids.length || dest === m.folder) return;
    submitPost("/mail/action", { f: m.folder, uid: m.uids, op: "move", dest: dest, back: m.back || "/mail?f=" + encodeURIComponent(m.folder) });
  });
  doc.addEventListener("dragend", function () { $$("a.folder.drop-target").forEach(function (x) { x.classList.remove("drop-target"); }); });

})();
