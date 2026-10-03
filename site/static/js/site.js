// Search, the light and dark switch, and diagrams. Works when the site is
// opened from disk: the search index is a script, not a fetch.
(function () {
  "use strict";
  var root = document.documentElement;
  var home = document.querySelector('link[rel="home"]');
  var base = new URL(home ? home.getAttribute("href") : "./", location.href);

  // Light and dark: follow the system until the reader picks one.
  function isDark() {
    if (root.dataset.theme) return root.dataset.theme === "dark";
    return window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches;
  }
  var toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = isDark() ? "light" : "dark";
      root.dataset.theme = next;
      try { localStorage.setItem("hslsa-theme", next); } catch (e) {}
      renderDiagrams(true);
    });
  }

  // Diagrams: mermaid is loaded only on pages that have one.
  var diagrams = [];
  document.querySelectorAll("pre.mermaid").forEach(function (el) {
    diagrams.push({ el: el, src: el.textContent });
  });
  function renderDiagrams(again) {
    if (!window.mermaid || !diagrams.length) return;
    if (again) {
      diagrams.forEach(function (d) { d.el.removeAttribute("data-processed"); d.el.textContent = d.src; });
    }
    var cs = getComputedStyle(root);
    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      fontFamily: cs.getPropertyValue("--font-body"),
      themeVariables: {
        darkMode: isDark(),
        background: cs.getPropertyValue("--surface").trim(),
        primaryColor: cs.getPropertyValue("--accent-soft").trim(),
        primaryBorderColor: cs.getPropertyValue("--accent").trim(),
        primaryTextColor: cs.getPropertyValue("--fg").trim(),
        lineColor: cs.getPropertyValue("--muted").trim(),
        secondaryColor: cs.getPropertyValue("--gold-soft").trim(),
        tertiaryColor: cs.getPropertyValue("--sunken").trim(),
        textColor: cs.getPropertyValue("--fg").trim(),
        fontSize: "14px"
      }
    });
    window.mermaid.run({ nodes: diagrams.map(function (d) { return d.el; }) });
  }
  var mm = document.querySelector("script[data-mermaid]");
  if (mm) {
    if (window.mermaid) renderDiagrams(false);
    else mm.addEventListener("load", function () { renderDiagrams(false); });
  }

  // The drawer on narrow screens closes when a link in it is followed.
  var navToggle = document.getElementById("nav-toggle");
  document.querySelectorAll(".sidebar a").forEach(function (a) {
    a.addEventListener("click", function () { if (navToggle) navToggle.checked = false; });
  });

  // Search: titles and headings first, then body text.
  var input = document.getElementById("search-input");
  var list = document.getElementById("search-results");
  var index = window.HSLSA_INDEX || [];
  if (!input || !list) return;

  function esc(s) {
    return s.replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; });
  }
  function mark(text, terms) {
    var out = esc(text);
    terms.forEach(function (t) {
      out = out.replace(new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig"), "<mark>$1</mark>");
    });
    return out;
  }
  function snippet(text, term) {
    var i = text.toLowerCase().indexOf(term);
    if (i < 0) return "";
    var start = Math.max(0, i - 60);
    var s = text.slice(start, i + 110).replace(/\s+/g, " ");
    return (start > 0 ? "…" : "") + s + "…";
  }
  function search(q) {
    var terms = q.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 1; });
    if (!terms.length) return [];
    var hits = [];
    index.forEach(function (p) {
      var title = p.t.toLowerCase();
      var body = (p.c || "").toLowerCase();
      var all = terms.every(function (t) { return title.indexOf(t) >= 0 || body.indexOf(t) >= 0 || (p.d || "").toLowerCase().indexOf(t) >= 0; });
      if (all) {
        var score = 0;
        terms.forEach(function (t) {
          if (title.indexOf(t) >= 0) score += 20;
          var n = body.split(t).length - 1;
          score += Math.min(n, 15);
        });
        hits.push({ score: score, title: p.t, where: p.s || "", url: p.u, snip: snippet(p.c || p.d || "", terms[0]) });
      }
      (p.h || []).forEach(function (h) {
        var ht = h.t.toLowerCase();
        if (terms.every(function (t) { return ht.indexOf(t) >= 0; })) {
          hits.push({ score: 30 + terms.length * 5 - ht.length / 40, title: h.t, where: p.t, url: p.u + "#" + h.i, snip: "" });
        }
      });
    });
    hits.sort(function (a, b) { return b.score - a.score; });
    return hits.slice(0, 12);
  }
  var active = -1;
  function show(q) {
    var hits = search(q);
    active = -1;
    if (!q.trim()) { list.hidden = true; list.innerHTML = ""; return; }
    var terms = q.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 1; });
    if (!hits.length) {
      list.innerHTML = '<li class="r-none">Nothing matches "' + esc(q) + '". Try a single word, such as a track or a command.</li>';
    } else {
      list.innerHTML = hits.map(function (h) {
        return '<li><a href="' + esc(new URL(h.url, base).href) + '">' +
          '<span class="r-title">' + mark(h.title, terms) + "</span>" +
          (h.where ? '<span class="r-where">' + esc(h.where) + "</span>" : "") +
          (h.snip ? '<span class="r-snip">' + mark(h.snip, terms) + "</span>" : "") +
          "</a></li>";
      }).join("");
    }
    list.hidden = false;
  }
  function move(d) {
    var links = list.querySelectorAll("a");
    if (!links.length) return;
    if (active >= 0) links[active].removeAttribute("aria-selected");
    active = (active + d + links.length) % links.length;
    links[active].setAttribute("aria-selected", "true");
    links[active].scrollIntoView({ block: "nearest" });
  }
  input.addEventListener("input", function () { show(input.value); });
  input.addEventListener("focus", function () { if (input.value) show(input.value); });
  input.addEventListener("keydown", function (e) {
    if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
    else if (e.key === "Enter") {
      var links = list.querySelectorAll("a");
      var pick = links[active >= 0 ? active : 0];
      if (pick) { e.preventDefault(); location.href = pick.href; }
    } else if (e.key === "Escape") { list.hidden = true; input.blur(); }
  });
  document.addEventListener("click", function (e) {
    if (!e.target.closest(".search")) list.hidden = true;
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== input && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
      e.preventDefault();
      input.focus();
    }
  });
})();
