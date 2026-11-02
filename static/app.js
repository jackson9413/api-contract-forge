(function () {
  "use strict";

  var state = { report: null, severity: "all", axis: "all", sessionId: null };

  function esc(s) {
    return String(s === undefined || s === null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function el(id) { return document.getElementById(id); }
  function verdictClass(v) {
    if (v === "prod_ready") return "v-good";
    if (v === "mostly_ready") return "v-ok";
    if (v === "needs_polish") return "v-warn";
    if (v === "tight_but_usable") return "v-bad";
    return "v-worst";
  }
  function axisColor(s) {
    if (s >= 85) return "var(--good)";
    if (s >= 70) return "var(--ok)";
    if (s >= 55) return "var(--warn)";
    return "var(--bad)";
  }
  function status(msg, isErr) {
    var s = el("status");
    s.textContent = msg || "";
    s.className = isErr ? "status err" : "status";
  }
  function api(url, opts) {
    return fetch(url, opts || {}).then(function (r) {
      return r.json().then(function (d) {
        return { ok: r.ok, data: d };
      });
    });
  }

  function loadSamples() {
    api("/api/samples").then(function (r) {
      if (!r.ok) return;
      var host = el("sampleList");
      host.innerHTML = "";
      r.data.samples.forEach(function (s) {
        var b = document.createElement("button");
        b.className = "sample";
        b.innerHTML = "<b>" + esc(s.title) + "</b><span>" + esc(s.description) + "</span>";
        b.onclick = function () {
          api("/api/sample/" + encodeURIComponent(s.id)).then(function (rr) {
            if (!rr.ok) return;
            el("input").value = rr.data.content;
            el("mode").value = rr.data.mode === "openapi" ? "openapi" : "brief";
            status("Loaded sample: " + rr.data.title);
            run();
          });
        };
        host.appendChild(b);
      });
    });
  }

  function loadHistory() {
    api("/api/sessions").then(function (r) {
      if (!r.ok) return;
      var host = el("history");
      host.innerHTML = "";
      if (!r.data.sessions.length) {
        host.innerHTML = "<div class='status'>No reviews yet.</div>";
        return;
      }
      r.data.sessions.forEach(function (s) {
        var d = document.createElement("div");
        d.className = "hist";
        d.innerHTML = "<span class='t'>" + esc(s.title || "Untitled API") +
          "<br><span class='status'>" + esc(s.mode) + " / " + esc(s.profile) + " / " +
          esc((s.created_at || "").slice(0, 19).replace("T", " ")) + "</span></span>" +
          "<span class='pill " + verdictClass(s.verdict) + "'>" + esc(s.score) + "</span>";
        d.onclick = function () { openSession(s.id); };
        host.appendChild(d);
      });
    });
  }

  function openSession(id) {
    api("/api/sessions/" + id).then(function (r) {
      if (!r.ok) return;
      state.report = r.data.report;
      state.sessionId = id;
      render();
      status("Opened review #" + id);
    });
  }

  function run() {
    var text = el("input").value;
    if (!text.trim()) {
      status("Paste a contract first.", true);
      return;
    }
    el("run").disabled = true;
    status("Reviewing...");
    api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: text, mode: el("mode").value, profile: el("profile").value })
    }).then(function (r) {
      el("run").disabled = false;
      if (!r.ok) {
        status(r.data.error || "Analysis failed.", true);
        return;
      }
      state.report = r.data;
      state.sessionId = r.data.session_id;
      render();
      status("Review saved as #" + r.data.session_id);
      loadHistory();
    }).catch(function (e) {
      el("run").disabled = false;
      status("Request failed: " + e, true);
    });
  }

  function findingsHtml() {
    var rep = state.report;
    var list = rep.findings.filter(function (f) {
      if (state.severity !== "all" && f.severity !== state.severity) return false;
      if (state.axis !== "all" && f.axis !== state.axis) return false;
      return true;
    });
    if (!list.length) {
      return "<div class='empty'>No findings match this filter.</div>";
    }
    return list.map(function (f) {
      var ev = (f.evidence || []).map(function (e) {
        return "<li>" + esc(e) + "</li>";
      }).join("");
      return "<div class='finding'>" +
        "<h4><span class='sev sev-" + esc(f.severity) + ">" + esc(f.severity) + "</span>" +
        esc(f.title) + "</h4>" +
        "<p>" + esc(f.why) + "</p>" +
        "<p class='fix'><b>Fix:</b> " + esc(f.fix) + "</p>" +
        (f.endpoint ? "<p>Endpoint: " + esc(f.endpoint) + "</p>" : "") +
        (ev ? "<ul>" + ev + "</ul>" : "") +
        "</div>";
    }).join("");
  }

  function endpointsHtml() {
    return state.report.examples.map(function (ex) {
      var rows = ex.fields.map(function (f) {
        return "<tr><td>" + esc(f.name) + "</td><td>" + esc(f.type) + "</td><td>" +
          (f.required ? "required" : "optional") + "</td></tr>";
      }).join("");
      var qrows = ex.query.map(function (f) {
        return "<tr><td>" + esc(f.name) + "</td><td>" + esc(f.type) + "</td><td>" +
          (f.default === null || f.default === undefined ? "" : esc(f.default)) + "</td></tr>";
      }).join("");
      return "<details class='endpoint'><summary>" +
        "<span class='m m-" + esc(ex.method) + "'>" + esc(ex.method) + "</span>" +
        "<span class='path'>" + esc(ex.path) + "</span>" +
        "<span class='codes'>" + (ex.statuses || []).join(", ") + "</span>" +
        "</summary><div class='ep-body'>" +
        (ex.summary ? "<p>" + esc(ex.summary) + "</p>" : "") +
        (rows ? "<table><thead><tr><th>field</th><th>type</th><th>required</th></tr></thead><tbody>" + rows + "</tbody></table>" : "") +
        (qrows ? "<table><thead><tr><th>query param</th><th>type</th><th>default</th></tr></thead><tbody>" + qrows + "</tbody></table>" : "") +
        "<pre>" + esc(ex.curl) + "</pre>" +
        "</div></details>";
    }).join("");
  }

  function render() {
    var rep = state.report;
    if (!rep) return;
    el("empty").hidden = true;
    var host = el("report");
    host.hidden = false;

    var axes = rep.axes.map(function (a) {
      var reasons = (a.reasons || []).map(function (r) { return "<li>" + esc(r) + "</li>"; }).join("");
      return "<div class='axis'><div class='row1'><span>" + esc(a.label) + "</span>" +
        "<span><b>" + esc(a.score) + "</b>/100</span></div>" +
        "<div class='bar'><i style='width:" + Math.max(2, a.score) + "%;background:" + axisColor(a.score) + "'></i></div>" +
        "<div class='status'>weight " + esc(a.weight) + (a.cap ? " | capped: " + esc(a.cap) : "") + "</div>" +
        (reasons ? "<ul>" + reasons + "</ul>" : "") + "</div>";
    }).join("");

    var prio = rep.priorities.map(function (p) {
      return "<li><b><span class='sev sev-" + esc(p.severity) + "'>" + esc(p.severity) + "</span>" +
        esc(p.title) + "</b><p>" + esc(p.fix) + "</p></li>";
    }).join("");

    var sevChips = ["all", "high", "medium", "low"].map(function (s) {
      return "<button class='chip " + (state.severity === s ? "on" : "") + "' data-sev='" + s + "'>" +
        s + "</button>";
    }).join("");
    var axisChips = ["all"].concat(rep.axes.map(function (a) { return a.key; })).map(function (a) {
      return "<button class='chip " + (state.axis === a ? "on" : "") + "' data-axis='" + esc(a) + "'>" + esc(a) + "</button>";
    }).join("");

    var sid = state.sessionId;
    host.innerHTML =
      "<div class='score-head'>" +
      "<div class='score-num'>" + esc(rep.score) + "<small>/100</small></div>" +
      "<div><div><span class='pill " + verdictClass(rep.verdict) + "'>" + esc(rep.verdict_label) + "</span></div>" +
      "<div class='meta' style='margin-top:8px'><span>" + esc(rep.title) + "</span>" +
      "<span>" + (rep.mode === "openapi" ? "OpenAPI document" : "written brief") + "</span>" +
      "<span>" + esc(rep.profile_label) + "</span>" +
      "<span>" + esc(rep.stats.endpoints) + " operations</span>" +
      "<span>" + esc(rep.stats.fields) + " fields</span>" +
      "<span>" + esc(rep.counts.high) + " high / " + esc(rep.counts.medium) + " medium / " + esc(rep.counts.low) + " low</span>" +
      "</div></div></div>" +
      "<div class='axes'>" + axes + "</div>" +
      "<h3>Fix plan</h3><ol class='prio'>" + prio + "</ol>" +
      "<h3>Findings</h3><div class='chips'>" + sevChips + axisChips + "</div>" +
      "<div id='findingList'>" + findingsHtml() + "</div>" +
      "<h3>Operations</h3>" + endpointsHtml() +
      "<h3>Export</h3><div class='exports'>" +
      "<a href='/api/export/" + sid + "?fmt=md'>Markdown review</a>" +
      "<a href='/api/export/" + sid + "?fmt=json'>JSON report</a>" +
      "<a href='/api/export/" + sid + "?fmt=yaml'>Starter OpenAPI (YAML)</a>" +
      "</div>" +
      "<div class='note-row'><div class='stars' id='stars'>" +
      [1, 2, 3, 4, 5].map(function (i) { return "<button data-star='" + i + "'>" + String.fromCharCode(9733) + "</button>"; }).join("") +
      "</div><input id='notes' placeholder='Notes on this review'><button id='saveNote'>Save note</button></div>";

    Array.prototype.forEach.call(host.querySelectorAll("[data-sev]"), function (b) {
      b.onclick = function () { state.severity = b.getAttribute("data-sev"); render(); };
    });
    Array.prototype.forEach.call(host.querySelectorAll("[data-axis]"), function (b) {
      b.onclick = function () { state.axis = b.getAttribute("data-axis"); render(); };
    });
    var starBtns = host.querySelectorAll("[data-star]");
    Array.prototype.forEach.call(starBtns, function (b) {
      b.onclick = function () { saveRating(parseInt(b.getAttribute("data-star"), 10)); };
    });
    var saveBtn = el("saveNote");
    if (saveBtn) {
      saveBtn.onclick = function () { saveNote(); };
    }
    if (sid) {
      api("/api/sessions/" + sid).then(function (r) {
        if (!r.ok) return;
        var noteInput = el("notes");
        if (noteInput) noteInput.value = r.data.notes || "";
        var stars = el("stars");
        if (stars && r.data.rating) {
          Array.prototype.forEach.call(stars.querySelectorAll("[data-star]"), function (b) {
            if (parseInt(b.getAttribute("data-star"), 10) <= r.data.rating) b.classList.add("on");
          });
        }
      });
    }
  }

  function saveRating(rating) {
    if (!state.sessionId) return;
    api("/api/sessions/" + state.sessionId, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rating: rating })
    }).then(function () {
      status("Saved rating " + rating + "/5");
      loadHistory();
      render();
    });
  }

  function saveNote() {
    if (!state.sessionId) return;
    var noteInput = el("notes");
    api("/api/sessions/" + state.sessionId, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ notes: noteInput ? noteInput.value : "" })
    }).then(function () {
      status("Note saved");
    });
  }

  el("run").onclick = run;
  loadSamples();
  loadHistory();
})();
