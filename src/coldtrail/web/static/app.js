(function () {
  "use strict";

  // 1. Custom scope toggle on /pivot
  var scope = document.getElementById("scope");
  var wrap = document.getElementById("custom-wrap");
  if (scope && wrap) {
    var syncScope = function () {
      wrap.classList.toggle("hidden", scope.value !== "custom");
    };
    scope.addEventListener("change", syncScope);
    syncScope();
  }

  // 1b. Client-side source filter on /sources
  var sourceFilter = document.getElementById("source-filter");
  if (sourceFilter) {
    sourceFilter.addEventListener("input", function () {
      var needle = this.value.toLowerCase();
      var rows = document.querySelectorAll("#sources-table tbody tr");
      for (var i = 0; i < rows.length; i++) {
        rows[i].style.display = rows[i].textContent.toLowerCase().indexOf(needle) >= 0 ? "" : "none";
      }
    });
  }

  // 2. Real-time SSE streaming on /jobs/{id}
  var jobPanel = document.getElementById("job-live");
  if (jobPanel && typeof EventSource !== "undefined") {
    var jobId = jobPanel.getAttribute("data-job-id");
    var jobStatus = jobPanel.getAttribute("data-job-status");
    var tbody = document.getElementById("job-events");
    var countsEl = document.getElementById("job-counts");
    var stateEl = document.getElementById("job-state");
    if (jobId && (jobStatus === "queued" || jobStatus === "running")) {
      var seen = tbody ? tbody.querySelectorAll("tr").length : 0;
      var checkedCount = seen;
      var foundCount = 0;
      var es = new EventSource("/api/jobs/" + encodeURIComponent(jobId) + "/stream");
      es.addEventListener("check", function (ev) {
        try {
          var row = JSON.parse(ev.data);
          checkedCount += 1;
          if (row.status === "found") foundCount += 1;
          if (stateEl) stateEl.textContent = "running";
          if (countsEl) countsEl.textContent = foundCount + " found / " + checkedCount + " checked";
          if (tbody) {
            var tr = document.createElement("tr");
            var tdSrc = document.createElement("td");
            tdSrc.className = "mono";
            tdSrc.textContent = row.source || "";
            var tdSt = document.createElement("td");
            var badge = document.createElement("span");
            badge.className = "badge status-" + (row.status || "error");
            badge.textContent = row.status || "";
            tdSt.appendChild(badge);
            var tdTgt = document.createElement("td");
            tdTgt.className = "mono";
            tdTgt.textContent = row.target || "";
            var tdUser = document.createElement("td");
            tdUser.className = "mono";
            if (row.url && row.url !== "#") {
              var a = document.createElement("a");
              a.href = row.url;
              a.target = "_blank";
              a.rel = "noopener";
              a.textContent = row.username || row.url;
              tdUser.appendChild(a);
            } else {
              tdUser.textContent = row.username || "";
            }
            var tdDet = document.createElement("td");
            tdDet.textContent = (row.detail || "").slice(0, 80);
            tr.appendChild(tdSrc);
            tr.appendChild(tdSt);
            tr.appendChild(tdTgt);
            tr.appendChild(tdUser);
            tr.appendChild(tdDet);
            tbody.insertBefore(tr, tbody.firstChild);
          }
        } catch (_e) {}
      });
      es.addEventListener("done", function (ev) {
        es.close();
        try {
          var summary = JSON.parse(ev.data);
          if (summary.run_id) {
            window.location.href = "/runs/" + summary.run_id;
            return;
          }
        } catch (_e) {}
        window.location.reload();
      });
    }
  }

  // 3. Interactive force-directed identity graph on /runs/{id}
  var canvas = document.getElementById("identity-graph");
  var inspector = document.getElementById("graph-inspector");
  if (canvas) {
    var runId = canvas.getAttribute("data-run-id");
    var ctx = canvas.getContext("2d");
    fetch("/api/runs/" + encodeURIComponent(runId) + "/graph")
      .then(function (r) { return r.json(); })
      .then(function (graph) {
        var nodes = graph.nodes || [];
        var edges = graph.edges || [];
        if (!nodes.length) {
          if (inspector) inspector.textContent = "No graph nodes in this run.";
          return;
        }
        var W = canvas.width;
        var H = canvas.height;
        var byId = {};
        nodes.forEach(function (n, idx) {
          var angle = (2 * Math.PI * idx) / Math.max(1, nodes.length);
          var radius = Math.min(W, H) * 0.44;
          n.x = W / 2 + radius * Math.cos(angle);
          n.y = H / 2 + radius * Math.sin(angle);
          n.vx = 0;
          n.vy = 0;
          byId[n.id] = n;
        });

        var dragging = null;
        var selected = null;
        var zoom = 1.0;

        function colorFor(n) {
          if (n.kind === "entity") return "#d29922";
          if (n.kind === "follow") return "#6e7b8c";
          if (n.cluster) return "#3fb950";
          return "#4f9cf9";
        }

        function step() {
          for (var i = 0; i < nodes.length; i++) {
            for (var j = i + 1; j < nodes.length; j++) {
              var a = nodes[i], b = nodes[j];
              var dx = b.x - a.x, dy = b.y - a.y;
              var d2 = dx * dx + dy * dy + 1;
              var f = 5200 / d2;
              var d = Math.sqrt(d2);
              a.vx -= (dx / d) * f;
              a.vy -= (dy / d) * f;
              b.vx += (dx / d) * f;
              b.vy += (dy / d) * f;
            }
          }
          edges.forEach(function (e) {
            var s = byId[e.source], t = byId[e.target];
            if (!s || !t) return;
            var dx = t.x - s.x, dy = t.y - s.y;
            var d = Math.sqrt(dx * dx + dy * dy) || 1;
            var targetLen = e.kind === "correlation" ? 150 : 105;
            var k = (d - targetLen) * 0.025;
            s.vx += (dx / d) * k;
            s.vy += (dy / d) * k;
            t.vx -= (dx / d) * k;
            t.vy -= (dy / d) * k;
          });
          nodes.forEach(function (n) {
            if (n === dragging) return;
            n.vx += (W / 2 - n.x) * 0.0014;
            n.vy += (H / 2 - n.y) * 0.0014;
            n.vx *= 0.85;
            n.vy *= 0.85;
            n.x = Math.max(28, Math.min(W - 28, n.x + n.vx));
            n.y = Math.max(24, Math.min(H - 24, n.y + n.vy));
          });
        }

        function draw() {
          ctx.clearRect(0, 0, W, H);
          ctx.save();
          ctx.translate(W / 2, H / 2);
          ctx.scale(zoom, zoom);
          ctx.translate(-W / 2, -H / 2);

          edges.forEach(function (e) {
            var s = byId[e.source], t = byId[e.target];
            if (!s || !t) return;
            ctx.beginPath();
            ctx.moveTo(s.x, s.y);
            ctx.lineTo(t.x, t.y);
            ctx.strokeStyle = e.kind === "correlation" ? "#3fb950" : (e.kind === "entity" ? "#d29922" : "#324052");
            ctx.lineWidth = e.kind === "correlation" ? 2.2 : 1.1;
            ctx.stroke();
          });

          nodes.forEach(function (n) {
            var r = n.kind === "profile" ? 9 : 6;
            ctx.beginPath();
            ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
            ctx.fillStyle = colorFor(n);
            ctx.fill();
            ctx.lineWidth = n === selected ? 2.5 : 1;
            ctx.strokeStyle = n === selected ? "#ffffff" : "#0e1116";
            ctx.stroke();

            ctx.font = "10px ui-monospace, monospace";
            ctx.lineWidth = 3;
            ctx.strokeStyle = "#0e1116";
            ctx.strokeText(n.id.slice(0, 24), n.x + r + 4, n.y + 4);
            ctx.fillStyle = "#d7dee8";
            ctx.fillText(n.id.slice(0, 24), n.x + r + 4, n.y + 4);
          });
          ctx.restore();
        }

        var ticks = 0;
        function animate() {
          if (ticks < 360 || dragging) {
            step();
            ticks += 1;
          }
          draw();
          requestAnimationFrame(animate);
        }
        animate();

        function pickNode(ev) {
          var rect = canvas.getBoundingClientRect();
          var scaleX = W / rect.width;
          var scaleY = H / rect.height;
          var mx = ((ev.clientX - rect.left) * scaleX - W / 2) / zoom + W / 2;
          var my = ((ev.clientY - rect.top) * scaleY - H / 2) / zoom + H / 2;
          for (var i = nodes.length - 1; i >= 0; i--) {
            var n = nodes[i];
            var dx = n.x - mx, dy = n.y - my;
            if (dx * dx + dy * dy <= 160) return { node: n, mx: mx, my: my };
          }
          return { node: null, mx: mx, my: my };
        }

        canvas.addEventListener("mousedown", function (ev) {
          var hit = pickNode(ev);
          if (hit.node) {
            dragging = hit.node;
            selected = hit.node;
            if (inspector) {
              var info = "[" + hit.node.kind + "] " + hit.node.id;
              if (hit.node.cluster) info += " · cluster " + hit.node.cluster;
              if (hit.node.bio) info += " — " + hit.node.bio;
              inspector.textContent = info;
            }
          }
        });
        canvas.addEventListener("mousemove", function (ev) {
          if (!dragging) return;
          var hit = pickNode(ev);
          dragging.x = hit.mx;
          dragging.y = hit.my;
          dragging.vx = 0;
          dragging.vy = 0;
        });
        window.addEventListener("mouseup", function () { dragging = null; });
        canvas.addEventListener("wheel", function (ev) {
          ev.preventDefault();
          zoom = Math.max(0.5, Math.min(2.5, zoom * (ev.deltaY < 0 ? 1.1 : 0.9)));
        });
      })
      .catch(function () {});
  }
})();
