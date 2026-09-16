/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Subdomains public table: Ports button above the Subdomain column.
 * Opens current Shodan ports for rows in that table (extra ports first).
 */
(function () {
    var COMMON_HTTP = { "80": true, "443": true };

    function esc(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function publicFrame() {
        return document.querySelector(
            ".inc-subdomains-tables .inc-subdomains-public"
        );
    }

    function publicTable() {
        return document.querySelector(
            ".inc-subdomains-public table.inc-data-table"
        );
    }

    function parsePorts(raw) {
        if (Array.isArray(raw)) {
            return raw
                .map(function (p) {
                    return String(p).trim();
                })
                .filter(Boolean);
        }
        var text = String(raw || "").trim();
        if (!text) {
            return [];
        }
        return text.split(/[,\s]+/).filter(Boolean);
    }

    function loadIndex() {
        if (
            typeof window.DISCOVER_SHODAN_INDEX === "object" &&
            window.DISCOVER_SHODAN_INDEX !== null
        ) {
            return Promise.resolve(window.DISCOVER_SHODAN_INDEX);
        }
        return new Promise(function (resolve) {
            var s = document.createElement("script");
            s.src = "../tools/shodan/index.js";
            s.async = true;
            s.onload = function () {
                resolve(
                    typeof window.DISCOVER_SHODAN_INDEX === "object"
                        ? window.DISCOVER_SHODAN_INDEX
                        : null
                );
            };
            s.onerror = function () {
                resolve(null);
            };
            (document.head || document.documentElement).appendChild(s);
        });
    }

    function makeToolbarBtn(id, label, title) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.id = id;
        btn.className = "inc-subdomains-ports-btn";
        btn.textContent = label;
        btn.title = title;
        return btn;
    }

    function ensureToolbar() {
        var frame = publicFrame();
        if (!frame) {
            return null;
        }
        var wrap = document.querySelector(".inc-subdomains-ports-wrap");
        if (!wrap) {
            wrap = document.createElement("div");
            wrap.className = "inc-subdomains-ports-wrap";
            frame.insertBefore(wrap, frame.firstChild);
        }
        var stray = document.getElementById("inc-subdomains-ports-filter-btn");
        if (stray && wrap.contains(stray)) {
            wrap.removeChild(stray);
        }
        var portsBtn = document.getElementById("inc-subdomains-ports-btn");
        if (!portsBtn) {
            portsBtn = makeToolbarBtn(
                "inc-subdomains-ports-btn",
                "Ports",
                "Show Shodan ports for hosts in this table"
            );
            wrap.appendChild(portsBtn);
        }
        return portsBtn;
    }

    function ensureModal() {
        var el = document.getElementById("inc-subdomains-ports-modal");
        if (el) {
            bindFilterBtn(el);
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-subdomains-ports-modal";
        el.className = "inc-report-export-modal inc-subdomains-ports-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-subdomains-ports-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-subdomains-ports-close="1"></div>' +
            '<div class="inc-report-export-dialog inc-subdomains-ports-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-subdomains-ports-title" class="inc-report-export-title">Ports</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-subdomains-ports-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div class="inc-subdomains-ports-modal-bar">' +
            '<button type="button" class="inc-subdomains-ports-btn" id="inc-subdomains-ports-filter-btn" title="Hide hosts whose only Shodan ports are 80 and/or 443">Filter 80/443</button>' +
            "</div>" +
            '<div id="inc-subdomains-ports-body" class="inc-subdomains-ports-body"></div>' +
            '<div class="inc-report-export-actions">' +
            '<button type="button" class="inc-report-export-cancel" data-inc-subdomains-ports-close="1">Close</button>' +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        el.addEventListener("click", function (ev) {
            var t = ev.target;
            if (t && t.getAttribute && t.getAttribute("data-inc-subdomains-ports-close")) {
                closeModal();
            }
        });
        bindFilterBtn(el);
        return el;
    }

    function closeModal() {
        var el = document.getElementById("inc-subdomains-ports-modal");
        if (el) {
            el.setAttribute("hidden", "hidden");
        }
    }

    function openModal() {
        ensureModal().removeAttribute("hidden");
        scrollModalTop();
    }

    function scrollModalTop() {
        var body = document.getElementById("inc-subdomains-ports-body");
        if (body) {
            body.scrollTop = 0;
        }
        var dialog = document.querySelector(
            "#inc-subdomains-ports-modal .inc-subdomains-ports-dialog"
        );
        if (dialog) {
            dialog.scrollTop = 0;
        }
    }

    function rowVisible(row) {
        if (!row || row.hidden) {
            return false;
        }
        if (row.style && row.style.display === "none") {
            return false;
        }
        return true;
    }

    function rowHasHttpStatus(row) {
        if (!row || !row.cells) {
            return false;
        }
        var t;
        if (row.cells.length > 4) {
            t = (row.cells[4].textContent || "").trim();
            if (/^\d{3}$/.test(t)) {
                return true;
            }
        }
        if (row.cells.length > 5) {
            t = (row.cells[5].textContent || "").trim();
            if (/^\d{3}$/.test(t)) {
                return true;
            }
        }
        var tds = row.querySelectorAll("td.inc-col-center");
        var i;
        for (i = 0; i < tds.length; i++) {
            t = (tds[i].textContent || "").trim();
            if (/^\d{3}$/.test(t)) {
                return true;
            }
        }
        return false;
    }

    function collectRows(index) {
        var table = publicTable();
        if (!table || !table.tBodies[0]) {
            return [];
        }
        var extra = [];
        var httpOnly = [];
        var seen = {};
        Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
            if (!rowVisible(row)) {
                return;
            }
            if (!rowHasHttpStatus(row)) {
                return;
            }
            var hostCell =
                row.querySelector("td.inc-subdomain-host") ||
                (row.cells && row.cells[0]);
            var ipCell =
                row.querySelector("td.inc-subdomain-ip") ||
                (row.cells && row.cells[2]);
            var host = hostCell
                ? (hostCell.textContent || "").replace(/▸/g, "").trim()
                : "";
            var ip = ipCell ? (ipCell.textContent || "").trim() : "";
            if (!host && !ip) {
                return;
            }
            var key = host + "\t" + ip;
            if (seen[key]) {
                return;
            }
            seen[key] = true;
            var meta = ip && index ? index[ip] : null;
            var ports = parsePorts(meta && meta.ports);
            var item = { host: host, ip: ip, ports: ports };
            if (ports.some(function (p) { return !COMMON_HTTP[p]; })) {
                extra.push(item);
            } else {
                httpOnly.push(item);
            }
        });
        return extra.concat(httpOnly);
    }

    function renderBody(items) {
        var body = document.getElementById("inc-subdomains-ports-body");
        if (!body) {
            return;
        }
        var withPorts = items
            .map(function (it) {
                var ports = (it.ports || []).slice();
                if (hideHttpOnly) {
                    ports = ports.filter(function (p) {
                        return !COMMON_HTTP[String(p)];
                    });
                }
                return { host: it.host, ip: it.ip, ports: ports };
            })
            .filter(function (it) {
                return it.ports && it.ports.length;
            });
        withPorts.sort(function (a, b) {
            return String(a.host || a.ip || "").localeCompare(
                String(b.host || b.ip || ""),
                undefined,
                { sensitivity: "base" }
            );
        });
        var html = [];
        if (!withPorts.length) {
            html.push(
                hideHttpOnly
                    ? "<p>No hosts with ports besides 80/443.</p>"
                    : "<p>No Shodan ports for hosts in this table.</p>"
            );
            body.innerHTML = html.join("");
            return;
        }
        var width = 0;
        withPorts.forEach(function (it) {
            var name = String(it.host || it.ip || "");
            if (name.length > width) {
                width = name.length;
            }
        });
        html.push('<pre class="inc-subdomains-ports-pre">');
        withPorts.forEach(function (it) {
            var name = String(it.host || it.ip || "");
            var pad = width - name.length + 3;
            var spaces = "";
            var i;
            for (i = 0; i < pad; i++) {
                spaces += " ";
            }
            html.push(
                esc(name) + spaces + esc(it.ports.join(", ")) + "\n"
            );
        });
        html.push("</pre>");
        body.innerHTML = html.join("");
    }

    var hideHttpOnly = false;
    var lastItems = [];

    function bindFilterBtn(modal) {
        var filterBtn = document.getElementById("inc-subdomains-ports-filter-btn");
        if (!filterBtn || filterBtn.getAttribute("data-inc-ports-bound") === "1") {
            return;
        }
        filterBtn.setAttribute("data-inc-ports-bound", "1");
        filterBtn.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            hideHttpOnly = !hideHttpOnly;
            filterBtn.setAttribute("aria-pressed", hideHttpOnly ? "true" : "false");
            renderBody(lastItems);
        });
    }

    function showPortsModal() {
        hideHttpOnly = false;
        lastItems = [];
        var filterBtn = document.getElementById("inc-subdomains-ports-filter-btn");
        if (filterBtn) {
            filterBtn.setAttribute("aria-pressed", "false");
        }
        var body = document.getElementById("inc-subdomains-ports-body");
        if (body) {
            body.innerHTML = "<p>Loading Shodan ports.</p>";
        }
        openModal();
        loadIndex().then(function (index) {
            lastItems = collectRows(index || {});
            renderBody(lastItems);
            scrollModalTop();
            requestAnimationFrame(scrollModalTop);
        });
    }

    function init() {
        if (
            !document.body ||
            !document.body.classList.contains("inc-subdomains-page")
        ) {
            return;
        }
        if (!publicTable()) {
            return;
        }
        var portsBtn = ensureToolbar();
        if (!portsBtn || portsBtn.getAttribute("data-inc-ports-bound") === "1") {
            return;
        }
        portsBtn.setAttribute("data-inc-ports-bound", "1");
        ensureModal();
        portsBtn.addEventListener("click", showPortsModal);
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape") {
                closeModal();
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
