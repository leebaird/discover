/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Software-filtered Subdomains: expand host row → launch host-scan tools.
 * Operator only (report-mode launches true + Discover session).
 * One tool at a time; live status via 127.0.0.1 statusd when available.
 * droopescan is gated: only when software is a supported CMS.
 */
(function () {
    /** Host-scan expand panel logic. */
    // Base tools quietest → loudest (droopescan inserted when CMS filter matches).
    var TOOLS_BASE = ["nuclei", "nikto", "ffuf"];
    // droopescan CMS label → plugin name (must match run-host-scan.sh).
    var DROOPESCAN_CMS = {
        drupal: "drupal",
        wordpress: "wordpress",
        wp: "wordpress",
        joomla: "joomla",
        moodle: "moodle",
        silverstripe: "silverstripe",
        ss: "silverstripe"
    };
    var STATUS_PORT_DEFAULT = 17322;
    var pollTimer = null;

    function querySoftware() {
        try {
            return (new URLSearchParams(window.location.search || "").get("software") || "").trim();
        } catch (e) {
            return "";
        }
    }

    function queryCve() {
        try {
            return (new URLSearchParams(window.location.search || "").get("cve") || "").trim();
        } catch (e) {
            return "";
        }
    }

    /** Map software filter (e.g. Drupal:7) → droopescan CMS or null. */
    function droopescanCms(software) {
        var s = (software || "").toLowerCase().trim();
        if (!s) {
            return null;
        }
        s = s.split("[")[0];
        s = s.split(":")[0];
        s = s.replace(/\s+/g, "");
        return DROOPESCAN_CMS[s] || null;
    }

    /** Tools for this expand panel (includes droopescan when gated CMS). */
    function toolsForSoftware(software) {
        if (droopescanCms(software)) {
            return ["nuclei", "droopescan", "nikto", "ffuf"];
        }
        return TOOLS_BASE.slice();
    }

    function reportMode() {
        var meta = document.querySelector('meta[name="discover-report-mode"]');
        if (meta && meta.getAttribute("content")) {
            return meta.getAttribute("content");
        }
        return null;
    }

    function launchesAllowed(modeObj) {
        if (modeObj && typeof modeObj.launches === "boolean") {
            return modeObj.launches;
        }
        var m = (modeObj && modeObj.mode) || reportMode() || "operator";
        return String(m).toLowerCase() === "operator";
    }

    function hostFromRow(row) {
        var link = row.querySelector("a.inc-subdomain-host-link");
        if (link) {
            return {
                host: (link.textContent || "").trim(),
                url: link.getAttribute("href") || ""
            };
        }
        var cell = row.querySelector("td.inc-subdomain-host");
        if (!cell) {
            return null;
        }
        var host = (cell.textContent || "").trim();
        if (!host) {
            return null;
        }
        return { host: host, url: "https://" + host };
    }

    function statusPort() {
        return STATUS_PORT_DEFAULT;
    }

    function fetchJson(url) {
        return fetch(url, { cache: "no-store" }).then(function (r) {
            if (!r.ok) {
                throw new Error("http " + r.status);
            }
            return r.json();
        });
    }

    function loadMode() {
        return fetchJson("http://127.0.0.1:" + statusPort() + "/mode").catch(function () {
            return fetchJson("../assets/report-mode.json").catch(function () {
                return { mode: "operator", launches: true };
            });
        });
    }

    function loadStatus() {
        return fetchJson("http://127.0.0.1:" + statusPort() + "/status").catch(function () {
            return fetchJson("../tools/host-scans/status.json").catch(function () {
                return { running: false, hosts: {} };
            });
        });
    }

    function encodeQuery(obj) {
        return Object.keys(obj)
            .filter(function (k) {
                return obj[k] != null && obj[k] !== "";
            })
            .map(function (k) {
                return encodeURIComponent(k) + "=" + encodeURIComponent(obj[k]);
            })
            .join("&");
    }

    function launchHref(tool, url, software) {
        return "discover-scan://" + tool + "?" + encodeQuery({ url: url, software: software });
    }

    function toolState(status, host, tool) {
        var hosts = (status && status.hosts) || {};
        var h = hosts[host] || {};
        return h[tool] || null;
    }

    /** Build TXT (+ HTM for nikto) buttons for a finished tool run. */
    function outputButtonsHtml(tool, st) {
        if (!st || !(st.output || st.output_rel)) {
            return "";
        }
        var rel = st.output_rel || st.output;
        if (String(rel).indexOf("../") !== 0) {
            rel = "../" + String(rel).replace(/^\//, "");
        }
        var safe = String(rel).replace(/"/g, "&quot;");
        var html =
            '<span class="inc-host-scan-btn-row">' +
            '<a class="inc-host-scan-out" href="' +
            safe +
            '" target="_blank" rel="noopener">txt</a>';
        if (tool === "nikto") {
            // nikto.htm lives next to output.txt in the run directory
            var htmRel = String(rel).replace(/[^/]+$/, "nikto.htm");
            html +=
                '<a class="inc-host-scan-out" href="' +
                htmRel.replace(/"/g, "&quot;") +
                '" target="_blank" rel="noopener">htm</a>';
        }
        if (tool === "ffuf") {
            // Absolute path via discover-ffuf: → open-ffuf-tabs.sh (Firefox CLI)
            var jsonRel = String(rel).replace(/[^/]+$/, "ffuf.json");
            var absJson = ffufJsonAbsolutePath(jsonRel);
            if (absJson) {
                html +=
                    '<a class="inc-host-scan-out" href="discover-ffuf:' +
                    encodeURI(absJson).replace(/"/g, "&quot;") +
                    '" title="Open each ffuf finding URL in Firefox">url</a>';
            }
        }
        html += "</span>";
        return html;
    }

    /** Best-effort absolute path for ffuf.json (for discover-ffuf: handler). */
    function ffufJsonAbsolutePath(relFromPages) {
        try {
            var a = document.createElement("a");
            a.href = relFromPages;
            // file:// or http(s):// to the report; handler wants filesystem path when possible
            var href = a.href || "";
            if (href.indexOf("file://") === 0) {
                return decodeURIComponent(href.replace(/^file:\/\//, ""));
            }
            // Served via http: pass report-relative tools/... path (handler resolves via current-report)
            var m = String(relFromPages).match(/(tools\/host-scans\/.+)/);
            if (m) {
                return m[1];
            }
            return relFromPages.replace(/^\.\.\//, "");
        } catch (e) {
            return "";
        }
    }

    function lastRunHtml(tool, st) {
        if (st && st.status === "running") {
            return "Running…";
        }
        if (st && (st.finished_display || st.finished)) {
            var last = st.finished_display || st.finished;
            var btns = outputButtonsHtml(tool, st);
            if (btns) {
                // Timestamp in its own span; buttons follow (CSS flex aligns them).
                return (
                    '<span class="inc-host-scan-last-time">' +
                    last +
                    "</span>" +
                    btns
                );
            }
            return '<span class="inc-host-scan-last-time">' + last + "</span>";
        }
        return "Not run";
    }

    function renderPanel(row, info, software, canLaunch, status) {
        var safeHost = String(info.host).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        var existing = row.parentNode.querySelector(
            'tr.inc-host-scan-panel-row[data-for-host="' + safeHost + '"]'
        );
        if (existing) {
            existing.parentNode.removeChild(existing);
            row.classList.remove("inc-host-scan-open");
            return;
        }

        // Close any other open panel
        row.parentNode.querySelectorAll("tr.inc-host-scan-panel-row").forEach(function (tr) {
            tr.parentNode.removeChild(tr);
        });
        row.parentNode.querySelectorAll("tr.inc-host-scan-open").forEach(function (tr) {
            tr.classList.remove("inc-host-scan-open");
        });

        row.classList.add("inc-host-scan-open");
        var panelRow = document.createElement("tr");
        panelRow.className = "inc-host-scan-panel-row";
        panelRow.setAttribute("data-for-host", info.host);
        var td = document.createElement("td");
        td.colSpan = row.cells.length;

        var running = !!(status && status.running);
        var html = '<div class="inc-host-scan-panel">';
        if (!canLaunch) {
            html +=
                '<div class="inc-host-scan-panel-meta"><div class="inc-audit-note">Launches disabled (client/defender package or Discover session inactive).</div></div>';
        }
        html += '<div class="inc-host-scan-tools">';

        var panelTools = toolsForSoftware(software);
        panelTools.forEach(function (tool) {
            var st = toolState(status, info.host, tool);
            var launchHtml;
            if (canLaunch && !running) {
                launchHtml =
                    '<a class="inc-host-scan-launch" href="' +
                    launchHref(tool, info.url, software).replace(/"/g, "&quot;") +
                    '">Run</a>';
            } else {
                launchHtml = '<span class="inc-host-scan-launch-disabled">Run</span>';
            }

            html += '<div class="inc-host-scan-tool" data-tool="' + tool + '">';
            html += '<div class="inc-host-scan-tool-head">';
            html +=
                '<span class="inc-host-scan-tool-name">' +
                (tool === "droopescan" ? "droopescan" : tool) +
                "</span>";
            html += launchHtml;
            html += "</div>";
            html +=
                '<span class="inc-host-scan-last">' +
                lastRunHtml(tool, st) +
                "</span></div>";
        });

        html += "</div></div>";
        td.innerHTML = html;

        panelRow.appendChild(td);
        if (row.nextSibling) {
            row.parentNode.insertBefore(panelRow, row.nextSibling);
        } else {
            row.parentNode.appendChild(panelRow);
        }
    }

    function addToggles(software, canLaunch) {
        var publicTable = document.querySelector(
            ".inc-subdomains-public table.inc-data-table"
        );
        if (!publicTable || !publicTable.tBodies[0]) {
            return;
        }

        // Append toggle as LAST column so Category/IP/Photo/Status/Web Server
        // keep the same nth-child indices (and widths) as the unfiltered page.
        var headRow = publicTable.tHead && publicTable.tHead.rows[0];
        if (headRow && !headRow.querySelector(".inc-host-scan-toggle-h")) {
            var th = document.createElement("th");
            th.className = "inc-host-scan-toggle-h";
            th.scope = "col";
            th.title = "Host scans";
            th.textContent = "";
            headRow.appendChild(th);
        }

        Array.prototype.forEach.call(publicTable.tBodies[0].rows, function (row) {
            if (row.classList.contains("inc-host-scan-panel-row")) {
                return;
            }
            if (row.classList.contains("inc-subdomains-filter-hide")) {
                return;
            }
            if (row.querySelector("td.inc-host-scan-toggle")) {
                return;
            }
            var info = hostFromRow(row);
            if (!info || !info.url) {
                return;
            }
            // Only hosts with a real HTTP status get scan UI
            var hasStatus = false;
            Array.prototype.forEach.call(row.querySelectorAll("td.inc-col-center"), function (td) {
                if (/^\d{3}$/.test((td.textContent || "").trim())) {
                    hasStatus = true;
                }
            });
            if (!hasStatus && !row.querySelector("a.inc-subdomain-host-link")) {
                return;
            }

            var td = document.createElement("td");
            td.className = "inc-host-scan-toggle";
            td.title = "Host scans";
            td.textContent = "▸";
            td.addEventListener("click", function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                Promise.all([loadMode(), loadStatus()]).then(function (pair) {
                    var mode = pair[0];
                    var status = pair[1];
                    var allow = canLaunch && launchesAllowed(mode);
                    if (row.classList.contains("inc-host-scan-open")) {
                        td.textContent = "▸";
                    } else {
                        td.textContent = "▾";
                    }
                    renderPanel(row, info, software, allow, status);
                });
            });
            row.appendChild(td);
        });
    }

    function startPolling() {
        if (pollTimer) {
            return;
        }
        pollTimer = setInterval(function () {
            var open = document.querySelector("tr.inc-host-scan-open");
            if (!open) {
                return;
            }
            var host = null;
            var panel = document.querySelector("tr.inc-host-scan-panel-row");
            if (panel) {
                host = panel.getAttribute("data-for-host");
            }
            if (!host) {
                return;
            }
            loadStatus().then(function (status) {
                // Refresh panel content by re-click simulation: update last-run labels
                panel.querySelectorAll(".inc-host-scan-tool").forEach(function (el) {
                    var tool = el.getAttribute("data-tool");
                    var st = toolState(status, host, tool);
                    var lastEl = el.querySelector(".inc-host-scan-last");
                    if (!lastEl) {
                        return;
                    }
                    lastEl.innerHTML = lastRunHtml(tool, st);
                });
                var running = !!(status && status.running);
                panel.querySelectorAll("a.inc-host-scan-launch").forEach(function (a) {
                    if (running) {
                        a.classList.add("is-disabled");
                    } else {
                        a.classList.remove("is-disabled");
                    }
                });
            });
        }, 2000);
    }

    function init() {
        var software = querySoftware();
        var cve = queryCve();
        // Enable host-scan UI for software filter or CVE filter (same filtered layout).
        // CVE mode has no single CMS label → base tools only (no droopescan).
        if (!software && !cve) {
            return;
        }

        loadMode().then(function (mode) {
            var canLaunch = launchesAllowed(mode);
            addToggles(software || "", canLaunch);
            if (canLaunch) {
                startPolling();
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
