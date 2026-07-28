/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Subdomains public table: ▸ toggle left of subdomain when Shodan has data
 * for that row's IP. Expand panel shows host detail.
 * Loads tools/shodan/index.js (file:// safe) or index.json.
 * Detail panel may lazy-load tools/shodan/hosts/<ip>.json.
 */
(function () {
    var INDEX_URL = "../tools/shodan/index.json";
    var HOST_URL_PREFIX = "../tools/shodan/hosts/";
    var SHODAN_WEB = "https://www.shodan.io/host/";
    var NVD_CVE = "https://nvd.nist.gov/vuln/detail/";
    var VULN_SHOW = 200;  // show full CVE lists for typical hosts
    var STATUS_PORT = 17322;

    var indexByIp = null;
    var hostCache = {};
    var kevSet = null; // uppercase CVE-ID → true
    var updateClicksBound = false;
    var updateInFlight = Object.create(null);
    // null = unknown / not statusd; true|false after /shodan-status
    var shodanApiKeyConfigured = null;
    var shodanApiKeyPath = "~/.discover/api-keys";

    function esc(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function fetchJson(url) {
        return fetch(url, { credentials: "same-origin", cache: "no-cache" }).then(
            function (res) {
                if (!res.ok) {
                    throw new Error("http " + res.status);
                }
                return res.json();
            }
        );
    }

    function publicTable() {
        return document.querySelector(
            ".inc-subdomains-public table.inc-data-table"
        );
    }

    function ipFromRow(row) {
        // Columns: 0 host, 1 category, 2 IP.
        var cells = row.cells;
        if (!cells || cells.length < 3) {
            return "";
        }
        var ipCell = row.querySelector("td.inc-subdomain-ip") || cells[2];
        return (ipCell.textContent || "").trim();
    }

    function hostCellFromRow(row) {
        return (
            row.querySelector("td.inc-subdomain-host") ||
            (row.cells && row.cells[0]) ||
            null
        );
    }

    function hasShodanData(meta) {
        return !!(meta && String(meta.status || "").toLowerCase() === "ok");
    }

    function safeIpFile(ip) {
        return String(ip).replace(/:/g, "_");
    }

    function tagLayoutHeaders(table) {
        var headRow = table.tHead && table.tHead.rows[0];
        if (!headRow) {
            return;
        }
        Array.prototype.forEach.call(headRow.cells, function (th) {
            var t = (th.textContent || "").replace(/\s+/g, " ").trim().toLowerCase();
            if (t === "web server" && !th.classList.contains("inc-subdomain-webserver-h")) {
                th.classList.add("inc-subdomain-webserver-h");
            }
        });
    }

    function tagIpCells(table) {
        Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
            if (row.classList.contains("inc-shodan-panel-row")) {
                return;
            }
            if (row.classList.contains("inc-host-scan-panel-row")) {
                return;
            }
            if (row.cells.length >= 3 && !row.cells[2].classList.contains("inc-subdomain-ip")) {
                row.cells[2].classList.add("inc-subdomain-ip");
            }
        });
    }

    /** Normalize lists to "a, b, c" (comma + space). */
    function formatList(value) {
        var parts = [];
        if (Array.isArray(value)) {
            parts = value.map(function (p) {
                return String(p).trim();
            }).filter(Boolean);
        } else {
            parts = String(value || "")
                .split(",")
                .map(function (p) {
                    return p.trim();
                })
                .filter(Boolean);
        }
        return parts.join(", ");
    }

    function formatPorts(ports) {
        return formatList(ports);
    }

    function formatHostnames(hostnames) {
        return formatList(hostnames);
    }

    function closeAllPanels(table) {
        table.querySelectorAll("tr.inc-shodan-panel-row").forEach(function (tr) {
            tr.parentNode.removeChild(tr);
        });
        table.querySelectorAll("tr.inc-shodan-open").forEach(function (tr) {
            tr.classList.remove("inc-shodan-open");
        });
        table.querySelectorAll(".inc-shodan-toggle.is-open").forEach(function (el) {
            el.classList.remove("is-open");
            el.textContent = "▸";
            el.setAttribute("aria-expanded", "false");
        });
    }

    function ensureKevSet() {
        if (kevSet) {
            return kevSet;
        }
        kevSet = Object.create(null);
        var raw = window.DISCOVER_KEV_IDS;
        if (Array.isArray(raw)) {
            raw.forEach(function (id) {
                if (id) {
                    kevSet[String(id).toUpperCase()] = true;
                }
            });
        } else if (raw && typeof raw === "object") {
            Object.keys(raw).forEach(function (id) {
                kevSet[String(id).toUpperCase()] = true;
            });
        }
        return kevSet;
    }

    function isKev(cveId) {
        return !!ensureKevSet()[String(cveId || "").toUpperCase()];
    }

    function kevBadgeHtml(cveId) {
        var id = String(cveId || "").toUpperCase();
        var href =
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" +
            "?search=" +
            encodeURIComponent(id) +
            "&field_date_added_wrapper=all&field_cve=&sort_by=field_date_added" +
            "&items_per_page=20&url=";
        return (
            '<a class="inc-kev-badge" href="' +
            href +
            '" target="_blank" rel="noopener noreferrer" ' +
            'title="CISA Known Exploited Vulnerability">' +
            "KEV</a>"
        );
    }

    function cveItemHtml(id) {
        var cve = String(id).toUpperCase();
        var link =
            '<a class="inc-shodan-cve" href="' +
            NVD_CVE +
            encodeURIComponent(cve) +
            '" target="_blank" rel="noopener noreferrer">' +
            esc(cve) +
            "</a>";
        if (isKev(cve)) {
            return (
                '<span class="inc-shodan-cve-item inc-shodan-cve-item--kev">' +
                link +
                kevBadgeHtml(cve) +
                "</span>"
            );
        }
        return '<span class="inc-shodan-cve-item">' + link + "</span>";
    }

    function formatVulnList(vulns) {
        var ids = [];
        if (Array.isArray(vulns)) {
            ids = vulns.map(String);
        } else if (typeof vulns === "string" && vulns.trim()) {
            // Comma-separated (summary.tsv / older index) or single id
            ids = vulns.split(",").map(function (s) {
                return s.trim();
            }).filter(function (s) {
                return s && s.indexOf("…") !== 0 && s.indexOf("(+") !== 0;
            });
        } else if (vulns && typeof vulns === "object") {
            ids = Object.keys(vulns);
        }
        // Keep only CVE-looking tokens
        ids = ids.filter(function (id) {
            return /^CVE-\d{4}-\d+/i.test(id);
        });
        // KEV first, then alphabetical
        ids.sort(function (a, b) {
            var ak = isKev(a) ? 0 : 1;
            var bk = isKev(b) ? 0 : 1;
            if (ak !== bk) {
                return ak - bk;
            }
            return String(a).toUpperCase().localeCompare(String(b).toUpperCase());
        });
        if (!ids.length) {
            return "—";
        }
        var show = ids.slice(0, VULN_SHOW);
        var html =
            '<span class="inc-shodan-cve-list">' +
            show.map(cveItemHtml).join(" ") +
            "</span>";
        if (ids.length > VULN_SHOW) {
            html +=
                ' <span class="inc-shodan-more">+' +
                (ids.length - VULN_SHOW) +
                " more</span>";
        }
        return html;
    }

    /**
     * Format Shodan last_update (ISO) as "mm-dd-yyyy - hh:mm Z".
     * Shodan timestamps are UTC (with or without a trailing Z).
     */
    function formatLastUpdate(raw) {
        if (raw == null || raw === "") {
            return "";
        }
        var s = String(raw).trim();
        var m = s.match(
            /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::\d{2})?/
        );
        if (m) {
            return m[2] + "-" + m[3] + "-" + m[1] + " - " + m[4] + ":" + m[5] + " Z";
        }
        return s;
    }

    function lastUpdatedKvHtml(raw) {
        var formatted = formatLastUpdate(raw);
        if (!formatted) {
            return "";
        }
        return (
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Last updated</span> ' +
            esc(formatted) +
            "</div>"
        );
    }

    /**
     * True only when this page is served by Discover statusd on localhost.
     * Update (API refresh) is operator-only — never on file:// or exports.
     */
    function isDiscoverHostedPage() {
        var host = location.hostname;
        if (host !== "127.0.0.1" && host !== "localhost") {
            return false;
        }
        var port = location.port;
        if (!port) {
            return false;
        }
        return port === String(STATUS_PORT);
    }

    /**
     * Load whether SHODAN_API_KEY is configured (statusd only; never the key).
     * Resolves to true/false, or null when not Discover-hosted / check failed.
     */
    function loadShodanApiKeyStatus() {
        if (!isDiscoverHostedPage()) {
            shodanApiKeyConfigured = null;
            return Promise.resolve(null);
        }
        return fetch("/shodan-status", {
            credentials: "same-origin",
            cache: "no-store",
        })
            .then(function (res) {
                if (!res.ok) {
                    throw new Error("http " + res.status);
                }
                return res.json();
            })
            .then(function (data) {
                shodanApiKeyConfigured = !!(data && data.api_key);
                if (data && data.path) {
                    shodanApiKeyPath = String(data.path);
                }
                return shodanApiKeyConfigured;
            })
            .catch(function () {
                // Leave prior value if any; null means "unknown"
                if (shodanApiKeyConfigured === null) {
                    shodanApiKeyConfigured = null;
                }
                return shodanApiKeyConfigured;
            });
    }

    /** Notice when operator has no Shodan API key configured. */
    function noApiKeyNoticeHtml() {
        if (shodanApiKeyConfigured !== false) {
            return "";
        }
        var pathDisp = shodanApiKeyPath || "~/.discover/api-keys";
        // Prefer short home-relative display when path is under the user home
        if (pathDisp.indexOf("/.discover/api-keys") !== -1) {
            pathDisp = "~/.discover/api-keys";
        }
        return (
            '<div class="inc-shodan-key-notice" role="status">' +
            "<strong>Shodan API key is not set.</strong> " +
            "Add <code>SHODAN_API_KEY=…</code> to <code>" +
            esc(pathDisp) +
            "</code> " +
            "(or <code>export SHODAN_API_KEY=…</code>). " +
            "If that file is missing, run Discover <strong>Update</strong> to create it from the template, " +
            "then edit it and click <strong>Update</strong> here." +
            "</div>"
        );
    }

    /** Panel title: linked "Shodan" → host page; Update when statusd-hosted. */
    function panelHeadHtml(ip) {
        var updateBtn = "";
        if (isDiscoverHostedPage()) {
            var noKey = shodanApiKeyConfigured === false;
            updateBtn =
                '<button type="button" class="inc-shodan-update-btn" data-ip="' +
                esc(ip) +
                '" title="' +
                (noKey
                    ? "Set SHODAN_API_KEY in ~/.discover/api-keys first"
                    : "Pull fresh data from Shodan for this IP") +
                '"' +
                (noKey ? " disabled" : "") +
                ">Update</button>";
        }
        return (
            '<div class="inc-shodan-panel-head">' +
            '<div class="inc-shodan-panel-head-row">' +
            '<a class="inc-shodan-title-link" href="' +
            SHODAN_WEB +
            encodeURIComponent(ip) +
            '" target="_blank" rel="noopener noreferrer"><strong>Shodan</strong></a>' +
            updateBtn +
            "</div>" +
            noApiKeyNoticeHtml() +
            '<div class="inc-shodan-update-status" hidden></div>' +
            "</div>"
        );
    }

    /** Format as "City - Country" (either part optional). */
    function formatLocation(city, country) {
        city = (city || "").trim();
        country = (country || "").trim();
        if (city && country) {
            return city + " - " + country;
        }
        return city || country || "";
    }

    function panelHtmlFromIndex(ip, meta) {
        var org = (meta && meta.org) || "";
        var isp = (meta && meta.isp) || "";
        var ports = formatPorts(meta && meta.ports);
        var hostnames = formatHostnames(meta && meta.hostnames);
        var loc = formatLocation(meta && meta.city, meta && meta.country);
        // Order: Last updated, Hostnames, Location, Org, ISP, Ports, Vulns
        return (
            '<div class="inc-shodan-panel">' +
            panelHeadHtml(ip) +
            '<div class="inc-shodan-panel-body">' +
            lastUpdatedKvHtml(meta && meta.last_update) +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Hostnames</span> ' +
            esc(hostnames || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Location</span> ' +
            esc(loc || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Org</span> ' +
            esc(org || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">ISP</span> ' +
            esc(isp || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Ports</span> ' +
            esc(ports || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Vulns</span> ' +
            formatVulnList(meta && (meta.vulns || meta.vuln_ids)) +
            "</div>" +
            "</div>" +
            "</div>"
        );
    }

    function panelHtmlFromHost(ip, rec) {
        var status = (rec && rec.discover_status) || "";
        if (status === "not_found") {
            return (
                '<div class="inc-shodan-panel">' +
                panelHeadHtml(ip) +
                '<div class="inc-shodan-panel-body">IP not present in the Shodan database.</div>' +
                "</div>"
            );
        }
        if (status !== "ok" || !rec.shodan) {
            return (
                '<div class="inc-shodan-panel">' +
                panelHeadHtml(ip) +
                '<div class="inc-shodan-panel-body">' +
                esc((rec && rec.discover_error) || "No detail available.") +
                "</div></div>"
            );
        }
        var sh = rec.shodan;
        var ports = Array.isArray(sh.ports) ? sh.ports.slice().sort(function (a, b) {
            return a - b;
        }) : [];
        var hostnames = Array.isArray(sh.hostnames) ? sh.hostnames : [];
        var loc = formatLocation(sh.city, sh.country_code || sh.country_name);

        // Order: Last updated, Hostnames, Location, Org, ISP, Ports, Vulns
        return (
            '<div class="inc-shodan-panel">' +
            panelHeadHtml(ip) +
            '<div class="inc-shodan-panel-body">' +
            lastUpdatedKvHtml(sh.last_update) +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Hostnames</span> ' +
            esc(hostnames.length ? formatHostnames(hostnames) : "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Location</span> ' +
            esc(loc || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Org</span> ' +
            esc(sh.org || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">ISP</span> ' +
            esc(sh.isp || "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Ports</span> ' +
            esc(ports.length ? formatPorts(ports) : "—") +
            "</div>" +
            '<div class="inc-shodan-kv"><span class="inc-shodan-k">Vulns</span> ' +
            formatVulnList(sh.vulns) +
            "</div>" +
            "</div>" +
            "</div>"
        );
    }

    function setPanelHtml(panelRow, td, html) {
        var body = panelRow.querySelector(".inc-shodan-panel");
        if (body) {
            body.outerHTML = html;
        } else if (td) {
            td.innerHTML = html;
        }
    }

    function setUpdateStatus(panelRow, message, isError) {
        var el = panelRow && panelRow.querySelector(".inc-shodan-update-status");
        if (!el) {
            return;
        }
        if (!message) {
            el.hidden = true;
            el.textContent = "";
            el.classList.remove("is-error");
            return;
        }
        el.hidden = false;
        el.textContent = message;
        if (isError) {
            el.classList.add("is-error");
        } else {
            el.classList.remove("is-error");
        }
    }

    function refreshShodanIp(ip, panelRow, td) {
        if (!ip || updateInFlight[ip]) {
            return;
        }
        updateInFlight[ip] = true;
        var btn = panelRow.querySelector(".inc-shodan-update-btn");
        if (btn) {
            btn.disabled = true;
            btn.textContent = "Updating…";
        }
        setUpdateStatus(panelRow, "Querying Shodan…", false);

        fetch("/shodan-refresh", {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip }),
        })
            .then(function (res) {
                return res.json().then(function (data) {
                    return { httpOk: res.ok, data: data || {} };
                });
            })
            .then(function (pack) {
                var data = pack.data;
                if (!data.ok) {
                    var err =
                        (data && data.error) ||
                        (!pack.httpOk ? "Refresh failed" : "Shodan update failed");
                    if (
                        err &&
                        /SHODAN_API_KEY|api key/i.test(String(err))
                    ) {
                        shodanApiKeyConfigured = false;
                    }
                    setUpdateStatus(panelRow, err, true);
                    // Re-paint head so the key-location notice appears when missing.
                    if (shodanApiKeyConfigured === false) {
                        var head = panelRow.querySelector(".inc-shodan-panel-head");
                        if (head) {
                            var notice = noApiKeyNoticeHtml();
                            var statusEl = head.querySelector(
                                ".inc-shodan-update-status"
                            );
                            var existing = head.querySelector(
                                ".inc-shodan-key-notice"
                            );
                            if (!existing && notice) {
                                if (statusEl) {
                                    statusEl.insertAdjacentHTML(
                                        "beforebegin",
                                        notice
                                    );
                                } else {
                                    head.insertAdjacentHTML("beforeend", notice);
                                }
                            }
                            var liveBtn = panelRow.querySelector(
                                ".inc-shodan-update-btn"
                            );
                            if (liveBtn) {
                                liveBtn.disabled = true;
                                liveBtn.title =
                                    "Set SHODAN_API_KEY in ~/.discover/api-keys first";
                            }
                        }
                    }
                    return;
                }

                if (data.status === "not_found") {
                    delete hostCache[ip];
                    if (indexByIp) {
                        delete indexByIp[ip];
                    }
                    setPanelHtml(
                        panelRow,
                        td,
                        panelHtmlFromHost(ip, {
                            discover_status: "not_found",
                            ip: ip,
                        })
                    );
                    setUpdateStatus(
                        panelRow,
                        "IP not present in the Shodan database.",
                        false
                    );
                    return;
                }

                var rec = data.host;
                if (rec) {
                    hostCache[ip] = rec;
                }
                if (data.index && indexByIp) {
                    indexByIp[ip] = data.index;
                }
                if (rec) {
                    setPanelHtml(panelRow, td, panelHtmlFromHost(ip, rec));
                } else if (data.index) {
                    setPanelHtml(
                        panelRow,
                        td,
                        panelHtmlFromIndex(ip, data.index)
                    );
                }
                setUpdateStatus(panelRow, "Updated info.", false);
            })
            .catch(function () {
                setUpdateStatus(
                    panelRow,
                    "Could not reach Discover statusd (is the report open via Import?).",
                    true
                );
            })
            .then(function () {
                delete updateInFlight[ip];
                var liveBtn = panelRow.querySelector(".inc-shodan-update-btn");
                if (liveBtn) {
                    liveBtn.disabled = false;
                    liveBtn.textContent = "Update";
                }
            });
    }

    function bindUpdateClicks(table) {
        if (updateClicksBound || !table) {
            return;
        }
        updateClicksBound = true;
        table.addEventListener("click", function (ev) {
            var btn = ev.target && ev.target.closest
                ? ev.target.closest(".inc-shodan-update-btn")
                : null;
            if (!btn || !table.contains(btn)) {
                return;
            }
            ev.preventDefault();
            ev.stopPropagation();
            if (btn.disabled) {
                return;
            }
            var panelRow = btn.closest("tr.inc-shodan-panel-row");
            if (!panelRow) {
                return;
            }
            var ip =
                btn.getAttribute("data-ip") ||
                panelRow.getAttribute("data-for-ip") ||
                "";
            var td = panelRow.cells && panelRow.cells[0];
            refreshShodanIp(ip, panelRow, td);
        });
    }

    function openPanel(row, toggle, ip, meta) {
        var table = row.parentNode && row.parentNode.parentNode;
        if (!table) {
            return;
        }
        var wasOpen = row.classList.contains("inc-shodan-open");
        closeAllPanels(table);
        if (wasOpen) {
            return;
        }

        row.classList.add("inc-shodan-open");
        if (toggle) {
            toggle.classList.add("is-open");
            toggle.textContent = "▾";
            toggle.setAttribute("aria-expanded", "true");
        }

        var panelRow = document.createElement("tr");
        panelRow.className = "inc-shodan-panel-row";
        panelRow.setAttribute("data-for-ip", ip);
        var td = document.createElement("td");
        td.colSpan = row.cells.length;
        // Build after a fresh key check when statusd-hosted so the notice is current.
        function paintPanel() {
            if (!panelRow.parentNode) {
                return;
            }
            td.innerHTML = panelHtmlFromIndex(ip, meta);
            if (hostCache[ip]) {
                setPanelHtml(panelRow, td, panelHtmlFromHost(ip, hostCache[ip]));
                return;
            }
            var url =
                HOST_URL_PREFIX + encodeURIComponent(safeIpFile(ip)) + ".json";
            fetchJson(url)
                .then(function (rec) {
                    hostCache[ip] = rec;
                    if (!panelRow.parentNode) {
                        return;
                    }
                    setPanelHtml(panelRow, td, panelHtmlFromHost(ip, rec));
                })
                .catch(function () {
                    // Keep index summary if full host file missing (common on file://)
                });
        }

        td.innerHTML =
            '<div class="inc-shodan-panel">' +
            panelHeadHtml(ip) +
            '<div class="inc-shodan-panel-body">' +
            '<span class="inc-shodan-muted">Loading…</span>' +
            "</div></div>";
        panelRow.appendChild(td);

        if (row.nextSibling) {
            row.parentNode.insertBefore(panelRow, row.nextSibling);
        } else {
            row.parentNode.appendChild(panelRow);
        }

        bindUpdateClicks(table);

        if (isDiscoverHostedPage()) {
            loadShodanApiKeyStatus().then(function () {
                paintPanel();
            });
        } else {
            paintPanel();
        }
    }

    /**
     * Add ▸ left of subdomain when Shodan has data for the row's public IP.
     * No extra table column.
     */
    function injectToggles(table, index) {
        table.classList.add("inc-subdomains-has-shodan");
        var frame = table.closest(".inc-subdomains-public");
        if (frame) {
            frame.classList.add("inc-subdomains-has-shodan");
        }

        // Drop any leftover Shodan column from an older script version
        var headRow = table.tHead && table.tHead.rows[0];
        if (headRow) {
            var oldTh = headRow.querySelector("th.inc-shodan-h");
            if (oldTh) {
                oldTh.parentNode.removeChild(oldTh);
            }
        }

        Array.prototype.forEach.call(table.tBodies[0].rows, function (row) {
            if (row.classList.contains("inc-shodan-panel-row")) {
                return;
            }
            if (row.classList.contains("inc-host-scan-panel-row")) {
                return;
            }
            // Remove old column cells if present
            var oldCell = row.querySelector("td.inc-shodan-cell");
            if (oldCell) {
                oldCell.parentNode.removeChild(oldCell);
            }
            if (row.querySelector(".inc-shodan-toggle")) {
                return;
            }

            if (row.cells[2] && !row.cells[2].classList.contains("inc-subdomain-ip")) {
                row.cells[2].classList.add("inc-subdomain-ip");
            }

            var ip = ipFromRow(row);
            var meta = ip ? index[ip] : null;
            if (!ip || !hasShodanData(meta)) {
                return;
            }

            var hostCell = hostCellFromRow(row);
            if (!hostCell) {
                return;
            }

            var toggle = document.createElement("span");
            toggle.className = "inc-shodan-toggle";
            toggle.setAttribute("role", "button");
            toggle.setAttribute("tabindex", "0");
            toggle.setAttribute("aria-expanded", "false");
            toggle.setAttribute("aria-label", "Show Shodan details for " + ip);
            toggle.title = "Shodan";
            toggle.textContent = "▸";
            toggle.setAttribute("data-ip", ip);

            toggle.addEventListener("click", function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                openPanel(row, toggle, ip, meta);
            });
            toggle.addEventListener("keydown", function (ev) {
                if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    ev.stopPropagation();
                    openPanel(row, toggle, ip, meta);
                }
            });

            hostCell.insertBefore(toggle, hostCell.firstChild);
            hostCell.classList.add("inc-subdomain-host--shodan");
        });
    }

    /** Load a relative script once; resolve even on error (optional assets). */
    function loadScript(src) {
        return new Promise(function (resolve) {
            var s = document.createElement("script");
            s.src = src;
            s.async = true;
            s.onload = function () {
                resolve(true);
            };
            s.onerror = function () {
                resolve(false);
            };
            (document.head || document.documentElement).appendChild(s);
        });
    }

    /**
     * Load Shodan IP index.
     * Prefer tools/shodan/index.js (works under file:// via <script>).
     * fetch(index.json) fails on file:// in most browsers.
     */
    function loadIndex() {
        if (
            typeof window.DISCOVER_SHODAN_INDEX === "object" &&
            window.DISCOVER_SHODAN_INDEX !== null
        ) {
            return Promise.resolve(window.DISCOVER_SHODAN_INDEX);
        }

        return loadScript("../tools/shodan/index.js").then(function (ok) {
            if (
                ok &&
                typeof window.DISCOVER_SHODAN_INDEX === "object" &&
                window.DISCOVER_SHODAN_INDEX !== null
            ) {
                return window.DISCOVER_SHODAN_INDEX;
            }
            // HTTP / same-origin servers can still use JSON
            return fetchJson(INDEX_URL);
        });
    }

    /** Optional CISA KEV id list for CVE badges (tools/shodan/kev-ids.js). */
    function loadKevIds() {
        if (window.DISCOVER_KEV_IDS) {
            ensureKevSet();
            return Promise.resolve();
        }
        return loadScript("../tools/shodan/kev-ids.js").then(function () {
            ensureKevSet();
        });
    }

    function init() {
        if (!document.body || !document.body.classList.contains("inc-subdomains-page")) {
            return;
        }
        var table = publicTable();
        if (!table || !table.tBodies[0]) {
            return;
        }

        tagLayoutHeaders(table);
        tagIpCells(table);

        // Load KEV in parallel with index so badges are ready when panels open.
        Promise.all([loadIndex(), loadKevIds()])
            .then(function (pair) {
                var index = pair[0];
                if (!index || typeof index !== "object") {
                    return;
                }
                var keys = Object.keys(index);
                if (!keys.length) {
                    return;
                }
                indexByIp = index;
                injectToggles(table, index);
            })
            .catch(function () {
                // No Shodan artifacts — leave table unchanged
            });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
