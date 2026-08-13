/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit page Config button (Discover statusd only).
 * Hub with three choice rows: APIs, Operator name, Time zone.
 * APIs/operator/timezone read-write via /config endpoints.
 * Timezone is display-only (stamps stay UTC on disk).
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;
    var configCache = null;
    var panel = "hub";

    function isDiscoverHostedPage() {
        var host = location.hostname;
        if (host !== "127.0.0.1" && host !== "localhost") {
            return false;
        }
        return location.port === String(STATUS_PORT);
    }

    function isAuditPage() {
        return (
            document.body.classList.contains("inc-audit-page") ||
            /\/audit\.htm/i.test(location.pathname || "")
        );
    }

    function statusdUrl(path) {
        return "http://127.0.0.1:" + STATUS_PORT + path;
    }

    function ensureModal() {
        var el = document.getElementById("inc-audit-config-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-audit-config-modal";
        el.className = "inc-report-export-modal inc-audit-config-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-audit-config-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-audit-config-close="1"></div>' +
            '<div class="inc-report-export-dialog inc-audit-config-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-audit-config-title" class="inc-report-export-title">Config</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-audit-config-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div id="inc-audit-config-body" class="inc-audit-config-body"></div>' +
            '<div class="inc-report-export-status" id="inc-audit-config-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-audit-config-actions"></div>' +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setStatus(msg, isError) {
        var el = document.getElementById("inc-audit-config-status");
        if (!el) {
            return;
        }
        if (!msg) {
            el.hidden = true;
            el.textContent = "";
            el.classList.remove("is-error");
            return;
        }
        el.hidden = false;
        el.textContent = msg;
        if (isError) {
            el.classList.add("is-error");
        } else {
            el.classList.remove("is-error");
        }
    }

    function loadConfig() {
        return fetch(statusdUrl("/config"), { cache: "no-store" })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { http: r.status, body: j };
                });
            })
            .then(function (res) {
                if (!res.body || !res.body.ok) {
                    throw new Error(
                        (res.body && res.body.error) ||
                            "Could not load config (HTTP " + res.http + ")."
                    );
                }
                configCache = res.body;
                return configCache;
            });
    }

    function renderHub() {
        panel = "hub";
        var body = document.getElementById("inc-audit-config-body");
        var actions = document.getElementById("inc-audit-config-actions");
        var title = document.getElementById("inc-audit-config-title");
        if (title) {
            title.textContent = "Config";
        }
        setStatus("");
        body.innerHTML =
            '<p class="inc-report-export-lead">Choose a setting to view or change.</p>' +
            '<div class="inc-audit-config-choices" role="list">' +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-config-panel="apis">' +
            "<strong>APIs</strong>" +
            "<span>NVD, Shodan, and WPScan keys for this machine</span>" +
            "</button>" +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-config-panel="operator">' +
            "<strong>Operator name</strong>" +
            "<span>First name on audit log lines (updates this report if changed)</span>" +
            "</button>" +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-config-panel="timezone">' +
            "<strong>Time zone</strong>" +
            "<span>How Audit times are shown (stamps stay UTC on disk)</span>" +
            "</button>" +
            "</div>";
        actions.innerHTML =
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-config-close="1">Close</button>';
    }

    function renderApis() {
        panel = "apis";
        var body = document.getElementById("inc-audit-config-body");
        var actions = document.getElementById("inc-audit-config-actions");
        var title = document.getElementById("inc-audit-config-title");
        var keys = (configCache && configCache.api_keys) || {};
        if (title) {
            title.textContent = "APIs";
        }
        setStatus("");
        body.innerHTML =
            '<p class="inc-report-export-lead">Stored in ~/.discover/api-keys.</p>' +
            '<p class="inc-report-export-lead">Edit and Save.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-config-nvd">' +
            "<span>NVD API key</span>" +
            '<input type="text" id="inc-audit-config-nvd" class="inc-audit-import-input" autocomplete="off" spellcheck="false" value="' +
            escapeAttr(keys.NVD_API_KEY || "") +
            '">' +
            "</label>" +
            '<label class="inc-audit-import-field" for="inc-audit-config-shodan">' +
            "<span>Shodan API key</span>" +
            '<input type="text" id="inc-audit-config-shodan" class="inc-audit-import-input" autocomplete="off" spellcheck="false" value="' +
            escapeAttr(keys.SHODAN_API_KEY || "") +
            '">' +
            "</label>" +
            '<label class="inc-audit-import-field" for="inc-audit-config-wpscan">' +
            "<span>WPScan API token</span>" +
            '<input type="text" id="inc-audit-config-wpscan" class="inc-audit-import-input" autocomplete="off" spellcheck="false" value="' +
            escapeAttr(keys.WPSCAN_API_TOKEN || "") +
            '">' +
            "</label>";
        actions.innerHTML =
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-config-panel="hub">Back</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-audit-config-save-apis">Save</button>';
    }

    function renderOperator() {
        panel = "operator";
        var body = document.getElementById("inc-audit-config-body");
        var actions = document.getElementById("inc-audit-config-actions");
        var title = document.getElementById("inc-audit-config-title");
        var name = (configCache && configCache.operator_name) || "";
        if (title) {
            title.textContent = "Operator name";
        }
        setStatus("");
        body.innerHTML =
            '<p class="inc-report-export-lead">Stored in ~/.discover/operator-name.</p>' +
            '<p class="inc-report-export-lead">First name only (1–10 letters). Changing it updates only your previous name in this report’s audit log (other operators’ lines stay as-is) and new lines going forward.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-config-name">' +
            "<span>Operator name</span>" +
            '<input type="text" id="inc-audit-config-name" class="inc-audit-import-input inc-audit-import-input--name" autocomplete="off" spellcheck="false" value="' +
            escapeAttr(name) +
            '" maxlength="10">' +
            "</label>";
        actions.innerHTML =
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-config-panel="hub">Back</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-audit-config-save-name">Save</button>';
    }

    function renderTimezone() {
        panel = "timezone";
        var body = document.getElementById("inc-audit-config-body");
        var actions = document.getElementById("inc-audit-config-actions");
        var title = document.getElementById("inc-audit-config-title");
        var current = (configCache && configCache.timezone) || "UTC";
        var list =
            (configCache && configCache.timezones) ||
            [{ id: "UTC", label: "UTC" }];
        if (title) {
            title.textContent = "Time zone";
        }
        setStatus("");
        var html =
            '<p class="inc-report-export-lead">Stored in ~/.discover/timezone.</p>' +
            '<p class="inc-report-export-lead">View only. Scan and audit stamps are always written in UTC.</p>' +
            '<div class="inc-audit-config-tz-list" role="radiogroup" aria-label="View timezone">';
        list.forEach(function (tz) {
            var id = tz.id || tz;
            var label = tz.label || id;
            var checked = id === current ? " checked" : "";
            html +=
                '<label class="inc-audit-config-tz-choice">' +
                '<input type="radio" name="inc-audit-config-tz" value="' +
                escapeAttr(id) +
                '"' +
                checked +
                ">" +
                "<span><strong>" +
                escapeHtml(label) +
                "</strong></span>" +
                "</label>";
        });
        html += "</div>";
        body.innerHTML = html;
        actions.innerHTML =
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-config-panel="hub">Back</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-audit-config-save-tz">Save</button>';
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function escapeAttr(s) {
        return escapeHtml(s).replace(/'/g, "&#39;");
    }

    function openModal() {
        var el = ensureModal();
        el.removeAttribute("hidden");
        setStatus("Loading.", false);
        loadConfig()
            .then(function () {
                renderHub();
            })
            .catch(function (err) {
                renderHub();
                setStatus(String(err.message || err), true);
            });
    }

    function closeModal() {
        var el = document.getElementById("inc-audit-config-modal");
        if (el) {
            el.setAttribute("hidden", "hidden");
        }
        panel = "hub";
        setStatus("");
    }

    function postJson(path, payload) {
        return fetch(statusdUrl(path), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload || {}),
            cache: "no-store",
        }).then(function (r) {
            return r.json().then(function (j) {
                return { http: r.status, body: j };
            });
        });
    }

    function saveApis() {
        var payload = {
            NVD_API_KEY: (
                document.getElementById("inc-audit-config-nvd") || {}
            ).value,
            SHODAN_API_KEY: (
                document.getElementById("inc-audit-config-shodan") || {}
            ).value,
            WPSCAN_API_TOKEN: (
                document.getElementById("inc-audit-config-wpscan") || {}
            ).value,
        };
        setStatus("Saving.", false);
        postJson("/config/api-keys", payload)
            .then(function (res) {
                if (!res.body || !res.body.ok) {
                    throw new Error(
                        (res.body && res.body.error) ||
                            "Save failed (HTTP " + res.http + ")."
                    );
                }
                if (configCache) {
                    // Prefer form values: save response may only report presence
                    // (set / empty), not secret material.
                    configCache.api_keys = payload;
                }
                setStatus("API keys saved.", false);
            })
            .catch(function (err) {
                setStatus(String(err.message || err), true);
            });
    }

    function saveName() {
        var name = (
            (document.getElementById("inc-audit-config-name") || {}).value || ""
        ).trim();
        setStatus("Saving.", false);
        postJson("/config/operator-name", { name: name })
            .then(function (res) {
                if (!res.body || !res.body.ok) {
                    throw new Error(
                        (res.body && res.body.error) ||
                            "Save failed (HTTP " + res.http + ")."
                    );
                }
                if (configCache) {
                    configCache.operator_name = res.body.operator_name || name;
                }
                var n = res.body.audit_lines_rewritten || 0;
                var msg = "Operator name saved as " + (res.body.operator_name || name) + ".";
                if (n > 0) {
                    msg +=
                        " Updated " +
                        n +
                        " audit line" +
                        (n === 1 ? "" : "s") +
                        ". Refresh Audit to see the name change.";
                }
                setStatus(msg, false);
            })
            .catch(function (err) {
                setStatus(String(err.message || err), true);
            });
    }

    function saveTimezone() {
        var selected = document.querySelector(
            'input[name="inc-audit-config-tz"]:checked'
        );
        var tz = selected ? selected.value : "UTC";
        setStatus("Saving.", false);
        postJson("/config/timezone", { timezone: tz })
            .then(function (res) {
                if (!res.body || !res.body.ok) {
                    throw new Error(
                        (res.body && res.body.error) ||
                            "Save failed (HTTP " + res.http + ")."
                    );
                }
                if (configCache) {
                    configCache.timezone = res.body.timezone || tz;
                }
                applyTimezoneView(res.body.timezone || tz);
                setStatus(
                    "View timezone set to " +
                        (res.body.timezone || tz) +
                        ". Audit times update on this page. Refresh Audit for Today and Yesterday metrics.",
                    false
                );
            })
            .catch(function (err) {
                setStatus(String(err.message || err), true);
            });
    }

    /**
     * Canonical UTC display: mm-dd-yyyy - hh:mm Z
     * Accepts legacy mm-dd-yyyy Z - hh:mm as well.
     */
    function normalizeUtcStamp(text) {
        var s = String(text || "").trim();
        var leg = s.match(
            /^(\d{2})-(\d{2})-(\d{4})\s+Z\s+-\s+(\d{2}):(\d{2})$/
        );
        if (leg) {
            return (
                leg[1] +
                "-" +
                leg[2] +
                "-" +
                leg[3] +
                " - " +
                leg[4] +
                ":" +
                leg[5] +
                " Z"
            );
        }
        var cur = s.match(
            /^(\d{2})-(\d{2})-(\d{4})\s+-\s+(\d{2}):(\d{2})\s+Z$/
        );
        if (cur) {
            return (
                cur[1] +
                "-" +
                cur[2] +
                "-" +
                cur[3] +
                " - " +
                cur[4] +
                ":" +
                cur[5] +
                " Z"
            );
        }
        return s;
    }

    /**
     * Convert Audit timestamps from UTC stamp to view timezone.
     * Source forms: mm-dd-yyyy - hh:mm Z or legacy mm-dd-yyyy Z - hh:mm
     */
    function parseAuditUtc(text) {
        var s = normalizeUtcStamp(text);
        var m = String(s || "").trim().match(
            /^(\d{2})-(\d{2})-(\d{4})\s+-\s+(\d{2}):(\d{2})\s+Z$/
        );
        if (!m) {
            return null;
        }
        var mm = parseInt(m[1], 10);
        var dd = parseInt(m[2], 10);
        var yyyy = parseInt(m[3], 10);
        var hh = parseInt(m[4], 10);
        var mi = parseInt(m[5], 10);
        return new Date(Date.UTC(yyyy, mm - 1, dd, hh, mi, 0));
    }

    function formatInZone(dt, tzId) {
        if (!dt || isNaN(dt.getTime())) {
            return "";
        }
        if (!tzId || tzId === "UTC") {
            var mo = String(dt.getUTCMonth() + 1).padStart(2, "0");
            var da = String(dt.getUTCDate()).padStart(2, "0");
            var ye = dt.getUTCFullYear();
            var ho = String(dt.getUTCHours()).padStart(2, "0");
            var mi = String(dt.getUTCMinutes()).padStart(2, "0");
            return mo + "-" + da + "-" + ye + " - " + ho + ":" + mi + " Z";
        }
        try {
            var parts = new Intl.DateTimeFormat("en-US", {
                timeZone: tzId,
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                hour12: false,
            }).formatToParts(dt);
            var map = {};
            parts.forEach(function (p) {
                map[p.type] = p.value;
            });
            // en-US month/day order
            return (
                map.month +
                "-" +
                map.day +
                "-" +
                map.year +
                " - " +
                map.hour +
                ":" +
                map.minute
            );
        } catch (e) {
            return "";
        }
    }

    function viewTzShortLabel(tzId) {
        if (!tzId || tzId === "UTC") {
            return "UTC";
        }
        var map = {
            "America/New_York": "Eastern",
            "America/Chicago": "Central",
            "America/Denver": "Mountain",
            "America/Phoenix": "Arizona",
            "America/Los_Angeles": "Pacific",
        };
        if (map[tzId]) {
            return map[tzId];
        }
        return tzId.replace(/^America\//, "").replace(/_/g, " ");
    }

    function convertUtcTextEl(el, tzId) {
        if (!el) {
            return;
        }
        var raw = (el.textContent || "").trim();
        if (!raw || raw === "—" || raw === "-") {
            return;
        }
        // Always store canonical UTC in data-utc (fixes legacy Z - hh:mm display).
        if (!el.getAttribute("data-utc")) {
            el.setAttribute("data-utc", normalizeUtcStamp(raw));
        } else {
            el.setAttribute(
                "data-utc",
                normalizeUtcStamp(el.getAttribute("data-utc"))
            );
        }
        var utcText = el.getAttribute("data-utc");
        var dt = parseAuditUtc(utcText);
        if (!dt) {
            // Still rewrite legacy text to canonical even if no zone convert.
            if (utcText && utcText !== raw) {
                el.textContent = utcText;
            }
            return;
        }
        var shown = formatInZone(dt, tzId || "UTC");
        if (shown) {
            el.textContent = shown;
        }
    }

    function setHeaderTimeLabel(th, baseLabel, tzId) {
        if (!th) {
            return;
        }
        var short = viewTzShortLabel(tzId);
        var label = baseLabel + " (" + short + ")";
        var sortable = th.querySelector(".inc-sortable");
        if (sortable) {
            sortable.textContent = label;
        } else {
            th.textContent = label;
        }
    }

    /**
     * Convert timestamps on all three Audit tables (display only).
     * 1) Audit log — Time column
     * 2) Target scans — per-tool finished stamps
     * 3) Exports — Exported column
     */
    function applyTimezoneView(tzId) {
        var zone = tzId || "UTC";

        // 1) Audit log
        var logTable = document.getElementById("inc-audit-log-table");
        if (logTable) {
            setHeaderTimeLabel(
                logTable.querySelector("th.inc-audit-col-time"),
                "Time",
                zone
            );
            logTable.querySelectorAll("td.inc-audit-col-time").forEach(function (td) {
                convertUtcTextEl(td, zone);
            });
        }

        // 2) Target scans (tool cell times)
        document
            .querySelectorAll("table.inc-audit-host-scans .inc-audit-tool-cell-time")
            .forEach(function (el) {
                convertUtcTextEl(el, zone);
            });

        // 3) Exports — Exported column (class or 2nd cell for older HTML)
        var expTable = document.querySelector("table.inc-audit-deliverables");
        if (expTable) {
            var expTh =
                expTable.querySelector("thead th.inc-audit-col-exported") ||
                expTable.querySelector("thead th:nth-child(1)");
            setHeaderTimeLabel(expTh, "Time", zone);
            var expCells = expTable.querySelectorAll(
                "tbody td.inc-audit-col-exported"
            );
            if (!expCells.length) {
                expCells = expTable.querySelectorAll("tbody tr > td:nth-child(1)");
            }
            expCells.forEach(function (td) {
                convertUtcTextEl(td, zone);
            });
        }
    }

    function injectButton() {
        var header =
            document.querySelector(".inc-page-header") ||
            document.querySelector(".container .inc-page-header");
        if (!header || header.querySelector(".inc-audit-config-btn")) {
            return;
        }
        header.classList.add("inc-page-header--with-export");
        header.classList.add("inc-page-header--with-audit-import");
        header.classList.add("inc-page-header--with-audit-config");

        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "inc-report-export-btn inc-audit-config-btn";
        btn.textContent = "Config";
        btn.title = "APIs, operator name, and view timezone";
        btn.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            openModal();
        });

        // Order: Config, Import, Export (left → right).
        var imp = header.querySelector(".inc-audit-import-btn");
        var exp = header.querySelector(
            ".inc-report-export-btn:not(.inc-audit-import-btn):not(.inc-audit-config-btn)"
        );
        if (imp) {
            header.insertBefore(btn, imp);
        } else if (exp) {
            header.insertBefore(btn, exp);
        } else {
            header.appendChild(btn);
        }
    }

    function bindOnce() {
        if (bound) {
            return;
        }
        bound = true;
        document.addEventListener(
            "click",
            function (ev) {
                var t = ev.target;
                if (!t || !t.closest) {
                    return;
                }
                var panelBtn = t.closest("[data-inc-audit-config-panel]");
                if (panelBtn) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    var which = panelBtn.getAttribute("data-inc-audit-config-panel");
                    if (which === "hub") {
                        renderHub();
                    } else if (which === "apis") {
                        renderApis();
                    } else if (which === "operator") {
                        renderOperator();
                    } else if (which === "timezone") {
                        renderTimezone();
                    }
                    return;
                }
                if (t.closest("#inc-audit-config-save-apis")) {
                    ev.preventDefault();
                    saveApis();
                    return;
                }
                if (t.closest("#inc-audit-config-save-name")) {
                    ev.preventDefault();
                    saveName();
                    return;
                }
                if (t.closest("#inc-audit-config-save-tz")) {
                    ev.preventDefault();
                    saveTimezone();
                    return;
                }
                if (t.closest("[data-inc-audit-config-close]")) {
                    ev.preventDefault();
                    window.setTimeout(closeModal, 0);
                    return;
                }
                if (t.closest("#inc-audit-config-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-audit-config-modal");
                if (el && !el.hasAttribute("hidden")) {
                    ev.preventDefault();
                    closeModal();
                }
            }
        });
    }

    function init() {
        if (!isDiscoverHostedPage() || !isAuditPage()) {
            return;
        }
        injectButton();
        bindOnce();
        // Apply saved view timezone on load (display only).
        loadConfig()
            .then(function (cfg) {
                if (cfg && cfg.timezone) {
                    applyTimezoneView(cfg.timezone);
                }
            })
            .catch(function () {
                /* ignore — page still works in UTC */
            });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
