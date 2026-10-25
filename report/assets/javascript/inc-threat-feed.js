/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Alerts button in the Active header, immediately left of Enrich.
 * Same size as Enrich. Discover statusd only. Opens the threat intel list.
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;
    var alerts = [];
    var view = "list";
    var detailIndex = -1;
    var meta = {
        schedule: "",
        timezone: "UTC",
        last_pull_utc: "",
        running: false,
        due: false,
        unreviewed: 0,
        bootstrapped: false,
        last_added: 0,
        last_notes: [],
        progress: [],
    };
    var watchTimer = 0;
    var sawBootstrap = false;

    function isDiscoverHostedPage() {
        var host = location.hostname;
        if (host !== "127.0.0.1" && host !== "localhost") {
            return false;
        }
        return location.port === String(STATUS_PORT);
    }

    function isActivePage() {
        return (
            (document.body && document.body.classList.contains("inc-active-page")) ||
            !!(document.querySelector && document.querySelector(".inc-active-page"))
        );
    }

    function statusdUrl(path) {
        return "http://127.0.0.1:" + STATUS_PORT + path;
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function postJson(path, payload) {
        return fetch(statusdUrl(path), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload || {}),
        }).then(function (res) {
            return res.json().then(function (body) {
                return { http: res.status, body: body };
            });
        });
    }

    function formatWhen(iso, tz) {
        if (!iso) {
            return "";
        }
        var date = new Date(iso);
        if (isNaN(date.getTime())) {
            return "";
        }
        var zone = tz || "UTC";
        if (zone === "UTC") {
            var mo = String(date.getUTCMonth() + 1).padStart(2, "0");
            var da = String(date.getUTCDate()).padStart(2, "0");
            var ye = date.getUTCFullYear();
            var ho = String(date.getUTCHours()).padStart(2, "0");
            var mi = String(date.getUTCMinutes()).padStart(2, "0");
            return mo + "/" + da + "/" + ye + " - " + ho + ":" + mi + " Z";
        }
        try {
            var parts = new Intl.DateTimeFormat("en-US", {
                timeZone: zone,
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                hourCycle: "h23",
            }).formatToParts(date);
            var map = {};
            parts.forEach(function (part) {
                map[part.type] = part.value;
            });
            if (map.hour === "24") {
                map.hour = "00";
            }
            return (
                map.month +
                "/" +
                map.day +
                "/" +
                map.year +
                " - " +
                map.hour +
                ":" +
                map.minute
            );
        } catch (err) {
            return "";
        }
    }

    function applyMeta(body) {
        if (!body) {
            return;
        }
        meta.schedule = body.schedule || "";
        meta.timezone = body.timezone || "UTC";
        meta.last_pull_utc = body.last_pull_utc || "";
        meta.running = !!body.running;
        meta.due = !!body.due;
        meta.unreviewed = body.unreviewed || 0;
        meta.bootstrapped = !!body.bootstrapped;
        meta.last_added = Number(body.last_added) || 0;
        meta.last_notes = Array.isArray(body.last_notes) ? body.last_notes : [];
        meta.progress = Array.isArray(body.progress) ? body.progress : [];
        if (Array.isArray(body.alerts)) {
            alerts = body.alerts;
        }
        paintCount();
    }

    function paintCount() {
        var btn = document.querySelector(".inc-page-header .inc-active-threat-btn");
        if (!btn) {
            return;
        }
        var count = meta.unreviewed || 0;
        btn.textContent = count > 0 ? "Alerts " + count : "Alerts";
        btn.title = count > 0
            ? count + " new alerts"
            : "Threat intel for software in this report";
    }

    function ensureModal() {
        var el = document.getElementById("inc-threat-feed-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-threat-feed-modal";
        el.className = "inc-report-export-modal inc-threat-feed-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-threat-feed-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-threat-feed-close="1"></div>' +
            '<div class="inc-report-export-dialog inc-threat-feed-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-threat-feed-title" class="inc-report-export-title">Threat intel</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-threat-feed-x="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div id="inc-threat-feed-body"></div>' +
            '<div class="inc-report-export-status" id="inc-threat-feed-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-threat-feed-actions"></div>' +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setBody(html) {
        var body = document.getElementById("inc-threat-feed-body");
        if (body) {
            body.innerHTML = html;
        }
    }

    function setActions(html) {
        var actions = document.getElementById("inc-threat-feed-actions");
        if (actions) {
            actions.innerHTML = html;
        }
    }

    function setStatus(msg, isError) {
        var el = document.getElementById("inc-threat-feed-status");
        if (!el) {
            return;
        }
        if (!msg) {
            el.hidden = true;
            el.textContent = "";
            el.classList.remove("is-error");
            el.classList.remove("is-ok");
            return;
        }
        el.hidden = false;
        el.textContent = msg;
        el.classList.toggle("is-error", !!isError);
        el.classList.toggle("is-ok", !isError);
    }

    function progressLines() {
        var allowed = [
            "[*] Checking NVD.",
            "[*] Checking KEV.",
            "[*] Checking advisories.",
            "[*] Checking GitHub.",
            "[*] Checking Metasploit.",
        ];
        var got = meta.progress || [];
        var lines = [];
        var xLine = "";
        var i;
        for (i = 0; i < got.length; i++) {
            if (/^\[\*\] Checking \d+ X accounts?\.$/.test(got[i])) {
                xLine = got[i];
            }
        }
        for (i = 0; i < allowed.length; i++) {
            if (got.indexOf(allowed[i]) !== -1) {
                lines.push(allowed[i]);
            }
        }
        if (xLine) {
            lines.push(xLine);
        }
        return lines;
    }

    function progressText() {
        var lines = progressLines();
        if (!lines.length) {
            lines.push("[*] Checking NVD.");
        }
        return lines.join("\n");
    }

    function finishText() {
        var notes = meta.last_notes || [];
        var failed = false;
        var i;
        for (i = 0; i < notes.length; i++) {
            if (notes[i] === "The check did not finish.") {
                failed = true;
            }
        }
        if (failed) {
            return "The check did not finish.";
        }
        var msg;
        if (!sawBootstrap && meta.bootstrapped) {
            msg = "Check finished. Recorded what is already public.";
        } else if (meta.last_added === 1) {
            msg = "Check finished. 1 new alert.";
        } else if (meta.last_added > 1) {
            msg = "Check finished. " + meta.last_added + " new alerts.";
        } else {
            msg = "Check finished. No new alerts.";
        }
        var extra = [];
        for (i = 0; i < notes.length; i++) {
            if (notes[i]) {
                extra.push(notes[i]);
            }
        }
        if (extra.length) {
            msg += "\n" + extra.join("\n");
        }
        return msg;
    }

    function scheduleLine() {
        var bits = [];
        if (meta.last_pull_utc) {
            var when = formatWhen(meta.last_pull_utc, meta.timezone);
            if (when) {
                bits.push("Last check " + when + ".");
            }
        } else {
            bits.push("No check yet.");
        }
        return bits.join(" ");
    }

    function renderList() {
        view = "list";
        detailIndex = -1;
        var title = document.getElementById("inc-threat-feed-title");
        if (title) {
            title.textContent = "Threat intel";
        }
        var line = scheduleLine();
        var html = line
            ? '<p class="inc-report-export-lead">' + escapeHtml(line) + "</p>"
            : "";
        if (!alerts.length) {
            html += '<p class="inc-report-export-lead">No alerts yet.</p>';
        } else {
            html += '<div class="inc-threat-feed-list">';
            alerts.forEach(function (item, index) {
                var fresh = item.state !== "reviewed" ? " inc-threat-feed-row--new" : "";
                html +=
                    '<button type="button" class="inc-threat-feed-row' +
                    fresh +
                    '" data-inc-threat-feed-open="' +
                    index +
                    '">' +
                    "<strong>" +
                    escapeHtml(item.title || "Alert") +
                    "</strong>" +
                    "<span>" +
                    escapeHtml([item.software, item.source].filter(Boolean).join(" · ")) +
                    "</span>" +
                    "</button>";
            });
            html += "</div>";
        }
        setBody(html);
        setActions(
            '<button type="button" class="inc-report-export-cancel" data-inc-threat-feed-close="1">Close</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-threat-feed-check"' +
            (meta.running ? " disabled" : "") +
            ">" +
            (meta.running ? "Checking" : "Check now") +
            "</button>"
        );
    }

    function renderDetail(index) {
        var item = alerts[index];
        if (!item) {
            renderList();
            return;
        }
        view = "detail";
        detailIndex = index;
        var title = document.getElementById("inc-threat-feed-title");
        if (title) {
            title.textContent = item.title || "Alert";
        }
        var bits = [];
        if (item.software) {
            bits.push(escapeHtml(item.software));
        }
        if (item.source) {
            bits.push(escapeHtml(item.source));
        }
        if (item.kind) {
            bits.push(escapeHtml(item.kind));
        }
        var when = formatWhen(item.published_utc, meta.timezone);
        if (when) {
            bits.push(escapeHtml(when));
        }
        var html = "";
        if (bits.length) {
            html += '<p class="inc-report-export-lead">' + bits.join(" · ") + "</p>";
        }
        if (item.summary) {
            html += '<p class="inc-threat-feed-summary">' + escapeHtml(item.summary) + "</p>";
        }
        if (item.url) {
            html +=
                '<p class="inc-report-export-lead"><a href="' +
                escapeHtml(item.url) +
                '" target="_blank" rel="noopener">Open source</a></p>';
        }
        setBody(html);
        setActions(
            '<button type="button" class="inc-report-export-cancel" data-inc-threat-feed-back="1">Back</button>'
        );
    }

    function refreshStatus() {
        return fetch(statusdUrl("/threat-feed"), { method: "GET" })
            .then(function (res) {
                return res.json();
            })
            .then(function (body) {
                applyMeta(body || {});
                return body || {};
            });
    }

    function modalOpen() {
        var el = document.getElementById("inc-threat-feed-modal");
        return !!(el && !el.hasAttribute("hidden"));
    }

    function showCheckProgress() {
        if (!modalOpen() || view !== "list") {
            return;
        }
        var next = progressText();
        var check = document.getElementById("inc-threat-feed-check");
        if (!check || !check.disabled) {
            renderList();
        }
        setStatus(next, false);
    }

    function showCheckFinished() {
        if (!modalOpen() || view !== "list") {
            return;
        }
        renderList();
        var failed = (meta.last_notes || []).indexOf("The check did not finish.") !== -1;
        var lines = progressLines();
        var msg = finishText();
        if (lines.length) {
            msg = lines.join("\n") + "\n\n" + msg;
        }
        setStatus(msg, failed);
    }

    function watchRunning() {
        if (watchTimer || !meta.running) {
            return;
        }
        watchTimer = window.setTimeout(function () {
            watchTimer = 0;
            refreshStatus()
                .then(function () {
                    if (meta.running) {
                        showCheckProgress();
                        watchRunning();
                        return;
                    }
                    showCheckFinished();
                })
                .catch(function () {
                    meta.running = false;
                    if (modalOpen() && view === "list") {
                        renderList();
                        setStatus("Could not tell whether the check finished.", true);
                    }
                });
        }, 1000);
    }

    function startCheck(force) {
        sawBootstrap = !!meta.bootstrapped;
        meta.running = true;
        meta.progress = [];
        paintCount();
        showCheckProgress();
        return postJson("/threat-feed/check", { force: !!force })
            .then(function (res) {
                if (!res.body || res.body.ok === false) {
                    throw new Error((res.body && res.body.error) || "Could not start the check.");
                }
                watchRunning();
            })
            .catch(function (err) {
                meta.running = false;
                if (modalOpen() && view === "list") {
                    renderList();
                    setStatus(String(err.message || err), true);
                }
            });
    }

    function openModal() {
        ensureModal();
        var el = document.getElementById("inc-threat-feed-modal");
        setStatus("");
        renderList();
        if (el) {
            el.removeAttribute("hidden");
        }
        refreshStatus()
            .then(function () {
                if (view === "list") {
                    renderList();
                    if (meta.running) {
                        setStatus(progressText(), false);
                        watchRunning();
                    }
                }
            })
            .catch(function () {
                setStatus("Could not load alerts.", true);
            });
    }

    function closeModal() {
        var el = document.getElementById("inc-threat-feed-modal");
        if (el) {
            el.setAttribute("hidden", "hidden");
        }
        view = "list";
        detailIndex = -1;
        setStatus("");
    }

    function finishDetail() {
        var item = alerts[detailIndex];
        if (!item || item.state === "reviewed") {
            renderList();
            return;
        }
        postJson("/threat-feed/reviewed", { id: item.id })
            .then(function (res) {
                if (!res.body || !res.body.ok) {
                    throw new Error((res.body && res.body.error) || "Could not update this alert.");
                }
                item.state = "reviewed";
                meta.unreviewed = alerts.filter(function (row) {
                    return row.state !== "reviewed";
                }).length;
                paintCount();
                setStatus("");
                renderList();
            })
            .catch(function (err) {
                setStatus(String(err.message || err), true);
            });
    }

    function injectButton() {
        var header =
            document.querySelector(".inc-page-header") ||
            document.querySelector(".container .inc-page-header");
        if (!header || header.querySelector(".inc-active-threat-btn")) {
            return;
        }
        header.classList.add("inc-page-header--with-export");
        header.classList.add("inc-page-header--with-active-update");
        header.classList.add("inc-page-header--with-alerts");
        var actions = header.querySelector(".inc-active-header-actions");
        if (!actions) {
            actions = document.createElement("div");
            actions.className = "inc-active-header-actions";
            header.appendChild(actions);
        }
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "inc-active-refresh-btn inc-active-threat-btn";
        btn.textContent = "Alerts";
        btn.title = "Threat intel for software in this report";
        var enrich = actions.querySelector(".inc-active-refresh-btn");
        if (enrich) {
            actions.insertBefore(btn, enrich);
        } else {
            actions.insertBefore(btn, actions.firstChild);
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
                if (t.closest(".inc-active-threat-btn")) {
                    ev.preventDefault();
                    openModal();
                    return;
                }
                if (t.closest("[data-inc-threat-feed-back]")) {
                    ev.preventDefault();
                    finishDetail();
                    return;
                }
                if (t.closest("[data-inc-threat-feed-x]")) {
                    ev.preventDefault();
                    if (view === "detail") {
                        finishDetail();
                    } else {
                        closeModal();
                    }
                    return;
                }
                if (t.closest("[data-inc-threat-feed-close]")) {
                    ev.preventDefault();
                    closeModal();
                    return;
                }
                if (t.closest("#inc-threat-feed-check")) {
                    ev.preventDefault();
                    if (!meta.running) {
                        startCheck(true);
                    }
                    return;
                }
                var row = t.closest("[data-inc-threat-feed-open]");
                if (row) {
                    ev.preventDefault();
                    setStatus("");
                    renderDetail(Number(row.getAttribute("data-inc-threat-feed-open")));
                    return;
                }
                if (t.closest("#inc-threat-feed-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key !== "Escape" && ev.keyCode !== 27) {
                return;
            }
            if (!modalOpen()) {
                return;
            }
            ev.preventDefault();
            if (view === "detail") {
                finishDetail();
                return;
            }
            closeModal();
        });
    }

    function init() {
        if (!isDiscoverHostedPage() || !isActivePage()) {
            return;
        }
        injectButton();
        bindOnce();
        refreshStatus().catch(function () {});
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
