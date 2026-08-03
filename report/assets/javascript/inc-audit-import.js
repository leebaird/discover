/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit page Import hub (Discover statusd only).
 * Choice rows: Operator scans · Names · Names, titles, and emails · Subdomains.
 * Always targets the report statusd is serving (current engagement).
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;
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
            document.body &&
            (document.body.classList.contains("inc-audit-page") ||
                /audit\.htm/i.test(location.pathname))
        );
    }

    function ensureModal() {
        var el = document.getElementById("inc-audit-import-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-audit-import-modal";
        el.className = "inc-report-export-modal inc-audit-import-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-audit-import-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-audit-import-close="1"></div>' +
            '<div class="inc-report-export-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-audit-import-title" class="inc-report-export-title">Import</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-audit-import-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div id="inc-audit-import-body" class="inc-audit-import-body"></div>' +
            '<div class="inc-report-export-status" id="inc-audit-import-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-audit-import-actions"></div>' +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function setStatus(msg, isError) {
        var status = document.getElementById("inc-audit-import-status");
        if (!status) {
            return;
        }
        if (!msg) {
            status.hidden = true;
            status.textContent = "";
            status.classList.remove("is-error", "is-ok", "is-path");
            return;
        }
        status.hidden = false;
        status.textContent = msg;
        status.classList.toggle("is-error", !!isError);
        status.classList.toggle("is-ok", !isError);
        status.classList.remove("is-path");
    }

    function setSuccess(summary) {
        var status = document.getElementById("inc-audit-import-status");
        if (!status) {
            return;
        }
        status.hidden = false;
        status.classList.remove("is-error");
        status.classList.add("is-ok", "is-path");
        status.innerHTML =
            '<div class="inc-report-export-status-label">Import complete</div>' +
            '<div class="inc-report-export-status-path" title="' +
            escapeHtml(summary) +
            '">' +
            escapeHtml(summary) +
            "</div>" +
            '<div class="inc-audit-import-refresh-note">Refresh this page to see updated Audit and report pages.</div>';
    }

    function setActionsHtml(html) {
        var actions = document.getElementById("inc-audit-import-actions");
        if (actions) {
            actions.innerHTML = html || "";
            actions.hidden = !html;
            if (html) {
                actions.removeAttribute("hidden");
            } else {
                actions.setAttribute("hidden", "hidden");
            }
        }
    }

    function setTitle(text) {
        var title = document.getElementById("inc-audit-import-title");
        if (title) {
            title.textContent = text;
        }
    }

    function renderHub() {
        panel = "hub";
        setTitle("Import");
        setStatus("");
        var body = document.getElementById("inc-audit-import-body");
        body.innerHTML =
            '<p class="inc-report-export-lead">Merge data into this Discover report.</p>' +
            '<div class="inc-audit-config-choices" role="list">' +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-import-panel="operator">' +
            "<strong>Operator scans</strong>" +
            "<span>Merge host-scans, screenshots, Active data, and audit lines from another operator</span>" +
            "</button>" +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-import-panel="names">' +
            "<strong>Names</strong>" +
            "<span>Merge manual contacts (Name, Title, Phone) into Names</span>" +
            "</button>" +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-import-panel="nte">' +
            "<strong>Names, titles, and emails</strong>" +
            "<span>Merge an external names dump (titles and emails) into this report</span>" +
            "</button>" +
            '<button type="button" class="inc-audit-config-choice" data-inc-audit-import-panel="subdomains">' +
            "<strong>Subdomains</strong>" +
            "<span>Import Firefox / Pentest-Tools / TSV or a CSV host list</span>" +
            "</button>" +
            "</div>";
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-close="1">Close</button>'
        );
    }

    function renderOperator() {
        panel = "operator";
        setTitle("Import operator scans");
        setStatus("");
        var body = document.getElementById("inc-audit-import-body");
        body.innerHTML =
            '<p class="inc-report-export-lead">Merge scans, screenshots, Active data, and audit lines from another operator’s report into this report.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-import-source">' +
            "<span>Path to their report (unpacked directory)</span>" +
            '<input type="text" id="inc-audit-import-source" class="inc-audit-import-input" autocomplete="off" spellcheck="false">' +
            "</label>" +
            '<label class="inc-audit-import-field" for="inc-audit-import-operator">' +
            "<span>Operator name (must match their Audit log)</span>" +
            '<input type="text" id="inc-audit-import-operator" class="inc-audit-import-input inc-audit-import-input--name" autocomplete="off" spellcheck="false">' +
            "</label>";
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub">Back</button>' +
                '<button type="button" class="inc-report-export-go" id="inc-audit-import-go" data-inc-audit-import-run="operator">Import</button>'
        );
        window.setTimeout(function () {
            var src = document.getElementById("inc-audit-import-source");
            if (src) {
                src.focus();
            }
        }, 0);
    }

    function renderNames() {
        panel = "names";
        setTitle("Import names");
        setStatus("");
        var body = document.getElementById("inc-audit-import-body");
        body.innerHTML =
            '<p class="inc-report-export-lead">Merge manual contacts into this report’s Names page. Format: Name, Title, Phone (tab-separated). Leave path blank to use tools/names-manual.tsv in this report.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-import-manual">' +
            "<span>Manual contacts file (optional)</span>" +
            '<input type="text" id="inc-audit-import-manual" class="inc-audit-import-input" autocomplete="off" spellcheck="false" placeholder="tools/names-manual.tsv in this report">' +
            "</label>";
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub">Back</button>' +
                '<button type="button" class="inc-report-export-go" id="inc-audit-import-go" data-inc-audit-import-run="names">Import</button>'
        );
        window.setTimeout(function () {
            var el = document.getElementById("inc-audit-import-manual");
            if (el) {
                el.focus();
            }
        }, 0);
    }

    function renderNte() {
        panel = "nte";
        setTitle("Import names, titles, and emails");
        setStatus("");
        var body = document.getElementById("inc-audit-import-body");
        body.innerHTML =
            '<p class="inc-report-export-lead">Merge an external names dump into tools/names and tools/emails. Free-form lines or tab-separated rows are accepted.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-import-nte-source">' +
            "<span>Path to names file</span>" +
            '<input type="text" id="inc-audit-import-nte-source" class="inc-audit-import-input" autocomplete="off" spellcheck="false">' +
            "</label>";
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub">Back</button>' +
                '<button type="button" class="inc-report-export-go" id="inc-audit-import-go" data-inc-audit-import-run="nte">Import</button>'
        );
        window.setTimeout(function () {
            var el = document.getElementById("inc-audit-import-nte-source");
            if (el) {
                el.focus();
            }
        }, 0);
    }

    function renderSubdomains() {
        panel = "subdomains";
        setTitle("Import subdomains");
        setStatus("");
        var body = document.getElementById("inc-audit-import-body");
        body.innerHTML =
            '<p class="inc-report-export-lead">Add hosts into this report. Existing hosts are kept; CSV list skips hosts already present.</p>' +
            '<div class="inc-audit-config-tz-list" role="radiogroup" aria-label="Import mode">' +
            '<label class="inc-audit-config-tz-choice">' +
            '<input type="radio" name="inc-audit-import-sub-mode" value="existing" checked>' +
            "<span><strong>Existing sources</strong> — firefox, Pentest-Tools JSON/text, or TSV</span>" +
            "</label>" +
            '<label class="inc-audit-config-tz-choice">' +
            '<input type="radio" name="inc-audit-import-sub-mode" value="team-csv">' +
            "<span><strong>CSV list</strong> — subdomain, IPv4, category</span>" +
            "</label>" +
            "</div>" +
            '<label class="inc-audit-import-field" for="inc-audit-import-sub-path">' +
            "<span>Path to import file (or type firefox)</span>" +
            '<input type="text" id="inc-audit-import-sub-path" class="inc-audit-import-input" autocomplete="off" spellcheck="false">' +
            "</label>" +
            '<label class="inc-audit-import-check" for="inc-audit-import-sub-active">' +
            '<input type="checkbox" id="inc-audit-import-sub-active">' +
            "<span>Run Active on newly imported public hosts only (CSV list; can take a long time)</span>" +
            "</label>";
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub">Back</button>' +
                '<button type="button" class="inc-report-export-go" id="inc-audit-import-go" data-inc-audit-import-run="subdomains">Import</button>'
        );
        window.setTimeout(function () {
            var el = document.getElementById("inc-audit-import-sub-path");
            if (el) {
                el.focus();
            }
        }, 0);
    }

    function showPanel(name) {
        if (name === "hub") {
            renderHub();
        } else if (name === "operator") {
            renderOperator();
        } else if (name === "names") {
            renderNames();
        } else if (name === "nte") {
            renderNte();
        } else if (name === "subdomains") {
            renderSubdomains();
        }
    }

    function openModal() {
        var el = ensureModal();
        el.removeAttribute("hidden");
        el.classList.add("is-open");
        renderHub();
    }

    function closeModal() {
        var el = document.getElementById("inc-audit-import-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
        panel = "hub";
    }

    function postJson(url, payload) {
        return fetch(url, {
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

    function finishOk(summary) {
        setSuccess(summary);
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-close="1">Close</button>'
        );
    }

    function finishErr(msg, runKind) {
        setStatus(msg, true);
        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub">Back</button>' +
                '<button type="button" class="inc-report-export-go" id="inc-audit-import-go" data-inc-audit-import-run="' +
                escapeHtml(runKind) +
                '">Import</button>'
        );
    }

    function runOperator() {
        var srcEl = document.getElementById("inc-audit-import-source");
        var opEl = document.getElementById("inc-audit-import-operator");
        var source = srcEl ? String(srcEl.value || "").trim() : "";
        var operator = opEl ? String(opEl.value || "").trim() : "";

        if (!source) {
            setStatus("Enter the path to their unpacked report directory.", true);
            return;
        }
        if (!operator) {
            setStatus("Enter their operator first name (letters only).", true);
            return;
        }
        if (operator.length > 10) {
            setStatus(
                "Operator name is too long (max 10 letters). You entered " +
                    operator.length +
                    " characters.",
                true
            );
            return;
        }
        if (!/^[A-Za-z]{1,10}$/.test(operator)) {
            setStatus(
                "Operator name: 1–10 letters only (no spaces or numbers).",
                true
            );
            return;
        }

        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub" disabled>Back</button>' +
                '<button type="button" class="inc-report-export-go" disabled>Importing</button>'
        );
        setStatus("Importing operator scans.", false);

        postJson("/import-operator-package", {
            source: source,
            operator: operator,
        })
            .then(function (res) {
                var j = res.body || {};
                if (j.ok) {
                    finishOk(
                        j.summary ||
                            "Merged package for " + (j.operator || operator) + "."
                    );
                } else {
                    finishErr(
                        j.error || "Import failed (HTTP " + res.http + ").",
                        "operator"
                    );
                }
            })
            .catch(function (err) {
                finishErr(
                    "Import failed: " +
                        (err && err.message ? err.message : String(err)),
                    "operator"
                );
            });
    }

    function runNames() {
        var el = document.getElementById("inc-audit-import-manual");
        var manual = el ? String(el.value || "").trim() : "";
        var payload = {};
        if (manual) {
            payload.manual = manual;
        }

        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub" disabled>Back</button>' +
                '<button type="button" class="inc-report-export-go" disabled>Importing</button>'
        );
        setStatus("Importing names.", false);

        postJson("/import-names", payload)
            .then(function (res) {
                var j = res.body || {};
                if (j.ok) {
                    finishOk(j.summary || "Names import complete.");
                } else {
                    finishErr(
                        j.error || "Import failed (HTTP " + res.http + ").",
                        "names"
                    );
                }
            })
            .catch(function (err) {
                finishErr(
                    "Import failed: " +
                        (err && err.message ? err.message : String(err)),
                    "names"
                );
            });
    }

    function runNte() {
        var el = document.getElementById("inc-audit-import-nte-source");
        var source = el ? String(el.value || "").trim() : "";
        if (!source) {
            setStatus("Enter the path to the names file.", true);
            return;
        }

        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub" disabled>Back</button>' +
                '<button type="button" class="inc-report-export-go" disabled>Importing</button>'
        );
        setStatus("Importing names, titles, and emails.", false);

        postJson("/import-names-titles-emails", { source: source })
            .then(function (res) {
                var j = res.body || {};
                if (j.ok) {
                    finishOk(
                        j.summary ||
                            "Names, titles, and emails import complete."
                    );
                } else {
                    finishErr(
                        j.error || "Import failed (HTTP " + res.http + ").",
                        "nte"
                    );
                }
            })
            .catch(function (err) {
                finishErr(
                    "Import failed: " +
                        (err && err.message ? err.message : String(err)),
                    "nte"
                );
            });
    }

    function runSubdomains() {
        var pathEl = document.getElementById("inc-audit-import-sub-path");
        var importPath = pathEl ? String(pathEl.value || "").trim() : "";
        var modeEl = document.querySelector(
            'input[name="inc-audit-import-sub-mode"]:checked'
        );
        var mode = modeEl ? String(modeEl.value || "existing") : "existing";
        var activeEl = document.getElementById("inc-audit-import-sub-active");
        var runActive = !!(activeEl && activeEl.checked);

        if (!importPath) {
            setStatus(
                "Enter the path to the import file (or type firefox).",
                true
            );
            return;
        }

        setActionsHtml(
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-panel="hub" disabled>Back</button>' +
                '<button type="button" class="inc-report-export-go" disabled>Importing</button>'
        );
        setStatus(
            runActive
                ? "Importing subdomains and running Active (this can take a long time)."
                : "Importing subdomains.",
            false
        );

        postJson("/import-subdomains", {
            mode: mode,
            path: importPath,
            run_active: runActive,
        })
            .then(function (res) {
                var j = res.body || {};
                if (j.ok) {
                    finishOk(j.summary || "Subdomains import complete.");
                } else {
                    finishErr(
                        j.error || "Import failed (HTTP " + res.http + ").",
                        "subdomains"
                    );
                }
            })
            .catch(function (err) {
                finishErr(
                    "Import failed: " +
                        (err && err.message ? err.message : String(err)),
                    "subdomains"
                );
            });
    }

    function runImport(kind) {
        if (kind === "operator") {
            runOperator();
        } else if (kind === "names") {
            runNames();
        } else if (kind === "nte") {
            runNte();
        } else if (kind === "subdomains") {
            runSubdomains();
        }
    }

    function injectButton() {
        var header =
            document.querySelector(".inc-page-header") ||
            document.querySelector(".container .inc-page-header");
        if (!header || header.querySelector(".inc-audit-import-btn")) {
            return;
        }
        header.classList.add("inc-page-header--with-export");
        header.classList.add("inc-page-header--with-audit-import");

        var imp = document.createElement("button");
        imp.type = "button";
        imp.className = "inc-report-export-btn inc-audit-import-btn";
        imp.textContent = "Import";
        imp.title = "Import into this report";
        imp.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            openModal();
        });

        // Place Import left of Export when Export is present.
        var exp = header.querySelector(
            ".inc-report-export-btn:not(.inc-audit-import-btn):not(.inc-audit-config-btn)"
        );
        if (exp) {
            header.insertBefore(imp, exp);
        } else {
            header.appendChild(imp);
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
                var runBtn = t.closest("[data-inc-audit-import-run]");
                if (runBtn) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    runImport(runBtn.getAttribute("data-inc-audit-import-run"));
                    return;
                }
                var panelBtn = t.closest("[data-inc-audit-import-panel]");
                if (panelBtn) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    showPanel(
                        panelBtn.getAttribute("data-inc-audit-import-panel") ||
                            "hub"
                    );
                    return;
                }
                if (t.closest("[data-inc-audit-import-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    window.setTimeout(closeModal, 0);
                    return;
                }
                if (t.closest("#inc-audit-import-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-audit-import-modal");
                if (el && !el.hasAttribute("hidden")) {
                    ev.preventDefault();
                    if (panel && panel !== "hub") {
                        showPanel("hub");
                    } else {
                        closeModal();
                    }
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
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
