/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit page: Import button (Discover statusd only) merges another operator's
 * report package into the live engagement (host-scans, screenshots, audit, …).
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;

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
            '<h2 id="inc-audit-import-title" class="inc-report-export-title">Import operator package</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-audit-import-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<p class="inc-report-export-lead">Merge host scans, screenshots, Active data, and audit lines from another operator’s report into this engagement.</p>' +
            '<label class="inc-audit-import-field" for="inc-audit-import-source">' +
            "<span>Path to their report (unpacked directory)</span>" +
            '<input type="text" id="inc-audit-import-source" class="inc-audit-import-input" ' +
            'autocomplete="off" spellcheck="false">' +
            "</label>" +
            '<label class="inc-audit-import-field" for="inc-audit-import-operator">' +
            "<span>Their operator name (first name, max 10 letters — must match their Audit log)</span>" +
            '<input type="text" id="inc-audit-import-operator" class="inc-audit-import-input" ' +
            'autocomplete="off" spellcheck="false">' +
            "</label>" +
            '<div class="inc-report-export-status" id="inc-audit-import-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-audit-import-actions">' +
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-import-close="1">Cancel</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-audit-import-go">Import</button>' +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setActionsVisible(visible) {
        var actions = document.getElementById("inc-audit-import-actions");
        if (!actions) {
            return;
        }
        if (visible) {
            actions.hidden = false;
            actions.removeAttribute("hidden");
        } else {
            actions.hidden = true;
            actions.setAttribute("hidden", "hidden");
        }
    }

    function openModal() {
        var el = ensureModal();
        var status = el.querySelector("#inc-audit-import-status");
        if (status) {
            status.hidden = true;
            status.textContent = "";
            status.classList.remove("is-error", "is-ok", "is-path");
        }
        var go = el.querySelector("#inc-audit-import-go");
        if (go) {
            go.disabled = false;
        }
        var src = el.querySelector("#inc-audit-import-source");
        var op = el.querySelector("#inc-audit-import-operator");
        if (src) {
            src.value = "";
        }
        if (op) {
            op.value = "";
        }
        setActionsVisible(true);
        el.removeAttribute("hidden");
        el.classList.add("is-open");
        if (src) {
            window.setTimeout(function () {
                src.focus();
            }, 0);
        }
    }

    function closeModal() {
        var el = document.getElementById("inc-audit-import-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
    }

    function escapeHtml(s) {
        return String(s)
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
            '<div class="inc-audit-import-refresh-note">Refresh this page to see the updated Audit log and Target scans.</div>';
    }

    function runImport() {
        var go = document.getElementById("inc-audit-import-go");
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
        // Do not use maxlength truncation — reject oversize / invalid names explicitly.
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

        if (go) {
            go.disabled = true;
        }
        setStatus("Importing…", false);

        fetch("/import-operator-package", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ source: source, operator: operator }),
            cache: "no-store",
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { http: r.status, body: j };
                });
            })
            .then(function (res) {
                var j = res.body || {};
                if (j.ok) {
                    var summary =
                        j.summary ||
                        "Merged package for " +
                            (j.operator || operator) +
                            ".";
                    setSuccess(summary);
                    setActionsVisible(false);
                } else {
                    setStatus(
                        j.error || "Import failed (HTTP " + res.http + ").",
                        true
                    );
                    if (go) {
                        go.disabled = false;
                    }
                    setActionsVisible(true);
                }
            })
            .catch(function (err) {
                setStatus(
                    "Import failed: " +
                        (err && err.message ? err.message : String(err)),
                    true
                );
                if (go) {
                    go.disabled = false;
                }
                setActionsVisible(true);
            });
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
        imp.title = "Import another operator’s report package";
        imp.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            openModal();
        });

        // Place Import left of Export when Export is present.
        var exp = header.querySelector(".inc-report-export-btn:not(.inc-audit-import-btn)");
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
                if (t.closest("#inc-audit-import-go")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    runImport();
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
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
