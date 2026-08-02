/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Report Export button — Audit page only (Discover statusd).
 * Visible only when the report is served by Discover statusd
 * (http://127.0.0.1:17322/…). Opens a modal: Client / Defender / Operator.
 * Not shown on Passive or Active.
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
            document.body.classList.contains("inc-audit-page") ||
            /\/audit\.htm/i.test(location.pathname || "")
        );
    }

    function ensureModal() {
        var el = document.getElementById("inc-report-export-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-report-export-modal";
        el.className = "inc-report-export-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-report-export-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-report-export-close="1"></div>' +
            '<div class="inc-report-export-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-report-export-title" class="inc-report-export-title">Export report</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-report-export-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<p class="inc-report-export-lead">Choose a package type, then Export.</p>' +
            '<div class="inc-report-export-choices" role="radiogroup" aria-label="Package type">' +
            '<label class="inc-report-export-choice">' +
            '<input type="radio" name="inc-report-export-kind" value="client" checked>' +
            "<span><strong>Client</strong> — HTML report; removes operator IPs; disables scans</span>" +
            "</label>" +
            '<label class="inc-report-export-choice">' +
            '<input type="radio" name="inc-report-export-kind" value="defender">' +
            "<span><strong>Defender</strong> — audit log only (CSV)</span>" +
            "</label>" +
            '<label class="inc-report-export-choice">' +
            '<input type="radio" name="inc-report-export-kind" value="operator">' +
            "<span><strong>Operator</strong> — full HTML report with everything (IPs included)</span>" +
            "</label>" +
            "</div>" +
            '<div class="inc-report-export-status" id="inc-report-export-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-report-export-actions">' +
            '<button type="button" class="inc-report-export-cancel" data-inc-report-export-close="1">Cancel</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-report-export-go">Export</button>' +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setActionsVisible(visible) {
        var actions = document.getElementById("inc-report-export-actions");
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
        var status = el.querySelector("#inc-report-export-status");
        if (status) {
            status.hidden = true;
            status.textContent = "";
            status.classList.remove("is-error", "is-ok", "is-path");
        }
        var go = el.querySelector("#inc-report-export-go");
        if (go) {
            go.disabled = false;
        }
        setActionsVisible(true);
        el.removeAttribute("hidden");
        el.classList.add("is-open");
    }

    function closeModal() {
        var el = document.getElementById("inc-report-export-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
    }

    function selectedKind() {
        var checked = document.querySelector(
            'input[name="inc-report-export-kind"]:checked'
        );
        return checked ? checked.value : "client";
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function setStatus(msg, isError) {
        var status = document.getElementById("inc-report-export-status");
        if (!status) {
            return;
        }
        status.hidden = false;
        status.textContent = msg;
        status.classList.toggle("is-error", !!isError);
        status.classList.toggle("is-ok", !isError);
        status.classList.remove("is-path");
    }

    /** Success: label on line 1, full path on line 2 (no wrap). */
    function setExportPath(path) {
        var status = document.getElementById("inc-report-export-status");
        if (!status) {
            return;
        }
        status.hidden = false;
        status.classList.remove("is-error");
        status.classList.add("is-ok", "is-path");
        status.innerHTML =
            '<div class="inc-report-export-status-label">Exported to:</div>' +
            '<div class="inc-report-export-status-path" title="' +
            escapeHtml(path) +
            '">' +
            escapeHtml(path) +
            "</div>";
    }

    function runExport() {
        var go = document.getElementById("inc-report-export-go");
        var kind = selectedKind();
        if (go) {
            go.disabled = true;
        }
        setStatus("Exporting " + kind + "…", false);

        fetch("/export", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ kind: kind }),
            cache: "no-store",
        })
            .then(function (r) {
                return r.json().then(function (j) {
                    return { http: r.status, body: j };
                });
            })
            .then(function (res) {
                var j = res.body || {};
                if (j.ok && j.path) {
                    setExportPath(j.path);
                    setActionsVisible(false);
                } else {
                    setStatus(
                        j.error || "Export failed (HTTP " + res.http + ").",
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
                    "Export failed: " +
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
        if (!header || header.querySelector(".inc-report-export-btn")) {
            return;
        }
        header.classList.add("inc-page-header--with-export");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "inc-report-export-btn";
        btn.textContent = "Export";
        btn.title = "Export engagement package";
        btn.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            openModal();
        });
        header.appendChild(btn);
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
                if (t.closest("#inc-report-export-go")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    runExport();
                    return;
                }
                if (t.closest("[data-inc-report-export-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    window.setTimeout(closeModal, 0);
                    return;
                }
                if (t.closest("#inc-report-export-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-report-export-modal");
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
