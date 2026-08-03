/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit log: per-line Delete (Discover statusd only).
 * Confirm modal: "<Operator>, are you sure you want to delete this line?"
 * Backend: POST /audit-line-delete {hash} → removes tools/audit/log.txt line + rebuilds Audit.
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;
    var pendingHash = "";
    var pendingRow = null;
    var operatorName = "";

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
                /audit\.htm/i.test(location.pathname || ""))
        );
    }

    function statusdUrl(path) {
        return "http://127.0.0.1:" + STATUS_PORT + path;
    }

    function ensureModal() {
        var el = document.getElementById("inc-audit-line-delete-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-audit-line-delete-modal";
        el.className = "inc-report-export-modal inc-audit-line-delete-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-audit-line-delete-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-audit-line-delete-close="1"></div>' +
            '<div class="inc-report-export-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-audit-line-delete-title" class="inc-report-export-title">Delete audit line</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-audit-line-delete-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<p class="inc-report-export-lead" id="inc-audit-line-delete-lead"></p>' +
            '<p class="inc-audit-line-delete-preview" id="inc-audit-line-delete-preview" hidden></p>' +
            '<div class="inc-report-export-status" id="inc-audit-line-delete-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-audit-line-delete-actions">' +
            '<button type="button" class="inc-report-export-cancel" data-inc-audit-line-delete-close="1">Cancel</button>' +
            '<button type="button" class="inc-report-export-go inc-audit-line-delete-confirm" id="inc-audit-line-delete-go">Delete</button>' +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setStatus(msg, isError) {
        var status = document.getElementById("inc-audit-line-delete-status");
        if (!status) {
            return;
        }
        if (!msg) {
            status.hidden = true;
            status.textContent = "";
            status.classList.remove("is-error", "is-ok");
            return;
        }
        status.hidden = false;
        status.textContent = msg;
        status.classList.toggle("is-error", !!isError);
        status.classList.toggle("is-ok", !isError);
    }

    function confirmLeadText() {
        var name = (operatorName || "").trim();
        if (name) {
            return name + ", are you sure you want to delete this line?";
        }
        return "Are you sure you want to delete this line?";
    }

    function openConfirm(row) {
        var hash = row.getAttribute("data-audit-hash") || "";
        if (!hash) {
            return;
        }
        pendingHash = hash;
        pendingRow = row;
        var el = ensureModal();
        var lead = document.getElementById("inc-audit-line-delete-lead");
        if (lead) {
            lead.textContent = confirmLeadText();
        }
        var preview = document.getElementById("inc-audit-line-delete-preview");
        var text = row.getAttribute("data-audit-preview") || "";
        if (preview) {
            if (text) {
                preview.hidden = false;
                preview.textContent = text;
            } else {
                preview.hidden = true;
                preview.textContent = "";
            }
        }
        setStatus("");
        var go = document.getElementById("inc-audit-line-delete-go");
        if (go) {
            go.disabled = false;
        }
        el.removeAttribute("hidden");
        el.classList.add("is-open");
        if (go) {
            window.setTimeout(function () {
                go.focus();
            }, 0);
        }
    }

    function closeModal() {
        var el = document.getElementById("inc-audit-line-delete-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
        pendingHash = "";
        pendingRow = null;
    }

    function runDelete() {
        if (!pendingHash) {
            return;
        }
        var go = document.getElementById("inc-audit-line-delete-go");
        if (go) {
            go.disabled = true;
        }
        setStatus("Deleting.", false);

        fetch(statusdUrl("/audit-line-delete"), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ hash: pendingHash }),
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
                    setStatus(j.summary || "Audit line deleted.", false);
                    // Reload so last-7-days metrics and table stay consistent.
                    window.setTimeout(function () {
                        location.reload();
                    }, 350);
                } else {
                    setStatus(
                        j.error || "Delete failed (HTTP " + res.http + ").",
                        true
                    );
                    if (go) {
                        go.disabled = false;
                    }
                }
            })
            .catch(function (err) {
                setStatus(
                    "Delete failed: " +
                        (err && err.message ? err.message : String(err)),
                    true
                );
                if (go) {
                    go.disabled = false;
                }
            });
    }

    function injectDeleteControls() {
        var table = document.getElementById("inc-audit-log-table");
        if (!table) {
            return;
        }
        var theadRow = table.querySelector("thead tr");
        if (theadRow && !theadRow.querySelector(".inc-audit-col-delete")) {
            var th = document.createElement("th");
            th.scope = "col";
            th.className = "inc-audit-col-delete";
            th.textContent = "Delete";
            theadRow.appendChild(th);
        }

        table.querySelectorAll("tbody tr[data-audit-hash]").forEach(function (tr) {
            if (tr.querySelector(".inc-audit-col-delete")) {
                return;
            }
            var td = document.createElement("td");
            td.className = "inc-audit-col-delete";
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "inc-audit-line-delete-btn";
            btn.textContent = "×";
            btn.title = "Delete this audit log line";
            btn.setAttribute("aria-label", "Delete this audit log line");
            btn.setAttribute("data-inc-audit-line-delete", "1");
            td.appendChild(btn);
            tr.appendChild(td);
        });

        // Empty-state colspan if present
        var empty = table.querySelector("tbody td.inc-audit-muted[colspan]");
        if (empty) {
            empty.setAttribute("colspan", "7");
        }
    }

    function loadOperatorName() {
        return fetch(statusdUrl("/config"), { cache: "no-store" })
            .then(function (r) {
                return r.json();
            })
            .then(function (j) {
                if (j && j.ok && j.operator_name) {
                    operatorName = String(j.operator_name).trim();
                }
            })
            .catch(function () {
                operatorName = "";
            });
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
                if (t.closest("#inc-audit-line-delete-go")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    runDelete();
                    return;
                }
                if (t.closest("[data-inc-audit-line-delete-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    window.setTimeout(closeModal, 0);
                    return;
                }
                var delBtn = t.closest("[data-inc-audit-line-delete]");
                if (delBtn) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    var row = delBtn.closest("tr[data-audit-hash]");
                    if (row) {
                        openConfirm(row);
                    }
                    return;
                }
                if (t.closest("#inc-audit-line-delete-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-audit-line-delete-modal");
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
        injectDeleteControls();
        bindOnce();
        loadOperatorName();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
