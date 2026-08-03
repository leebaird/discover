/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit log: filter rows by operator (client-side).
 * Dropdown next to the Audit log heading; optional ?operator=Name in the URL.
 * Works on statusd and file:// (no backend).
 */
(function () {
    function isAuditPage() {
        return (
            document.body &&
            (document.body.classList.contains("inc-audit-page") ||
                /audit\.htm/i.test(location.pathname || ""))
        );
    }

    function queryOperator() {
        try {
            return (
                new URLSearchParams(window.location.search || "").get(
                    "operator"
                ) || ""
            ).trim();
        } catch (err) {
            return "";
        }
    }

    function setQueryOperator(name) {
        try {
            var url = new URL(window.location.href);
            if (name) {
                url.searchParams.set("operator", name);
            } else {
                url.searchParams.delete("operator");
            }
            window.history.replaceState({}, "", url.pathname + url.search + url.hash);
        } catch (err) {
            /* ignore */
        }
    }

    function rowOperator(tr) {
        if (!tr || !tr.getAttribute) {
            return "";
        }
        if (tr.hasAttribute("data-audit-operator")) {
            return String(tr.getAttribute("data-audit-operator") || "").trim();
        }
        var td = tr.querySelector("td.inc-audit-col-op");
        if (!td) {
            return "";
        }
        var t = String(td.textContent || "").trim();
        if (t === "—" || t === "-" || t === "–") {
            return "";
        }
        return t;
    }

    function collectOperators(table) {
        var seen = {};
        var list = [];
        table.querySelectorAll("tbody tr").forEach(function (tr) {
            if (tr.querySelector("td.inc-audit-muted")) {
                return;
            }
            var op = rowOperator(tr);
            var key = op.toLowerCase();
            if (Object.prototype.hasOwnProperty.call(seen, key)) {
                return;
            }
            seen[key] = true;
            list.push(op);
        });
        list.sort(function (a, b) {
            if (!a && b) {
                return 1;
            }
            if (a && !b) {
                return -1;
            }
            return a.toLowerCase().localeCompare(b.toLowerCase());
        });
        return list;
    }

    function applyFilter(table, selected) {
        var want = (selected || "").trim().toLowerCase();
        var visible = 0;
        var total = 0;
        table.querySelectorAll("tbody tr").forEach(function (tr) {
            if (tr.querySelector("td.inc-audit-muted")) {
                return;
            }
            total += 1;
            var op = rowOperator(tr).toLowerCase();
            var show = !want || op === want;
            if (show) {
                tr.classList.remove("inc-audit-log-filter-hide");
                visible += 1;
            } else {
                tr.classList.add("inc-audit-log-filter-hide");
            }
        });
        return { visible: visible, total: total };
    }

    function buildSelect(operators, selected) {
        var sel = document.createElement("select");
        sel.id = "inc-audit-op-filter";
        sel.className = "inc-audit-op-filter-select";
        sel.setAttribute("aria-label", "Filter by operator");

        var all = document.createElement("option");
        all.value = "";
        all.textContent = "All operators";
        sel.appendChild(all);

        operators.forEach(function (op) {
            var opt = document.createElement("option");
            opt.value = op;
            opt.textContent = op || "(none)";
            sel.appendChild(opt);
        });

        if (selected) {
            var match = false;
            for (var i = 0; i < sel.options.length; i++) {
                if (
                    sel.options[i].value.toLowerCase() === selected.toLowerCase()
                ) {
                    sel.selectedIndex = i;
                    match = true;
                    break;
                }
            }
            if (!match) {
                // Unknown operator in URL — still select All, keep param until change.
                sel.selectedIndex = 0;
            }
        }
        return sel;
    }

    function init() {
        if (!isAuditPage()) {
            return;
        }
        var table = document.getElementById("inc-audit-log-table");
        if (!table) {
            return;
        }

        var operators = collectOperators(table);
        // No real rows (empty state) — leave slot empty.
        if (!operators.length) {
            return;
        }

        var slot = document.getElementById("inc-audit-log-filter");
        if (!slot) {
            var section = table.closest("section.inc-audit-section--log");
            if (section) {
                slot = document.createElement("div");
                slot.id = "inc-audit-log-filter";
                slot.className = "inc-audit-log-filter";
                var title = section.querySelector(".inc-audit-section-title");
                if (title && title.parentNode) {
                    var wrap = document.createElement("div");
                    wrap.className = "inc-audit-log-header";
                    title.parentNode.insertBefore(wrap, title);
                    wrap.appendChild(title);
                    wrap.appendChild(slot);
                } else {
                    section.insertBefore(slot, section.firstChild);
                }
            }
        }
        if (!slot) {
            return;
        }

        var initial = queryOperator();
        // Prefer exact case from collected list when URL matches case-insensitively.
        if (initial) {
            for (var i = 0; i < operators.length; i++) {
                if (operators[i].toLowerCase() === initial.toLowerCase()) {
                    initial = operators[i];
                    break;
                }
            }
        }

        slot.innerHTML = "";
        var label = document.createElement("label");
        label.className = "inc-audit-op-filter-label";
        label.htmlFor = "inc-audit-op-filter";
        label.textContent = "Operator";
        var sel = buildSelect(operators, initial);
        slot.appendChild(label);
        slot.appendChild(sel);

        function onChange() {
            var value = sel.value || "";
            applyFilter(table, value);
            setQueryOperator(value);
        }

        sel.addEventListener("change", onChange);
        applyFilter(table, sel.value || "");
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
