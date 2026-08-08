/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Audit metrics range dropdown: Last 7 days | Last week | All.
 * Switches pre-rendered panels and keeps the select in the visible panel head
 * (aligned with By CVE / Targets scanned).
 */
(function () {
    function root() {
        return document.getElementById("inc-audit-metrics");
    }

    function panels(metrics) {
        return metrics.querySelectorAll(".inc-audit-metrics-panel");
    }

    function selectEl(metrics) {
        return metrics.querySelector("#inc-audit-metrics-range");
    }

    function placeSelect(metrics, range) {
        var sel = selectEl(metrics);
        if (!sel) {
            return;
        }
        var panel = metrics.querySelector(
            '.inc-audit-metrics-panel[data-range="' + range + '"]'
        );
        if (!panel) {
            return;
        }
        var slot = panel.querySelector(".inc-audit-metrics-range-slot");
        if (!slot) {
            return;
        }
        if (sel.parentNode !== slot) {
            slot.appendChild(sel);
        }
        sel.value = range;
    }

    function showRange(metrics, range) {
        panels(metrics).forEach(function (panel) {
            var match = panel.getAttribute("data-range") === range;
            if (match) {
                panel.removeAttribute("hidden");
            } else {
                panel.setAttribute("hidden", "hidden");
            }
        });
        placeSelect(metrics, range);
    }

    function init() {
        var metrics = root();
        if (!metrics) {
            return;
        }
        var sel = selectEl(metrics);
        if (!sel) {
            return;
        }
        var initial = sel.value || "7d";
        showRange(metrics, initial);
        sel.addEventListener("change", function () {
            showRange(metrics, sel.value || "7d");
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
