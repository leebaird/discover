/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Filter the public Subdomains table by software version.
 * Active Software versions links use: subdomains.htm?software=Apache:2.4.37
 *
 * Matches exact tech tokens (comma-separated) so Apache:2.4.6 does not
 * match Apache:2.4.67.
 */
(function () {
    function querySoftware() {
        try {
            var params = new URLSearchParams(window.location.search || "");
            return (params.get("software") || "").trim();
        } catch (err) {
            return "";
        }
    }

    function techTokens(row) {
        var el = row.querySelector(".inc-subdomain-techs");
        if (!el) {
            return [];
        }
        var raw = (el.getAttribute("title") || el.textContent || "").trim();
        if (!raw) {
            return [];
        }
        return raw.split(",").map(function (part) {
            return part.trim();
        }).filter(Boolean);
    }

    function rowHasSoftware(row, software) {
        var tokens = techTokens(row);
        var i;
        for (i = 0; i < tokens.length; i++) {
            if (tokens[i] === software) {
                return true;
            }
        }
        return false;
    }

    function clearUrl() {
        try {
            var url = new URL(window.location.href);
            url.searchParams.delete("software");
            var qs = url.searchParams.toString();
            return url.pathname + (qs ? "?" + qs : "") + url.hash;
        } catch (err) {
            return "subdomains.htm";
        }
    }

    function applyFilter(software) {
        var publicFrame = document.querySelector(".inc-subdomains-public");
        var publicTable = publicFrame
            ? publicFrame.querySelector("table.inc-data-table")
            : document.querySelector("table.inc-data-table");
        if (!publicTable) {
            return;
        }

        var tbody = publicTable.tBodies[0];
        if (!tbody) {
            return;
        }

        var rows = Array.prototype.slice.call(tbody.rows);
        var shown = 0;
        var i;
        var row;

        for (i = 0; i < rows.length; i++) {
            row = rows[i];
            if (rowHasSoftware(row, software)) {
                row.classList.remove("inc-subdomains-filter-hide");
                shown += 1;
            } else {
                row.classList.add("inc-subdomains-filter-hide");
            }
        }

        // Private table has no tech enrichment — hide while filtering.
        document.querySelectorAll(
            ".inc-subdomains-tables .inc-content-frame--table:not(.inc-subdomains-public)"
        ).forEach(function (frame) {
            frame.style.display = "none";
        });

        var note = document.querySelector(".inc-subdomains-note");
        var banner = document.getElementById("inc-subdomains-filter-banner");
        if (!banner) {
            banner = document.createElement("div");
            banner.id = "inc-subdomains-filter-banner";
            banner.className = "inc-subdomains-filter-banner";
            banner.setAttribute("role", "status");
            if (note && note.parentNode) {
                note.parentNode.insertBefore(banner, note.nextSibling);
            } else if (publicFrame && publicFrame.parentNode) {
                publicFrame.parentNode.insertBefore(banner, publicFrame);
            } else {
                document.body.insertBefore(banner, document.body.firstChild);
            }
        }

        // Applied software uses the same red pill style as Active KEV badges.
        banner.innerHTML =
            "Showing <strong>" +
            shown +
            "</strong> subdomain" +
            (shown === 1 ? "" : "s") +
            " running " +
            '<span class="inc-filter-applied"></span> ' +
            '<a class="inc-filter-clear" href="' +
            clearUrl() +
            '">Clear filter</a>';
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = software;
        }
    }

    function init() {
        var software = querySoftware();
        if (!software) {
            return;
        }
        applyFilter(software);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
