/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Filter the public Subdomains table by software, CVE, category, status, or web server.
 * Active Software versions:  subdomains.htm?software=Apache:2.4.37
 * Active CVE search:         subdomains.htm?cve=CVE-2024-38475
 * Active Alive by category:  subdomains.htm?category=Dev  (or category=(none))
 * Active Status codes:       subdomains.htm?status=200
 * Active Top web servers:    subdomains.htm?webserver=Apache
 *
 * CVE mode resolves software labels via tools/cve-software-index.js
 * (or software-cves-cache.json) then matches tech tokens like software=.
 * Category / status / webserver match the corresponding Subdomains columns.
 */
(function () {
    function queryParam(name) {
        try {
            return (new URLSearchParams(window.location.search || "").get(name) || "").trim();
        } catch (err) {
            return "";
        }
    }

    function querySoftware() {
        return queryParam("software");
    }

    function queryCategory() {
        // Preserve intentional empty via (none) from Active category table.
        try {
            var params = new URLSearchParams(window.location.search || "");
            if (!params.has("category")) {
                return null;
            }
            return (params.get("category") || "").trim();
        } catch (err) {
            return null;
        }
    }

    function queryStatus() {
        var raw = queryParam("status");
        if (!raw) {
            return "";
        }
        // Normalize to digits only when possible (e.g. "200" / " 200 ").
        var s = String(raw).trim();
        if (/^\d{3}$/.test(s)) {
            return s;
        }
        return s;
    }

    function queryWebserver() {
        return queryParam("webserver");
    }

    function queryCve() {
        var raw = queryParam("cve");
        if (!raw) {
            return "";
        }
        var s = raw.toUpperCase().replace(/\s+/g, "").replace(/_/g, "-");
        if (/^\d{4}-\d+$/.test(s)) {
            s = "CVE-" + s;
        }
        s = s.replace(/^CVE(?!-)/, "CVE-").replace(/^CVE-+/, "CVE-");
        if (!/^CVE-\d{4}-\d+$/.test(s)) {
            return raw.toUpperCase(); // still try display; match may fail
        }
        return s;
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

    /** Category cell is column index 1 (Subdomain, Category, IP, …). */
    function rowCategory(row) {
        if (!row || !row.cells || row.cells.length < 2) {
            return "";
        }
        return (row.cells[1].textContent || "").trim();
    }

    /**
     * HTTP status: prefer column index 4 (Photo=3, Status=4); fall back to any
     * centered cell that is exactly three digits.
     */
    function rowStatus(row) {
        if (!row || !row.cells) {
            return "";
        }
        if (row.cells.length > 4) {
            var cell = (row.cells[4].textContent || "").trim();
            if (/^\d{3}$/.test(cell)) {
                return cell;
            }
        }
        var i;
        var tds = row.querySelectorAll("td.inc-col-center");
        for (i = 0; i < tds.length; i++) {
            var t = (tds[i].textContent || "").trim();
            if (/^\d{3}$/.test(t)) {
                return t;
            }
        }
        return "";
    }

    /** Match Active webserver_label(): drop parenthetical notes for compare. */
    function normalizeWebserver(s) {
        return String(s || "")
            .replace(/\s*\([^)]*\)/g, "")
            .replace(/\s+/g, " ")
            .trim()
            .toLowerCase();
    }

    function rowWebserver(row) {
        var el = row.querySelector(".inc-subdomain-webserver");
        if (!el) {
            return "";
        }
        return (el.textContent || "").trim();
    }

    function rowHasWebserver(row, want) {
        var raw = rowWebserver(row);
        var w = String(want || "").trim();
        if (!w) {
            return !raw;
        }
        if (raw === w) {
            return true;
        }
        return normalizeWebserver(raw) === normalizeWebserver(w);
    }

    function normalizeLabel(s) {
        return String(s || "")
            .toLowerCase()
            .replace(/\|/g, ":")
            .replace(/\s+/g, " ")
            .trim();
    }

    function rowHasSoftware(row, software) {
        var tokens = techTokens(row);
        var i;
        var want = software;
        var wantNorm = normalizeLabel(software);
        for (i = 0; i < tokens.length; i++) {
            if (tokens[i] === want || normalizeLabel(tokens[i]) === wantNorm) {
                return true;
            }
        }
        return false;
    }

    function rowHasAnySoftware(row, softwares) {
        var i;
        for (i = 0; i < softwares.length; i++) {
            if (rowHasSoftware(row, softwares[i])) {
                return true;
            }
        }
        return false;
    }

    function clearUrl() {
        try {
            var url = new URL(window.location.href);
            url.searchParams.delete("software");
            url.searchParams.delete("cve");
            url.searchParams.delete("category");
            url.searchParams.delete("status");
            url.searchParams.delete("webserver");
            var qs = url.searchParams.toString();
            return url.pathname + (qs ? "?" + qs : "") + url.hash;
        } catch (err) {
            return "subdomains.htm";
        }
    }

    /** Clear filter (full Subdomains) + Back (Active page). */
    function filterNavHtml() {
        return (
            '<a class="inc-filter-clear" href="' +
            clearUrl() +
            '">Clear filter</a>' +
            ' <a class="inc-filter-back" href="active.htm">Back</a>'
        );
    }

    function hidePrivateTables() {
        document.querySelectorAll(
            ".inc-subdomains-tables .inc-content-frame--table:not(.inc-subdomains-public)"
        ).forEach(function (frame) {
            frame.style.display = "none";
        });
    }

    function ensureBanner(publicFrame) {
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
        return banner;
    }

    function filterRows(matchFn) {
        var publicFrame = document.querySelector(".inc-subdomains-public");
        var publicTable = publicFrame
            ? publicFrame.querySelector("table.inc-data-table")
            : document.querySelector("table.inc-data-table");
        if (!publicTable || !publicTable.tBodies[0]) {
            return { shown: 0, publicFrame: publicFrame };
        }
        var rows = Array.prototype.slice.call(publicTable.tBodies[0].rows);
        var shown = 0;
        var i;
        var row;
        for (i = 0; i < rows.length; i++) {
            row = rows[i];
            if (row.classList.contains("inc-shodan-panel-row") ||
                row.classList.contains("inc-host-scan-panel-row")) {
                continue;
            }
            if (matchFn(row)) {
                row.classList.remove("inc-subdomains-filter-hide");
                shown += 1;
            } else {
                row.classList.add("inc-subdomains-filter-hide");
            }
        }
        hidePrivateTables();
        return { shown: shown, publicFrame: publicFrame };
    }

    function applySoftwareFilter(software) {
        var result = filterRows(function (row) {
            return rowHasSoftware(row, software);
        });
        var banner = ensureBanner(result.publicFrame);
        banner.innerHTML =
            "Showing <strong>" +
            result.shown +
            "</strong> subdomain" +
            (result.shown === 1 ? "" : "s") +
            " running " +
            '<span class="inc-filter-applied"></span> ' +
            filterNavHtml();
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = software;
        }
    }

    function applyCategoryFilter(category) {
        // Active table uses "(none)" for empty category cells.
        var want = category === "(none)" ? "" : category;
        var result = filterRows(function (row) {
            var cat = rowCategory(row);
            if (want === "") {
                return !cat;
            }
            return cat === want;
        });
        var banner = ensureBanner(result.publicFrame);
        var display = category === "" ? "(none)" : category;
        banner.innerHTML =
            "Showing <strong>" +
            result.shown +
            "</strong> subdomain" +
            (result.shown === 1 ? "" : "s") +
            " in category " +
            '<span class="inc-filter-applied"></span> ' +
            filterNavHtml();
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = display;
        }
    }

    function applyStatusFilter(status) {
        var want = String(status || "").trim();
        var result = filterRows(function (row) {
            return rowStatus(row) === want;
        });
        var banner = ensureBanner(result.publicFrame);
        banner.innerHTML =
            "Showing <strong>" +
            result.shown +
            "</strong> subdomain" +
            (result.shown === 1 ? "" : "s") +
            " with status " +
            '<span class="inc-filter-applied"></span> ' +
            filterNavHtml();
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = want;
        }
    }

    function applyWebserverFilter(webserver) {
        var want = String(webserver || "").trim();
        var result = filterRows(function (row) {
            return rowHasWebserver(row, want);
        });
        var banner = ensureBanner(result.publicFrame);
        banner.innerHTML =
            "Showing <strong>" +
            result.shown +
            "</strong> subdomain" +
            (result.shown === 1 ? "" : "s") +
            " with web server " +
            '<span class="inc-filter-applied"></span> ' +
            filterNavHtml();
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = want;
        }
    }

    function applyCveFilter(cve, softwares) {
        var result = filterRows(function (row) {
            return softwares.length ? rowHasAnySoftware(row, softwares) : false;
        });
        var banner = ensureBanner(result.publicFrame);
        var softHtml = "";
        if (softwares.length) {
            softHtml =
                " via " +
                softwares
                    .map(function (s) {
                        return (
                            '<a class="inc-filter-software-link" href="subdomains.htm?software=' +
                            encodeURIComponent(s) +
                            '">' +
                            escapeHtml(s) +
                            "</a>"
                        );
                    })
                    .join(", ");
        } else {
            softHtml =
                ' <span class="inc-filter-none">(no matching software in NVD cache)</span>';
        }
        banner.innerHTML =
            "Showing <strong>" +
            result.shown +
            "</strong> subdomain" +
            (result.shown === 1 ? "" : "s") +
            " for " +
            '<span class="inc-filter-applied"></span>' +
            softHtml +
            " " +
            filterNavHtml();
        var applied = banner.querySelector(".inc-filter-applied");
        if (applied) {
            applied.textContent = cve;
        }
    }

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function loadCveSoftwareMap() {
        if (
            typeof window.DISCOVER_CVE_SOFTWARE === "object" &&
            window.DISCOVER_CVE_SOFTWARE !== null
        ) {
            return Promise.resolve(window.DISCOVER_CVE_SOFTWARE);
        }
        return new Promise(function (resolve) {
            var s = document.createElement("script");
            s.src = "../tools/cve-software-index.js";
            s.async = true;
            s.onload = function () {
                resolve(
                    typeof window.DISCOVER_CVE_SOFTWARE === "object" &&
                        window.DISCOVER_CVE_SOFTWARE
                        ? window.DISCOVER_CVE_SOFTWARE
                        : {}
                );
            };
            s.onerror = function () {
                // HTTP fallback
                fetch("../tools/software-cves-cache.json", {
                    credentials: "same-origin",
                    cache: "no-cache",
                })
                    .then(function (res) {
                        if (!res.ok) {
                            throw new Error("cache missing");
                        }
                        return res.json();
                    })
                    .then(function (cache) {
                        resolve(buildMapFromCache(cache));
                    })
                    .catch(function () {
                        resolve({});
                    });
            };
            (document.head || document.documentElement).appendChild(s);
        });
    }

    function buildMapFromCache(cache) {
        var index = {};
        var entries = (cache && cache.entries) || {};
        Object.keys(entries).forEach(function (key) {
            var ent = entries[key];
            if (!ent || typeof ent !== "object") {
                return;
            }
            var product = (ent.product || "").trim();
            var version = (ent.version || "").trim();
            if (!product) {
                return;
            }
            var label = version ? product + ":" + version : product;
            var ids = {};
            (ent.cves || []).forEach(function (c) {
                if (c && c.id) {
                    ids[String(c.id).toUpperCase()] = true;
                }
            });
            if (ent.top_cve) {
                ids[String(ent.top_cve).toUpperCase()] = true;
            }
            Object.keys(ids).forEach(function (cid) {
                if (cid.indexOf("CVE-") !== 0) {
                    return;
                }
                if (!index[cid]) {
                    index[cid] = [];
                }
                if (index[cid].indexOf(label) === -1) {
                    index[cid].push(label);
                }
            });
        });
        return index;
    }

    function init() {
        var software = querySoftware();
        var cve = queryCve();
        var category = queryCategory();
        var status = queryStatus();
        var webserver = queryWebserver();

        if (software) {
            applySoftwareFilter(software);
            return;
        }
        if (category !== null) {
            applyCategoryFilter(category);
            return;
        }
        if (status) {
            applyStatusFilter(status);
            return;
        }
        if (webserver) {
            applyWebserverFilter(webserver);
            return;
        }
        if (!cve) {
            return;
        }

        loadCveSoftwareMap().then(function (map) {
            var softwares = map[cve] || map[cve.toUpperCase()] || [];
            applyCveFilter(cve, softwares);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
