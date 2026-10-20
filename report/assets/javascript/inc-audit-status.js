/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Poll localhost statusd for Audit "Scan running" card when available.
 * On the Discover-hosted Audit page, reload when pages/audit.htm is rebuilt
 * so a new log line shows up, then scroll to that row.
 */
(function () {
    var SHOW_KEY = "discover-audit-show-log";
    var RANGE_KEY = "discover-audit-range";
    var seenRev = null;
    var reloading = false;

    function hostedAudit() {
        var host = location.hostname;
        var onPort =
            (host === "127.0.0.1" || host === "localhost") &&
            location.port === "17322";
        if (!onPort) {
            return false;
        }
        return /\/audit\.htm$/i.test(location.pathname || "");
    }

    function dialogOpen() {
        var nodes = document.querySelectorAll('[aria-modal="true"]');
        var i;
        for (i = 0; i < nodes.length; i++) {
            if (!nodes[i].hasAttribute("hidden")) {
                return true;
            }
        }
        return false;
    }

    function rememberRange() {
        var sel = document.getElementById("inc-audit-metrics-range");
        if (!sel || !sel.value) {
            return;
        }
        try {
            sessionStorage.setItem(RANGE_KEY, sel.value);
        } catch (err) {
            /* private mode */
        }
    }

    function scrollToNewest() {
        var row = document.querySelector("#inc-audit-log-table tbody tr");
        if (row && row.scrollIntoView) {
            row.scrollIntoView({ block: "center" });
        }
    }

    // Metrics reads the flag during its init. Clear it on the next turn,
    // after that init has restored the range.
    var pendingShow = false;
    if (hostedAudit()) {
        try {
            pendingShow = sessionStorage.getItem(SHOW_KEY) === "1";
        } catch (err) {
            pendingShow = false;
        }
        var armShow = function () {
            setTimeout(function () {
                if (pendingShow) {
                    scrollToNewest();
                }
                try {
                    sessionStorage.removeItem(SHOW_KEY);
                } catch (err) {
                    /* private mode */
                }
            }, 0);
        };
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", armShow);
        } else {
            armShow();
        }
    }

    function reloadForNewLine() {
        if (reloading) {
            return;
        }
        reloading = true;
        rememberRange();
        try {
            sessionStorage.setItem(SHOW_KEY, "1");
        } catch (err) {
            /* still reload */
        }
        location.reload();
    }

    function tick() {
        fetch("http://127.0.0.1:17322/status", { cache: "no-store" })
            .then(function (r) {
                return r.json();
            })
            .then(function (status) {
                var el = document.getElementById("inc-audit-running");
                if (el) {
                    if (status && status.running && status.current) {
                        el.textContent =
                            (status.current.tool || "?") +
                            " @ " +
                            (status.current.host || "?");
                    } else {
                        el.textContent = "No";
                    }
                }
                if (!hostedAudit() || !status || status.audit_rev == null) {
                    return;
                }
                var rev = String(status.audit_rev);
                if (seenRev === null) {
                    seenRev = rev;
                    return;
                }
                if (rev === seenRev || dialogOpen()) {
                    return;
                }
                reloadForNewLine();
            })
            .catch(function () {
                /* statusd not running — leave static HTML */
            });
    }

    tick();
    setInterval(tick, 3000);

    // On the Discover host, web still opens Firefox via the desktop handler.
    // Edge on Windows has no handler, so the href (web.htm) is left alone.
    document.addEventListener("click", function (ev) {
        var host = location.hostname;
        var hosted =
            (host === "127.0.0.1" || host === "localhost") &&
            location.port === "17322";
        if (!hosted || /Windows NT/i.test(navigator.userAgent || "")) {
            return;
        }
        var node = ev.target;
        var anchor = null;
        if (node && node.closest) {
            anchor = node.closest("a[data-discover-scheme]");
        }
        if (!anchor) {
            return;
        }
        var scheme = anchor.getAttribute("data-discover-scheme") || "";
        var artifact = anchor.getAttribute("data-discover-artifact") || "";
        // Literal prefixes only. The attribute value is not copied into the URL.
        var prefix = "";
        if (scheme === "discover-robots") {
            prefix = "discover-robots:";
        } else if (scheme === "discover-ffuf") {
            prefix = "discover-ffuf:";
        } else if (scheme === "discover-ferox") {
            prefix = "discover-ferox:";
        } else if (scheme === "discover-nmap-web") {
            prefix = "discover-nmap-web:";
        }
        if (!prefix || !artifact) {
            return;
        }
        ev.preventDefault();
        window.location.href = prefix + encodeURI(artifact);
    });
})();
