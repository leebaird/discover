/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Poll localhost statusd for Audit "Scan running" card when available.
 */
(function () {
    function tick() {
        fetch("http://127.0.0.1:17322/status", { cache: "no-store" })
            .then(function (r) {
                return r.json();
            })
            .then(function (status) {
                var el = document.getElementById("inc-audit-running");
                if (!el) {
                    return;
                }
                if (status && status.running && status.current) {
                    el.textContent =
                        (status.current.tool || "?") +
                        " @ " +
                        (status.current.host || "?");
                } else {
                    el.textContent = "No";
                }
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
