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
})();
