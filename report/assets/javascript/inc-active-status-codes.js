/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Active page: click "Status codes" section title → modal with brief
 * HTTP status descriptions (operator reference).
 */
(function () {
    var CODES = [
        {
            code: "200",
            name: "OK",
            desc: "Successful response. Host returned a normal page or payload.",
        },
        {
            code: "204",
            name: "No Content",
            desc: "Success with an empty body. Common for APIs and some redirects.",
        },
        {
            code: "301",
            name: "Moved Permanently",
            desc: "Permanent redirect. Client should use the new URL going forward.",
        },
        {
            code: "302",
            name: "Found",
            desc: "Temporary redirect. Common for login bounce and short-lived moves.",
        },
        {
            code: "303",
            name: "See Other",
            desc: "Redirect that usually forces a GET to another URL (often after POST).",
        },
        {
            code: "307",
            name: "Temporary Redirect",
            desc: "Temporary redirect that preserves the original request method.",
        },
        {
            code: "308",
            name: "Permanent Redirect",
            desc: "Permanent redirect that preserves the original request method.",
        },
        {
            code: "400",
            name: "Bad Request",
            desc: "Server rejected the request as malformed or invalid.",
        },
        {
            code: "401",
            name: "Unauthorized",
            desc: "Authentication required or credentials missing/invalid.",
        },
        {
            code: "403",
            name: "Forbidden",
            desc: "Access denied. May mean authz failure, WAF block, or IP deny.",
        },
        {
            code: "404",
            name: "Not Found",
            desc: "Resource does not exist at this path (or is hidden).",
        },
        {
            code: "405",
            name: "Method Not Allowed",
            desc: "HTTP method not permitted for this resource (e.g. POST where only GET).",
        },
        {
            code: "429",
            name: "Too Many Requests",
            desc: "Rate limited. Server or edge is throttling the client.",
        },
        {
            code: "500",
            name: "Internal Server Error",
            desc: "Server-side failure while handling the request.",
        },
        {
            code: "502",
            name: "Bad Gateway",
            desc: "Proxy/gateway got an invalid response from an upstream server.",
        },
        {
            code: "503",
            name: "Service Unavailable",
            desc: "Temporarily unavailable (overload, maintenance, or backend down).",
        },
        {
            code: "504",
            name: "Gateway Timeout",
            desc: "Proxy/gateway timed out waiting for an upstream server.",
        },
    ];

    function escapeHtml(s) {
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function ensureModal() {
        var el = document.getElementById("inc-active-status-codes-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-active-status-codes-modal";
        el.className = "inc-active-status-codes-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-active-status-codes-title");
        el.innerHTML =
            '<div class="inc-active-status-codes-backdrop" data-inc-active-status-codes-close="1"></div>' +
            '<div class="inc-active-status-codes-dialog">' +
            '<div class="inc-active-status-codes-header">' +
            '<h2 id="inc-active-status-codes-title" class="inc-active-status-codes-title">HTTP status codes</h2>' +
            '<button type="button" class="inc-active-status-codes-x" data-inc-active-status-codes-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<p class="inc-active-status-codes-lead">Common response codes seen in Active / httpx results.</p>' +
            '<div class="inc-active-status-codes-body" id="inc-active-status-codes-body"></div>' +
            "</div>";
        document.body.appendChild(el);

        var body = el.querySelector("#inc-active-status-codes-body");
        if (body) {
            var html = '<dl class="inc-active-status-codes-list">';
            var i;
            for (i = 0; i < CODES.length; i++) {
                html +=
                    "<div class=\"inc-active-status-codes-row\">" +
                    "<dt><span class=\"inc-active-status-codes-code\">" +
                    escapeHtml(CODES[i].code) +
                    "</span> " +
                    escapeHtml(CODES[i].name) +
                    "</dt>" +
                    "<dd>" +
                    escapeHtml(CODES[i].desc) +
                    "</dd>" +
                    "</div>";
            }
            html += "</dl>";
            body.innerHTML = html;
        }
        return el;
    }

    function openModal() {
        var el = ensureModal();
        el.removeAttribute("hidden");
        el.classList.add("is-open");
    }

    function closeModal() {
        var el = document.getElementById("inc-active-status-codes-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
    }

    function bindOnce() {
        if (document.documentElement.getAttribute("data-inc-active-status-codes") === "1") {
            return;
        }
        document.documentElement.setAttribute("data-inc-active-status-codes", "1");

        document.addEventListener(
            "click",
            function (ev) {
                var t = ev.target;
                if (!t || !t.closest) {
                    return;
                }
                if (t.closest("[data-inc-active-status-codes-help]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    openModal();
                    return;
                }
                if (t.closest("[data-inc-active-status-codes-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    window.setTimeout(closeModal, 0);
                    return;
                }
                if (t.closest("#inc-active-status-codes-modal")) {
                    ev.stopPropagation();
                }
            },
            true
        );

        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-active-status-codes-modal");
                if (el && !el.hasAttribute("hidden")) {
                    ev.preventDefault();
                    closeModal();
                }
            }
        });
    }

    function init() {
        // Only bind when the Status codes section exists on Active.
        if (
            !document.querySelector(
                ".inc-active-section--status, [data-inc-active-status-codes-help]"
            )
        ) {
            return;
        }
        bindOnce();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
