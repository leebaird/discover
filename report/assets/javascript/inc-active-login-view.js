/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Login pages Category header icon switches By source / By type (does not sort).
 */
(function () {
    function root() {
        return document.querySelector(".inc-active-section--login");
    }

    function currentView(section) {
        var typePanel = section.querySelector(
            '.inc-active-login-panel[data-login-view="type"]'
        );
        if (typePanel && !typePanel.hasAttribute("hidden")) {
            return "type";
        }
        return "source";
    }

    function showView(section, view) {
        var panels = section.querySelectorAll(".inc-active-login-panel");
        var i;
        var match;
        for (i = 0; i < panels.length; i++) {
            match = panels[i].getAttribute("data-login-view") === view;
            if (match) {
                panels[i].removeAttribute("hidden");
            } else {
                panels[i].setAttribute("hidden", "hidden");
            }
        }
        var toggles = section.querySelectorAll(".inc-login-view-toggle");
        for (i = 0; i < toggles.length; i++) {
            toggles[i].classList.remove("inc-sort-asc", "inc-sort-desc");
            if (view === "type") {
                toggles[i].classList.add("inc-sort-desc");
                toggles[i].setAttribute("aria-sort", "descending");
            } else {
                toggles[i].classList.add("inc-sort-asc");
                toggles[i].setAttribute("aria-sort", "ascending");
            }
            toggles[i].setAttribute(
                "aria-label",
                view === "type"
                    ? "Login pages view: By type. Activate for By source."
                    : "Login pages view: By source. Activate for By type."
            );
        }
        try {
            window.dispatchEvent(new Event("resize"));
        } catch (err) {
            /* ignore */
        }
    }

    function init() {
        var section = root();
        if (!section) {
            return;
        }
        var toggles = section.querySelectorAll(".inc-login-view-toggle");
        if (!toggles.length) {
            return;
        }
        showView(section, "source");
        function onActivate(ev) {
            ev.preventDefault();
            ev.stopPropagation();
            showView(
                section,
                currentView(section) === "source" ? "type" : "source"
            );
        }
        var i;
        for (i = 0; i < toggles.length; i++) {
            toggles[i].addEventListener("click", onActivate);
            toggles[i].addEventListener("keydown", function (ev) {
                if (ev.key === "Enter" || ev.key === " ") {
                    onActivate(ev);
                }
            });
        }
        bindHelp();
    }

    function ensureHelpModal() {
        var el = document.getElementById("inc-active-login-help-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-active-login-help-modal";
        el.className = "inc-active-status-codes-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-active-login-help-title");
        el.innerHTML =
            '<div class="inc-active-status-codes-backdrop" data-inc-active-login-help-close="1"></div>' +
            '<div class="inc-active-status-codes-dialog">' +
            '<div class="inc-active-status-codes-header">' +
            '<h2 id="inc-active-login-help-title" class="inc-active-status-codes-title">Login pages</h2>' +
            '<button type="button" class="inc-active-status-codes-x" data-inc-active-login-help-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div class="inc-active-status-codes-body">' +
            '<dl class="inc-active-status-codes-list">' +
            '<div class="inc-active-status-codes-row">' +
            "<dt>Switching views</dt>" +
            "<dd>The icon next to Source or Type switches By source and By type. It does not sort that column.</dd>" +
            "</div>" +
            '<div class="inc-active-status-codes-row">' +
            "<dt>By source</dt>" +
            "<dd>Path, Title, Tech, and Status. A host can match more than one, so those counts add up to more than the number of hosts.</dd>" +
            "</div>" +
            '<div class="inc-active-status-codes-row">' +
            "<dt>By type</dt>" +
            "<dd>Basic is HTTP challenge auth (Basic, Digest, NTLM, Negotiate). Form is an HTML login page (path, title, product, or a password field). A host is usually one or the other.</dd>" +
            "</div>" +
            '<div class="inc-active-status-codes-row">' +
            "<dt>Why the totals differ</dt>" +
            "<dd>Adding the By source rows counts the same host more than once. Adding Basic and Form is closer to unique hosts.</dd>" +
            "</div>" +
            "</dl>" +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function openHelp() {
        var el = ensureHelpModal();
        el.removeAttribute("hidden");
        el.classList.add("is-open");
    }

    function closeHelp() {
        var el = document.getElementById("inc-active-login-help-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
    }

    function bindHelp() {
        if (document.documentElement.getAttribute("data-inc-active-login-help-bound") === "1") {
            return;
        }
        document.documentElement.setAttribute("data-inc-active-login-help-bound", "1");
        document.addEventListener(
            "click",
            function (ev) {
                var t = ev.target;
                if (!t || !t.closest) {
                    return;
                }
                if (t.closest("[data-inc-active-login-help-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    window.setTimeout(closeHelp, 0);
                    return;
                }
                if (t.closest("[data-inc-active-login-help]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    openHelp();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-active-login-help-modal");
                if (el && !el.hasAttribute("hidden")) {
                    ev.preventDefault();
                    closeHelp();
                }
            }
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
