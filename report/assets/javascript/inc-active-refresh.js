/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Active page Enrich modal (Discover statusd only).
 * Optional: bulk Shodan force-refresh + Software CVE (NVD/KEV) refresh.
 */
(function () {
    var STATUS_PORT = 17322;
    var bound = false;

    function isDiscoverHostedPage() {
        var host = location.hostname;
        if (host !== "127.0.0.1" && host !== "localhost") {
            return false;
        }
        return location.port === String(STATUS_PORT);
    }

    function isActivePage() {
        return !!(document.body && document.body.classList.contains("inc-active-page")) ||
            !!(document.querySelector && document.querySelector(".inc-active-page"));
    }

    function ensureModal() {
        var el = document.getElementById("inc-active-refresh-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-active-refresh-modal";
        el.className = "inc-report-export-modal inc-active-refresh-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-active-refresh-title");
        el.innerHTML =
            '<div class="inc-report-export-backdrop" data-inc-active-refresh-close="1"></div>' +
            '<div class="inc-report-export-dialog">' +
            '<div class="inc-report-export-header">' +
            '<h2 id="inc-active-refresh-title" class="inc-report-export-title">Enrich engagement intel</h2>' +
            '<button type="button" class="inc-report-export-x" data-inc-active-refresh-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<p class="inc-report-export-lead">Refresh data for this report without re-running Active recon. ' +
            "Both options are safe to leave checked.</p>" +
            '<div class="inc-report-export-choices" role="group" aria-label="Enrich options">' +
            '<label class="inc-report-export-choice">' +
            '<input type="checkbox" id="inc-active-refresh-shodan" checked>' +
            "<span><strong>Shodan</strong> — re-query all public IPs (ports, org, host vulns). " +
            "Requires SHODAN_API_KEY in ~/.discover/api-keys. Rate-limited; large engagements take time.</span>" +
            "</label>" +
            '<label class="inc-report-export-choice">' +
            '<input type="checkbox" id="inc-active-refresh-cves" checked>' +
            "<span><strong>Software CVEs</strong> — re-query NVD for software versions with missing or empty CVE data, " +
            "re-apply CISA KEV badges, and rebuild the Software versions table. " +
            "Optional NVD_API_KEY speeds lookups. Some products are intentionally skipped.</span>" +
            "</label>" +
            "</div>" +
            '<div class="inc-report-export-status" id="inc-active-refresh-status" hidden></div>' +
            '<div class="inc-report-export-actions" id="inc-active-refresh-actions">' +
            '<button type="button" class="inc-report-export-cancel" data-inc-active-refresh-close="1">Cancel</button>' +
            '<button type="button" class="inc-report-export-go" id="inc-active-refresh-go">Enrich</button>' +
            "</div>" +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function setActionsVisible(visible) {
        var actions = document.getElementById("inc-active-refresh-actions");
        if (!actions) {
            return;
        }
        if (visible) {
            actions.hidden = false;
            actions.removeAttribute("hidden");
        } else {
            actions.hidden = true;
            actions.setAttribute("hidden", "hidden");
        }
    }

    function openModal() {
        var el = ensureModal();
        var status = el.querySelector("#inc-active-refresh-status");
        if (status) {
            status.hidden = true;
            status.textContent = "";
            status.classList.remove("is-error", "is-ok");
        }
        var go = el.querySelector("#inc-active-refresh-go");
        if (go) {
            go.disabled = false;
        }
        var sh = document.getElementById("inc-active-refresh-shodan");
        var cv = document.getElementById("inc-active-refresh-cves");
        if (sh) {
            sh.checked = true;
            sh.disabled = false;
        }
        if (cv) {
            cv.checked = true;
            cv.disabled = false;
        }
        setActionsVisible(true);
        el.removeAttribute("hidden");
        el.classList.add("is-open");
    }

    function closeModal() {
        var el = document.getElementById("inc-active-refresh-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
    }

    function setStatus(msg, isError) {
        var status = document.getElementById("inc-active-refresh-status");
        if (!status) {
            return;
        }
        status.hidden = false;
        status.textContent = msg;
        status.classList.toggle("is-error", !!isError);
        status.classList.toggle("is-ok", !isError);
        status.classList.remove("is-summary");
    }

    function setStatusHtml(html, isError) {
        var status = document.getElementById("inc-active-refresh-status");
        if (!status) {
            return;
        }
        status.hidden = false;
        status.innerHTML = html;
        status.classList.toggle("is-error", !!isError);
        status.classList.toggle("is-ok", !isError);
        status.classList.add("is-summary");
    }

    function esc(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function formatShodanSummary(j) {
        var st = j.stats || {};
        var ch = j.changes || {};
        var lines = [];
        lines.push("<strong>Shodan</strong>");
        lines.push(
            "Queried " +
                (st.queried != null ? st.queried : "0") +
                " · with data " +
                (st.ok != null ? st.ok : "0") +
                " · not in Shodan " +
                (st.not_found != null ? st.not_found : "0") +
                " · errors " +
                (st.error != null ? st.error : "0")
        );
        lines.push(
            "Changed: " +
                (ch.ips_updated != null ? ch.ips_updated : 0) +
                " IP(s)" +
                (ch.ips_new_ok ? " · " + ch.ips_new_ok + " newly found" : "") +
                (ch.ports_changed ? " · " + ch.ports_changed + " port list(s)" : "") +
                (ch.last_update_changed
                    ? " · " + ch.last_update_changed + " last_update"
                    : "") +
                (ch.vuln_count_changed
                    ? " · " + ch.vuln_count_changed + " vuln count"
                    : "")
        );
        if (ch.ips_updated === 0 && (st.queried || 0) > 0) {
            lines.push("No port/last_update/vuln differences vs prior index.");
        }
        var samples = ch.samples || [];
        if (samples.length) {
            lines.push("Examples:");
            samples.slice(0, 8).forEach(function (s) {
                var bits = [esc(s.ip)];
                if (s.ports_before !== s.ports_after) {
                    bits.push(
                        "ports " +
                            esc(s.ports_before || "—") +
                            " → " +
                            esc(s.ports_after || "—")
                    );
                }
                if (s.last_update_before !== s.last_update_after) {
                    bits.push("last_update changed");
                }
                if (s.vuln_count_before !== s.vuln_count_after) {
                    bits.push(
                        "vulns " +
                            esc(s.vuln_count_before) +
                            " → " +
                            esc(s.vuln_count_after)
                    );
                }
                lines.push("· " + bits.join(" · "));
            });
            if (samples.length > 8) {
                lines.push("· …and " + (samples.length - 8) + " more");
            }
        }
        return lines.join("<br>");
    }

    function formatCveSummary(j) {
        var st = j.stats || {};
        var lines = [];
        lines.push("<strong>Software CVEs</strong>");
        lines.push(
            "NVD lookups " +
                (st.looked_up != null ? st.looked_up : "0") +
                " · cache reused " +
                (st.cached != null ? st.cached : "0") +
                " · skipped " +
                (st.skipped != null ? st.skipped : "0")
        );
        lines.push(
            "Changed " +
                (st.changed != null ? st.changed : 0) +
                " product(s)" +
                (st.newly_with_cves
                    ? " · " + st.newly_with_cves + " newly with CVEs"
                    : "") +
                (st.kev_gained ? " · " + st.kev_gained + " gained KEV top" : "") +
                (st.kev_lost ? " · " + st.kev_lost + " lost KEV top" : "") +
                (st.still_empty
                    ? " · " + st.still_empty + " still empty after re-query"
                    : "")
        );
        if ((st.changed || 0) === 0 && (st.looked_up || 0) > 0) {
            lines.push(
                "Re-queried products but NVD returned the same counts (no table deltas)."
            );
        }
        if ((st.looked_up || 0) === 0 && (st.changed || 0) === 0) {
            lines.push("Nothing to re-query; KEV/display already current.");
        }
        var changes = st.changes || [];
        if (changes.length) {
            lines.push("Examples:");
            changes.slice(0, 12).forEach(function (c) {
                var parts = [esc(c.label)];
                if (c.cve_count_before !== c.cve_count_after) {
                    parts.push(
                        "CVEs " +
                            esc(c.cve_count_before) +
                            " → " +
                            esc(c.cve_count_after)
                    );
                }
                if (c.top_cve_before !== c.top_cve_after) {
                    parts.push(
                        "top " +
                            esc(c.top_cve_before || "—") +
                            " → " +
                            esc(c.top_cve_after || "—")
                    );
                }
                if (!!c.kev_before !== !!c.kev_after) {
                    parts.push(
                        c.kev_after ? "KEV added" : "KEV removed"
                    );
                }
                lines.push("· " + parts.join(" · "));
            });
            if (changes.length > 12) {
                lines.push("· …and " + (changes.length - 12) + " more");
            }
        }
        return lines.join("<br>");
    }

    function postJson(path, body) {
        return fetch(path, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body || {}),
            cache: "no-store",
            credentials: "same-origin",
        }).then(function (r) {
            return r.json().then(function (j) {
                return { http: r.status, body: j || {} };
            });
        });
    }

    function reenableControls() {
        var go = document.getElementById("inc-active-refresh-go");
        if (go) {
            go.disabled = false;
        }
        ["inc-active-refresh-shodan", "inc-active-refresh-cves"].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) {
                el.disabled = false;
            }
        });
    }

    function runUpdate() {
        var go = document.getElementById("inc-active-refresh-go");
        var wantShodan = !!(
            document.getElementById("inc-active-refresh-shodan") &&
            document.getElementById("inc-active-refresh-shodan").checked
        );
        var wantCves = !!(
            document.getElementById("inc-active-refresh-cves") &&
            document.getElementById("inc-active-refresh-cves").checked
        );
        if (!wantShodan && !wantCves) {
            setStatus("Select Shodan and/or Software CVEs.", true);
            return;
        }
        if (go) {
            go.disabled = true;
        }
        ["inc-active-refresh-shodan", "inc-active-refresh-cves"].forEach(function (id) {
            var el = document.getElementById(id);
            if (el) {
                el.disabled = true;
            }
        });

        var blocks = [];
        var anyFail = false;
        var cveOk = false;
        var chain = Promise.resolve();

        if (wantShodan) {
            chain = chain.then(function () {
                setStatus(
                    "Updating Shodan for all public IPs… (may take several minutes)",
                    false
                );
                return postJson("/shodan-refresh-all", { force: true }).then(
                    function (res) {
                        var j = res.body || {};
                        if (j.ok) {
                            blocks.push(formatShodanSummary(j));
                        } else {
                            anyFail = true;
                            blocks.push(
                                "<strong>Shodan</strong><br>Failed: " +
                                    esc(j.error || "HTTP " + res.http)
                            );
                        }
                    }
                );
            });
        }

        if (wantCves) {
            chain = chain.then(function () {
                setStatus("Updating Software CVEs from NVD…", false);
                return postJson("/software-cve-refresh", {
                    force_all: false,
                }).then(function (res) {
                    var j = res.body || {};
                    if (j.ok) {
                        cveOk = true;
                        blocks.push(formatCveSummary(j));
                    } else {
                        anyFail = true;
                        blocks.push(
                            "<strong>Software CVEs</strong><br>Failed: " +
                                esc(j.error || "HTTP " + res.http)
                        );
                    }
                });
            });
        }

        chain
            .then(function () {
                var html = blocks.join("<hr class=\"inc-active-refresh-hr\">");
                if (cveOk) {
                    html +=
                        '<hr class="inc-active-refresh-hr">' +
                        '<p class="inc-active-refresh-reload-note">' +
                        "Active page was rebuilt. Reload to see the Software versions table.</p>" +
                        '<button type="button" class="inc-report-export-go" id="inc-active-refresh-reload">' +
                        "Reload Active page</button>";
                }
                setStatusHtml(html, anyFail);
                reenableControls();
                var reload = document.getElementById("inc-active-refresh-reload");
                if (reload) {
                    reload.addEventListener("click", function (ev) {
                        ev.preventDefault();
                        location.reload();
                    });
                }
            })
            .catch(function (err) {
                setStatus(
                    "Enrich failed: " +
                        (err && err.message ? err.message : String(err)),
                    true
                );
                reenableControls();
            });
    }

    function injectButton() {
        var header =
            document.querySelector(".inc-page-header") ||
            document.querySelector(".container .inc-page-header");
        if (!header || header.querySelector(".inc-active-refresh-btn")) {
            return;
        }
        header.classList.add("inc-page-header--with-export");
        header.classList.add("inc-page-header--with-active-update");
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "inc-active-refresh-btn";
        btn.textContent = "Enrich";
        btn.title = "Enrich Shodan and/or Software CVEs for this engagement";
        btn.addEventListener("click", function (ev) {
            ev.preventDefault();
            ev.stopPropagation();
            openModal();
        });
        // Cluster: Enrich then scan date (date to the right of the button).
        var actions = header.querySelector(".inc-active-header-actions");
        if (!actions) {
            actions = document.createElement("div");
            actions.className = "inc-active-header-actions";
            header.appendChild(actions);
        }
        actions.appendChild(btn);
        var dateEl = header.querySelector(".inc-active-scan-date");
        if (dateEl && dateEl.parentNode !== actions) {
            actions.appendChild(dateEl);
        }
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
                if (t.closest("#inc-active-refresh-go")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    runUpdate();
                    return;
                }
                if (t.closest("[data-inc-active-refresh-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    closeModal();
                }
            },
            true
        );
        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape") {
                var el = document.getElementById("inc-active-refresh-modal");
                if (el && !el.hasAttribute("hidden")) {
                    closeModal();
                }
            }
        });
    }

    function init() {
        if (!isActivePage() || !isDiscoverHostedPage()) {
            return;
        }
        injectButton();
        bindOnce();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
