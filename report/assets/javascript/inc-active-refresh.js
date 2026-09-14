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

    function formatPortDelta(s) {
        var bits = [];
        var added = s.ports_added;
        var removed = s.ports_removed;
        if (Array.isArray(added) && added.length) {
            bits.push("added " + added.map(esc).join(", "));
        }
        if (Array.isArray(removed) && removed.length) {
            bits.push("removed " + removed.map(esc).join(", "));
        }
        if (bits.length) {
            return bits.join("; ");
        }
        if (s.ports_before !== s.ports_after) {
            return (
                "ports " +
                esc(s.ports_before || "-") +
                " to " +
                esc(s.ports_after || "-")
            );
        }
        return "";
    }

    function formatCveList(ids, limit) {
        var list = Array.isArray(ids) ? ids.slice() : [];
        var cap = limit || 9;
        var shown = list.slice(0, cap).map(esc);
        if (list.length > cap) {
            shown.push("+" + (list.length - cap) + " more");
        }
        return shown.join(", ");
    }

    function formatVulnDelta(s) {
        var bits = [];
        var before = s.vuln_count_before;
        var after = s.vuln_count_after;
        if (before != null && after != null && before !== after) {
            bits.push("CVEs " + esc(before) + " to " + esc(after));
        }
        var added = s.vulns_added;
        var removed = s.vulns_removed;
        if (Array.isArray(added) && added.length) {
            bits.push("added " + formatCveList(added, 9));
        }
        if (Array.isArray(removed) && removed.length) {
            bits.push("removed " + formatCveList(removed, 9));
        }
        if (bits.length) {
            return bits.join("; ");
        }
        if (after != null && Number(after) > 0) {
            return "CVEs " + esc(after);
        }
        return "";
    }

    function sortByIp(rows) {
        return rows.slice().sort(function (a, b) {
            return String(a.ip || "").localeCompare(String(b.ip || ""), undefined, {
                numeric: true,
            });
        });
    }

    function formatIpRows(rows, detailFn, extra, nameClass, skipSort) {
        var html = [];
        var cap = 40;
        var nameCls = nameClass || "inc-active-refresh-ip";
        var list = skipSort ? rows.slice() : sortByIp(rows);
        list
            .slice(0, cap)
            .forEach(function (s) {
                var detail = detailFn(s);
                if (extra) {
                    detail = extra(s, detail);
                }
                html.push(
                    '<div class="inc-active-refresh-iprow">' +
                        '<span class="' +
                        nameCls +
                        '">' +
                        esc(s.ip || s.label || "") +
                        "</span> " +
                        '<span class="inc-active-refresh-ipdetail">' +
                        (detail || "-") +
                        "</span>" +
                        "</div>"
                );
            });
        if (rows.length > cap) {
            html.push(
                '<div class="inc-active-refresh-more">' +
                    "and " +
                    (rows.length - cap) +
                    " more</div>"
            );
        }
        return html.join("");
    }

    function formatShodanSummary(j) {
        var st = j.stats || {};
        var ch = j.changes || {};
        var lines = [];
        lines.push("<strong>Shodan</strong>");
        lines.push(
            "Queried " +
                (st.queried != null ? st.queried : "0") +
                " · " +
                (st.ok != null ? st.ok : "0") +
                " with data · " +
                (st.not_found != null ? st.not_found : "0") +
                " not in Shodan" +
                (st.error ? " · errors " + st.error : "")
        );
        lines.push(
            "Changed: " +
                (ch.ips_updated != null ? ch.ips_updated : 0) +
                " IPs" +
                (ch.ips_new_ok ? " · " + ch.ips_new_ok + " newly found" : "") +
                (ch.ports_changed
                    ? " · " + ch.ports_changed + " with port changes"
                    : "") +
                (ch.ports_added_total
                    ? " · " +
                      ch.ports_added_total +
                      (ch.ports_added_total === 1 ? " new port" : " new ports")
                    : "") +
                (ch.ports_removed_total
                    ? " · " +
                      ch.ports_removed_total +
                      (ch.ports_removed_total === 1
                          ? " port no longer seen"
                          : " ports no longer seen")
                    : "") +
                (ch.last_update_changed
                    ? " · " + ch.last_update_changed + " Shodan timestamps"
                    : "") +
                (ch.vuln_count_changed
                    ? " · " +
                      ch.vuln_count_changed +
                      (ch.vuln_count_changed === 1
                          ? " IP with CVE changes"
                          : " IPs with CVE changes")
                    : "")
        );
        if (ch.ips_updated === 0 && (st.queried || 0) > 0) {
            lines.push("No port, timestamp, or CVE differences vs prior index.");
        }
        var vulnNowTotal =
            ch.vuln_now_total != null
                ? ch.vuln_now_total
                : (ch.vuln_now || []).length;
        if (vulnNowTotal) {
            lines.push(
                "Shodan host vulns on " +
                    vulnNowTotal +
                    (vulnNowTotal === 1 ? " IP." : " IPs.")
            );
        } else {
            lines.push("No Shodan host vulns on these IPs.");
        }
        var portNowTotal =
            ch.port_now_total != null
                ? ch.port_now_total
                : (ch.port_now || []).length;
        if (portNowTotal) {
            var extraN = ch.port_now_extra || 0;
            lines.push(
                "Shodan ports on " +
                    portNowTotal +
                    (portNowTotal === 1 ? " IP" : " IPs") +
                    (extraN
                        ? " · " + extraN + " with ports besides 80/443."
                        : ".")
            );
        }

        var portSamples = ch.port_samples || [];
        if (!portSamples.length) {
            portSamples = (ch.samples || []).filter(function (s) {
                return (
                    (s.ports_added && s.ports_added.length) ||
                    (s.ports_removed && s.ports_removed.length) ||
                    s.ports_before !== s.ports_after ||
                    s.is_new
                );
            });
        }
        if (portSamples.length) {
            lines.push(
                '<div class="inc-active-refresh-h">Ports (changed this run)</div>' +
                    formatIpRows(portSamples, formatPortDelta, function (s, delta) {
                        if (s.is_new && !delta && s.ports_after) {
                            return "new in Shodan " + esc(s.ports_after);
                        }
                        if (s.is_new && delta) {
                            return "new in Shodan; " + delta;
                        }
                        return delta;
                    })
            );
        }

        var portNow = ch.port_now || [];
        if (portNow.length) {
            lines.push(
                '<div class="inc-active-refresh-h">Ports</div>' +
                    formatIpRows(portNow, function (s) {
                        var ports = s.ports;
                        if (Array.isArray(ports) && ports.length) {
                            return ports.map(esc).join(", ");
                        }
                        return esc(s.ports_after || s.ports_label || "-");
                    })
            );
        }

        var vulnSamples = ch.vuln_samples || [];
        if (!vulnSamples.length) {
            vulnSamples = (ch.samples || []).filter(function (s) {
                return (
                    (s.vulns_added && s.vulns_added.length) ||
                    (s.vulns_removed && s.vulns_removed.length) ||
                    (s.vuln_count_before != null &&
                        s.vuln_count_after != null &&
                        s.vuln_count_before !== s.vuln_count_after)
                );
            });
        }
        if (vulnSamples.length) {
            lines.push(
                '<div class="inc-active-refresh-h">Shodan host vulns (changed this run)</div>'
            );
            lines.push(formatIpRows(vulnSamples, formatVulnDelta));
        }

        var vulnNow = ch.vuln_now || [];
        if (vulnNow.length) {
            lines.push(
                '<div class="inc-active-refresh-h">Shodan host vulns</div>' +
                formatIpRows(vulnNow, function (s) {
                    var n =
                        s.vuln_count != null
                            ? s.vuln_count
                            : (s.vulns || []).length;
                    var bits = [
                        n + (Number(n) === 1 ? " CVE" : " CVEs"),
                    ];
                    if (s.vulns && s.vulns.length) {
                        bits.push(formatCveList(s.vulns, 9));
                    }
                    return bits.join("  ");
                })
            );
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
                (st.kev_gained
                    ? " · " + st.kev_gained + " product(s) newly KEV top"
                    : "") +
                (st.kev_lost
                    ? " · " + st.kev_lost + " product(s) no longer KEV top"
                    : "") +
                (st.still_empty
                    ? " · " + st.still_empty + " still empty after re-query"
                    : "")
        );
        if ((st.looked_up || 0) === 0 && (st.changed || 0) === 0) {
            lines.push("Cache already current. Showing products with NVD CVEs.");
        }
        var changes = st.changes || [];
        if (changes.length) {
            lines.push(
                '<div class="inc-active-refresh-h">Changed this run</div>' +
                    formatIpRows(
                        changes.map(function (c) {
                            return {
                                ip: c.label,
                                cve_count_before: c.cve_count_before,
                                cve_count_after: c.cve_count_after,
                                top_cve_before: c.top_cve_before,
                                top_cve_after: c.top_cve_after,
                                kev_before: c.kev_before,
                                kev_after: c.kev_after,
                            };
                        }),
                        function (c) {
                            var bits = [];
                            if (c.cve_count_before !== c.cve_count_after) {
                                bits.push(
                                    "CVEs " +
                                        esc(c.cve_count_before) +
                                        " to " +
                                        esc(c.cve_count_after)
                                );
                            }
                            if (c.top_cve_before !== c.top_cve_after) {
                                bits.push(
                                    "top " +
                                        esc(c.top_cve_before || "-") +
                                        " to " +
                                        esc(c.top_cve_after || "-")
                                );
                            }
                            if (!!c.kev_before !== !!c.kev_after) {
                                bits.push(
                                    c.kev_after
                                        ? "top is now KEV"
                                        : "top no longer KEV"
                                );
                            }
                            return bits.join("; ") || "updated";
                        }
                    )
            );
        }
        var now = st.software_now || [];
        var nowTotal =
            st.software_now_total != null ? st.software_now_total : now.length;
        if (nowTotal) {
            lines.push(
                "NVD CVEs on " +
                    nowTotal +
                    (nowTotal === 1 ? " product." : " products.")
            );
        } else {
            lines.push("No NVD CVEs on software versions.");
        }
        var lists = "";
        if (now.length) {
            lists +=
                '<div class="inc-active-refresh-h">Software versions</div>' +
                formatIpRows(
                    now.map(function (s) {
                        var copy = {};
                        Object.keys(s).forEach(function (k) {
                            copy[k] = s[k];
                        });
                        copy.ip = s.label || s.ip;
                        return copy;
                    }),
                    function (s) {
                        var n = s.cve_count != null ? s.cve_count : 0;
                        var bits = [
                            n + (Number(n) === 1 ? " CVE" : " CVEs"),
                        ];
                        if (s.top_cve) {
                            bits.push(esc(s.top_cve) + (s.kev ? " KEV" : ""));
                        }
                        if (s.cvss) {
                            bits.push("CVSS " + esc(s.cvss));
                        }
                        if (s.hosts) {
                            bits.push(
                                esc(s.hosts) +
                                    (Number(s.hosts) === 1
                                        ? " host"
                                        : " hosts")
                            );
                        }
                        return bits.join("  ");
                    },
                    null,
                    "inc-active-refresh-sw",
                    true
                );
        }
        var emptyLabels = st.still_empty_labels || [];
        if (emptyLabels.length) {
            lists +=
                '<div class="inc-active-refresh-h">Still empty after NVD</div>' +
                formatIpRows(
                    emptyLabels.map(function (label) {
                        return { ip: label };
                    }),
                    function () {
                        return "no CVEs";
                    },
                    null,
                    "inc-active-refresh-sw"
                );
        }
        if (lists) {
            lines.push(lists);
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
                    "Updating Shodan data on public IPs.",
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
                setStatus("Updating software CVEs from NVD.", false);
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
