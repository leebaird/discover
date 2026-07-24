/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Subdomains expand host row → launch host-scan tools (operator mode only).
 * Chevrons only when the page is served by Discover statusd
 * (http://127.0.0.1:17322/… from Import report / Active) — not file:// manual open.
 * One tool at a time; live status via same origin /mode|/status when hosted.
 * droopescan / wpscan gate on software query when present, else row tech/title.
 * Tool boxes: Unicode ⓘ opens a short modal (what / when / Run / outputs).
 */
(function () {
    /** Host-scan expand panel logic. */
    // Base tools quietest → loudest (CMS tools inserted when software matches).
    var TOOLS_BASE = ["nuclei", "nikto", "ffuf"];
    // droopescan CMS label → plugin name (must match run-host-scan.sh).
    var DROOPESCAN_CMS = {
        drupal: "drupal",
        wordpress: "wordpress",
        wp: "wordpress",
        joomla: "joomla",
        moodle: "moodle",
        silverstripe: "silverstripe",
        ss: "silverstripe"
    };
    var STATUS_PORT_DEFAULT = 17322;
    var pollTimer = null;
    var infoModalBound = false;

    /** Default UA matches run-host-scan.sh fallback (resource/user-agent.txt preferred). */
    var HOST_SCAN_UA =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0";

    /**
     * Short operator help for each host-scan tool (modal via ⓘ).
     * Command text is filled at open time from url + software (see commandForTool).
     */
    var TOOL_INFO = {
        nuclei: {
            title: "nuclei",
            sections: [
                {
                    h: "What it does",
                    p:
                        "ProjectDiscovery template scanner. Runs a quiet two-pass check against the host URL and writes structured findings."
                },
                {
                    h: "When shown",
                    p: "Always on expand (every public host with an HTTP status)."
                },
                {
                    h: "What Run does",
                    p:
                        "Launches via Discover. Prefer quieter defaults before louder tools such as Nikto or ffuf. Pass 2 runs only when runnable CVE templates exist for this software."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT under tools/host-scans/ for this host. Empty findings report “No vulnerabilities discovered.” Open TXT from the box when a run finishes."
                }
            ]
        },
        droopescan: {
            title: "droopescan",
            sections: [
                {
                    h: "What it does",
                    p:
                        "CMS enumeration (plugins, themes, and related checks) for supported products such as Drupal, WordPress, Joomla, Moodle, and Silverstripe."
                },
                {
                    h: "When shown",
                    p:
                        "When the software filter is a supported CMS, or when the row’s Title/Technologies text looks like that CMS (e.g. contains “Drupal”)."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs droopescan against the host URL with the inferred or filtered CMS plugin."
                },
                {
                    h: "Outputs",
                    p: "TXT (and related artifacts) under tools/host-scans/ for this host."
                }
            ]
        },
        wpscan: {
            title: "wpscan",
            sections: [
                {
                    h: "What it does",
                    p:
                        "WordPress-focused scanner: core/plugin/theme enumeration and known-issue checks for WP targets."
                },
                {
                    h: "When shown",
                    p:
                        "When the software filter is WordPress, or when the row’s Title/Technologies text looks like WordPress."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs WPScan against the host URL. Optional free API token: export WPSCAN_API_TOKEN=… for richer vuln matching."
                },
                {
                    h: "Outputs",
                    p: "TXT under tools/host-scans/ for this host."
                }
            ]
        },
        nikto: {
            title: "nikto",
            sections: [
                {
                    h: "What it does",
                    p:
                        "Classic web server checker for misconfigurations, default files, and common issues. Louder than nuclei."
                },
                {
                    h: "When shown",
                    p: "Always on expand."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs Nikto non-interactively with Discover’s hardened defaults (HTTP pre-check, maxtime 15m, hard stop 16m, SNI-friendly HTTPS)."
                },
                {
                    h: "Outputs",
                    p: "TXT and HTM when present. Open either button from the box after a run."
                }
            ]
        },
        ffuf: {
            title: "ffuf",
            sections: [
                {
                    h: "What it does",
                    p:
                        "Content discovery (directory/file fuzzing) with Discover’s quiet defaults—useful paths without a full aggressive wordlist blast."
                },
                {
                    h: "When shown",
                    p: "Always on expand."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs ffuf against the host URL. Louder than nuclei; use after quieter checks when appropriate."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT of findings plus a URL control that opens each hit in Firefox when available."
                }
            ]
        }
    };

    function shellQuote(s) {
        return "'" + String(s || "").replace(/'/g, "'\\''") + "'";
    }

    /** Nuclei pass-1 extra flags (mirrors run-host-scan.sh f_nuclei_args). */
    function nucleiPass1Extra(software) {
        var softLc = (software || "").toLowerCase();
        if (softLc.indexOf("drupal") === 0) {
            return "-tags drupal -c 5 -rl 25";
        }
        if (
            softLc.indexOf("wordpress") === 0 ||
            softLc.indexOf("wp") === 0 ||
            (softLc.indexOf("jquery") === 0 && softLc.indexOf("wordpress") >= 0)
        ) {
            return "-tags wordpress -c 5 -rl 25";
        }
        if (softLc.indexOf("joomla") === 0) {
            return "-tags joomla -c 5 -rl 25";
        }
        if (softLc.indexOf("grafana") === 0) {
            return "-tags grafana -c 5 -rl 25";
        }
        if (softLc.indexOf("apache") === 0) {
            return "-tags apache -c 5 -rl 25";
        }
        if (softLc.indexOf("nginx") === 0) {
            return "-tags nginx -c 5 -rl 25";
        }
        return "-tags tech -c 5 -rl 20";
    }

    /**
     * Command line(s) Discover actually runs (misc/run-host-scan.sh).
     * Uses this host URL and software filter/fingerprint when available.
     */
    function commandForTool(tool, url, software) {
        var u = (url || "").trim() || "https://target.example";
        var soft = (software || "").trim();
        var ua = HOST_SCAN_UA;
        var cms;
        var ffufUrl;
        var sslFlag;

        if (tool === "nuclei") {
            return (
                "nuclei -u " +
                shellQuote(u) +
                " -H " +
                shellQuote("User-Agent: " + ua) +
                " " +
                nucleiPass1Extra(soft) +
                " -silent -nc -duc -o nuclei.txt\n" +
                "# Pass 2 (when runnable CVE/KEV templates exist for this software):\n" +
                "nuclei -u " +
                shellQuote(u) +
                " -H " +
                shellQuote("User-Agent: " + ua) +
                " -id <cve-template-ids> -c 5 -rl 25 -timeout 15 -retries 1 -silent -nc -duc -o nuclei-pass2.txt"
            );
        }
        if (tool === "droopescan") {
            cms = droopescanCms(soft) || "drupal";
            return (
                "droopescan scan " +
                cms +
                " -u " +
                shellQuote(u) +
                " -e a -t 4 -o standard"
            );
        }
        if (tool === "wpscan") {
            return (
                "wpscan --url " +
                shellQuote(u) +
                " --random-user-agent --user-agent " +
                shellQuote(ua) +
                " --disable-tls-checks --plugins-detection passive" +
                " --enumerate vp,vt,tt,cb,dbe,u --format cli-no-colour --no-banner"
            );
        }
        if (tool === "nikto") {
            sslFlag = /^https:\/\//i.test(u) ? " -ssl" : "";
            return (
                "timeout --foreground --signal=TERM --kill-after=45s 16m nikto" +
                " -config <run-dir>/nikto.conf -host " +
                shellQuote(u) +
                sslFlag +
                " -useragent " +
                shellQuote(ua) +
                " -nointeractive -nocheck -maxtime 15m" +
                " -Format htm -output <run-dir>/nikto.htm"
            );
        }
        if (tool === "ffuf") {
            ffufUrl = u.indexOf("FUZZ") >= 0 ? u : u.replace(/\/?$/, "") + "/FUZZ";
            return (
                "ffuf -u " +
                shellQuote(ffufUrl) +
                " -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" +
                " -t 8 -rate 20 -H " +
                shellQuote("User-Agent: " + ua) +
                " -of json -o ffuf.json" +
                " -fc 301,302,307,400,401,403,404,405,429 -noninteractive"
            );
        }
        return "";
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function attrEscape(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/</g, "&lt;");
    }

    function querySoftware() {
        try {
            return (new URLSearchParams(window.location.search || "").get("software") || "").trim();
        } catch (e) {
            return "";
        }
    }

    function queryCve() {
        try {
            return (new URLSearchParams(window.location.search || "").get("cve") || "").trim();
        } catch (e) {
            return "";
        }
    }

    /** Normalize software filter to product base (e.g. Drupal:7 → drupal). */
    function softwareBase(software) {
        var s = (software || "").toLowerCase().trim();
        if (!s) {
            return "";
        }
        s = s.split("[")[0];
        s = s.split(":")[0];
        s = s.replace(/\s+/g, "");
        return s;
    }

    /** Map software filter (e.g. Drupal:7) → droopescan CMS or null. */
    function droopescanCms(software) {
        var s = softwareBase(software);
        return s ? DROOPESCAN_CMS[s] || null : null;
    }

    /** True when software filter is WordPress (for wpscan). */
    function isWordpress(software) {
        var s = softwareBase(software);
        return s === "wordpress" || s === "wp";
    }

    /**
     * Infer software label from Subdomains row tech/title (unfiltered page).
     * Prefer explicit product names so run-host-scan CMS gates still work.
     */
    function softwareFromRow(row) {
        if (!row) {
            return "";
        }
        var techEl = row.querySelector(".inc-subdomain-techs");
        var titleEl = row.querySelector(".inc-subdomain-title");
        var tech =
            (techEl && (techEl.getAttribute("title") || techEl.textContent || "")) || "";
        var title = (titleEl && titleEl.textContent) || "";
        var blob = (tech + " " + title).toLowerCase();
        if (/\bwordpress\b/.test(blob) || /wp-login/.test(blob) || /— wordpress/.test(blob)) {
            return "WordPress";
        }
        if (/\bdrupal\b/.test(blob)) {
            return "Drupal";
        }
        if (/\bjoomla\b/.test(blob)) {
            return "Joomla";
        }
        if (/\bmoodle\b/.test(blob)) {
            return "Moodle";
        }
        if (/\bsilverstripe\b/.test(blob)) {
            return "Silverstripe";
        }
        return "";
    }

    /** Query software wins; else fingerprint from the host row. */
    function resolveSoftware(querySoftware, row) {
        if (querySoftware) {
            return querySoftware;
        }
        return softwareFromRow(row);
    }

    /** Tools for this expand panel (CMS tools when software matches). */
    function toolsForSoftware(software) {
        var tools = ["nuclei"];
        if (droopescanCms(software)) {
            tools.push("droopescan");
        }
        if (isWordpress(software)) {
            tools.push("wpscan");
        }
        tools.push("nikto", "ffuf");
        return tools;
    }

    function reportMode() {
        var meta = document.querySelector('meta[name="discover-report-mode"]');
        if (meta && meta.getAttribute("content")) {
            return meta.getAttribute("content");
        }
        return null;
    }

    function launchesAllowed(modeObj) {
        if (modeObj && typeof modeObj.launches === "boolean") {
            return modeObj.launches;
        }
        var m = (modeObj && modeObj.mode) || reportMode() || "operator";
        return String(m).toLowerCase() === "operator";
    }

    function hostFromRow(row) {
        var link = row.querySelector("a.inc-subdomain-host-link");
        if (link) {
            return {
                host: (link.textContent || "").trim(),
                url: link.getAttribute("href") || ""
            };
        }
        var cell = row.querySelector("td.inc-subdomain-host");
        if (!cell) {
            return null;
        }
        var host = (cell.textContent || "").trim();
        if (!host) {
            return null;
        }
        return { host: host, url: "https://" + host };
    }

    function statusPort() {
        return STATUS_PORT_DEFAULT;
    }

    /**
     * True only when this page is served by Discover statusd on localhost.
     * Manual file:// open never qualifies, even if statusd is still running.
     */
    function isDiscoverHostedPage() {
        var host = location.hostname;
        if (host !== "127.0.0.1" && host !== "localhost") {
            return false;
        }
        var port = location.port;
        if (!port) {
            return false;
        }
        return port === String(statusPort());
    }

    function statusdUrl(path) {
        if (isDiscoverHostedPage()) {
            return path;
        }
        return "http://127.0.0.1:" + statusPort() + path;
    }

    function fetchJson(url) {
        return fetch(url, { cache: "no-store" }).then(function (r) {
            if (!r.ok) {
                throw new Error("http " + r.status);
            }
            return r.json();
        });
    }

    function loadMode() {
        // Only when hosted by statusd; no file:// / report-mode.json fallback.
        if (!isDiscoverHostedPage()) {
            return Promise.resolve({ mode: "client", launches: false });
        }
        return fetchJson(statusdUrl("/mode")).catch(function () {
            return { mode: "client", launches: false };
        });
    }

    function loadStatus() {
        if (!isDiscoverHostedPage()) {
            return Promise.resolve({ running: false, hosts: {} });
        }
        return fetchJson(statusdUrl("/status")).catch(function () {
            return { running: false, hosts: {} };
        });
    }

    function encodeQuery(obj) {
        return Object.keys(obj)
            .filter(function (k) {
                return obj[k] != null && obj[k] !== "";
            })
            .map(function (k) {
                return encodeURIComponent(k) + "=" + encodeURIComponent(obj[k]);
            })
            .join("&");
    }

    function launchHref(tool, url, software) {
        return "discover-scan://" + tool + "?" + encodeQuery({ url: url, software: software });
    }

    function toolState(status, host, tool) {
        var hosts = (status && status.hosts) || {};
        var h = hosts[host] || {};
        return h[tool] || null;
    }

    /** Build TXT (+ HTM for nikto) buttons for a finished tool run. */
    function outputButtonsHtml(tool, st) {
        if (!st || !(st.output || st.output_rel)) {
            return "";
        }
        var rel = st.output_rel || st.output;
        if (String(rel).indexOf("../") !== 0) {
            rel = "../" + String(rel).replace(/^\//, "");
        }
        var safe = String(rel).replace(/"/g, "&quot;");
        var html =
            '<span class="inc-host-scan-btn-row">' +
            '<a class="inc-host-scan-out" href="' +
            safe +
            '" target="_blank" rel="noopener">txt</a>';
        if (tool === "nikto") {
            // nikto.htm lives next to output.txt in the run directory
            var htmRel = String(rel).replace(/[^/]+$/, "nikto.htm");
            html +=
                '<a class="inc-host-scan-out" href="' +
                htmRel.replace(/"/g, "&quot;") +
                '" target="_blank" rel="noopener">htm</a>';
        }
        if (tool === "ffuf") {
            // Absolute path via discover-ffuf: → open-ffuf-tabs.sh (Firefox CLI)
            var jsonRel = String(rel).replace(/[^/]+$/, "ffuf.json");
            var absJson = ffufJsonAbsolutePath(jsonRel);
            if (absJson) {
                html +=
                    '<a class="inc-host-scan-out" href="discover-ffuf:' +
                    encodeURI(absJson).replace(/"/g, "&quot;") +
                    '" title="Open each ffuf finding URL in Firefox">url</a>';
            }
        }
        html += "</span>";
        return html;
    }

    /** Best-effort absolute path for ffuf.json (for discover-ffuf: handler). */
    function ffufJsonAbsolutePath(relFromPages) {
        try {
            var a = document.createElement("a");
            a.href = relFromPages;
            // file:// or http(s):// to the report; handler wants filesystem path when possible
            var href = a.href || "";
            if (href.indexOf("file://") === 0) {
                return decodeURIComponent(href.replace(/^file:\/\//, ""));
            }
            // Served via http: pass report-relative tools/... path (handler resolves via current-report)
            var m = String(relFromPages).match(/(tools\/host-scans\/.+)/);
            if (m) {
                return m[1];
            }
            return relFromPages.replace(/^\.\.\//, "");
        } catch (e) {
            return "";
        }
    }

    function lastRunHtml(tool, st) {
        if (st && st.status === "running") {
            return "Running…";
        }
        if (st && (st.finished_display || st.finished)) {
            var last = st.finished_display || st.finished;
            var btns = outputButtonsHtml(tool, st);
            if (btns) {
                // Timestamp in its own span; buttons follow (CSS flex aligns them).
                return (
                    '<span class="inc-host-scan-last-time">' +
                    last +
                    "</span>" +
                    btns
                );
            }
            return '<span class="inc-host-scan-last-time">' + last + "</span>";
        }
        return "Not run";
    }

    function ensureInfoModal() {
        var el = document.getElementById("inc-host-scan-info-modal");
        if (el) {
            return el;
        }
        el = document.createElement("div");
        el.id = "inc-host-scan-info-modal";
        el.className = "inc-host-scan-info-modal";
        el.setAttribute("hidden", "hidden");
        el.setAttribute("role", "dialog");
        el.setAttribute("aria-modal", "true");
        el.setAttribute("aria-labelledby", "inc-host-scan-info-title");
        el.innerHTML =
            '<div class="inc-host-scan-info-backdrop" data-inc-host-scan-info-close="1"></div>' +
            '<div class="inc-host-scan-info-dialog">' +
            '<div class="inc-host-scan-info-header">' +
            '<h2 id="inc-host-scan-info-title" class="inc-host-scan-info-title"></h2>' +
            '<button type="button" class="inc-host-scan-info-close" data-inc-host-scan-info-close="1" aria-label="Close">×</button>' +
            "</div>" +
            '<div class="inc-host-scan-info-body"></div>' +
            "</div>";
        document.body.appendChild(el);
        return el;
    }

    function closeToolInfo() {
        var el = document.getElementById("inc-host-scan-info-modal");
        if (!el) {
            return;
        }
        el.setAttribute("hidden", "hidden");
        el.classList.remove("is-open");
        el.classList.remove(
            "inc-host-scan-info-modal--nuclei",
            "inc-host-scan-info-modal--nikto",
            "inc-host-scan-info-modal--ffuf"
        );
    }

    function openToolInfo(tool, url, software) {
        var meta = TOOL_INFO[tool];
        if (!meta) {
            return;
        }
        var el = ensureInfoModal();
        var titleEl = el.querySelector(".inc-host-scan-info-title");
        var bodyEl = el.querySelector(".inc-host-scan-info-body");
        var i;
        var sec;
        var html = "";
        var cmd = commandForTool(tool, url, software);

        if (titleEl) {
            titleEl.textContent = meta.title;
        }
        // Longer command blocks need more vertical room (less scrolling).
        el.classList.remove(
            "inc-host-scan-info-modal--nuclei",
            "inc-host-scan-info-modal--nikto",
            "inc-host-scan-info-modal--ffuf"
        );
        if (tool === "nuclei") {
            el.classList.add("inc-host-scan-info-modal--nuclei");
        } else if (tool === "nikto") {
            el.classList.add("inc-host-scan-info-modal--nikto");
        } else if (tool === "ffuf") {
            el.classList.add("inc-host-scan-info-modal--ffuf");
        }
        if (bodyEl) {
            for (i = 0; i < meta.sections.length; i++) {
                sec = meta.sections[i];
                // Insert Command immediately above Outputs.
                if (sec.h === "Outputs" && cmd) {
                    html +=
                        '<section class="inc-host-scan-info-section">' +
                        "<h3>Command</h3>" +
                        '<pre class="inc-host-scan-info-cmd">' +
                        escapeHtml(cmd) +
                        "</pre>" +
                        '<div class="inc-host-scan-info-spacer" aria-hidden="true"></div>' +
                        '<p class="inc-host-scan-info-ua-note">' +
                        "User-Agent: Discover’s default is the Edge (Chromium) string from " +
                        "resource/user-agent.txt " +
                        "(updated periodically — no longer an older browser UA). " +
                        "The command above shows the current fallback string if that file is empty." +
                        "</p>" +
                        "</section>";
                }
                html +=
                    '<section class="inc-host-scan-info-section">' +
                    "<h3>" +
                    escapeHtml(sec.h) +
                    "</h3>" +
                    "<p>" +
                    escapeHtml(sec.p) +
                    "</p>" +
                    "</section>";
            }
            bodyEl.innerHTML = html;
        }
        el.removeAttribute("hidden");
        el.classList.add("is-open");
        var closeBtn = el.querySelector(".inc-host-scan-info-close");
        if (closeBtn && typeof closeBtn.focus === "function") {
            try {
                closeBtn.focus();
            } catch (e) {
                /* ignore */
            }
        }
    }

    function bindInfoModalOnce() {
        if (infoModalBound) {
            return;
        }
        infoModalBound = true;

        // Capture phase so modal dismiss never falls through to the host-scan
        // chevron/row underneath (which would collapse the tool bar).
        document.addEventListener(
            "click",
            function (ev) {
                var t = ev.target;
                if (!t || !t.closest) {
                    return;
                }
                var btn = t.closest(".inc-host-scan-info-btn");
                if (btn) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    openToolInfo(
                        btn.getAttribute("data-tool") || "",
                        btn.getAttribute("data-url") || "",
                        btn.getAttribute("data-software") || ""
                    );
                    return;
                }
                if (t.closest("[data-inc-host-scan-info-close]")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    // Defer hide so this click cannot hit the chevron under the overlay.
                    window.setTimeout(function () {
                        closeToolInfo();
                    }, 0);
                    return;
                }
                if (t.closest("#inc-host-scan-info-modal")) {
                    // Clicks inside the dialog (scroll, select text) stay local.
                    ev.stopPropagation();
                }
            },
            true
        );

        document.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape" || ev.keyCode === 27) {
                var el = document.getElementById("inc-host-scan-info-modal");
                if (el && !el.hasAttribute("hidden")) {
                    ev.preventDefault();
                    ev.stopPropagation();
                    closeToolInfo();
                }
            }
        });
    }

    function renderPanel(row, info, software, canLaunch, status) {
        var safeHost = String(info.host).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        var existing = row.parentNode.querySelector(
            'tr.inc-host-scan-panel-row[data-for-host="' + safeHost + '"]'
        );
        if (existing) {
            existing.parentNode.removeChild(existing);
            row.classList.remove("inc-host-scan-open");
            return;
        }

        // Close any other open panel
        row.parentNode.querySelectorAll("tr.inc-host-scan-panel-row").forEach(function (tr) {
            tr.parentNode.removeChild(tr);
        });
        row.parentNode.querySelectorAll("tr.inc-host-scan-open").forEach(function (tr) {
            tr.classList.remove("inc-host-scan-open");
        });

        row.classList.add("inc-host-scan-open");
        var panelRow = document.createElement("tr");
        panelRow.className = "inc-host-scan-panel-row";
        panelRow.setAttribute("data-for-host", info.host);
        var td = document.createElement("td");
        td.colSpan = row.cells.length;

        var running = !!(status && status.running);
        var html = '<div class="inc-host-scan-panel">';
        if (!canLaunch) {
            html +=
                '<div class="inc-host-scan-panel-meta"><div class="inc-audit-note">Launches disabled (client/defender package or Discover session inactive).</div></div>';
        }
        html += '<div class="inc-host-scan-tools">';

        var panelTools = toolsForSoftware(software);
        panelTools.forEach(function (tool) {
            var st = toolState(status, info.host, tool);
            var launchHtml;
            var label =
                tool === "droopescan" ? "droopescan" : tool === "wpscan" ? "wpscan" : tool;
            if (canLaunch && !running) {
                launchHtml =
                    '<a class="inc-host-scan-launch" href="' +
                    launchHref(tool, info.url, software).replace(/"/g, "&quot;") +
                    '">Run</a>';
            } else {
                launchHtml = '<span class="inc-host-scan-launch-disabled">Run</span>';
            }

            html += '<div class="inc-host-scan-tool" data-tool="' + tool + '">';
            html +=
                '<button type="button" class="inc-host-scan-info-btn" data-tool="' +
                tool +
                '" data-url="' +
                attrEscape(info.url) +
                '" data-software="' +
                attrEscape(software || "") +
                '" title="About ' +
                label +
                '" aria-label="About ' +
                label +
                '">ⓘ</button>';
            html += '<div class="inc-host-scan-tool-head">';
            html += '<span class="inc-host-scan-tool-name">' + label + "</span>";
            html += launchHtml;
            html += "</div>";
            html +=
                '<span class="inc-host-scan-last">' +
                lastRunHtml(tool, st) +
                "</span></div>";
        });

        html += "</div></div>";
        td.innerHTML = html;

        panelRow.appendChild(td);
        if (row.nextSibling) {
            row.parentNode.insertBefore(panelRow, row.nextSibling);
        } else {
            row.parentNode.appendChild(panelRow);
        }
        bindInfoModalOnce();
    }

    function addToggles(software, canLaunch) {
        var publicTable = document.querySelector(
            ".inc-subdomains-public table.inc-data-table"
        );
        if (!publicTable || !publicTable.tBodies[0]) {
            return;
        }

        // Append toggle as LAST column so Category/IP/Photo/Status/Web Server
        // keep the same nth-child indices (and widths) as the unfiltered page.
        var headRow = publicTable.tHead && publicTable.tHead.rows[0];
        if (headRow && !headRow.querySelector(".inc-host-scan-toggle-h")) {
            var th = document.createElement("th");
            th.className = "inc-host-scan-toggle-h";
            th.scope = "col";
            th.title = "Host scans";
            th.textContent = "";
            headRow.appendChild(th);
        }

        Array.prototype.forEach.call(publicTable.tBodies[0].rows, function (row) {
            if (row.classList.contains("inc-host-scan-panel-row")) {
                return;
            }
            if (row.classList.contains("inc-subdomains-filter-hide")) {
                return;
            }
            if (row.querySelector("td.inc-host-scan-toggle")) {
                return;
            }
            var info = hostFromRow(row);
            if (!info || !info.url) {
                return;
            }
            // Only hosts with a real HTTP status get scan UI
            var hasStatus = false;
            Array.prototype.forEach.call(row.querySelectorAll("td.inc-col-center"), function (td) {
                if (/^\d{3}$/.test((td.textContent || "").trim())) {
                    hasStatus = true;
                }
            });
            if (!hasStatus && !row.querySelector("a.inc-subdomain-host-link")) {
                return;
            }

            var td = document.createElement("td");
            td.className = "inc-host-scan-toggle";
            td.title = "Host scans";
            td.textContent = "▸";
            td.addEventListener("click", function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                Promise.all([loadMode(), loadStatus()]).then(function (pair) {
                    var mode = pair[0];
                    var status = pair[1];
                    var allow = canLaunch && launchesAllowed(mode);
                    // Per-row software: query filter when set, else tech/title fingerprint.
                    var rowSoftware = resolveSoftware(software, row);
                    if (row.classList.contains("inc-host-scan-open")) {
                        td.textContent = "▸";
                    } else {
                        td.textContent = "▾";
                    }
                    renderPanel(row, info, rowSoftware, allow, status);
                });
            });
            row.appendChild(td);
        });
    }

    function startPolling() {
        if (pollTimer) {
            return;
        }
        pollTimer = setInterval(function () {
            var open = document.querySelector("tr.inc-host-scan-open");
            if (!open) {
                return;
            }
            var host = null;
            var panel = document.querySelector("tr.inc-host-scan-panel-row");
            if (panel) {
                host = panel.getAttribute("data-for-host");
            }
            if (!host) {
                return;
            }
            loadStatus().then(function (status) {
                // Refresh panel content by re-click simulation: update last-run labels
                panel.querySelectorAll(".inc-host-scan-tool").forEach(function (el) {
                    var tool = el.getAttribute("data-tool");
                    var st = toolState(status, host, tool);
                    var lastEl = el.querySelector(".inc-host-scan-last");
                    if (!lastEl) {
                        return;
                    }
                    lastEl.innerHTML = lastRunHtml(tool, st);
                });
                var running = !!(status && status.running);
                panel.querySelectorAll("a.inc-host-scan-launch").forEach(function (a) {
                    if (running) {
                        a.classList.add("is-disabled");
                    } else {
                        a.classList.remove("is-disabled");
                    }
                });
            });
        }, 2000);
    }

    function init() {
        // Chevrons only on http://127.0.0.1:<statusd>/… (Import opens this URL).
        // Manual file:// open of the same tree: never show host-scan UI.
        if (!isDiscoverHostedPage()) {
            return;
        }
        var software = querySoftware();

        loadMode().then(function (mode) {
            if (!launchesAllowed(mode)) {
                return;
            }
            addToggles(software || "", true);
            startPolling();
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
