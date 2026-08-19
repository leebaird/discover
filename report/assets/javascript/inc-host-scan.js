/**
 * Planning by Lee Baird (@discoverscripts)
 * Coded by Grok (xAI)
 *
 * Subdomains expand host row → launch host-scan tools (operator mode only).
 * Chevrons only when the page is served by Discover statusd
 * (http://127.0.0.1:17322/… from Open report / Active) — not file:// manual open.
 * One tool at a time; live status via same origin /mode|/status when hosted.
 * Software: ?software= query wins, else fingerprint row tech/title/webserver/host.
 * nuclei is shown only when a product is known; robots/nikto/feroxbuster/ffuf always on expand.
 * droopescan / wpscan gate on CMS software (query or fingerprint).
 * Tool boxes: Unicode ⓘ opens a short modal (what / when / Run / outputs).
 */
(function () {
    /** Host-scan expand panel logic. */
    // droopescan CMS label → plugin name (must match run-host-scan.sh).
    // WordPress is wpscan-only — do not offer droopescan for WP (poor results).
    var DROOPESCAN_CMS = {
        drupal: "drupal",
        joomla: "joomla",
        moodle: "moodle",
        silverstripe: "silverstripe",
        ss: "silverstripe"
    };
    /**
     * Products we fingerprint from row tech (priority order: first match wins).
     * label = software string passed to run-host-scan (optionally + :version).
     */
    var ROW_PRODUCT_PRIORITY = [
        { id: "wordpress", label: "WordPress" },
        { id: "drupal", label: "Drupal" },
        { id: "joomla", label: "Joomla" },
        { id: "moodle", label: "Moodle" },
        { id: "silverstripe", label: "Silverstripe" },
        { id: "kibana", label: "Kibana" },
        { id: "grafana", label: "Grafana" },
        { id: "elasticsearch", label: "Elasticsearch" },
        { id: "jenkins", label: "Jenkins" },
        { id: "tomcat", label: "Tomcat" },
        { id: "iis", label: "IIS" },
        { id: "nginx", label: "nginx" },
        { id: "apache", label: "Apache" },
        { id: "php", label: "PHP" },
        { id: "nodejs", label: "Node.js" }
    ];
    var STATUS_PORT_DEFAULT = 17322;
    var pollTimer = null;
    var infoModalBound = false;
    var viewTimezone = "UTC";

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
                    p:
                        "Only when a product is known: Active software filter (?software=) or fingerprint from the row Technologies / title / web server (for example Kibana:9.4.2). Hidden when no product is known so you never get a blind tech-only pass."
                },
                {
                    h: "What Run does",
                    p:
                        "Launches via Discover with product tags for Pass 1. Prefer quieter defaults before louder tools such as Nikto or ffuf. Pass 2 runs only when runnable CVE templates exist for this software."
                },
                {
                    h: "Safety check",
                    p:
                        "Before nuclei starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the scan is skipped and the box shows Unreachable (txt note only)."
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
                        "CMS enumeration (plugins, themes, and related checks) for Drupal, Joomla, Moodle, and Silverstripe. WordPress uses wpscan instead."
                },
                {
                    h: "When shown",
                    p:
                        "When the software filter is a supported CMS (not WordPress), or when the row’s Title/Technologies text looks like that CMS (e.g. contains “Drupal”)."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs droopescan against the host URL with the inferred or filtered CMS plugin."
                },
                {
                    h: "Safety check",
                    p:
                        "Before droopescan starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the scan is skipped and the box shows Unreachable (txt note only)."
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
                        "Runs WPScan against the host URL. Optional free API token (richer vuln DB matching): set WPSCAN_API_TOKEN in ~/.discover/api-keys (preferred), or export WPSCAN_API_TOKEN. Get a free token at https://wpscan.com/api. Without a token the scan still runs with local enumeration only."
                },
                {
                    h: "Safety check",
                    p:
                        "Before WPScan starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the scan is skipped and the box shows Unreachable (txt note only)."
                },
                {
                    h: "Outputs",
                    p: "TXT under tools/host-scans/ for this host."
                }
            ]
        },
        robots: {
            title: "robots",
            sections: [
                {
                    h: "What it does",
                    p:
                        "Fetches /robots.txt and lists Disallow directories (same idea as Discover menu → Open multiple tabs in Firefox → Directories in robots.txt)."
                },
                {
                    h: "When shown",
                    p: "Always on expand."
                },
                {
                    h: "What Run does",
                    p:
                        "One curl GET of robots.txt for this host. Parses Disallow paths into full URLs. Does not open Firefox during Run — use the green htm button after it finishes."
                },
                {
                    h: "Safety check",
                    p:
                        "Before the fetch, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the run is skipped and the box shows Unreachable (txt note only)."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT is the raw robots.txt body. HTM opens each Disallow directory in Firefox (desktop handler; not shown when there are no Disallow paths or on Unreachable). Tabs open one at a time with about 1.5s between them, plus up to 40% jitter for OPSEC (cap 40 tabs)."
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
                        "Runs Nikto non-interactively with Discover hardened defaults (request timeout 5s, FAILURES=8, maxtime 10m, hard stop 11m, SNI-friendly HTTPS)."
                },
                {
                    h: "Safety check",
                    p:
                        "Before Nikto starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, Nikto is not launched. The box shows Unreachable and only the txt note (no HTM)."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT after every attempt. HTM only when Nikto actually ran and wrote a report (not on Unreachable)."
                }
            ]
        },
        ffuf: {
            title: "ffuf",
            sections: [
                {
                    h: "What it does",
                    p:
                        "Content discovery (directory/file fuzzing) with Discover quiet defaults: useful paths without a full aggressive wordlist blast."
                },
                {
                    h: "When shown",
                    p: "Always on expand."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs ffuf against the host URL with a software-aware SecLists wordlist when a product is known (for example WordPress, Grafana, IIS, Apache); otherwise SecLists common.txt (or quiet fallbacks). Request timeout 5s, maxtime 10m, stop on spurious errors, hard stop 11m. Louder than nuclei; use after quieter checks when appropriate."
                },
                {
                    h: "Safety check",
                    p:
                        "Before ffuf starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the scan is skipped and the box shows Unreachable (txt note only)."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT of findings plus a URL control that opens each hit in Firefox when the run has at least one finding URL. Tabs open one at a time with about 1.5s between them, plus up to 40% jitter for OPSEC (cap 40 tabs)."
                }
            ]
        },
        feroxbuster: {
            title: "feroxbuster",
            sections: [
                {
                    h: "What it does",
                    p:
                        "Content discovery (same idea as ffuf) with Discover quiet defaults: no recursion, no link crawl, software-aware SecLists wordlist."
                },
                {
                    h: "When shown",
                    p: "Always on expand (before ffuf)."
                },
                {
                    h: "What Run does",
                    p:
                        "Runs feroxbuster against the host URL with the same wordlist picker as ffuf. Threads 10, 20 req/s, request timeout 5s, time-limit 10m, auto-bail, hard stop 11m."
                },
                {
                    h: "Safety check",
                    p:
                        "Before feroxbuster starts, Discover runs a curl HTTP/1.1 GET (15s). If the host does not answer HTTP, the scan is skipped and the box shows Unreachable (txt note only)."
                },
                {
                    h: "Outputs",
                    p:
                        "TXT of findings plus a URL control that opens each hit in Firefox when the run has at least one finding URL. Tabs open one at a time with about 1.5s between them, plus up to 40% jitter for OPSEC (cap 40 tabs)."
                }
            ]
        }
    };

    function shellQuote(s) {
        return "'" + String(s || "").replace(/'/g, "'\\''") + "'";
    }

    /** Nuclei pass-1 extra flags (mirrors run-host-scan.sh f_nuclei_args). */
    function nucleiPass1Extra(software) {
        var softLc = (software || "").toLowerCase().replace(/\s+/g, "");
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
        if (softLc.indexOf("moodle") === 0) {
            return "-tags moodle -c 5 -rl 25";
        }
        if (softLc.indexOf("kibana") === 0) {
            return "-tags kibana -c 5 -rl 25";
        }
        if (softLc.indexOf("grafana") === 0) {
            return "-tags grafana -c 5 -rl 25";
        }
        if (softLc.indexOf("elasticsearch") === 0) {
            return "-tags elasticsearch -c 5 -rl 25";
        }
        if (softLc.indexOf("jenkins") === 0) {
            return "-tags jenkins -c 5 -rl 25";
        }
        if (softLc.indexOf("tomcat") === 0) {
            return "-tags tomcat -c 5 -rl 25";
        }
        if (softLc.indexOf("iis") === 0 || softLc.indexOf("microsoft-iis") === 0) {
            return "-tags iis -c 5 -rl 25";
        }
        if (softLc.indexOf("apache") === 0) {
            return "-tags apache -c 5 -rl 25";
        }
        if (softLc.indexOf("nginx") === 0) {
            return "-tags nginx -c 5 -rl 25";
        }
        if (softLc.indexOf("php") === 0) {
            return "-tags php -c 5 -rl 25";
        }
        if (softLc.indexOf("node") === 0) {
            return "-tags nodejs -c 5 -rl 25";
        }
        // Known product without a dedicated tag map: still product-scoped via Pass 2 when cache allows.
        return "-tags tech -c 5 -rl 20";
    }

    /**
     * Approximate SecLists path for the help modal (mirrors f_ffuf_wordlist).
     * Runtime selection is in misc/run-host-scan.sh (may use alt SecLists root).
     */
    function ffufWordlistForSoftware(software) {
        var base =
            "/usr/share/wordlists/seclists/Discovery/Web-Content";
        var soft = String(software || "")
            .trim()
            .toLowerCase();
        var i = soft.indexOf(":");
        if (i >= 0) {
            soft = soft.slice(0, i);
        }
        i = soft.indexOf("[");
        if (i >= 0) {
            soft = soft.slice(0, i);
        }
        soft = soft.replace(/\s+/g, " ").trim();
        var rel = "";
        if (soft === "wordpress" || soft === "wp") {
            rel = "CMS/wordpress.fuzz.txt";
        } else if (
            soft === "kibana" ||
            soft === "elasticsearch" ||
            soft === "elastic"
        ) {
            rel = "Service-Specific/Elasticsearch-Kibana.txt";
        } else if (soft === "grafana") {
            rel = "Service-Specific/Grafana.txt";
        } else if (soft === "jenkins") {
            rel = "Service-Specific/Jenkins-Hudson.txt";
        } else if (soft === "gitlab" || soft === "gitea" || soft === "gogs") {
            rel = "Service-Specific/GitLab.txt";
        } else if (soft === "keycloak") {
            rel = "Service-Specific/Keycloak-Identity-Access-Management.txt";
        } else if (soft === "tomcat") {
            rel = "Web-Servers/Apache-Tomcat.txt";
        } else if (soft === "iis") {
            rel = "Web-Servers/IIS.txt";
        } else if (soft === "nginx") {
            rel = "Web-Servers/nginx.txt";
        } else if (soft === "apache") {
            rel = "Web-Servers/Apache.txt";
        } else if (soft === "php") {
            rel = "Programming-Language-Specific/PHP.fuzz.txt";
        } else if (
            soft === "spring" ||
            soft.indexOf("spring") === 0 ||
            soft === "java"
        ) {
            rel = "Programming-Language-Specific/Java-Spring-Boot.txt";
        } else if (soft === "sharepoint") {
            rel = "CMS/Sharepoint.txt";
        } else if (soft === "confluence") {
            rel = "Service-Specific/confluence-administration.txt";
        } else if (soft === "weblogic") {
            rel = "Service-Specific/Oracle-WebLogic.txt";
        }
        if (rel) {
            return base + "/" + rel;
        }
        return base + "/common.txt";
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
        if (tool === "robots") {
            return (
                "curl -kLsS --http1.1 --connect-timeout 8 --max-time 15 -A " +
                shellQuote(ua) +
                " -o robots.txt " +
                shellQuote(u.replace(/\/?$/, "") + "/robots.txt")
            );
        }
        if (tool === "nikto") {
            sslFlag = /^https:\/\//i.test(u) ? " -ssl" : "";
            return (
                "timeout --foreground --signal=TERM --kill-after=45s 11m nikto" +
                " -config <run-dir>/nikto.conf -host " +
                shellQuote(u) +
                sslFlag +
                " -useragent " +
                shellQuote(ua) +
                " -nointeractive -nocheck -timeout 5 -maxtime 10m" +
                " -Format htm -output <run-dir>/nikto.htm"
            );
        }
        if (tool === "ffuf") {
            ffufUrl = u.indexOf("FUZZ") >= 0 ? u : u.replace(/\/?$/, "") + "/FUZZ";
            return (
                "ffuf -u " +
                shellQuote(ffufUrl) +
                " -w " +
                shellQuote(ffufWordlistForSoftware(software)) +
                " -t 10 -rate 20 -timeout 5 -maxtime 600 -se -H " +
                shellQuote("User-Agent: " + ua) +
                " -of json -o ffuf.json" +
                " -fc 301,302,307,400,403,404,405,429 -noninteractive"
            );
        }
        if (tool === "feroxbuster") {
            return (
                "timeout --foreground --signal=TERM --kill-after=15s 11m feroxbuster" +
                " -u " +
                shellQuote(u) +
                " -w " +
                shellQuote(ffufWordlistForSoftware(software)) +
                " -a " +
                shellQuote(ua) +
                " -t 10 --rate-limit 20 -T 5 --time-limit 10m" +
                " --auto-bail -n --dont-extract-links -k" +
                " -C 301,302,307,400,403,404,405,429" +
                " -q --json -o ferox.json --no-state"
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

    /** True when token suffix looks like a version (e.g. 9.4.2, v1.2). */
    function isVersionish(v) {
        return !!(v && /^v?\d/i.test(String(v).trim()));
    }

    /**
     * Map a tech token name (lower, no spaces) to a ROW_PRODUCT_PRIORITY id or "".
     */
    function productIdFromName(nameLc) {
        var n = String(nameLc || "")
            .toLowerCase()
            .replace(/\s+/g, "")
            .replace(/_/g, "-");
        if (!n || n === "-" || n === "hsts" || n === "bootstrap" || n === "html5") {
            return "";
        }
        if (n === "wordpress" || n === "wp" || n.indexOf("wordpress") === 0) {
            return "wordpress";
        }
        if (n === "drupal" || n.indexOf("drupal") === 0) {
            return "drupal";
        }
        if (n === "joomla" || n.indexOf("joomla") === 0) {
            return "joomla";
        }
        if (n === "moodle" || n.indexOf("moodle") === 0) {
            return "moodle";
        }
        if (n === "silverstripe" || n === "ss") {
            return "silverstripe";
        }
        if (n === "kibana" || n.indexOf("kibana") === 0) {
            return "kibana";
        }
        if (n === "grafana" || n.indexOf("grafana") === 0) {
            return "grafana";
        }
        if (n === "elasticsearch" || n.indexOf("elasticsearch") === 0) {
            return "elasticsearch";
        }
        if (n === "jenkins" || n.indexOf("jenkins") === 0) {
            return "jenkins";
        }
        if (n.indexOf("tomcat") >= 0) {
            return "tomcat";
        }
        if (n === "iis" || n === "microsoft-iis" || n.indexOf("microsoft-iis") === 0) {
            return "iis";
        }
        if (n === "nginx" || n.indexOf("nginx") === 0) {
            return "nginx";
        }
        if (n === "apache" || n.indexOf("apachehttp") === 0 || n.indexOf("apache/") === 0) {
            return "apache";
        }
        if (n === "php" || n.indexOf("php/") === 0 || n.indexOf("php:") === 0) {
            return "php";
        }
        if (n === "node.js" || n === "nodejs" || n === "node") {
            return "nodejs";
        }
        return "";
    }

    /**
     * Infer software label from Subdomains row (tech tokens preferred, with version).
     * Fallback: title, webserver cell, then hostname label (e.g. kibana.oke-…).
     */
    function softwareFromRow(row) {
        if (!row) {
            return "";
        }
        var techEl = row.querySelector(".inc-subdomain-techs");
        var titleEl = row.querySelector(".inc-subdomain-title");
        var webEl = row.querySelector(".inc-subdomain-webserver");
        var hostEl = row.querySelector(".inc-subdomain-host-link");
        var tech =
            (techEl && (techEl.getAttribute("title") || techEl.textContent || "")) || "";
        var title = ((titleEl && titleEl.textContent) || "").trim();
        var web = ((webEl && webEl.textContent) || "").trim();
        var host = ((hostEl && hostEl.textContent) || "").trim();

        // id -> best version seen (prefer versioned token)
        var found = {};
        var tokens = String(tech)
            .split(",")
            .map(function (t) {
                return t.trim();
            })
            .filter(Boolean);
        var i;
        var token;
        var colon;
        var namePart;
        var verPart;
        var pid;
        for (i = 0; i < tokens.length; i++) {
            token = tokens[i];
            colon = token.indexOf(":");
            if (colon > 0) {
                namePart = token.slice(0, colon).trim();
                verPart = token.slice(colon + 1).trim();
            } else {
                namePart = token;
                verPart = "";
            }
            pid = productIdFromName(namePart);
            if (!pid) {
                continue;
            }
            if (!found[pid] || (isVersionish(verPart) && !isVersionish(found[pid]))) {
                found[pid] = isVersionish(verPart) ? verPart : "";
            }
        }

        // Title / webserver as unversioned signals (e.g. title "Elastic" is weak; "Grafana" ok)
        [title, web].forEach(function (blob) {
            if (!blob || blob === "-") {
                return;
            }
            pid = productIdFromName(blob);
            if (pid && found[pid] === undefined) {
                found[pid] = "";
            }
            // Also scan words in webserver like "Apache/2.4.41"
            var m = String(blob).match(/^([A-Za-z][A-Za-z0-9._-]*)\/?v?([\d][\d.]*)?/);
            if (m) {
                pid = productIdFromName(m[1]);
                if (pid) {
                    if (found[pid] === undefined) {
                        found[pid] = "";
                    }
                    if (isVersionish(m[2]) && !isVersionish(found[pid])) {
                        found[pid] = m[2];
                    }
                }
            }
        });

        // Hostname first label: kibana.oke-011… → Kibana when tech missed it
        if (host) {
            var first = host.split(".")[0].toLowerCase();
            pid = productIdFromName(first);
            if (!pid) {
                // first label may be kibana-devtest style
                for (i = 0; i < ROW_PRODUCT_PRIORITY.length; i++) {
                    if (first.indexOf(ROW_PRODUCT_PRIORITY[i].id) >= 0) {
                        pid = ROW_PRODUCT_PRIORITY[i].id;
                        break;
                    }
                }
            }
            if (pid && found[pid] === undefined) {
                found[pid] = "";
            }
        }

        // WordPress signals not always in tech tokens
        var blobAll = (tech + " " + title).toLowerCase();
        if (
            (/\bwordpress\b/.test(blobAll) || /wp-login/.test(blobAll)) &&
            found.wordpress === undefined
        ) {
            found.wordpress = "";
        }

        for (i = 0; i < ROW_PRODUCT_PRIORITY.length; i++) {
            var p = ROW_PRODUCT_PRIORITY[i];
            if (found[p.id] !== undefined) {
                return found[p.id] ? p.label + ":" + found[p.id] : p.label;
            }
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

    /**
     * Tools for this expand panel.
     * nuclei only when a product is known (filter or fingerprint).
     * robots/nikto/ffuf/feroxbuster always; CMS tools when matched.
     * Order: quietest → loudest.
     */
    function toolsForSoftware(software) {
        var tools = [];
        var soft = (software || "").trim();
        if (soft) {
            tools.push("nuclei");
        }
        if (droopescanCms(software)) {
            tools.push("droopescan");
        }
        if (isWordpress(software)) {
            tools.push("wpscan");
        }
        tools.push("robots", "nikto", "feroxbuster", "ffuf");
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

    function loadViewTimezone() {
        if (!isDiscoverHostedPage()) {
            return Promise.resolve("UTC");
        }
        return fetchJson(statusdUrl("/config"))
            .then(function (cfg) {
                viewTimezone = (cfg && cfg.timezone) || "UTC";
                return viewTimezone;
            })
            .catch(function () {
                return "UTC";
            });
    }

    function parseUtcStamp(text) {
        var s = String(text || "").trim();
        var m = s.match(
            /^(\d{2})[-/](\d{2})[-/](\d{4})\s+Z\s+-\s+(\d{2}):(\d{2})$/
        );
        if (!m) {
            m = s.match(
                /^(\d{2})[-/](\d{2})[-/](\d{4})\s+-\s+(\d{2}):(\d{2})(?:\s+Z)?$/
            );
        }
        if (!m) {
            return null;
        }
        return new Date(
            Date.UTC(
                parseInt(m[3], 10),
                parseInt(m[1], 10) - 1,
                parseInt(m[2], 10),
                parseInt(m[4], 10),
                parseInt(m[5], 10),
                0
            )
        );
    }

    function formatInViewZone(dt, tzId) {
        if (!dt || isNaN(dt.getTime())) {
            return "";
        }
        var tz = tzId || "UTC";
        if (tz === "UTC") {
            var mo = String(dt.getUTCMonth() + 1).padStart(2, "0");
            var da = String(dt.getUTCDate()).padStart(2, "0");
            var ye = dt.getUTCFullYear();
            var ho = String(dt.getUTCHours()).padStart(2, "0");
            var mi = String(dt.getUTCMinutes()).padStart(2, "0");
            return mo + "/" + da + "/" + ye + " - " + ho + ":" + mi + " Z";
        }
        try {
            var parts = new Intl.DateTimeFormat("en-US", {
                timeZone: tz,
                year: "numeric",
                month: "2-digit",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit",
                hour12: false,
            }).formatToParts(dt);
            var map = {};
            parts.forEach(function (p) {
                map[p.type] = p.value;
            });
            return (
                map.month +
                "/" +
                map.day +
                "/" +
                map.year +
                " - " +
                map.hour +
                ":" +
                map.minute
            );
        } catch (e) {
            return "";
        }
    }

    function formatViewStamp(raw) {
        var s = String(raw || "").trim();
        if (!s) {
            return s;
        }
        var dt = parseUtcStamp(s);
        if (!dt) {
            return s.replace(/^(\d{2})-(\d{2})-(\d{4})(\s+-)/, "$1/$2/$3$4");
        }
        return formatInViewZone(dt, viewTimezone) || s;
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

    /**
     * Build green output buttons.
     * robots: txt → robots.txt body; htm → Firefox Disallow tabs.
     * nikto: txt + htm when report exists.
     * ffuf / feroxbuster: txt + url when there is at least one finding URL.
     */
    function findingUrlCount(st) {
        if (!st || st.url_count == null || st.url_count === "") {
            return null;
        }
        var n = Number(st.url_count);
        return isNaN(n) ? null : n;
    }

    function outputButtonsHtml(tool, st) {
        if (!st || !(st.output || st.output_rel)) {
            return "";
        }
        var rel = st.output_rel || st.output;
        if (String(rel).indexOf("../") !== 0) {
            rel = "../" + String(rel).replace(/^\//, "");
        }
        var txtRel = rel;
        // robots txt shows the raw robots.txt body (not the summary output.txt).
        if (tool === "robots" && st.skip_reason !== "host_unreachable") {
            txtRel = String(rel).replace(/[^/]+$/, "robots.txt");
        }
        var safe = String(txtRel).replace(/"/g, "&quot;");
        var html =
            '<span class="inc-host-scan-btn-row">' +
            '<a class="inc-host-scan-out" href="' +
            safe +
            '" target="_blank" rel="noopener">txt</a>';
        // Nikto HTML report is only written when Nikto actually ran — not on
        // reachability skip (host_unreachable).
        if (tool === "nikto" && st.skip_reason !== "host_unreachable") {
            // nikto.htm lives next to output.txt in the run directory
            var htmRel = String(rel).replace(/[^/]+$/, "nikto.htm");
            html +=
                '<a class="inc-host-scan-out" href="' +
                htmRel.replace(/"/g, "&quot;") +
                '" target="_blank" rel="noopener">htm</a>';
        }
        // robots: htm opens Disallow directories in Firefox (discover-robots:).
        if (
            tool === "robots" &&
            st.skip_reason !== "host_unreachable" &&
            Number(st.disallow_count) > 0
        ) {
            var listRel = String(rel).replace(/[^/]+$/, "disallow-urls.txt");
            var absList = hostScanArtifactAbsolutePath(listRel);
            if (absList) {
                html +=
                    '<a class="inc-host-scan-out" href="discover-robots:' +
                    encodeURI(absList).replace(/"/g, "&quot;") +
                    '" title="Open each robots.txt Disallow directory in Firefox">htm</a>';
            }
        }
        if (tool === "ffuf") {
            // Absolute path via discover-ffuf: → open-ffuf-tabs.sh (Firefox CLI)
            var jsonRel = String(rel).replace(/[^/]+$/, "ffuf.json");
            var absJson = hostScanArtifactAbsolutePath(jsonRel);
            var ffufUrls = findingUrlCount(st);
            if (absJson && ffufUrls !== 0) {
                html +=
                    '<a class="inc-host-scan-out" href="discover-ffuf:' +
                    encodeURI(absJson).replace(/"/g, "&quot;") +
                    '" title="Open each ffuf finding URL in Firefox">url</a>';
            }
        }
        if (tool === "feroxbuster") {
            var feroxRel = String(rel).replace(/[^/]+$/, "ferox.json");
            var absFerox = hostScanArtifactAbsolutePath(feroxRel);
            var feroxUrls = findingUrlCount(st);
            if (absFerox && feroxUrls !== 0) {
                html +=
                    '<a class="inc-host-scan-out" href="discover-ferox:' +
                    encodeURI(absFerox).replace(/"/g, "&quot;") +
                    '" title="Open each feroxbuster finding URL in Firefox">url</a>';
            }
        }
        html += "</span>";
        return html;
    }

    /**
     * Best-effort absolute or report-relative path for desktop handlers
     * (discover-ffuf: / discover-ferox: / discover-robots:).
     */
    function hostScanArtifactAbsolutePath(relFromPages) {
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
            return "Running.";
        }
        if (st && (st.finished_display || st.finished || st.skip_reason)) {
            var last = st.finished_display || st.finished || "";
            var btns = outputButtonsHtml(tool, st);
            var parts = [];
            if (last) {
                parts.push(
                    '<span class="inc-host-scan-last-time">' +
                    formatViewStamp(last) +
                    "</span>"
                );
            }
            // Expand-panel note when reachability pre-check skipped this tool.
            if (st.skip_reason === "host_unreachable") {
                parts.push(
                    '<span class="inc-host-scan-skip" title="curl pre-check: no HTTP response from this host within 15s">Unreachable</span>'
                );
            }
            if (btns) {
                parts.push(btns);
            }
            if (parts.length) {
                return parts.join("");
            }
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
            "inc-host-scan-info-modal--ffuf",
            "inc-host-scan-info-modal--feroxbuster"
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
            "inc-host-scan-info-modal--ffuf",
            "inc-host-scan-info-modal--feroxbuster"
        );
        if (tool === "nuclei") {
            el.classList.add("inc-host-scan-info-modal--nuclei");
        } else if (tool === "nikto") {
            el.classList.add("inc-host-scan-info-modal--nikto");
        } else if (tool === "ffuf") {
            el.classList.add("inc-host-scan-info-modal--ffuf");
        } else if (tool === "feroxbuster") {
            el.classList.add("inc-host-scan-info-modal--feroxbuster");
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
                tool === "droopescan"
                    ? "droopescan"
                    : tool === "wpscan"
                      ? "wpscan"
                      : tool === "robots"
                        ? "robots"
                        : tool;
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
                Promise.all([loadMode(), loadStatus(), loadViewTimezone()]).then(function (pair) {
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

        Promise.all([loadMode(), loadViewTimezone()]).then(function (pair) {
            var mode = pair[0];
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
