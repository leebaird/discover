import html
import importlib.util
import json
import os
import re
from collections import Counter
from urllib.parse import urlparse

NOISE_PLUGINS = {
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "content-language",
    "cookies",
    "country",
    "email",
    "html5",
    "httponly",
    "httpserver",
    "ip",
    "redirectlocation",
    "script",
    "strict-transport-security",
    "title",
    "uncommonheaders",
    "via-proxy",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
}


# Semantic renames only (keys must be separator-normalized: lowercase, spaces).
TECH_ALIASES = {
    "apache http server": "apache",
    "asp net": "asp.net",
    "google cloud cdn": "google cloud",
    "google cloud load balancing": "google cloud",
    "microsoft asp.net": "asp.net",
    "microsoft iis": "iis",
}

# Canonical display names keyed by tech_key().
TECH_DISPLAY_NAMES = {
    "amazon cloudfront": "Amazon CloudFront",
    "apache": "Apache",
    "asp.net": "Microsoft ASP.NET",
    "f5 bigip": "F5 BigIP",
    "google analytics": "Google Analytics",
    "google cloud": "Google Cloud",
    "iis": "IIS",
    "jquery": "jQuery",
    "jquery migrate": "jQuery Migrate",
    "jquery ui": "jQuery UI",
    "microsoft httpapi": "Microsoft HTTPAPI",
    "mod jk": "mod_jk",
    "nginx": "nginx",
}


def normalize_tech_separators(value):
    """Collapse -, _, and whitespace so spelling variants share one identity."""
    value = str(value).strip().lower()
    if not value:
        return ""
    return re.sub(r"[-_\s]+", " ", value).strip()


def technology_base_name(label):
    """Noise-list form: separator-normalized key with spaces as hyphens."""
    key = tech_key(label)
    if not key:
        return ""
    return key.replace(" ", "-")


def is_noise_technology(label):
    base = technology_base_name(label)
    if not base:
        return False
    if base in NOISE_PLUGINS:
        return True
    # Also match space-form keys if any are ever added to the noise set.
    return base.replace("-", " ") in NOISE_PLUGINS


def host_from_url(url):
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


def plugin_label(name, data):
    if not isinstance(data, dict):
        return name

    values = []
    for key in ("version", "string", "os", "account", "model", "firmware", "module", "filepath"):
        raw = data.get(key)
        if raw is None:
            continue
        if isinstance(raw, list):
            values.extend(str(item) for item in raw if str(item).strip())
        elif str(raw).strip():
            values.append(str(raw))

    values = [value for value in values if str(value).strip().upper() != "N/A"]

    if values:
        # Do not use commas — technology lists are comma-separated.
        return f"{name}:{'; '.join(values)}"
    return name


def tech_name_and_version(label):
    """Split a tech label into (name, version) with bracket form normalized."""
    label = str(label).strip()
    if not label:
        return "", ""

    bracket = re.match(r"^([^:\[]+)\[(.+)\]$", label)
    if bracket:
        return bracket.group(1).strip(), bracket.group(2).strip()

    if ":" in label:
        # Keep X-Powered-By / X-UA-Compatible style headers intact as the name
        # when the whole label is a header-style token handled in tech_key.
        lower = label.lower()
        if lower.startswith("x-powered-by:") or lower.startswith("x-ua-compatible:"):
            return label, ""
        name, version = label.split(":", 1)
        return name.strip(), version.strip()

    return label, ""


def tech_key(label):
    label = str(label).strip()
    if not label:
        return ""

    lower = label.lower()

    if lower.startswith("x-powered-by:"):
        inner = normalize_tech_separators(label.split(":", 1)[1])
        return TECH_ALIASES.get(inner, inner)

    if lower.startswith("x-powered-by["):
        inner = normalize_tech_separators(label[label.index("[") + 1 : label.rindex("]")])
        return TECH_ALIASES.get(inner, inner)

    name, _version = tech_name_and_version(label)
    if not name:
        return ""

    # Header-style labels without a real product version suffix.
    if name.lower().startswith("x-ua-compatible:"):
        return normalize_tech_separators(name)

    base = normalize_tech_separators(name)
    return TECH_ALIASES.get(base, base)


def whatweb_plugin_labels(plugins):
    if not isinstance(plugins, dict):
        return []

    labels = []
    for name in sorted(plugins.keys(), key=lambda value: str(value).lower()):
        if str(name).lower() in NOISE_PLUGINS:
            continue
        labels.append(plugin_label(str(name), plugins[name]))
    return labels


def whatweb_webserver(plugins):
    if not isinstance(plugins, dict):
        return ""

    httpserver = plugins.get("HTTPServer")
    if not isinstance(httpserver, dict):
        return ""

    values = httpserver.get("string")
    if isinstance(values, list) and values:
        return str(values[0]).strip()
    if isinstance(values, str) and values.strip():
        return values.strip()
    return ""


def load_whatweb_by_host(path):
    by_host = {}
    if not path or not os.path.isfile(path):
        return by_host

    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return by_host

    entries = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    for entry in entries:
        host = host_from_url(entry.get("target") or "")
        if not host:
            continue
        current = by_host.setdefault(host, {"plugins": {}, "status": ""})
        plugins = entry.get("plugins")
        if isinstance(plugins, dict):
            current["plugins"].update(plugins)
        status = entry.get("http_status")
        if status not in (None, "") and not current["status"]:
            current["status"] = str(status)
    return by_host


def httpx_score(entry):
    score = 0
    scheme = entry.get("scheme") or ""
    status = entry.get("status_code")
    if scheme == "https":
        score += 10
    if isinstance(status, int):
        if 200 <= status < 400:
            score += 20
        elif status in (401, 403, 405):
            score += 8
        elif 300 <= status < 400:
            score += 4
    return score


def load_httpx_rows(path):
    rows = {}
    if not path or not os.path.isfile(path):
        return rows

    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue

            host = host_from_url(entry.get("url") or entry.get("input") or "")
            if not host:
                continue

            candidate = {
                "host": host,
                "status": entry.get("status_code"),
                "webserver": (entry.get("webserver") or "").strip(),
                "title": format_page_title(entry.get("title")),
                "httpx_tech": [
                    str(item).strip() for item in (entry.get("tech") or []) if str(item).strip()
                ],
                "score": httpx_score(entry),
            }

            current = rows.get(host)
            if not current or candidate["score"] > current["score"]:
                rows[host] = candidate
    return rows


# Generic HTTP status page titles — hide these from the report Title row.
SUPPRESSED_PAGE_TITLES = {
    "301 moved permanently",
    "302 found",
    "401 unauthorized",
    "403 - forbidden: access is denied.",
    "403 forbidden",
    "404 not found",
    "404 - file or directory not found.",
    "503 service currently unavailable",
    "503 service unavailable",
    "error 401 unauthorized",
    "error 404",
    "error: the request could not be satisfied",
    "error",
    "invalid url",
    "http status 404 - not found",
    "not found",
    "object moved",
    "page not found",
    "redirect",
    "server unavailable",
}


def normalize_page_title_key(title):
    # Treat en/em dashes like ASCII hyphens for suppress matching.
    return title.replace("\u2013", "-").replace("\u2014", "-").casefold()


def format_page_title(value):
    title = (value or "").strip()
    if not title:
        return ""
    # Drop a leading "- " (or multiple) before the real title text.
    while title.startswith("-"):
        stripped = title[1:].lstrip()
        if stripped == title:
            break
        title = stripped
    title = title.strip()
    if not title:
        return ""
    if normalize_page_title_key(title) in SUPPRESSED_PAGE_TITLES:
        return ""
    return title


def format_status(value):
    if value is None or value == "":
        return ""
    return str(value)


def trim_version(version):
    version = str(version).strip()
    if re.fullmatch(r"\d+\.0", version):
        return version[:-2]
    return version


def format_webserver(value):
    value = (value or "").strip()
    if not value or value.upper() == "N/A":
        return ""

    match = re.match(r"^Microsoft-IIS/(.+)$", value, re.IGNORECASE)
    if match:
        return f"Microsoft-IIS/{trim_version(match.group(1))}"

    return value


def direct_tech_versions(technologies):
    versions = {}
    if not technologies:
        return versions

    for label in technologies.split(","):
        label = label.strip()
        match = re.match(r"^([^:\[]+):(.+)$", label)
        if match:
            key = tech_key(f"{match.group(1)}:{match.group(2)}")
            version = trim_version(match.group(2).strip())
            versions.setdefault(key, set()).add(version)
            continue

        bracket = re.match(r"^([^:\[]+)\[(.+)\]$", label)
        if bracket:
            key = tech_key(bracket.group(1))
            version = trim_version(bracket.group(2).strip())
            versions.setdefault(key, set()).add(version)
    return versions


# When a versioned tech already covers this product, optionally keep a short
# server token instead of dropping it entirely.
WEBSERVER_SHORT_NAMES = {
    "apache": "Apache",
    "iis": "Microsoft-IIS",
    "nginx": "nginx",
}


def strip_redundant_technology_labels(technologies, webserver):
    if not technologies or not webserver:
        return technologies

    webserver_lower = webserver.lower()
    kept = []
    for label in technologies.split(","):
        label = label.strip()
        if not label:
            continue
        if ":" in label or "[" in label:
            kept.append(label)
            continue
        if label.lower() in webserver_lower:
            continue
        # Also drop unversioned tech that matches a normalized webserver product.
        if tech_key(label) and tech_key(label) == tech_key(webserver.split("/")[0]):
            continue
        kept.append(label)
    return ", ".join(kept)


def strip_noise_technology_labels(technologies):
    if not technologies:
        return technologies

    kept = []
    for label in technologies.split(","):
        label = label.strip()
        if not label or is_noise_technology(label):
            continue
        kept.append(label)
    return ", ".join(kept)


def strip_redundant_webserver_tokens(webserver, technologies):
    if not webserver:
        return webserver

    covered = direct_tech_versions(technologies)
    if not covered:
        return webserver

    kept = []
    for segment in re.findall(r"\([^)]+\)|\S+", webserver):
        match = re.match(r"^([^/]+)/(.+)$", segment)
        if match:
            raw_name = match.group(1).strip()
            version = trim_version(match.group(2).strip())
            product_key = tech_key(raw_name)
            if product_key in covered and version in covered[product_key]:
                short_name = WEBSERVER_SHORT_NAMES.get(product_key)
                if short_name:
                    kept.append(short_name)
                    continue
                continue
        kept.append(segment)
    return " ".join(kept)


# Analytics / ads property IDs are not software versions.
TRACKING_ID_RE = re.compile(
    r"(?i)(?:^|[\s;,:]+)(?:UA-\d{4,}-\d+|G-[A-Z0-9]+|GTM-[A-Z0-9]+|AW-\d+)\b"
)


def strip_tracking_ids(value):
    value = TRACKING_ID_RE.sub("", value or "")
    value = re.sub(r"\s*;\s*", "; ", value)
    value = re.sub(r"[\s;,:]+$", "", value)
    return value.strip(" ;,")


def format_technology_label(label):
    label = str(label).strip()
    if not label:
        return ""

    name, version = tech_name_and_version(label)
    if version.upper() == "N/A":
        version = ""
    version = strip_tracking_ids(version)
    # If the whole label was only a tracking id (unusual), drop it from name too.
    name = strip_tracking_ids(name) if name else name

    key = tech_key(label if not version else name)
    # Header-style labels (X-UA-Compatible, etc.): keep original text.
    if name.lower().startswith("x-ua-compatible:") or name.lower().startswith("x-powered-by"):
        return name if not version else f"{name}:{version}"

    pretty = TECH_DISPLAY_NAMES.get(key)
    if pretty:
        base = pretty
    else:
        base = name.strip()
        # Prefer spaces over hyphens for multi-word product names; keep
        # underscore products (mod_jk is handled via TECH_DISPLAY_NAMES).
        if "_" not in base:
            base = re.sub(r"-+", " ", base)
            base = re.sub(r"\s+", " ", base).strip()

    if version:
        # Only collapse trailing ".0" for IIS (IIS:10.0 -> IIS:10).
        if key == "iis":
            version = trim_version(version)
        # Non-numeric leftovers like "Universal" are product editions, not
        # useful as a software-version suffix when the ID was the only signal.
        if key in {"google analytics", "google tag manager"} and not re.search(r"\d", version):
            return base
        return f"{base}:{version}"
    return base


def has_version_suffix(label):
    label = str(label).strip()
    return ":" in label or "[" in label


def merge_technologies(httpx_tech, whatweb_plugins):
    merged = {}
    httpx_keys = set()

    for item in httpx_tech:
        if is_noise_technology(item):
            continue
        key = tech_key(item)
        if not key:
            continue
        merged[key] = item
        httpx_keys.add(key)

    for item in whatweb_plugin_labels(whatweb_plugins):
        key = tech_key(item)
        if not key:
            continue
        current = merged.get(key)
        if current is None:
            merged[key] = item
        elif key in httpx_keys:
            if not has_version_suffix(current) and has_version_suffix(item):
                merged[key] = item
        elif has_version_suffix(item) and not has_version_suffix(current):
            merged[key] = item

    labels = sorted(
        (format_technology_label(value) for value in merged.values()),
        key=lambda value: value.lower(),
    )
    return ", ".join(labels)


def host_tech_row(httpx_row, whatweb_row):
    whatweb_plugins = whatweb_row.get("plugins", {})

    status = httpx_row.get("status")
    if status in (None, ""):
        status = whatweb_row.get("status", "")

    technologies = merge_technologies(
        httpx_row.get("httpx_tech", []),
        whatweb_plugins,
    )
    webserver = format_webserver(
        httpx_row.get("webserver") or whatweb_webserver(whatweb_plugins)
    )
    webserver = strip_redundant_webserver_tokens(webserver, technologies)
    technologies = strip_redundant_technology_labels(technologies, webserver)
    technologies = strip_noise_technology_labels(technologies)

    return {
        "status": format_status(status),
        "webserver": webserver,
        "title": format_page_title(httpx_row.get("title")),
        "technologies": technologies,
    }


def load_host_tech(httpx_path, whatweb_path):
    httpx_rows = load_httpx_rows(httpx_path)
    whatweb_rows = load_whatweb_by_host(whatweb_path)
    hosts = set(httpx_rows) | set(whatweb_rows)

    return {
        host: host_tech_row(httpx_rows.get(host, {}), whatweb_rows.get(host, {}))
        for host in hosts
    }


IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
# Preferred display order for common HTTP statuses (others follow sorted).
STATUS_CODE_ORDER = (200, 204, 301, 302, 303, 400, 401, 403, 404, 500, 502, 503, 504)


def is_private_ip(ip):
    if not IPV4_RE.match(ip or ""):
        return False
    octets = [int(part) for part in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False


def load_subdomain_rows(path):
    rows = []
    if not path or not os.path.isfile(path):
        return rows

    with open(path, newline="", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            if "\t" in raw:
                parts = raw.split("\t")
                host = parts[0].strip()
                ipaddr = parts[1].strip() if len(parts) > 1 else ""
                category = parts[2].strip() if len(parts) > 2 else ""
            else:
                parts = raw.split()
                if not parts:
                    continue
                host = parts[0]
                ipaddr = parts[1] if len(parts) > 1 else ""
                category = parts[2] if len(parts) > 2 else ""
            if host:
                rows.append((host, ipaddr, category))
    return rows


def load_alive_hosts(path):
    alive = {}
    if not path or not os.path.isfile(path):
        return alive

    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) < 3 or not parts[0]:
                continue
            try:
                alive[parts[0].lower()] = int(parts[2])
            except ValueError:
                continue
    return alive


def httpx_scan_date(path):
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entry = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                timestamp = entry.get("timestamp") or ""
                if "T" in timestamp:
                    date_part = timestamp.split("T", 1)[0]
                    year, month, day = date_part.split("-")
                    return f"{month}-{day}-{year}"
    return ""


def format_count(value):
    return f"{value:,}"


def summary_table(title, label_header, rows, sort_last_labels=None, section_class=""):
    sort_last_labels = set(sort_last_labels or [])
    class_names = "inc-active-section"
    if section_class:
        class_names = f"{class_names} {section_class}"
    lines = [
        f'    <section class="{class_names}">',
        f'        <h3 class="inc-active-section-title">{html.escape(title)}</h3>',
        '        <div class="inc-content-frame inc-content-frame--table">',
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        f'                    <th scope="col" class="inc-sortable">{html.escape(label_header)}</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">Count</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    for label, count in rows:
        sort_last_attr = ' data-sort-last' if label in sort_last_labels else ""
        lines.append(
            "                <tr>"
            f"<td{sort_last_attr}>{html.escape(label)}</td>"
            f'<td class="inc-col-center">{format_count(count)}</td>'
            "</tr>"
        )

    lines.extend(
        [
            "            </tbody>",
            "        </table>",
            "        </div>",
            "    </section>",
        ]
    )
    return lines


def cve_nvd_link_html(cve_id):
    """Render a single CVE id as an NVD detail link."""
    cve_id = str(cve_id or "").strip()
    if not cve_id:
        return ""
    if re.fullmatch(r"CVE-\d{4}-\d+", cve_id, flags=re.IGNORECASE):
        cve_id = cve_id.upper()
        href = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return (
            f'<a href="{html.escape(href, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer">{html.escape(cve_id)}</a>'
        )
    return html.escape(cve_id)


def software_versions_table(rows, section_class="inc-active-section--software-versions"):
    """Render Software versions with Count, CVSS, CVE count, and top CVE link.

    rows: iterable of (label, count, max_cvss, cve_count, top_cve)
    """
    class_names = "inc-active-section"
    if section_class:
        class_names = f"{class_names} {section_class}"
    lines = [
        f'    <section class="{class_names}">',
        '        <h3 class="inc-active-section-title">Software versions</h3>',
        '        <div class="inc-content-frame inc-content-frame--table">',
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Software</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">Count</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">CVSS</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">CVEs</th>',
        '                    <th scope="col" class="inc-sortable">Top CVE</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    for label, count, max_cvss, cve_count, top_cve in rows:
        cve_cell = cve_nvd_link_html(top_cve)
        lines.append(
            "                <tr>"
            f"<td>{html.escape(str(label))}</td>"
            f'<td class="inc-col-center">{format_count(count)}</td>'
            f'<td class="inc-col-center">{html.escape(str(max_cvss))}</td>'
            f'<td class="inc-col-center">{html.escape(str(cve_count))}</td>'
            f'<td class="inc-subdomain-cve-links">{cve_cell}</td>'
            "</tr>"
        )

    lines.extend(
        [
            "            </tbody>",
            "        </table>",
            "        </div>",
            "    </section>",
        ]
    )
    return lines


def _load_software_cve_module():
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "software-cve.py")
    spec = importlib.util.spec_from_file_location("software_cve", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def enrich_software_rows_for_report(software_version_rows, httpx_path):
    """Attach CVSS/CVE fields; degrade gracefully if NVD is unavailable."""
    if not software_version_rows:
        return []

    cache_path = ""
    if httpx_path:
        cache_path = os.path.join(
            os.path.dirname(os.path.abspath(httpx_path)),
            "software-cves-cache.json",
        )

    try:
        software_cve = _load_software_cve_module()
        # Load private .env before reading DISCOVER_SKIP_CVE / progress flags
        # so values defined only in .env are honored (shell exports still win).
        software_cve.load_discover_env_files()

        if (os.environ.get("DISCOVER_SKIP_CVE") or "").strip() in {"1", "true", "yes"}:
            return [
                (label, count, "", "", "")
                for label, count in software_version_rows
            ]

        progress = (os.environ.get("DISCOVER_CVE_PROGRESS") or "").strip() in {
            "1",
            "true",
            "yes",
        }
        return software_cve.enrich_software_version_rows(
            software_version_rows,
            cache_path,
            progress=progress,
        )
    except Exception:
        return [
            (label, count, "", "", "")
            for label, count in software_version_rows
        ]


def active_grid(columns):
    lines = ['    <div class="inc-active-grid">']

    for sections in columns:
        lines.append('        <div class="inc-active-column">')
        for index, section in enumerate(sections):
            if index:
                lines.append("")
            lines.extend(section)
        lines.append("        </div>")

    lines.append("    </div>")
    return lines


def counter_rows(counter, limit=None):
    return list(counter.most_common(limit))


def webserver_label(value):
    value = (value or "").strip()
    if not value:
        return ""
    return value.split()[0].split("(")[0].strip()


def technology_label_key(label):
    label = label.strip()
    if ":" in label:
        return label.split(":", 1)[0].strip()
    if "[" in label:
        return label.split("[", 1)[0].strip()
    return label


def is_software_version_label(label):
    """True for versioned product labels useful in the Software versions table."""
    label = (label or "").strip()
    if not label:
        return False

    low = label.lower()
    if low.startswith("x-ua-compatible"):
        return False
    if re.fullmatch(r"iis:\s*10(\.0)?", low):
        return False

    return bool(re.search(r":\s*.*\d", label) or re.search(r"\[\s*.*\d", label))


def ordered_status_rows(status_counter):
    """Build status rows from real counts only (no padded zeros)."""
    rows = []
    seen = set()
    for code in STATUS_CODE_ORDER:
        count = status_counter.get(code, 0)
        if count:
            rows.append((str(code), count))
            seen.add(code)
    for code in sorted(status_counter):
        if code not in seen and status_counter[code]:
            rows.append((str(code), status_counter[code]))
    return rows


def load_httpx_status_counts(httpx_path):
    """One status per host from httpx (same host pick as tech enrichment)."""
    counts = Counter()
    for _host, row in load_httpx_rows(httpx_path).items():
        status = row.get("status")
        if status is None or status == "":
            continue
        try:
            counts[int(status)] += 1
        except (TypeError, ValueError):
            continue
    return counts


def build_active_summary(subdomains_path, private_path, alive_tsv_path, httpx_path, whatweb_path):
    all_subdomain_rows = load_subdomain_rows(subdomains_path)
    # Scope "Public" must exclude RFC1918 rows that live in tools/subdomains.
    public_rows = [
        (host, ipaddr, category)
        for host, ipaddr, category in all_subdomain_rows
        if ipaddr and not is_private_ip(ipaddr)
    ]
    private_count = sum(1 for _ in load_subdomain_rows(private_path))
    alive_hosts = load_alive_hosts(alive_tsv_path)
    host_tech = load_host_tech(httpx_path, whatweb_path)

    # Status codes: all httpx responses (includes 404/5xx filtered out of "alive").
    status_counter = load_httpx_status_counts(httpx_path)
    responding_hosts = sum(status_counter.values())

    category_counts = {}
    webserver_counts = {}
    technology_counts = {}
    software_version_counts = {}

    # Category / tech / software: alive public hosts only (screenshot/whatweb scope).
    for host, _ipaddr, category in public_rows:
        host_key = host.lower()
        if host_key not in alive_hosts:
            continue
        label = category.strip() or "(none)"
        category_counts[label] = category_counts.get(label, 0) + 1

        tech = host_tech.get(host_key, {})
        webserver = webserver_label(tech.get("webserver", ""))
        if webserver:
            webserver_counts[webserver] = webserver_counts.get(webserver, 0) + 1

        technologies = tech.get("technologies", "")
        if technologies:
            for item in technologies.split(","):
                item = item.strip()
                if not item:
                    continue
                key = technology_label_key(item)
                technology_counts[key] = technology_counts.get(key, 0) + 1
                if is_software_version_label(item):
                    software_version_counts[item] = (
                        software_version_counts.get(item, 0) + 1
                    )

    category_counter = Counter(category_counts)
    webserver_counter = Counter(webserver_counts)
    technology_counter = Counter(technology_counts)
    software_version_counter = Counter(software_version_counts)

    lines = []

    status_rows = ordered_status_rows(status_counter)

    software_version_rows = sorted(
        software_version_counter.items(),
        key=lambda item: item[0].lower(),
    )
    software_version_enriched = enrich_software_rows_for_report(
        software_version_rows,
        httpx_path,
    )

    lines.extend(
        active_grid(
            [
                [
                    summary_table(
                        "Scope",
                        "Metric",
                        [
                            ("Public subdomains", len(public_rows)),
                            ("Private subdomains", private_count),
                            ("Responding hosts", responding_hosts),
                        ],
                    ),
                    summary_table(
                        "Status codes",
                        "Status Code",
                        status_rows,
                        section_class="inc-active-section--status",
                    ),
                ],
                [
                    summary_table(
                        "Alive by category",
                        "Category",
                        counter_rows(category_counter),
                        sort_last_labels={"(none)"},
                        section_class="inc-active-section--categories",
                    ),
                ],
                [
                    summary_table(
                        "Top web servers",
                        "Web Server",
                        counter_rows(webserver_counter, 5),
                    ),
                    summary_table(
                        "Top technologies",
                        "Technology",
                        counter_rows(technology_counter, 6),
                        section_class="inc-active-section--technologies",
                    ),
                ],
                [
                    software_versions_table(software_version_enriched),
                ],
            ]
        )
    )

    return "\n".join(lines)