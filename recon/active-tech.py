import html
import importlib.util
import json
import os
import re
import shutil
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter
from urllib.parse import quote, urlparse

NOISE_PLUGINS = {
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "content-language",
    "cookies",
    "country",
    "email",
    "emailfield",
    "hiddenfield",
    "html5",
    "httponly",
    "httpserver",
    "ip",
    # HTML meta generator is marketing / multi-product blob noise, not a stack product.
    "metagenerator",
    "passwordfield",
    "redirectlocation",
    "script",
    "strict-transport-security",
    "textfield",
    "title",
    "uncommonheaders",
    "via-proxy",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
}

# Product names that must never appear in the Software versions table.
SOFTWARE_NOISE_PRODUCTS = {
    "emailfield",
    "hiddenfield",
    "metagenerator",
    "passwordfield",
    "poweredby",
    "textfield",
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
    # Tech lists are comma-separated — never embed raw commas from WhatWeb strings
    # (MetaGenerator marketing copy was splitting into fake "products").
    values = [re.sub(r"\s*,\s*", " · ", str(value).strip()) for value in values]
    values = [re.sub(r"\s*;\s*", " · ", value) for value in values]

    if values:
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

            raw_url = (entry.get("url") or entry.get("input") or "").strip()
            host = host_from_url(raw_url)
            if not host:
                continue

            # Prefer the full httpx URL for report hyperlinks.
            link_url = (entry.get("url") or "").strip()
            if not link_url and raw_url:
                link_url = raw_url if "://" in raw_url else f"https://{raw_url}"

            final_url = (entry.get("final_url") or link_url or "").strip()
            candidate = {
                "host": host,
                "url": link_url,
                "final_url": final_url,
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

    match = re.match(r"^Microsoft-IIS(?:/(.+))?$", value, re.IGNORECASE)
    if match:
        version = (match.group(1) or "").strip()
        if version:
            return f"Microsoft IIS/{trim_version(version)}"
        return "Microsoft IIS"

    # httpx/Azure header forms → readable labels
    if re.fullmatch(
        r"Microsoft-Azure-Application-Gateway/v2",
        value,
        flags=re.IGNORECASE,
    ):
        return "Microsoft Azure Application Gateway v2"

    if re.fullmatch(
        r"Microsoft-Azure-Application-LB/AGC",
        value,
        flags=re.IGNORECASE,
    ):
        return "Microsoft Azure Application LB/AGC"

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
    "iis": "Microsoft IIS",
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

    link_url = (httpx_row.get("url") or "").strip()
    if link_url and "://" not in link_url:
        link_url = f"https://{link_url}"
    final_url = (httpx_row.get("final_url") or link_url or "").strip()
    if final_url and "://" not in final_url:
        final_url = f"https://{final_url}"

    return {
        "status": format_status(status),
        "url": link_url,
        "final_url": final_url,
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
    """Latest httpx timestamp as mm-dd-yyyy (not first line — batch merges keep old rows first)."""
    latest = ""
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
                timestamp = str(entry.get("timestamp") or "")
                if "T" not in timestamp:
                    continue
                date_part = timestamp.split("T", 1)[0]
                if len(date_part) >= 10 and (not latest or date_part > latest):
                    latest = date_part
    if latest:
        year, month, day = latest.split("-", 2)
        return f"{month}-{day}-{year}"
    return ""


def format_count(value):
    return f"{value:,}"


def category_label_html(label):
    """Link Alive-by-category labels to filtered Subdomains (?category=)."""
    label_text = str(label)
    escaped = html.escape(label_text)
    href = f"subdomains.htm?category={quote(label_text, safe='')}"
    return (
        f'<a class="inc-category-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains in this category">'
        f"{escaped}</a>"
    )


def status_label_html(label):
    """Link Status codes to filtered Subdomains (?status=200)."""
    label_text = str(label).strip()
    escaped = html.escape(label_text)
    href = f"subdomains.htm?status={quote(label_text, safe='')}"
    return (
        f'<a class="inc-status-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this HTTP status">'
        f"{escaped}</a>"
    )


def webserver_label_html(label):
    """Link Top web servers to filtered Subdomains (?webserver=Apache)."""
    label_text = str(label).strip()
    escaped = html.escape(label_text)
    href = f"subdomains.htm?webserver={quote(label_text, safe='')}"
    return (
        f'<a class="inc-webserver-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this web server">'
        f"{escaped}</a>"
    )


def technology_label_html(label):
    """Link Top technologies to filtered Subdomains (?tech=jQuery)."""
    label_text = str(label).strip()
    escaped = html.escape(label_text)
    href = f"subdomains.htm?tech={quote(label_text, safe='')}"
    return (
        f'<a class="inc-tech-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this technology">'
        f"{escaped}</a>"
    )


def cms_label_html(label):
    """Link CMS table labels to filtered Subdomains (?tech=WordPress)."""
    label_text = str(label).strip()
    escaped = html.escape(label_text)
    href = f"subdomains.htm?tech={quote(label_text, safe='')}"
    return (
        f'<a class="inc-tech-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this CMS">'
        f"{escaped}</a>"
    )


def summary_table(
    title,
    label_header,
    rows,
    sort_last_labels=None,
    section_class="",
    label_html_fn=None,
    title_help=False,
):
    sort_last_labels = set(sort_last_labels or [])
    class_names = "inc-active-section"
    if section_class:
        class_names = f"{class_names} {section_class}"
    if title_help:
        # Title plus ⓘ (Status codes → HTTP reference modal).
        title_html = (
            f"{html.escape(title)}"
            f'<button type="button" class="inc-active-status-codes-info-btn" '
            f'data-inc-active-status-codes-help="1" '
            f'title="HTTP status code reference" '
            f'aria-label="HTTP status code reference">ⓘ</button>'
        )
        title_h3_class = "inc-active-section-title inc-active-section-title--with-help"
    else:
        title_html = html.escape(title)
        title_h3_class = "inc-active-section-title"
    lines = [
        f'    <section class="{class_names}">',
        f'        <h3 class="{title_h3_class}">{title_html}</h3>',
        '        <div class="inc-content-frame inc-content-frame--table">',
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        f'                    <th scope="col" class="inc-sortable">{html.escape(label_header)}</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center inc-active-count">Count</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    for label, count in rows:
        sort_last_attr = ' data-sort-last' if label in sort_last_labels else ""
        if label_html_fn is not None:
            label_cell = label_html_fn(label)
        else:
            label_cell = html.escape(label)
        lines.append(
            "                <tr>"
            f"<td{sort_last_attr}>{label_cell}</td>"
            f'<td class="inc-col-center inc-active-count">{format_count(count)}</td>'
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


def cve_nvd_link_html(cve_id, is_kev=False):
    """Render a single CVE id as an NVD detail link; badge when CISA KEV."""
    cve_id = str(cve_id or "").strip()
    if not cve_id:
        return ""
    if re.fullmatch(r"CVE-\d{4}-\d+", cve_id, flags=re.IGNORECASE):
        cve_id = cve_id.upper()
        href = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        link = (
            f'<a class="inc-cve-id" href="{html.escape(href, quote=True)}" '
            f'data-cve="{html.escape(cve_id, quote=True)}" target="_blank" '
            f'rel="noopener noreferrer" '
            f'title="Open NVD, Rapid7, Tenable, Exploit-DB, Sploitus, CVEbase, and GitHub in Firefox">'
            f"{html.escape(cve_id)}</a>"
        )
    else:
        link = f'<span class="inc-cve-id">{html.escape(cve_id)}</span>'

    if is_kev:
        # CISA catalog search for this CVE (opens in a new tab).
        kev_href = (
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            f"?search={html.escape(cve_id, quote=True)}"
            "&field_date_added_wrapper=all&field_cve=&sort_by=field_date_added"
            "&items_per_page=20&url="
        )
        badge = (
            f'<a class="inc-kev-badge" href="{kev_href}" target="_blank" '
            f'rel="noopener noreferrer" '
            f'title="CISA Known Exploited Vulnerability — open catalog entry">'
            "KEV</a>"
        )
        # Inner flex wrapper so badge can pin right even when table cells use width:1%.
        return f'<span class="inc-cve-cell-inner inc-cve-cell-inner--kev">{link}{badge}</span>'
    return f'<span class="inc-cve-cell-inner">{link}</span>'


def software_has_cves(cve_count, top_cve):
    """True when NVD enrichment found at least one CVE for this software."""
    if str(top_cve or "").strip():
        return True
    raw = str(cve_count or "").strip()
    if not raw or raw in {"-", "—", "n/a", "N/A"}:
        return False
    try:
        return float(raw) > 0
    except ValueError:
        return bool(raw)


def software_label_html(label, cve_count, top_cve):
    """Link versioned software with CVEs to a filtered Subdomains list."""
    label_text = str(label)
    escaped = html.escape(label_text)
    if not software_has_cves(cve_count, top_cve):
        return escaped
    # Hosts carry software tokens in tech; CVEs attach at the version level.
    href = f"subdomains.htm?software={quote(label_text, safe='')}"
    return (
        f'<a class="inc-software-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this software">'
        f"{escaped}</a>"
    )


def software_versions_table(rows, section_class="inc-active-section--software-versions"):
    """Render Software versions with Count, CVSS, CVE count, and top CVE link.

    rows: iterable of (label, count, max_cvss, cve_count, top_cve, top_is_kev)
    """
    class_names = "inc-active-section"
    if section_class:
        class_names = f"{class_names} {section_class}"
    lines = [
        f'    <section class="{class_names}">',
        '        <h3 class="inc-active-section-title">Software versions</h3>',
        '        <div class="inc-content-frame inc-content-frame--table">',
        # Default sort: CVSS column (index 2) descending — highest risk first.
        '        <table class="table table-bordered inc-data-table" '
        'data-default-col="2" data-default-dir="-1">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Software</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center inc-active-count">Count</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">CVSS</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">CVEs</th>',
        '                    <th scope="col" class="inc-sortable">Top CVE</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    for row in rows:
        if len(row) >= 6:
            label, count, max_cvss, cve_count, top_cve, top_is_kev = row[:6]
        else:
            label, count, max_cvss, cve_count, top_cve = row[:5]
            top_is_kev = False
        cve_cell = cve_nvd_link_html(top_cve, is_kev=bool(top_is_kev))
        label_cell = software_label_html(label, cve_count, top_cve)
        lines.append(
            "                <tr>"
            f"<td>{label_cell}</td>"
            f'<td class="inc-col-center inc-active-count">{format_count(count)}</td>'
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


def enrich_software_rows_for_report(
    software_version_rows,
    httpx_path,
    *,
    force: bool = False,
    force_missing_only: bool = False,
):
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
                (label, count, "", "", "", False)
                for label, count in software_version_rows
            ]

        progress = (os.environ.get("DISCOVER_CVE_PROGRESS") or "").strip() in {
            "1",
            "true",
            "yes",
        }
        rows_out = software_cve.enrich_software_version_rows(
            software_version_rows,
            cache_path,
            progress=progress,
            force=force,
            force_missing_only=force_missing_only,
        )
        enrich_software_rows_for_report.last_stats = getattr(
            software_cve.enrich_software_version_rows, "last_stats", {}
        ) or {}
        return rows_out
    except Exception:
        enrich_software_rows_for_report.last_stats = {}
        return [
            (label, count, "", "", "", False)
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
    """Normalize web server for Active Top web servers counts.

    Drops parenthetical notes (e.g. ``Apache (Debian)`` → ``Apache``) but keeps
    multi-word product names intact.
    """
    value = (value or "").strip()
    if not value:
        return ""
    return re.sub(r"\s*\([^)]*\)", "", value).strip()


def technology_label_key(label):
    label = label.strip()
    if ":" in label:
        return label.split(":", 1)[0].strip()
    if "[" in label:
        return label.split("[", 1)[0].strip()
    return label


# CMS product bases → display label (aligned with droopescan / wpscan host-scan gates).
CMS_ALIASES = {
    "wordpress": "WordPress",
    "wp": "WordPress",
    "drupal": "Drupal",
    "joomla": "Joomla",
    "moodle": "Moodle",
    "silverstripe": "Silverstripe",
    "ss": "Silverstripe",
}


def detect_cms_labels(technologies):
    """Return set of canonical CMS display names found in a tech string."""
    found = set()
    if not technologies:
        return found
    for item in str(technologies).split(","):
        item = item.strip()
        if not item:
            continue
        base = technology_label_key(item).lower().replace(" ", "")
        # also try full lower key without strip of spaces mid-name
        base_sp = technology_label_key(item).lower().strip()
        for key in (base, base_sp, base_sp.replace(" ", "")):
            if key in CMS_ALIASES:
                found.add(CMS_ALIASES[key])
                break
    return found


# --- Login pages signals (Active table + Subdomains ?login=) -----------------
# Four signal keys: path (ffuf), title (httpx), tech (fingerprint), status (401).
LOGIN_SIGNAL_ORDER = ("path", "title", "tech", "status")
LOGIN_SIGNAL_LABELS = {
    "path": "Path",
    "title": "Title",
    "tech": "Tech",
    "status": "Status",
}

# High-confidence path basenames / short paths (avoid bare admin/portal SPA noise).
LOGIN_PATH_EXACT = {
    "login",
    "logon",
    "signin",
    "sign-in",
    "sign_in",
    "signon",
    "sign-on",
    "wp-login.php",
    "wp-admin",
    "wp-admin/",
    "user/login",
    "users/sign_in",
    "users/signin",
    "account/login",
    "auth/login",
    "oauth",
    "oauth/authorize",
    "sso",
    "sso/login",
    "cas/login",
    "owa",
    "ecp",
    "remote/login",
}

LOGIN_PATH_RE = re.compile(
    r"(?i)(?:^|/)"
    r"(?:"
    r"login(?:\.(?:php|aspx|jsp|html?|cgi))?|"
    r"logon(?:\.(?:php|aspx))?|"
    r"sign[-_]?in(?:\.(?:php|aspx|jsp|html?))?|"
    r"sign[-_]?on(?:\.(?:php|aspx))?|"
    r"wp-login\.php|"
    r"wp-admin(?:/index\.php)?|"
    r"user/login|users/sign[-_]?in|"
    r"account/login|auth/login|"
    r"oauth(?:/authorize)?|"
    r"sso(?:/login)?|"
    r"cas/login|"
    r"openid(?:-connect)?|"
    r"owa(?:/auth(?:/logon\.aspx)?)?|"
    r"remote/login"
    r")"
    r"(?:/|$|\?)"
)

LOGIN_TITLE_RE = re.compile(
    r"(?i)\b(?:"
    r"log\s*[\s_-]*in|log\s*[\s_-]*on|"
    r"sign\s*[\s_-]*in|sign\s*[\s_-]*on|"
    r"sso|single\s+sign|"
    r"authentication|"
    r"authorization\s+required|"
    r"401\s+unauthori[sz]ed|"
    r"unauthori[sz]ed|"
    r"password\s*(?:required|protected)?"
    r")\b"
)

# Tech bases that usually expose a login surface (matched via technology_label_key).
LOGIN_TECH_BASES = {
    "wordpress",
    "drupal",
    "joomla",
    "moodle",
    "silverstripe",
    "grafana",
    "kibana",
    "jenkins",
    "gitlab",
    "gitea",
    "gogs",
    "keycloak",
    "okta",
    "auth0",
    "phpmyadmin",
    "cpanel",
    "roundcube",
    "zimbra",
    "citrix",
    "fortinet",
    "sonicwall",
    "pulse secure",
    "ivanti",
    "globalprotect",
    "outlook web app",
    "microsoft exchange",
    "sharepoint",
    "confluence",
    "jira",
    "sonarqube",
    "nexus",
    "artifactory",
    "portainer",
    "rancher",
    "prometheus",
}


def is_login_path(path: str) -> bool:
    """True when a fuzz path looks like a login / auth endpoint."""
    raw = (path or "").strip().lstrip("/")
    if not raw:
        return False
    # Drop query/fragment for exact basenames
    bare = raw.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    low = bare.lower()
    if low in LOGIN_PATH_EXACT or (low + "/") in LOGIN_PATH_EXACT:
        return True
    # basename exact (e.g. deep/path/login)
    base = low.rsplit("/", 1)[-1]
    if base in LOGIN_PATH_EXACT:
        return True
    return bool(LOGIN_PATH_RE.search(raw))


def is_login_title(title: str) -> bool:
    """True when page title suggests a login / auth page."""
    t = (title or "").strip()
    if not t or t == "-":
        return False
    return bool(LOGIN_TITLE_RE.search(t))


def is_login_tech(technologies: str) -> bool:
    """True when technologies include a product that typically has a login UI."""
    if not technologies:
        return False
    for item in str(technologies).split(","):
        item = item.strip()
        if not item:
            continue
        key = technology_label_key(item).lower().strip()
        if key in LOGIN_TECH_BASES:
            return True
        # CMS aliases share the same idea
        compact = key.replace(" ", "")
        if compact in CMS_ALIASES:
            return True
    return False


def is_login_status(status, tech: dict | None = None) -> bool:
    """True for HTTP 401 when the page title also looks like auth.

    Bare 403 is out (WAF / API deny). Bare 401 with an empty title is usually
    tenant/API gatekeeping (e.g. "Company sub-domain required"), not a login UI.
    401 + auth-ish title (SSO, Authorization Required, …) still counts.
    """
    try:
        code = int(str(status).strip())
    except (TypeError, ValueError):
        return False
    if code != 401:
        return False
    tech = tech or {}
    title = str(tech.get("title") or "").strip()
    if not title or title == "-":
        return False
    return is_login_title(title)


# External IdP login surfaces operators usually skip (hosted Microsoft SSO).
MS_LOGIN_URL_RE = re.compile(
    r"(?i)(?:"
    r"login\.microsoftonline\.com|"
    r"login\.microsoft\.com|"
    r"login\.live\.com|"
    r"login\.windows\.net|"
    r"sts\.windows\.net|"
    r"aadcdn\.msauth\.net|"
    r"login\.partner\.microsoftonline\.cn"
    r")"
)


def is_microsoft_login_redirect(tech: dict | None) -> bool:
    """True when httpx landed on / embeds a Microsoft SSO login URL.

    Covers direct redirects and app bounce URLs (e.g. ServiceNow
    ``auth_redirect.do?...login.microsoftonline.com...``).
    """
    tech = tech or {}
    blob = " ".join(
        [
            str(tech.get("final_url") or ""),
            str(tech.get("url") or ""),
        ]
    )
    return bool(blob and MS_LOGIN_URL_RE.search(blob))


# Browser-like UA for short Citrix nFactor probes (not host-scan).
_LOGIN_PROBE_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def _login_probe_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(
    url: str,
    *,
    data: bytes | None = None,
    timeout: float = 12.0,
) -> tuple[int, str, str]:
    """GET/POST; returns (status, body, final_url). Best-effort on errors."""
    req = urllib.request.Request(
        url,
        data=data,
        method="POST" if data is not None else "GET",
        headers={"User-Agent": _LOGIN_PROBE_UA},
    )
    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=_login_probe_ssl_context()
        ) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200) or 200), body, resp.geturl()
    except Exception:
        return 0, "", ""


def citrix_gateway_uses_microsoft_sso(host: str, timeout: float = 12.0) -> bool:
    """True when Citrix nFactor auth posts into Microsoft SAML (login.microsoftonline.com).

    httpx often stops at ``/logon/LogonPoint/tmindex.html``; the Microsoft hop only
    appears after ``POST /p/u/doAuthentication.do`` → ``doSaml``. Best-effort network
    probe — failures return False (host keeps Login pages signals).
    """
    host = (host or "").strip().lower()
    if not host or "/" in host or "://" in host:
        return False
    auth_url = f"https://{host}/p/u/doAuthentication.do"
    _status, body, _final = _http_request(
        auth_url, data=b"login=&passwd=", timeout=timeout
    )
    if not body:
        return False
    if MS_LOGIN_URL_RE.search(body):
        return True
    m = re.search(r"<RedirectURL>([^<]+)</RedirectURL>", body, flags=re.I)
    if not m:
        return False
    redir = (
        m.group(1)
        .strip()
        .replace("&amp;", "&")
        .replace("&#38;", "&")
    )
    if not redir:
        return False
    if MS_LOGIN_URL_RE.search(redir):
        return True
    # nFactor SAML bounce on the gateway itself.
    if "doSaml" not in redir and "saml" not in redir.lower():
        return False
    if redir.startswith("/"):
        redir = f"https://{host}{redir}"
    elif "://" not in redir:
        redir = f"https://{host}/{redir.lstrip('/')}"
    _st2, body2, final2 = _http_request(redir, timeout=timeout)
    blob = f"{body2} {final2}"
    return bool(MS_LOGIN_URL_RE.search(blob))


# RNAS = CGI remote network access Citrix gateways (LogonPoint only; not app logins).
LOGIN_SKIP_TITLE_RE = re.compile(r"(?i)\bunified\s+access\s+rnas\b")


def is_rnas_access_gateway(host: str, tech: dict | None) -> bool:
    """True for Unified Access RNAS / rnas-* Citrix remote-access hosts."""
    tech = tech or {}
    title = str(tech.get("title") or "")
    if LOGIN_SKIP_TITLE_RE.search(title):
        return True
    h = (host or "").lower().strip()
    if not h:
        return False
    # rnas-mtl.ua.cgi.com, rnas.example.com, foo.rnas.bar
    if h.startswith("rnas-") or h.startswith("rnas.") or ".rnas." in h:
        return True
    return False


def collect_login_skip_hosts(host_tech: dict) -> set[str]:
    """Hosts omitted from Login pages (Microsoft SSO / known noise gateways).

    - httpx final_url / url embeds Microsoft IdP
    - Unified Access RNAS / rnas-* remote-access Citrix hosts
    - Citrix gateway nFactor → Microsoft SAML (short live probe)
    """
    skip: set[str] = set()
    for host, tech in (host_tech or {}).items():
        host_key = (host or "").lower().strip()
        if not host_key:
            continue
        if is_microsoft_login_redirect(tech):
            skip.add(host_key)
            continue
        if is_rnas_access_gateway(host_key, tech):
            skip.add(host_key)
            continue
        techs = (tech.get("technologies") or "").lower()
        if "citrix" not in techs:
            continue
        # Only probe when Citrix would contribute a tech signal (or already known).
        if not is_login_tech(tech.get("technologies") or ""):
            continue
        try:
            if citrix_gateway_uses_microsoft_sso(host_key):
                skip.add(host_key)
        except Exception:
            continue
    return skip


# Path SPA / soft-200 filter: when most ffuf hits share one body length, that
# length is treated as the catch-all app shell. Login-like paths with that same
# length are ignored (e.g. client-side routers returning 200 for every path).
# Small result sets (Grafana/Kibana with a few real hits) are not filtered.
LOGIN_PATH_SPA_MIN_RESULTS = 50
LOGIN_PATH_SPA_MIN_MODE_COUNT = 20
LOGIN_PATH_SPA_MIN_MODE_SHARE = 0.5


def _ffuf_result_fuzz(result: dict) -> str:
    """FUZZ input or path from result URL."""
    fuzz = ""
    inp = result.get("input")
    if isinstance(inp, dict):
        fuzz = str(inp.get("FUZZ") or "").strip()
    if fuzz:
        return fuzz
    url = str(result.get("url") or "")
    if "://" in url:
        try:
            return urlparse(url).path.lstrip("/")
        except Exception:
            return ""
    return ""


def _ffuf_spa_shell_length(results: list) -> int | None:
    """Dominant response length when it looks like a catch-all SPA shell.

    Returns that length, or None when the run is too small / diverse to treat
    as soft-200 noise.
    """
    lengths: list[int] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        raw = result.get("length")
        if raw is None or raw == "":
            continue
        try:
            lengths.append(int(raw))
        except (TypeError, ValueError):
            continue
    n = len(lengths)
    if n < LOGIN_PATH_SPA_MIN_RESULTS:
        return None
    counts = Counter(lengths)
    mode_len, mode_n = counts.most_common(1)[0]
    if mode_n < LOGIN_PATH_SPA_MIN_MODE_COUNT:
        return None
    if (mode_n / n) < LOGIN_PATH_SPA_MIN_MODE_SHARE:
        return None
    return mode_len


def collect_login_path_hosts(report_dir: str) -> dict[str, list[str]]:
    """host.lower() → login-like FUZZ paths from newest tools/host-scans/.../ffuf.json.

    Applies a mode-length filter: when most results share one body length
    (SPA catch-all), login-named paths with that same length are dropped.
    """
    out: dict[str, list[str]] = {}
    scans = os.path.join(
        os.path.abspath(os.path.expanduser(report_dir or "")),
        "tools",
        "host-scans",
    )
    if not os.path.isdir(scans):
        return out
    try:
        hosts = os.listdir(scans)
    except OSError:
        return out
    for host_name in hosts:
        host_dir = os.path.join(scans, host_name)
        ffuf_root = os.path.join(host_dir, "ffuf")
        if not os.path.isdir(ffuf_root):
            continue
        try:
            stamps = sorted(
                (
                    d
                    for d in os.listdir(ffuf_root)
                    if os.path.isdir(os.path.join(ffuf_root, d))
                ),
                reverse=True,
            )
        except OSError:
            continue
        json_path = ""
        for stamp in stamps:
            candidate = os.path.join(ffuf_root, stamp, "ffuf.json")
            if os.path.isfile(candidate):
                json_path = candidate
                break
        if not json_path:
            continue
        try:
            data = json.load(open(json_path, encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError, TypeError):
            continue
        results = data.get("results") or []
        if not isinstance(results, list):
            continue
        spa_len = _ffuf_spa_shell_length(results)
        paths: list[str] = []
        seen: set[str] = set()
        for result in results:
            if not isinstance(result, dict):
                continue
            fuzz = _ffuf_result_fuzz(result)
            if not fuzz or not is_login_path(fuzz):
                continue
            # SPA soft-200: same body length as the catch-all shell → ignore.
            if spa_len is not None:
                try:
                    body_len = int(result.get("length"))
                except (TypeError, ValueError):
                    body_len = None
                if body_len is not None and body_len == spa_len:
                    continue
            key = fuzz.lower()
            if key in seen:
                continue
            seen.add(key)
            paths.append(fuzz)
        if paths:
            out[host_name.lower()] = paths
    return out


def host_login_signals(
    host: str,
    tech: dict | None,
    path_hosts: dict[str, list[str]] | None = None,
    skip_hosts: set[str] | None = None,
) -> set[str]:
    """Return set of signal keys present for this host (path/title/tech/status)."""
    signals: set[str] = set()
    host_key = (host or "").lower().strip()
    tech = tech or {}
    path_hosts = path_hosts or {}
    skip_hosts = skip_hosts or set()

    # Skip Microsoft SSO, RNAS remote-access gateways, Citrix→MS SAML, etc.
    if (
        host_key in skip_hosts
        or is_microsoft_login_redirect(tech)
        or is_rnas_access_gateway(host_key, tech)
    ):
        return signals

    if host_key in path_hosts and path_hosts[host_key]:
        signals.add("path")

    title = tech.get("title") or ""
    if is_login_title(title):
        signals.add("title")

    technologies = tech.get("technologies") or ""
    if is_login_tech(technologies):
        signals.add("tech")

    if is_login_status(tech.get("status"), tech):
        signals.add("status")

    return signals


def login_data_attrs(
    host: str,
    tech: dict | None,
    path_hosts: dict[str, list[str]] | None = None,
    skip_hosts: set[str] | None = None,
) -> str:
    """HTML attributes for a public Subdomains row (data-login-path=1 …)."""
    signals = host_login_signals(host, tech, path_hosts, skip_hosts=skip_hosts)
    if not signals:
        return ""
    parts = []
    for key in LOGIN_SIGNAL_ORDER:
        if key in signals:
            parts.append(f' data-login-{key}="1"')
    return "".join(parts)


def login_signal_counts(
    public_rows: list,
    host_tech: dict,
    path_hosts: dict[str, list[str]] | None = None,
    alive_hosts: set | None = None,
    skip_hosts: set[str] | None = None,
) -> list[tuple[str, int]]:
    """Ordered (display_label, host_count) for Active Login pages table.

    Counts unique public hosts per signal. When alive_hosts is set, only those
    hosts are counted (same scope as Categories / tech tables).
    """
    path_hosts = path_hosts or {}
    skip_hosts = skip_hosts or set()
    counters = {key: 0 for key in LOGIN_SIGNAL_ORDER}
    for host, _ip, _cat in public_rows:
        host_key = (host or "").lower()
        if alive_hosts is not None and host_key not in alive_hosts:
            continue
        tech = host_tech.get(host_key, {})
        for key in host_login_signals(
            host, tech, path_hosts, skip_hosts=skip_hosts
        ):
            counters[key] += 1
    rows = []
    for key in LOGIN_SIGNAL_ORDER:
        n = counters[key]
        if n:
            rows.append((LOGIN_SIGNAL_LABELS[key], n))
    return rows


def login_label_html(label):
    """Link Login pages signal labels to filtered Subdomains (?login=path)."""
    label_text = str(label).strip()
    # Map display → query key
    key = label_text.lower()
    if key not in LOGIN_SIGNAL_ORDER:
        for k, disp in LOGIN_SIGNAL_LABELS.items():
            if disp.lower() == key:
                key = k
                break
    escaped = html.escape(label_text)
    href = f"subdomains.htm?login={quote(key, safe='')}"
    return (
        f'<a class="inc-login-subdomains-link" '
        f'href="{html.escape(href, quote=True)}" '
        f'title="Show subdomains with this Login pages signal">'
        f"{escaped}</a>"
    )


def _is_clean_software_pair(name, version):
    """Product + version pair suitable for the Software versions table."""
    name = (name or "").strip()
    version = (version or "").strip()
    if not name or not version:
        return False

    name_key = normalize_tech_separators(name)
    if not name_key or name_key in SOFTWARE_NOISE_PRODUCTS:
        return False
    if is_noise_technology(name):
        return False

    # Short product token (e.g. nginx, jQuery Migrate, Microsoft ASP.NET) — not prose.
    if len(name) > 48 or len(name.split()) > 5:
        return False
    if re.search(r"[;]|plugin for|drag and drop|comfortable|mobile-friendly", name, re.I):
        return False
    if name_key.endswith(" ver") or name_key in {"ver", "version"}:
        return False

    # Real version-ish suffix (starts with digit or v1…); reject control ids / essays.
    if len(version) > 40:
        return False
    if "$" in version or version.lower().startswith("ctl00"):
        return False
    if ";" in version or " · " in version:
        return False
    if not re.match(r"^v?\d", version, re.I):
        return False
    if not re.search(r"\d", version):
        return False
    # IIS:10 is too low-signal for this table (still shown as web server / tech).
    if name_key == "iis" and re.fullmatch(r"10(\.0)?", version):
        return False

    return True


def is_software_version_label(label):
    """True for versioned product labels useful in the Software versions table.

    Accepts short Product:version / Product[version] only. Rejects WhatWeb form
    fields, MetaGenerator marketing blobs, and comma-split prose fragments.
    """
    label = (label or "").strip()
    if not label:
        return False

    if is_noise_technology(label):
        return False

    low = label.lower()
    if low.startswith("x-ua-compatible") or low.startswith("x-powered-by"):
        return False
    # Freeform / multi-product blobs (often MetaGenerator fragments after bad splits).
    if len(label) > 80 or ";" in label or label.count(":") > 1:
        return False
    if re.search(
        r"plugin for wordpress|drag and drop|comfortable|mobile-friendly slider|"
        r"powered by slider|css_print_method|responsive,",
        low,
    ):
        return False

    bracket = re.match(r"^([^:\[]+)\[(.+)\]$", label)
    if bracket:
        return _is_clean_software_pair(bracket.group(1), bracket.group(2))

    if ":" not in label:
        return False

    name, version = label.split(":", 1)
    return _is_clean_software_pair(name, version)


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


def build_active_summary(
    subdomains_path,
    private_path,
    alive_tsv_path,
    httpx_path,
    whatweb_path,
    *,
    force_cve: bool = False,
    force_cve_missing_only: bool = False,
    report_dir: str = "",
):
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

    # Resolve engagement root for host-scans (ffuf path signals).
    if not report_dir:
        # tools/httpx.jsonl → report root
        if httpx_path:
            report_dir = os.path.dirname(os.path.dirname(os.path.abspath(httpx_path)))
    path_hosts = collect_login_path_hosts(report_dir) if report_dir else {}
    login_skip_hosts = collect_login_skip_hosts(host_tech)

    # Status codes: all httpx responses (includes 404/5xx filtered out of "alive").
    status_counter = load_httpx_status_counts(httpx_path)
    responding_hosts = sum(status_counter.values())

    category_counts = {}
    webserver_counts = {}
    technology_counts = {}
    software_version_counts = {}
    cms_counts = {}

    # Category / tech / software / CMS: alive public hosts only (screenshot/whatweb scope).
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
            # One count per CMS product per host (not per version token).
            for cms_name in detect_cms_labels(technologies):
                cms_counts[cms_name] = cms_counts.get(cms_name, 0) + 1

    category_counter = Counter(category_counts)
    webserver_counter = Counter(webserver_counts)
    technology_counter = Counter(technology_counts)
    software_version_counter = Counter(software_version_counts)
    cms_counter = Counter(cms_counts)

    login_rows = login_signal_counts(
        public_rows,
        host_tech,
        path_hosts=path_hosts,
        alive_hosts=alive_hosts,
        skip_hosts=login_skip_hosts,
    )

    lines = []

    status_rows = ordered_status_rows(status_counter)

    software_version_rows = sorted(
        software_version_counter.items(),
        key=lambda item: item[0].lower(),
    )
    software_version_enriched = enrich_software_rows_for_report(
        software_version_rows,
        httpx_path,
        force=force_cve,
        force_missing_only=force_cve_missing_only,
    )

    categories_column = [
        summary_table(
            "Categories",
            "Category",
            counter_rows(category_counter),
            sort_last_labels={"(none)"},
            section_class="inc-active-section--categories",
            label_html_fn=category_label_html,
        ),
        # CMS products found on alive hosts (droopescan/wpscan set); links use ?tech=
        summary_table(
            "CMS",
            "CMS",
            counter_rows(cms_counter),
            section_class="inc-active-section--cms",
            label_html_fn=cms_label_html,
        ),
    ]
    if login_rows:
        categories_column.append(
            summary_table(
                "Login pages",
                "Signal",
                login_rows,
                section_class="inc-active-section--login",
                label_html_fn=login_label_html,
            )
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
                        label_html_fn=status_label_html,
                        title_help=True,
                    ),
                ],
                categories_column,
                [
                    summary_table(
                        "Top web servers",
                        "Web Server",
                        counter_rows(webserver_counter, 5),
                        section_class="inc-active-section--webservers",
                        label_html_fn=webserver_label_html,
                    ),
                    summary_table(
                        "Top technologies",
                        "Technology",
                        counter_rows(technology_counter, 6),
                        section_class="inc-active-section--technologies",
                        label_html_fn=technology_label_html,
                    ),
                ],
                [
                    software_versions_table(software_version_enriched),
                ],
            ]
        )
    )

    return "\n".join(lines)

def _discover_root() -> str:
    explicit = (os.environ.get("DISCOVER") or "").strip()
    if explicit:
        return explicit
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sync_host_scan_ui_assets(report_dir: str) -> None:
    """Copy current host-scan / Subdomains UI assets into the engagement tree.

    Open report does this via import-report.sh; Active rebuild must too so
    tools like robots appear without a separate Open report.
    """
    root = _discover_root()
    src_js = os.path.join(root, "report", "assets", "javascript")
    src_css = os.path.join(root, "report", "assets", "css")
    dst_js = os.path.join(report_dir, "assets", "javascript")
    dst_css = os.path.join(report_dir, "assets", "css")
    try:
        os.makedirs(dst_js, exist_ok=True)
        os.makedirs(dst_css, exist_ok=True)
    except OSError:
        return
    for name in (
        "inc-host-scan.js",
        "inc-shodan.js",
        "inc-subdomains-filter.js",
        "inc-data-table.js",
    ):
        src = os.path.join(src_js, name)
        if os.path.isfile(src):
            try:
                shutil.copy2(src, os.path.join(dst_js, name))
            except OSError:
                pass
    css = os.path.join(src_css, "modern.css")
    if os.path.isfile(css):
        try:
            shutil.copy2(css, os.path.join(dst_css, "modern.css"))
        except OSError:
            pass


def _load_photo_hosts(gowitness_jsonl: str, screenshots_dir: str) -> dict:
    """host -> relative href for gowitness screenshot (https preferred)."""
    photos: dict[str, str] = {}
    if not gowitness_jsonl or not os.path.isfile(gowitness_jsonl) or not screenshots_dir:
        return photos
    with open(gowitness_jsonl, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if entry.get("failed"):
                continue
            file_name = (entry.get("file_name") or "").strip()
            if not file_name:
                continue
            screenshot_path = os.path.join(screenshots_dir, file_name)
            if not os.path.isfile(screenshot_path):
                continue
            url_value = entry.get("url") or entry.get("final_url") or ""
            if "://" not in url_value:
                url_value = "https://" + url_value
            parsed = urlparse(url_value)
            host = (parsed.hostname or "").lower()
            if not host:
                continue
            scheme = parsed.scheme
            rel_href = f"../tools/gowitness/screenshots/{file_name}"
            current = photos.get(host)
            if not current or scheme == "https":
                photos[host] = rel_href
    return photos


def write_subdomains_active_page(report_dir: str) -> dict:
    """Rewrite pages/subdomains.htm Photo/Status/Web Server/Title/Tech from tools/.

    Same data path as Domain Active (httpx + whatweb + gowitness). Keeps the
    Software versions → Subdomains ?software= filter aligned with Active counts.
    """
    report_dir = os.path.abspath(os.path.expanduser(report_dir))
    tools = os.path.join(report_dir, "tools")
    page = os.path.join(report_dir, "pages", "subdomains.htm")
    result: dict = {"ok": False, "report": report_dir, "page": page}

    subdomains_file = os.path.join(tools, "subdomains")
    private_file = os.path.join(tools, "private-subs")
    httpx_path = os.path.join(tools, "httpx.jsonl")
    whatweb_path = os.path.join(tools, "whatweb.json")
    gowitness_jsonl = os.path.join(tools, "gowitness", "gowitness.jsonl")
    screenshots_dir = os.path.join(tools, "gowitness", "screenshots")

    if not os.path.isfile(subdomains_file):
        result["error"] = "missing tools/subdomains"
        return result
    if not os.path.isfile(httpx_path):
        result["error"] = "missing tools/httpx.jsonl"
        return result

    template = os.path.join(_discover_root(), "report", "pages", "subdomains.htm")
    if not os.path.isfile(template):
        result["error"] = f"missing template {template}"
        return result

    host_tech = load_host_tech(
        httpx_path,
        whatweb_path if os.path.isfile(whatweb_path) else "",
    )
    photo_hosts = _load_photo_hosts(
        gowitness_jsonl if os.path.isfile(gowitness_jsonl) else "",
        screenshots_dir if os.path.isdir(screenshots_dir) else "",
    )
    path_hosts = collect_login_path_hosts(report_dir)
    login_skip_hosts = collect_login_skip_hosts(host_tech)

    all_rows = load_subdomain_rows(subdomains_file)
    private_rows = load_subdomain_rows(private_file) if os.path.isfile(private_file) else []
    if not private_rows:
        private_rows = [
            (h, ip, cat) for h, ip, cat in all_rows if ip and is_private_ip(ip)
        ]
    public_rows = [
        (h, ip, cat) for h, ip, cat in all_rows if ip and not is_private_ip(ip)
    ]

    def host_cell(subdomain: str, status: str, url: str) -> str:
        text = html.escape(subdomain)
        if not str(status or "").strip():
            return f'<td class="inc-subdomain-host">{text}</td>'
        href = (url or "").strip()
        if not href:
            href = f"https://{subdomain}"
        elif "://" not in href:
            href = f"https://{href}"
        return (
            f'<td class="inc-subdomain-host">'
            f'<a class="inc-subdomain-host-link" href="{html.escape(href, quote=True)}" '
            f'target="_blank" rel="noopener noreferrer">{text}</a>'
            f"</td>"
        )

    def tech_cell(title: str, technologies: str) -> str:
        title_text = (title or "").strip() or "-"
        tech_title = (
            f' title="{html.escape(technologies)}"' if technologies else ""
        )
        return (
            f'<td class="inc-subdomain-tech">'
            f'<div class="inc-subdomain-title" data-sort-field="title">'
            f"{html.escape(title_text)}</div>"
            f'<div class="inc-subdomain-techs" data-sort-field="tech"{tech_title}>'
            f"{html.escape(technologies)}</div>"
            f"</td>"
        )

    def photo_cell(subdomain: str) -> str:
        href = photo_hosts.get(subdomain.lower())
        if not href:
            return ""
        return f'<a href="{html.escape(href)}" target="_blank">Yes</a>'

    def build_private_table(rows: list) -> list[str]:
        lines = [
            '        <table class="table table-bordered inc-data-table">',
            "            <thead>",
            "                <tr>",
            '                    <th scope="col" class="inc-sortable">Subdomain</th>',
            '                    <th scope="col" class="inc-sortable">Category</th>',
            '                    <th scope="col" class="inc-sortable">Private IP Address</th>',
            "                </tr>",
            "            </thead>",
            "            <tbody>",
        ]
        if rows:
            for subdomain, ipaddr, category in rows:
                lines.append(
                    "                <tr>"
                    f"<td>{html.escape(subdomain)}</td>"
                    f"<td>{html.escape(category)}</td>"
                    f"<td>{html.escape(ipaddr)}</td>"
                    "</tr>"
                )
        else:
            lines.append(
                '<tr><td colspan="3">No private subdomains found.</td></tr>'
            )
        lines.extend(["            </tbody>", "        </table>"])
        return lines

    def build_public_table(rows: list) -> list[str]:
        lines = [
            '        <table class="table table-bordered inc-data-table">',
            "            <thead>",
            "                <tr>",
            '                    <th scope="col" class="inc-sortable">Subdomain</th>',
            '                    <th scope="col" class="inc-sortable">Category</th>',
            '                    <th scope="col" class="inc-sortable">IP Address</th>',
            '                    <th scope="col" class="inc-sortable inc-col-center" data-sort-then="4,5">Photo</th>',
            '                    <th scope="col" class="inc-sortable inc-col-center">Status</th>',
            '                    <th scope="col" class="inc-sortable inc-subdomain-webserver-h">Web Server</th>',
            '                    <th scope="col" class="inc-subdomain-title-tech-header">',
            '                        <span class="inc-sortable" data-sort-field="title">Title</span>',
            '                        <span class="inc-sortable" data-sort-field="tech">Technologies</span>',
            "                    </th>",
            "                </tr>",
            "            </thead>",
            "            <tbody>",
        ]
        if rows:
            for subdomain, ipaddr, category in rows:
                tech = host_tech.get(subdomain.lower(), {})
                status = tech.get("status", "")
                webserver = tech.get("webserver", "")
                title = tech.get("title", "")
                technologies = tech.get("technologies", "")
                row_attrs = login_data_attrs(
                    subdomain, tech, path_hosts, skip_hosts=login_skip_hosts
                )
                lines.append(
                    f"                <tr{row_attrs}>"
                    f"{host_cell(subdomain, status, tech.get('url', ''))}"
                    f"<td>{html.escape(category)}</td>"
                    f'<td class="inc-subdomain-ip">{html.escape(ipaddr)}</td>'
                    f'<td class="inc-col-center">{photo_cell(subdomain)}</td>'
                    f'<td class="inc-col-center">{html.escape(status)}</td>'
                    f'<td class="inc-subdomain-webserver">{html.escape(webserver)}</td>'
                    f"{tech_cell(title, technologies)}"
                    "</tr>"
                )
        else:
            lines.append(
                '<tr><td colspan="7">No data found.</td></tr>'
            )
        lines.extend(["            </tbody>", "        </table>"])
        return lines

    # Company / domain for template placeholders
    company = ""
    domain = os.path.basename(report_dir.rstrip(os.sep))
    for source in (
        os.path.join(report_dir, "pages", "active.htm"),
        os.path.join(report_dir, "index.htm"),
    ):
        if not os.path.isfile(source):
            continue
        text = open(source, encoding="utf-8", errors="replace").read()
        m = re.search(
            r'inc-home-meta-label">Company</span>\s*<span class="value">([^<]*)</span>',
            text,
        )
        if m and not company:
            company = m.group(1).strip()
        m = re.search(
            r'inc-home-meta-label">Domain</span>\s*<span class="value">([^<]*)</span>',
            text,
        )
        if m:
            domain = m.group(1).strip() or domain

    content = open(template, encoding="utf-8").read()
    content = content.replace("#COMPANY#", company)
    content = content.replace("#DOMAIN#", domain)
    # Keep host-scan expand assets current (robots tool, etc.).
    sync_host_scan_ui_assets(report_dir)
    # Template ends before dynamic tables (same as Active: append after copy).
    # Write template then append tables (mirrors f_active_write_report).
    os.makedirs(os.path.dirname(page), exist_ok=True)
    with open(page, "w", encoding="utf-8") as handle:
        handle.write(content)

    out: list[str] = []
    if private_rows:
        out.append('    <div class="inc-content-frame inc-content-frame--table">')
        out.extend(build_private_table(private_rows))
        out.append("    </div>")
    if public_rows or not private_rows:
        out.append(
            '    <div class="inc-content-frame inc-content-frame--table inc-subdomains-public">'
        )
        out.extend(build_public_table(public_rows if public_rows else []))
        out.append("    </div>")
    out.extend(
        [
            "    </div>",
            "</div>",
            "",
            '<script src="../assets/javascript/inc-data-table.js"></script>',
            '<script src="../tools/cve-software-index.js"></script>',
            '<script src="../assets/javascript/inc-subdomains-filter.js?v=17"></script>',
            '<script src="../tools/shodan/index.js"></script>',
            '<script src="../tools/shodan/kev-ids.js"></script>',
            '<script src="../assets/javascript/inc-shodan.js?v=18"></script>',
            '<script src="../assets/javascript/inc-host-scan.js?v=37"></script>',
            "</body>",
            "</html>",
            "",
        ]
    )
    with open(page, "a", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")

    result["ok"] = True
    result["public_hosts"] = len(public_rows)
    return result


def rebuild_active_page(
    report_dir: str,
    *,
    force_cve: bool = False,
    force_cve_missing_only: bool = True,
) -> dict:
    """Rebuild pages/active.htm from existing tools/ artifacts + NVD enrich.

    Used by statusd POST /software-cve-refresh (operator Update modal).
    Does not re-run httpx/whatweb/gowitness.
    Also refreshes pages/subdomains.htm Active columns so software/tech filters
    match Software versions counts.
    """
    report_dir = os.path.abspath(os.path.expanduser(report_dir))
    tools = os.path.join(report_dir, "tools")
    page = os.path.join(report_dir, "pages", "active.htm")
    result = {
        "ok": False,
        "report": report_dir,
        "page": page,
        "force_cve": force_cve,
        "force_cve_missing_only": force_cve_missing_only,
    }

    paths = {
        "subdomains": os.path.join(tools, "subdomains"),
        "private": os.path.join(tools, "private-subs"),
        "alive": os.path.join(tools, "active-alive.tsv"),
        "httpx": os.path.join(tools, "httpx.jsonl"),
        "whatweb": os.path.join(tools, "whatweb.json"),
    }
    if not os.path.isfile(paths["httpx"]):
        result["error"] = "missing tools/httpx.jsonl — run Active recon first"
        return result
    if not os.path.isfile(paths["subdomains"]):
        result["error"] = "missing tools/subdomains"
        return result

    summary = build_active_summary(
        paths["subdomains"],
        paths["private"] if os.path.isfile(paths["private"]) else "",
        paths["alive"] if os.path.isfile(paths["alive"]) else "",
        paths["httpx"],
        paths["whatweb"] if os.path.isfile(paths["whatweb"]) else "",
        force_cve=force_cve,
        force_cve_missing_only=force_cve_missing_only,
    )
    scan_date = httpx_scan_date(paths["httpx"])

    template = os.path.join(_discover_root(), "report", "pages", "active.htm")
    if os.path.isfile(template):
        content = open(template, encoding="utf-8").read()
    elif os.path.isfile(page):
        # Fall back: replace body content block if markers missing
        content = open(page, encoding="utf-8").read()
        if "#ACTIVE_CONTENT#" not in content:
            # Strip previous dynamic content between container markers is fragile;
            # require template from Discover install.
            result["error"] = f"Discover active.htm template not found at {template}"
            return result
    else:
        result["error"] = "active.htm template and report page both missing"
        return result

    # Preserve company/domain from existing report index or page
    company = ""
    domain = ""
    index_htm = os.path.join(report_dir, "index.htm")
    for source in (page if os.path.isfile(page) else "", index_htm):
        if not source or not os.path.isfile(source):
            continue
        text = open(source, encoding="utf-8", errors="replace").read()
        import re as _re

        m = _re.search(
            r'inc-home-meta-label">Company</span>\s*<span class="value">([^<]*)</span>',
            text,
        )
        if m and not company:
            company = m.group(1).strip()
        m = _re.search(
            r'inc-home-meta-label">Domain</span>\s*<span class="value">([^<]*)</span>',
            text,
        )
        if m and not domain:
            domain = m.group(1).strip()
    if not domain:
        domain = os.path.basename(report_dir.rstrip(os.sep))

    content = content.replace("#ACTIVE_CONTENT#", summary)
    content = content.replace("#ACTIVE_SCAN_DATE#", scan_date)
    content = content.replace("#COMPANY#", company)
    content = content.replace("#DOMAIN#", domain)

    os.makedirs(os.path.dirname(page), exist_ok=True)
    with open(page, "w", encoding="utf-8") as handle:
        handle.write(content)

    # Keep Subdomains filter targets in sync with Active software/tech counts.
    sub_result = write_subdomains_active_page(report_dir)
    result["subdomains_rebuilt"] = bool(sub_result.get("ok"))
    if not sub_result.get("ok"):
        result["subdomains_error"] = sub_result.get("error") or "subdomains rebuild failed"

    try:
        touch_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "touch-report-date.py")
        if os.path.isfile(touch_path):
            spec_t = importlib.util.spec_from_file_location("touch_report_date", touch_path)
            if spec_t is not None and spec_t.loader is not None:
                touch_mod = importlib.util.module_from_spec(spec_t)
                spec_t.loader.exec_module(touch_mod)
                touch_mod.touch_report_index_date(report_dir)
    except Exception:
        pass

    result["ok"] = True
    result["scan_date"] = scan_date
    result["stats"] = getattr(enrich_software_rows_for_report, "last_stats", {}) or {}
    return result


def _append_audit_refresh(report_dir: str, action: str) -> None:
    """Best-effort audit line (operator name; egress may be unknown)."""
    try:
        software_cve = _load_software_cve_module()
        if hasattr(software_cve, "load_discover_env_files"):
            software_cve.load_discover_env_files()
    except Exception:
        pass
    audit_dir = os.path.join(report_dir, "tools", "audit")
    audit_log = os.path.join(audit_dir, "log.txt")
    try:
        os.makedirs(audit_dir, exist_ok=True)
    except OSError:
        return
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%m-%d-%Y - %H:%M Z")
    op = "unknown"
    try:
        op_path = os.path.join(os.path.expanduser("~"), ".discover", "operator-name")
        if os.path.isfile(op_path):
            raw = open(op_path, encoding="utf-8", errors="replace").readline().strip()
            cleaned = re.sub(r"[^A-Za-z]", "", raw)[:10]
            if cleaned:
                op = cleaned[0].upper() + cleaned[1:].lower() if len(cleaned) > 1 else cleaned.upper()
    except OSError:
        pass
    if not action.endswith("."):
        action = action + "."
    # Software CVE / NVD refresh: no operator egress IP on Audit (dash placeholder).
    line = f"{ts} | {op} | - | {action}\n"
    try:
        with open(audit_log, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass


if __name__ == "__main__":
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(
        description="Rebuild Active page software CVEs from existing tools/ data.",
    )
    parser.add_argument(
        "report_dir",
        nargs="?",
        help="Engagement report root (contains tools/ and pages/)",
    )
    parser.add_argument(
        "--refresh-cves",
        action="store_true",
        help="Force re-query NVD for missing/zero-CVE software and rebuild active.htm",
    )
    parser.add_argument(
        "--force-all",
        action="store_true",
        help="With --refresh-cves: re-query all CPE-mapped products (not only missing/empty)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON result",
    )
    parser.add_argument(
        "--skip-audit",
        action="store_true",
        help="Do not append audit log",
    )
    args = parser.parse_args()
    if not args.refresh_cves or not args.report_dir:
        parser.print_help()
        raise SystemExit(2)

    out = rebuild_active_page(
        args.report_dir,
        force_cve=bool(args.force_all),
        force_cve_missing_only=not bool(args.force_all),
    )
    if out.get("ok") and not args.skip_audit:
        stats = out.get("stats") or {}
        looked = stats.get("looked_up", 0)
        _append_audit_refresh(
            args.report_dir,
            f"Updated software CVE data ({looked} NVD lookups"
            + (", force-all" if args.force_all else ", missing/empty only")
            + ")",
        )
    if args.json:
        print(_json.dumps(out, separators=(",", ":")))
    else:
        if out.get("ok"):
            print(f"[*] Rebuilt {out.get('page')}")
            print(f"    stats: {out.get('stats')}")
        else:
            print(f"[!] {out.get('error')}", file=sys.stderr)
            raise SystemExit(1)
