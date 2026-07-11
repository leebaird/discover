import html
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


def technology_base_name(label):
    label = str(label).strip()
    if ":" in label:
        label = label.split(":", 1)[0].strip()
    elif "[" in label:
        label = label.split("[", 1)[0].strip()
    return label.lower().replace(" ", "-")


def is_noise_technology(label):
    return technology_base_name(label) in NOISE_PLUGINS


TECH_ALIASES = {
    "apache http server": "apache",
    "asp_net": "asp.net",
    "google cloud cdn": "google cloud",
    "google cloud load balancing": "google cloud",
    "jquery": "jquery",
    "microsoft asp.net": "asp.net",
    "microsoft-iis": "iis",
}


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
        return f"{name}:{', '.join(values)}"
    return name


def tech_key(label):
    label = str(label).strip()
    if not label:
        return ""

    lower = label.lower()

    if lower.startswith("x-powered-by:"):
        inner = label.split(":", 1)[1].strip().lower()
        return TECH_ALIASES.get(inner, inner.replace(" ", ""))

    if lower.startswith("x-powered-by["):
        inner = label[label.index("[") + 1 : label.rindex("]")].strip().lower()
        return TECH_ALIASES.get(inner, inner.replace(" ", ""))

    base = label.split("[", 1)[0].strip().lower()
    if ":" in base:
        base = base.split(":", 1)[0].strip()

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
                "httpx_tech": [
                    str(item).strip() for item in (entry.get("tech") or []) if str(item).strip()
                ],
                "score": httpx_score(entry),
            }

            current = rows.get(host)
            if not current or candidate["score"] > current["score"]:
                rows[host] = candidate
    return rows


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


WEBSERVER_TECH_ALIASES = {
    "microsoft-iis": "iis",
}

WEBSERVER_SHORT_NAMES = {
    "apache": "Apache",
    "microsoft-iis": "Microsoft-IIS",
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
            name = re.sub(r"\s+", "", raw_name.lower())
            version = trim_version(match.group(2).strip())
            tech_name = WEBSERVER_TECH_ALIASES.get(name, name)
            if tech_name in covered and version in covered[tech_name]:
                short_name = WEBSERVER_SHORT_NAMES.get(name)
                if short_name:
                    kept.append(short_name)
                    continue
                continue
        kept.append(segment)
    return " ".join(kept)


def format_technology_label(label):
    label = str(label).strip()
    bracket = re.match(r"^([^:\[]+)\[(.+)\]$", label)
    if bracket:
        label = f"{bracket.group(1)}:{bracket.group(2)}"
    if ":" in label:
        name, version = label.split(":", 1)
        if version.strip().upper() == "N/A":
            label = name.strip()
    match = re.match(r"^IIS:(.+)$", label, re.IGNORECASE)
    if match:
        return f"IIS:{trim_version(match.group(1))}"
    if re.match(r"^Nginx(?=:|$)", label, re.IGNORECASE):
        return f"nginx{label[5:]}"
    return label


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
STATUS_CODE_ORDER = (200, 301, 303, 403, 302, 404, 503)


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


def build_active_summary(subdomains_path, private_path, alive_tsv_path, httpx_path, whatweb_path):
    public_rows = load_subdomain_rows(subdomains_path)
    private_count = sum(1 for _ in load_subdomain_rows(private_path))
    alive_hosts = load_alive_hosts(alive_tsv_path)
    host_tech = load_host_tech(httpx_path, whatweb_path)

    category_counts = {}
    webserver_counts = {}
    technology_counts = {}
    status_counts = {}

    for host, _ipaddr, category in public_rows:
        host_key = host.lower()
        if host_key not in alive_hosts:
            continue
        label = category.strip() or "(none)"
        category_counts[label] = category_counts.get(label, 0) + 1

        status_counts[alive_hosts[host_key]] = (
            status_counts.get(alive_hosts[host_key], 0) + 1
        )

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

    category_counter = Counter(category_counts)
    webserver_counter = Counter(webserver_counts)
    technology_counter = Counter(technology_counts)
    status_counter = Counter(status_counts)

    alive_count = sum(status_counter.values())
    lines = []

    status_rows = [
        (str(code), status_counter.get(code, 0)) for code in STATUS_CODE_ORDER
    ]
    for code in sorted(status_counter):
        if code not in STATUS_CODE_ORDER:
            status_rows.append((str(code), status_counter[code]))

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
                            ("Alive hosts", alive_count),
                        ],
                    ),
                ],
                [
                    summary_table(
                        "Alive by category",
                        "Category",
                        counter_rows(category_counter),
                        sort_last_labels={"(none)"},
                    ),
                ],
                [
                    summary_table(
                        "Status codes (alive hosts)",
                        "Status Code",
                        status_rows,
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
            ]
        )
    )

    return "\n".join(lines)