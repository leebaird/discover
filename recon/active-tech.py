import json
import os
import re
from urllib.parse import urlparse

NOISE_PLUGINS = {
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
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

TECH_ALIASES = {
    "apache http server": "apache",
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

    if values:
        return f"{name}[{', '.join(values)}]"
    return name


def tech_key(label):
    label = str(label).strip()
    if not label:
        return ""

    lower = label.lower()

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
        if not match:
            continue
        name = re.sub(r"\s+", "", match.group(1).strip().lower())
        version = match.group(2).strip()
        versions.setdefault(name, set()).add(version)
    return versions


WEBSERVER_TECH_ALIASES = {
    "microsoft-iis": "iis",
}


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
                if name == "microsoft-iis":
                    kept.append("Microsoft-IIS")
                    continue
                continue
        kept.append(segment)
    return " ".join(kept)


def format_technology_label(label):
    label = str(label).strip()
    match = re.match(r"^IIS:(.+)$", label, re.IGNORECASE)
    if match:
        return f"IIS:{trim_version(match.group(1))}"
    return label


def merge_technologies(httpx_tech, whatweb_plugins):
    merged = {}
    httpx_keys = set()

    for item in httpx_tech:
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
            if "[" not in current and ":" not in current and "[" in item:
                merged[key] = item
        elif "[" in item and "[" not in current:
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