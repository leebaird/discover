"""Map Discover software version labels to NVD CVEs / CVSS scores.

Results are cached under the report tools directory so active report rebuilds
do not re-query NVD for every run. Set NVD_API_KEY for higher rate limits.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "Discover-software-cve/1.0 (https://github.com/leebaird/discover)"
DEFAULT_SLEEP_SECONDS = 6.5  # stay under unauthenticated NVD rate limits
CACHE_VERSION = 1

# product base name (after tech normalization) -> (cpe_vendor, cpe_product)
CPE_PRODUCT_MAP = {
    "apache": ("apache", "http_server"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "drupal": ("drupal", "drupal"),
    "grafana": ("grafana", "grafana"),
    "java servlet": ("oracle", "java_servlet"),
    "javaserver pages": ("oracle", "jsp"),
    "jquery": ("jquery", "jquery"),
    "jquery migrate": ("jquery", "jquery_migrate"),
    "jquery ui": ("jquery", "jquery_ui"),
    "kibana": ("elastic", "kibana"),
    "microsoft asp.net": ("microsoft", "asp.net"),
    "asp.net": ("microsoft", "asp.net"),
    "microsoft httpapi": ("microsoft", "httpapi"),
    "mod jk": ("apache", "tomcat_connectors"),
    "mod_jk": ("apache", "tomcat_connectors"),
    "nginx": ("f5", "nginx"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "underscore.js": ("jashkenas", "underscore"),
    "varnish": ("varnish_cache", "varnish"),
}

# Skip low-signal or poorly CPE-mapped banners.
SKIP_PRODUCTS = {
    "microsoft httpapi",
    "java servlet",
    "javaserver pages",
}


def parse_software_label(label: str) -> tuple[str, str]:
    """Return (product_name, version) from a formatted tech label."""
    label = (label or "").strip()
    if not label:
        return "", ""

    bracket = re.match(r"^([^:\[]+)\[(.+)\]$", label)
    if bracket:
        return bracket.group(1).strip(), bracket.group(2).strip()

    if ":" in label:
        name, version = label.split(":", 1)
        return name.strip(), version.strip()

    return label, ""


def product_key(product_name: str) -> str:
    name = re.sub(r"[-_\s]+", " ", (product_name or "").strip().lower()).strip()
    return name


def build_cpe23(product_name: str, version: str) -> str | None:
    key = product_key(product_name)
    if not key or not version or key in SKIP_PRODUCTS:
        return None

    mapping = CPE_PRODUCT_MAP.get(key)
    if not mapping:
        return None

    vendor, product = mapping
    # CPE 2.3 component escaping: keep simple versions as-is.
    ver = version.replace(":", "\\:")
    return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"


def cache_key(product_name: str, version: str) -> str:
    return f"{product_key(product_name)}|{version.strip()}"


def load_cache(path: str) -> dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {"version": CACHE_VERSION, "entries": {}}

    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"version": CACHE_VERSION, "entries": {}}

    if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
        return {"version": CACHE_VERSION, "entries": {}}

    entries = payload.get("entries")
    if not isinstance(entries, dict):
        entries = {}
    return {"version": CACHE_VERSION, "entries": entries}


def save_cache(path: str, cache: dict[str, Any]) -> None:
    if not path:
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(cache, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


def extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str]:
    """Prefer CVSS v3.1 > v3.0 > v4.0 > v2.0. Return (score, severity)."""
    if not isinstance(metrics, dict):
        return None, ""

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        items = metrics.get(key)
        if not isinstance(items, list) or not items:
            continue
        primary = None
        for item in items:
            if isinstance(item, dict) and item.get("type") == "Primary":
                primary = item
                break
        if primary is None:
            primary = items[0] if isinstance(items[0], dict) else None
        if not primary:
            continue
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        severity = (
            data.get("baseSeverity")
            or primary.get("baseSeverity")
            or ""
        )
        try:
            return float(score), str(severity).upper()
        except (TypeError, ValueError):
            continue
    return None, ""


def nvd_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    api_key = (os.environ.get("NVD_API_KEY") or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def nvd_get(params: dict[str, str], timeout: float = 45.0) -> dict[str, Any] | None:
    query = urllib.parse.urlencode(params)
    url = f"{NVD_CVE_API}?{query}"
    req = urllib.request.Request(url, headers=nvd_headers())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def query_nvd_for_cpe(cpe23: str, results_per_page: int = 100) -> list[dict[str, Any]]:
    """Return simplified CVE records for a CPE name."""
    params = {
        "cpeName": cpe23,
        "resultsPerPage": str(results_per_page),
    }
    payload = nvd_get(params)
    if not payload:
        return []

    out = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id") or ""
        score, severity = extract_cvss(cve.get("metrics") or {})
        if not cve_id:
            continue
        out.append(
            {
                "id": cve_id,
                "score": score,
                "severity": severity,
            }
        )
    return out


def query_nvd_keyword(product: str, version: str, results_per_page: int = 50) -> list[dict[str, Any]]:
    """Fallback keyword search when CPE mapping is unavailable."""
    keyword = f"{product} {version}".strip()
    if not keyword:
        return []
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(results_per_page),
    }
    payload = nvd_get(params)
    if not payload:
        return []

    out = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id") or ""
        score, severity = extract_cvss(cve.get("metrics") or {})
        if not cve_id:
            continue
        out.append(
            {
                "id": cve_id,
                "score": score,
                "severity": severity,
            }
        )
    return out


def summarize_cves(cves: list[dict[str, Any]]) -> dict[str, Any]:
    max_score = None
    max_severity = ""
    top_cve = ""
    scored = []
    for entry in cves:
        score = entry.get("score")
        if score is None:
            continue
        scored.append(entry)
        if max_score is None or score > max_score:
            max_score = score
            max_severity = entry.get("severity") or ""
            top_cve = entry.get("id") or ""

    return {
        "cve_count": len(cves),
        "max_cvss": max_score,
        "max_severity": max_severity,
        "top_cve": top_cve,
        "cves": sorted(
            scored,
            key=lambda item: (-(item.get("score") or 0), item.get("id") or ""),
        )[:20],
        "source": "nvd",
    }


def lookup_software(
    product_name: str,
    version: str,
    cache: dict[str, Any],
    sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
    allow_keyword_fallback: bool = False,
) -> dict[str, Any]:
    key = cache_key(product_name, version)
    entries = cache.setdefault("entries", {})
    if key in entries:
        return entries[key]

    result: dict[str, Any] = {
        "product": product_name,
        "version": version,
        "cpe": None,
        "cve_count": 0,
        "max_cvss": None,
        "max_severity": "",
        "top_cve": "",
        "cves": [],
        "source": "",
        "error": "",
    }

    if product_key(product_name) in SKIP_PRODUCTS:
        result["error"] = "skipped"
        entries[key] = result
        return result

    cpe = build_cpe23(product_name, version)
    result["cpe"] = cpe
    cves: list[dict[str, Any]] = []

    if cpe:
        cves = query_nvd_for_cpe(cpe)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    elif allow_keyword_fallback:
        cves = query_nvd_keyword(product_name, version)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    else:
        result["error"] = "no-cpe"
        entries[key] = result
        return result

    if cves is None:
        result["error"] = "nvd-error"
        entries[key] = result
        return result

    summary = summarize_cves(cves)
    result.update(summary)
    entries[key] = result
    return result


def format_cvss(score: float | None) -> str:
    if score is None:
        return ""
    return f"{score:.1f}"


def enrich_software_version_rows(
    rows: list[tuple[str, int]],
    cache_path: str,
    sleep_seconds: float | None = None,
    progress: bool = False,
) -> list[tuple[str, int, str, str, str]]:
    """Enrich (label, count) rows with CVSS fields.

    Returns list of:
      (label, count, max_cvss_display, cve_count_display, top_cve)

    Missing CVSS/CVE data uses blank cells (not dashes) so descending
    sorts put real scores first.
    """
    if sleep_seconds is None:
        # Authenticated NVD allows ~50 req/30s; unauthenticated ~5/30s.
        sleep_seconds = 0.7 if (os.environ.get("NVD_API_KEY") or "").strip() else DEFAULT_SLEEP_SECONDS

    cache = load_cache(cache_path)
    enriched: list[tuple[str, int, str, str, str]] = []
    dirty = False

    for index, (label, count) in enumerate(rows, start=1):
        product, version = parse_software_label(label)
        key = cache_key(product, version)
        cached = cache.get("entries", {}).get(key)
        if cached is None:
            if progress:
                print(f"[*] NVD lookup {index}/{len(rows)}: {label}")
            lookup_software(product, version, cache, sleep_seconds=sleep_seconds)
            dirty = True
            cached = cache["entries"].get(key) or {}

        error = cached.get("error") or ""
        max_cvss = format_cvss(cached.get("max_cvss"))
        cve_count = cached.get("cve_count") or 0
        top_cve = cached.get("top_cve") or ""

        if error in {"skipped", "no-cpe", "nvd-error"} or not max_cvss:
            max_cvss = ""
            top_cve = ""
            cve_count_display = ""
        elif cve_count:
            cve_count_display = str(cve_count)
        else:
            cve_count_display = ""

        enriched.append((label, count, max_cvss, cve_count_display, top_cve))

    if dirty:
        save_cache(cache_path, cache)

    return enriched


def collect_httpx_cpes(httpx_path: str) -> dict[str, list[str]]:
    """Optional helper: host -> list of CPE strings from httpx.jsonl."""
    by_host: dict[str, list[str]] = {}
    if not httpx_path or not os.path.isfile(httpx_path):
        return by_host

    with open(httpx_path, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            host = (entry.get("input") or entry.get("host") or "").strip().lower()
            if not host:
                continue
            cpes = []
            for item in entry.get("cpe") or []:
                if isinstance(item, dict):
                    cpe = (item.get("cpe") or "").strip()
                else:
                    cpe = str(item).strip()
                if cpe:
                    cpes.append(cpe)
            if cpes:
                by_host[host] = cpes
    return by_host
