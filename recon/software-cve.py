"""Map Discover software version labels to NVD CVEs / CVSS scores.

Results are cached under the report tools directory so active report rebuilds
do not re-query NVD for every run.

NVD_API_KEY (optional) enables higher rate limits. Discover checks, in order:
  1. Existing shell environment (export NVD_API_KEY=...)
  2. Private key file: ~/.discover/api-keys

Legacy ``$DISCOVER/.env`` and ``~/.discover/.env`` are moved into
``~/.discover/api-keys`` automatically when found (merge; existing api-keys
values win; legacy files are removed after a successful write).

Request a free key: https://nvd.nist.gov/developers/request-an-api-key
Skip lookups: DISCOVER_SKIP_CVE=1
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
CACHE_VERSION = 2
_ENV_FILES_LOADED = False
NVD_RESULTS_PER_PAGE = 2000  # NVD maximum per request

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
    "passwordfield",
    "emailfield",
    "textfield",
    "hiddenfield",
    "metagenerator",
    "poweredby",
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


def discover_root() -> str:
    explicit = (os.environ.get("DISCOVER") or "").strip()
    if explicit:
        return explicit
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def env_file_paths() -> list[str]:
    """Private API key file locations (after legacy migration).

    Preferred: ``~/.discover/api-keys``. Legacy ``.env`` paths are listed only
    as a fallback if migration could not remove them.
    """
    home_discover = os.path.join(os.path.expanduser("~"), ".discover")
    candidates = [
        os.path.join(home_discover, "api-keys"),
        os.path.join(discover_root(), ".env"),
        os.path.join(home_discover, ".env"),
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for path in candidates:
        abs_path = os.path.abspath(path)
        if abs_path in seen:
            continue
        seen.add(abs_path)
        paths.append(abs_path)
    return paths


def legacy_api_key_env_paths() -> list[str]:
    """Legacy locations that should be moved into ``~/.discover/api-keys``."""
    home_discover = os.path.join(os.path.expanduser("~"), ".discover")
    return [
        os.path.abspath(os.path.join(discover_root(), ".env")),
        os.path.abspath(os.path.join(home_discover, ".env")),
    ]


def parse_env_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[7:].strip()
    if "=" not in line:
        return None

    key, _, value = line.partition("=")
    key = key.strip()
    if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return None

    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return key, value


def _read_env_file_pairs(path: str) -> list[tuple[str, str]]:
    """Return ordered (key, value) pairs from a KEY=VALUE file."""
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    try:
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                parsed = parse_env_line(raw)
                if not parsed:
                    continue
                key, value = parsed
                if key in seen:
                    continue
                seen.add(key)
                pairs.append((key, value))
    except OSError:
        return []
    return pairs


def migrate_legacy_api_key_files() -> list[str]:
    """Move legacy ``.env`` key files into ``~/.discover/api-keys``.

    - If ``api-keys`` is missing, create it from legacy content (home ``.env``
      first, then ``$DISCOVER/.env`` for keys not already present).
    - If ``api-keys`` exists, keep its values; fill missing keys from legacy.
    - After a successful write, remove each legacy file that was migrated.

    Returns absolute paths of legacy files successfully removed.
    """
    home_discover = os.path.join(os.path.expanduser("~"), ".discover")
    api_keys_path = os.path.abspath(os.path.join(home_discover, "api-keys"))
    legacy_paths = [p for p in legacy_api_key_env_paths() if os.path.isfile(p)]
    # Never treat api-keys itself as legacy
    legacy_paths = [p for p in legacy_paths if p != api_keys_path]
    if not legacy_paths:
        return []

    # Merge: existing api-keys wins, then home .env, then $DISCOVER/.env
    # legacy_api_key_env_paths order is discover then home — prefer home first
    # for content when api-keys is empty.
    home_env = os.path.abspath(os.path.join(home_discover, ".env"))
    disc_env = os.path.abspath(os.path.join(discover_root(), ".env"))
    read_order: list[str] = []
    if os.path.isfile(api_keys_path):
        read_order.append(api_keys_path)
    for p in (home_env, disc_env):
        if p in legacy_paths and p not in read_order:
            read_order.append(p)

    merged: list[tuple[str, str]] = []
    seen_keys: set[str] = set()
    for path in read_order:
        for key, value in _read_env_file_pairs(path):
            if key in seen_keys:
                continue
            seen_keys.add(key)
            merged.append((key, value))

    if not merged and not os.path.isfile(api_keys_path):
        # Empty legacy files — still remove them so they don't linger
        removed: list[str] = []
        for path in legacy_paths:
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                pass
        return removed

    try:
        os.makedirs(home_discover, exist_ok=True)
        tmp_path = api_keys_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write("# Discover API keys — ~/.discover/api-keys\n")
            handle.write("# Shell exports always win over values in this file.\n")
            if legacy_paths:
                handle.write(
                    "# Migrated from legacy .env location(s); edit this file only.\n"
                )
            handle.write("\n")
            for key, value in merged:
                # Values may contain spaces; write unquoted when safe
                handle.write(f"{key}={value}\n")
        os.replace(tmp_path, api_keys_path)
        try:
            os.chmod(api_keys_path, 0o600)
        except OSError:
            pass
    except OSError:
        # Leave legacy files in place if we cannot write the destination
        try:
            if os.path.isfile(api_keys_path + ".tmp"):
                os.remove(api_keys_path + ".tmp")
        except OSError:
            pass
        return []

    removed = []
    for path in legacy_paths:
        try:
            os.remove(path)
            removed.append(path)
        except OSError:
            pass
    return removed


def load_discover_env_files() -> list[str]:
    """Load KEY=VALUE pairs from private key files (api-keys / legacy .env).

    Migrates legacy ``.env`` files into ``~/.discover/api-keys`` first.
    Non-empty variables already present in the process environment (e.g. from
    ``export NVD_API_KEY=...``) are never overridden.
    """
    global _ENV_FILES_LOADED
    loaded: list[str] = []

    try:
        migrate_legacy_api_key_files()
    except Exception:
        # Never block key loading if migration fails
        pass

    for path in env_file_paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                for raw in handle:
                    parsed = parse_env_line(raw)
                    if not parsed:
                        continue
                    key, value = parsed
                    if (os.environ.get(key) or "").strip():
                        continue
                    os.environ[key] = value
            loaded.append(path)
        except OSError:
            continue

    _ENV_FILES_LOADED = True
    return loaded


def get_nvd_api_key() -> str:
    """Return NVD API key from shell env or private key files."""
    if not _ENV_FILES_LOADED:
        load_discover_env_files()
    return (os.environ.get("NVD_API_KEY") or "").strip()


def nvd_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    api_key = get_nvd_api_key()
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


def _parse_nvd_vulnerabilities(payload: dict[str, Any]) -> list[dict[str, Any]]:
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


def query_nvd_for_cpe(
    cpe23: str,
    results_per_page: int = NVD_RESULTS_PER_PAGE,
    sleep_seconds: float = 0.0,
) -> list[dict[str, Any]]:
    """Return simplified CVE records for a CPE name (paginated)."""
    out: list[dict[str, Any]] = []
    start_index = 0
    total_results = None

    while True:
        params = {
            "cpeName": cpe23,
            "resultsPerPage": str(results_per_page),
            "startIndex": str(start_index),
        }
        payload = nvd_get(params)
        if not payload:
            break

        batch = _parse_nvd_vulnerabilities(payload)
        out.extend(batch)
        if total_results is None:
            try:
                total_results = int(payload.get("totalResults") or 0)
            except (TypeError, ValueError):
                total_results = 0

        start_index += len(batch)
        if not batch or start_index >= total_results:
            break
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

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


def cisa_kev_catalog_path() -> str:
    return os.path.join(discover_root(), "resource", "known_exploited_vulnerabilities.json")


def load_cisa_kev_ids(path: str | None = None) -> set[str]:
    """Load CVE IDs from the CISA KEV catalog (resource/ or explicit path)."""
    catalog = path or cisa_kev_catalog_path()
    if not catalog or not os.path.isfile(catalog):
        return set()

    try:
        with open(catalog, encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return set()

    ids: set[str] = set()
    for entry in payload.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve_id = (entry.get("cveID") or entry.get("cve_id") or "").strip().upper()
        if cve_id.startswith("CVE-"):
            ids.add(cve_id)
    return ids


def _cve_sort_key(item: dict[str, Any]) -> tuple:
    return (
        item.get("score") is None,
        -(item.get("score") or 0),
        item.get("id") or "",
    )


def select_top_cve(
    cves: list[dict[str, Any]],
    kev_ids: set[str] | None = None,
) -> tuple[str, bool]:
    """Pick Top CVE: prefer CISA KEV matches (highest CVSS), else highest CVSS.

    Returns (cve_id, is_kev).
    """
    kev_ids = kev_ids or set()
    if not cves:
        return "", False

    kev_matches = [
        entry
        for entry in cves
        if (entry.get("id") or "").strip().upper() in kev_ids
    ]
    pool = kev_matches if kev_matches else cves
    ordered = sorted(pool, key=_cve_sort_key)
    top = ordered[0]
    cve_id = (top.get("id") or "").strip().upper()
    return cve_id, bool(cve_id and cve_id in kev_ids)


def summarize_cves(
    cves: list[dict[str, Any]],
    kev_ids: set[str] | None = None,
) -> dict[str, Any]:
    max_score = None
    max_severity = ""
    ordered = sorted(cves, key=_cve_sort_key)
    for entry in ordered:
        score = entry.get("score")
        if score is None:
            continue
        if max_score is None or score > max_score:
            max_score = score
            max_severity = entry.get("severity") or ""

    top_cve, top_is_kev = select_top_cve(cves, kev_ids)

    return {
        "cve_count": len(cves),
        "max_cvss": max_score,
        "max_severity": max_severity,
        "top_cve": top_cve,
        "top_is_kev": top_is_kev,
        "cves": ordered,
        "source": "nvd",
    }


def lookup_software(
    product_name: str,
    version: str,
    cache: dict[str, Any],
    sleep_seconds: float = DEFAULT_SLEEP_SECONDS,
    allow_keyword_fallback: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    key = cache_key(product_name, version)
    entries = cache.setdefault("entries", {})
    if key in entries and not force:
        return entries[key]
    if force and key in entries:
        del entries[key]

    result: dict[str, Any] = {
        "product": product_name,
        "version": version,
        "cpe": None,
        "cve_count": 0,
        "max_cvss": None,
        "max_severity": "",
        "top_cve": "",
        "top_is_kev": False,
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
        cves = query_nvd_for_cpe(cpe, sleep_seconds=sleep_seconds)
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

    # KEV preference applied at enrich time against the current catalog so
    # Update-refreshed KEV data applies without re-querying NVD.
    summary = summarize_cves(cves, kev_ids=None)
    result.update(summary)
    entries[key] = result
    return result


def format_cvss(score: float | None) -> str:
    if score is None:
        return ""
    return f"{score:.1f}"


def _should_requery_cached(
    product_name: str,
    cached: dict[str, Any] | None,
    *,
    force: bool,
    force_missing_only: bool,
) -> bool:
    """Decide whether to re-hit NVD for a cache entry."""
    if force:
        # Permanent skips stay skipped unless we remove them from SKIP_PRODUCTS.
        if product_key(product_name) in SKIP_PRODUCTS:
            return False
        return True
    if not force_missing_only:
        return cached is None
    if cached is None:
        return True
    if product_key(product_name) in SKIP_PRODUCTS:
        return False
    err = (cached.get("error") or "").strip()
    if err in {"skipped", "no-cpe"}:
        return False
    if err == "nvd-error":
        return True
    cve_count = cached.get("cve_count") or 0
    try:
        cve_n = int(cve_count)
    except (TypeError, ValueError):
        cve_n = 0
    # Re-query empty results (may be stale zero from an earlier NVD miss).
    if cve_n == 0 and not (cached.get("cves") or []):
        return True
    return False


def enrich_software_version_rows(
    rows: list[tuple[str, int]],
    cache_path: str,
    sleep_seconds: float | None = None,
    progress: bool = False,
    kev_catalog_path: str | None = None,
    force: bool = False,
    force_missing_only: bool = False,
) -> list[tuple[str, int, str, str, str, bool]]:
    """Enrich (label, count) rows with CVSS fields.

    Returns list of:
      (label, count, max_cvss_display, cve_count_display, top_cve, top_is_kev)

    Top CVE prefers CISA KEV matches when present; otherwise highest CVSS.

    force: re-query all CPE-mapped products (except SKIP_PRODUCTS).
    force_missing_only: re-query missing entries, nvd-error, and zero-CVE results.
    """
    if sleep_seconds is None:
        # Authenticated NVD allows ~50 req/30s; unauthenticated ~5/30s.
        sleep_seconds = 0.7 if get_nvd_api_key() else DEFAULT_SLEEP_SECONDS

    kev_ids = load_cisa_kev_ids(kev_catalog_path)
    cache = load_cache(cache_path)
    enriched: list[tuple[str, int, str, str, str, bool]] = []
    dirty = False
    stats: dict[str, Any] = {
        "looked_up": 0,
        "cached": 0,
        "skipped": 0,
        "changed": 0,
        "newly_with_cves": 0,
        "still_empty": 0,
        "kev_gained": 0,
        "kev_lost": 0,
        "changes": [],  # compact per-label deltas (capped)
    }
    change_cap = 40

    def _snap(
        entry: dict[str, Any] | None,
        *,
        recompute_kev: bool = True,
    ) -> dict[str, Any]:
        entry = entry if isinstance(entry, dict) else {}
        cves_list = entry.get("cves") or []
        try:
            cve_n = int(entry.get("cve_count") or 0)
        except (TypeError, ValueError):
            cve_n = 0
        if recompute_kev:
            top, is_kev = select_top_cve(cves_list, kev_ids)
            if not top:
                top = (entry.get("top_cve") or "").strip().upper()
                is_kev = bool(top and top in kev_ids)
        else:
            top = (entry.get("top_cve") or "").strip().upper()
            is_kev = bool(entry.get("top_is_kev"))
            if top and not is_kev and top in kev_ids:
                # stored flag may lag catalog
                is_kev = True
        return {
            "cve_count": cve_n,
            "top_cve": top,
            "top_is_kev": bool(is_kev),
            "error": (entry.get("error") or "").strip(),
        }

    def _record_change(label: str, before: dict[str, Any], after: dict[str, Any]) -> None:
        if (
            before["cve_count"] == after["cve_count"]
            and before["top_cve"] == after["top_cve"]
            and before["top_is_kev"] == after["top_is_kev"]
        ):
            return
        stats["changed"] += 1
        if before["cve_count"] == 0 and after["cve_count"] > 0:
            stats["newly_with_cves"] += 1
        if not before["top_is_kev"] and after["top_is_kev"]:
            stats["kev_gained"] += 1
        if before["top_is_kev"] and not after["top_is_kev"]:
            stats["kev_lost"] += 1
        if len(stats["changes"]) < change_cap:
            stats["changes"].append(
                {
                    "label": label,
                    "cve_count_before": before["cve_count"],
                    "cve_count_after": after["cve_count"],
                    "top_cve_before": before["top_cve"],
                    "top_cve_after": after["top_cve"],
                    "kev_before": before["top_is_kev"],
                    "kev_after": after["top_is_kev"],
                }
            )

    for index, (label, count) in enumerate(rows, start=1):
        product, version = parse_software_label(label)
        key = cache_key(product, version)
        cached = cache.get("entries", {}).get(key)
        # "before" = what the Active table last showed (stored top_is_kev / counts)
        before = _snap(
            cached if isinstance(cached, dict) else None,
            recompute_kev=False,
        )
        do_query = _should_requery_cached(
            product,
            cached if isinstance(cached, dict) else None,
            force=force,
            force_missing_only=force_missing_only,
        )
        if do_query:
            if progress:
                print(f"[*] NVD lookup {index}/{len(rows)}: {label}", flush=True)
            lookup_software(
                product,
                version,
                cache,
                sleep_seconds=sleep_seconds,
                force=bool(cached is not None),
            )
            dirty = True
            stats["looked_up"] += 1
            cached = cache["entries"].get(key) or {}
        else:
            if cached is None:
                # Should not happen often; treat as empty
                cached = {}
            if (cached.get("error") or "") in {"skipped", "no-cpe"}:
                stats["skipped"] += 1
            else:
                stats["cached"] += 1

        after = _snap(cached if isinstance(cached, dict) else None, recompute_kev=True)
        if do_query and after["cve_count"] == 0 and after["error"] not in {
            "skipped",
            "no-cpe",
        }:
            stats["still_empty"] += 1
        _record_change(label, before, after)

        error = cached.get("error") or ""
        max_cvss = format_cvss(cached.get("max_cvss"))
        cve_count = cached.get("cve_count") or 0
        cves_list = cached.get("cves") or []
        top_cve, top_is_kev = select_top_cve(cves_list, kev_ids)
        if not top_cve:
            top_cve = (cached.get("top_cve") or "").strip().upper()
            top_is_kev = bool(top_cve and top_cve in kev_ids)

        if error in {"skipped", "no-cpe", "nvd-error"} or not max_cvss:
            max_cvss = ""
            top_cve = ""
            top_is_kev = False
            cve_count_display = ""
        elif cve_count:
            cve_count_display = str(cve_count)
        else:
            cve_count_display = ""

        enriched.append(
            (label, count, max_cvss, cve_count_display, top_cve, top_is_kev)
        )

    if dirty:
        save_cache(cache_path, cache)

    # Always refresh CVE → software map for Active CVE search / Subdomains ?cve=
    write_cve_software_index_js(cache_path)

    # Stash stats for CLI / statusd callers
    enrich_software_version_rows.last_stats = stats  # type: ignore[attr-defined]
    return enriched


def write_cve_software_index_js(cache_path: str) -> str:
    """Write tools/cve-software-index.js (file://-safe) beside the NVD cache.

    Maps CVE-ID → software version labels used on Subdomains tech tokens
    (e.g. ``Apache:2.4.37``).
    """
    if not cache_path:
        return ""
    cache = load_cache(cache_path)
    index: dict[str, list[str]] = {}
    for ent in (cache.get("entries") or {}).values():
        if not isinstance(ent, dict):
            continue
        product = (ent.get("product") or "").strip()
        version = (ent.get("version") or "").strip()
        if not product:
            continue
        label = f"{product}:{version}" if version else product
        ids: set[str] = set()
        for item in ent.get("cves") or []:
            if not isinstance(item, dict):
                continue
            cid = (item.get("id") or "").strip().upper()
            if cid.startswith("CVE-"):
                ids.add(cid)
        top = (ent.get("top_cve") or "").strip().upper()
        if top.startswith("CVE-"):
            ids.add(top)
        for cid in ids:
            bucket = index.setdefault(cid, [])
            if label not in bucket:
                bucket.append(label)
    for cid in index:
        index[cid] = sorted(index[cid], key=str.lower)

    out_path = os.path.join(
        os.path.dirname(os.path.abspath(cache_path)),
        "cve-software-index.js",
    )
    try:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(
                "/* Generated from software-cves-cache.json — CVE → software labels. */\n"
            )
            handle.write("window.DISCOVER_CVE_SOFTWARE = ")
            json.dump(index, handle, separators=(",", ":"), sort_keys=True)
            handle.write(";\n")
    except OSError:
        return ""
    return out_path


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
