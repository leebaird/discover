#!/usr/bin/env python3
"""Threat intel for software already in an engagement.

Watches the Software versions cache. Check now records
new NVD CVEs, CISA KEV entries, Exploit-DB items, vendor and CISA advisories,
public GitHub exploit repositories, local Metasploit exploit modules, and
posts from the operator's X accounts.

The first check only records what is already public. Later checks add alerts.
Queries use product and CVE identifiers. The client domain is not sent.

No audit log line. Client and Defender exports omit tools/threat-feed/.
"""

from __future__ import annotations

import argparse
import email.utils
import hashlib
import json
import os
import re
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from zoneinfo import ZoneInfo

DISCOVER = Path(__file__).resolve().parents[1]
USER_AGENT = "Discover-threat-feed/1.0 (https://github.com/leebaird/discover)"
NVD_RANGE_DAYS = 120
NVD_PRODUCT_CAP = 25
GITHUB_CAP = 20
X_BOOTSTRAP_POSTS = 5
X_POLL_POSTS = 10
SUMMARY_MAX = 500
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
ATOM_NS = "http://www.w3.org/2005/Atom"

CHECK_PROGRESS = (
    "[*] Checking NVD.",
    "[*] Checking KEV.",
    "[*] Checking advisories.",
    "[*] Checking GitHub.",
    "[*] Checking Metasploit.",
)
X_PROGRESS_RE = re.compile(r"^\[\*\] Checking \d+ X accounts?\.$")
EXPLOITDB_FEED = "https://www.exploit-db.com/rss.xml"
CISA_FEED = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
VENDOR_FEEDS = (
    ("wordpress", "https://wordpress.org/news/category/security/feed/"),
    ("drupal", "https://www.drupal.org/security/rss.xml"),
)
GITHUB_SKIP_REPOS = {
    "github/advisory-database",
    "cveproject/cvelistv5",
    "projectdiscovery/nuclei-templates",
    "nomi-sec/poc-in-github",
}
EXPLOIT_WORDS = ("exploit", "poc", "proof of concept", "proof-of-concept")
MSF_METADATA_PATHS = (
    Path("/usr/share/metasploit-framework/db/modules_metadata_base.json"),
    Path("/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json"),
    Path(
        "/snap/metasploit-framework/current/opt/metasploit-framework"
        "/embedded/framework/db/modules_metadata_base.json"
    ),
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def feed_dir(report: Path) -> Path:
    return report / "tools" / "threat-feed"


def alerts_path(report: Path) -> Path:
    return feed_dir(report) / "alerts.json"


def state_path(report: Path) -> Path:
    return feed_dir(report) / "state.json"


def running_path(report: Path) -> Path:
    return feed_dir(report) / "running.json"


def _read_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_state(report: Path) -> dict[str, Any]:
    raw = _read_json(state_path(report))
    state = raw if isinstance(raw, dict) else {}
    state.setdefault("bootstrapped", False)
    state.setdefault("last_pull_utc", "")
    state.setdefault("last_scheduled_date", "")
    state.setdefault("github_since", "")
    seen = state.get("seen")
    if not isinstance(seen, dict):
        seen = {}
    for key in ("nvd", "kev", "feed", "github", "x"):
        vals = seen.get(key)
        if not isinstance(vals, list):
            vals = []
        seen[key] = vals
    state["seen"] = seen
    cursors = state.get("x_since")
    state["x_since"] = cursors if isinstance(cursors, dict) else {}
    return state


def load_alerts(report: Path) -> list[dict[str, Any]]:
    raw = _read_json(alerts_path(report))
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict) and isinstance(raw.get("alerts"), list):
        items = raw["alerts"]
    else:
        items = []
    out = []
    for item in items:
        if isinstance(item, dict) and item.get("id"):
            out.append(item)
    return out


def save_alerts(report: Path, alerts: list[dict[str, Any]]) -> None:
    _write_json(alerts_path(report), {"alerts": alerts})


def _software_cve():
    path = DISCOVER / "recon" / "software-cve.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("discover_software_cve_feed", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("software-cve.py missing")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _config():
    path = DISCOVER / "recon" / "discover-config.py"
    import importlib.util

    spec = importlib.util.spec_from_file_location("discover_config_feed", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("discover-config.py missing")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_software(report: Path) -> list[dict[str, Any]]:
    """Versioned products from the engagement CVE cache. Skips permanent noise."""
    cve = _software_cve()
    cache = cve.load_cache(str(report / "tools" / "software-cves-cache.json"))
    rows = []
    for key, entry in (cache.get("entries") or {}).items():
        if not isinstance(entry, dict) or "|" not in str(key):
            continue
        name_key, version = str(key).split("|", 1)
        if name_key in cve.SKIP_PRODUCTS or not version.strip():
            continue
        product = str(entry.get("product") or name_key).strip()
        version = str(entry.get("version") or version).strip()
        if not product or not version:
            continue
        cves = []
        best = -1.0
        for item in entry.get("cves") or []:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("id") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            try:
                score = float(item.get("score") or 0)
            except (TypeError, ValueError):
                score = 0.0
            cves.append({"id": cve_id, "score": score})
            if score > best:
                best = score
        rows.append(
            {
                "product": product,
                "version": version,
                "label": f"{product}:{version}",
                "name_key": name_key,
                "cpe": str(entry.get("cpe") or ""),
                "cves": cves,
                "max_score": best,
            }
        )
    rows.sort(key=lambda row: (-row["max_score"], row["label"].casefold()))
    return rows


def product_names(software: list[dict[str, Any]]) -> list[str]:
    seen = set()
    names = []
    for row in software:
        name = row["product"].strip()
        key = name.casefold()
        if len(name) < 3 or key in seen:
            continue
        seen.add(key)
        names.append(name)
    return names


def phrase_in(text: str, phrase: str) -> bool:
    if not text or not phrase:
        return False
    pattern = r"(?<![A-Za-z0-9])" + re.escape(phrase) + r"(?![A-Za-z0-9])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def matching_labels(software: list[dict[str, Any]], text: str) -> list[str]:
    labels = []
    folded = set()
    for name in product_names(software):
        if not phrase_in(text, name):
            continue
        for row in software:
            if row["product"].casefold() != name.casefold():
                continue
            if row["label"] not in folded:
                folded.add(row["label"])
                labels.append(row["label"])
    return labels


def cve_labels(software: list[dict[str, Any]], cve_id: str) -> list[str]:
    want = cve_id.upper()
    labels = []
    for row in software:
        if any(item["id"] == want for item in row["cves"]):
            labels.append(row["label"])
    return labels


def alert_id(source: str, external_id: str, software_label: str) -> str:
    raw = f"{source}|{external_id}|{software_label}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def _clip(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= SUMMARY_MAX:
        return text
    return text[: SUMMARY_MAX - 1].rstrip() + "."


def make_alert(
    *,
    source: str,
    kind: str,
    external_id: str,
    software_label: str,
    title: str,
    summary: str,
    url: str,
    published_utc: str,
    now: datetime,
) -> dict[str, str]:
    return {
        "id": alert_id(source, external_id, software_label),
        "source": source,
        "kind": kind,
        "software": software_label,
        "title": title.strip() or "Alert",
        "summary": _clip(summary),
        "url": url.strip(),
        "published_utc": published_utc,
        "seen_at_utc": iso_z(now),
        "state": "new",
    }


def consider(
    *,
    bootstrap: bool,
    seen: list[str],
    seen_key: str,
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    item: dict[str, str] | None,
) -> int:
    if seen_key in seen:
        return 0
    seen.append(seen_key)
    if bootstrap or item is None:
        return 0
    if item["id"] in known_ids:
        return 0
    alerts.append(item)
    known_ids.add(item["id"])
    return 1


def parse_http_date(value: str) -> str:
    if not value:
        return ""
    text = value.strip()
    if text.endswith("Z") and "T" in text:
        return text
    try:
        parsed = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return ""
    if parsed is None:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return iso_z(parsed)


def _xml_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    if child is None or child.text is None:
        return ""
    return child.text.strip()


def parse_feed_xml(xml_text: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    items = []
    for node in root.findall(".//item"):
        link = _xml_text(node, "link")
        guid = _xml_text(node, "guid") or link
        if not guid:
            continue
        items.append(
            {
                "id": guid,
                "title": _xml_text(node, "title"),
                "link": link,
                "summary": _xml_text(node, "description"),
                "published": parse_http_date(_xml_text(node, "pubDate")),
            }
        )
    for node in root.findall(f".//{{{ATOM_NS}}}entry"):
        link = ""
        for link_node in node.findall(f"{{{ATOM_NS}}}link"):
            href = link_node.attrib.get("href") or ""
            if href:
                link = href
                break
        guid = _xml_text(node, f"{{{ATOM_NS}}}id") or link
        if not guid:
            continue
        summary = _xml_text(node, f"{{{ATOM_NS}}}summary") or _xml_text(
            node, f"{{{ATOM_NS}}}content"
        )
        published = parse_http_date(
            _xml_text(node, f"{{{ATOM_NS}}}published")
            or _xml_text(node, f"{{{ATOM_NS}}}updated")
        )
        items.append(
            {
                "id": guid,
                "title": _xml_text(node, f"{{{ATOM_NS}}}title"),
                "link": link,
                "summary": summary,
                "published": published,
            }
        )
    return items


def feed_kind(title: str, summary: str) -> str:
    text = f"{title} {summary}"
    if phrase_in(text, "0-day") or phrase_in(text, "zero-day") or phrase_in(text, "0day"):
        return "zero-day"
    lowered = text.casefold()
    if any(word in lowered for word in EXPLOIT_WORDS):
        return "exploit"
    if CVE_RE.search(text):
        return "cve"
    return "vendor-alert"


def labels_for_text(software: list[dict[str, Any]], text: str) -> list[str]:
    labels = list(matching_labels(software, text))
    folded = set(labels)
    for cve_id in CVE_RE.findall(text or ""):
        for label in cve_labels(software, cve_id):
            if label not in folded:
                folded.add(label)
                labels.append(label)
    return labels


def x_kind(text: str) -> str:
    if phrase_in(text, "0-day") or phrase_in(text, "zero-day") or phrase_in(text, "0day"):
        return "zero-day"
    lowered = text.casefold()
    if any(word in lowered for word in EXPLOIT_WORDS):
        return "exploit"
    if CVE_RE.search(text or ""):
        return "cve"
    if any(word in lowered for word in ("advisory", "patch", "vulnerability")):
        return "vendor-alert"
    return ""


def x_matches(software: list[dict[str, Any]], text: str) -> tuple[str, list[str]]:
    """Return (kind, labels) when a post is about report software."""
    kind = x_kind(text)
    if not kind:
        return "", []
    labels = labels_for_text(software, text)
    if not labels:
        return "", []
    if kind == "cve" and not CVE_RE.search(text or ""):
        return "", []
    return kind, labels


def github_is_exploit(repo: dict[str, Any], cve_id: str) -> bool:
    full = str(repo.get("full_name") or "")
    if full.casefold() in GITHUB_SKIP_REPOS:
        return False
    name = str(repo.get("name") or "")
    description = str(repo.get("description") or "")
    topics = " ".join(repo.get("topics") or [])
    blob = f"{name} {description}"
    if cve_id.casefold() == name.casefold():
        return True
    if cve_id.upper() not in blob.upper() and cve_id.upper() not in topics.upper():
        return False
    hay = f"{name} {description} {topics}".casefold()
    return any(word in hay for word in EXPLOIT_WORDS)


class UrlNet:
    def __init__(self, timeout: float = 25.0):
        self.timeout = timeout

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> Any:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
            return None

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> str:
        req = urllib.request.Request(url, headers=headers or {"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
            return ""


def _key(name: str) -> str:
    cve = _software_cve()
    cve.load_discover_env_files()
    return (os.environ.get(name) or "").strip()


def pull_kev(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    catalog: dict[str, Any] | None,
    fresh: list[tuple[str, str]] | None = None,
) -> int:
    added = 0
    seen = state["seen"]["kev"]
    if not isinstance(catalog, dict):
        return 0
    names = product_names(software)
    for entry in catalog.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get("cveID") or "").upper()
        if not cve_id.startswith("CVE-"):
            continue
        labels = cve_labels(software, cve_id)
        blob = " ".join(
            str(entry.get(field) or "")
            for field in ("vendorProject", "product", "vulnerabilityName", "shortDescription")
        )
        if not labels:
            for name in names:
                if phrase_in(blob, name):
                    labels = [
                        row["label"]
                        for row in software
                        if row["product"].casefold() == name.casefold()
                    ]
                    break
        if not labels:
            continue
        summary = str(entry.get("shortDescription") or "")
        title = str(entry.get("vulnerabilityName") or cve_id)
        published = str(entry.get("dateAdded") or "")
        if published and "T" not in published:
            published = published + "T00:00:00Z"
        for label in labels:
            item = make_alert(
                source="kev",
                kind="kev",
                external_id=cve_id,
                software_label=label,
                title=title,
                summary=summary,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_utc=published,
                now=now,
            )
            got = consider(
                bootstrap=bootstrap,
                seen=seen,
                seen_key=f"{cve_id}|{label}",
                alerts=alerts,
                known_ids=known_ids,
                item=item,
            )
            added += got
            if got and fresh is not None:
                fresh.append((cve_id, label))
    return added


def pull_feeds(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    net: Any,
    notes: list[str],
) -> int:
    added = 0
    seen = state["seen"]["feed"]
    names = {name.casefold() for name in product_names(software)}
    urls = [
        (CISA_FEED, "advisory", "CISA"),
        (EXPLOITDB_FEED, "exploit-db", "Exploit-DB"),
    ]
    feed_labels = {"wordpress": "WordPress", "drupal": "Drupal"}
    for name_key, url in VENDOR_FEEDS:
        if name_key in names or any(name_key in row["name_key"] for row in software):
            urls.append((url, "advisory", feed_labels.get(name_key, name_key)))
    for url, source, label in urls:
        xml_text = net.get_text(url, {"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"})
        items = parse_feed_xml(xml_text) if xml_text else []
        if xml_text == "" and not bootstrap:
            notes.append(f"{label} did not respond.")
        for entry in items:
            text = f"{entry.get('title') or ''} {entry.get('summary') or ''}"
            labels = labels_for_text(software, text)
            if not labels:
                consider(
                    bootstrap=True,
                    seen=seen,
                    seen_key=f"{source}|{entry['id']}",
                    alerts=alerts,
                    known_ids=known_ids,
                    item=None,
                )
                continue
            if source == "exploit-db":
                kind = "exploit"
            else:
                kind = feed_kind(entry.get("title") or "", entry.get("summary") or "")
            for label in labels:
                item = make_alert(
                    source=source,
                    kind=kind,
                    external_id=entry["id"],
                    software_label=label,
                    title=entry.get("title") or "Alert",
                    summary=entry.get("summary") or "",
                    url=entry.get("link") or "",
                    published_utc=entry.get("published") or "",
                    now=now,
                )
                added += consider(
                    bootstrap=bootstrap,
                    seen=seen,
                    seen_key=f"{source}|{entry['id']}|{label}",
                    alerts=alerts,
                    known_ids=known_ids,
                    item=item,
                )
    return added


def _nvd_window(last_pull: str, now: datetime) -> tuple[str, str]:
    end = now.astimezone(timezone.utc)
    start = end - timedelta(days=1)
    if last_pull:
        try:
            parsed = datetime.fromisoformat(last_pull.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            start = parsed
        except ValueError:
            start = end - timedelta(days=1)
    earliest = end - timedelta(days=NVD_RANGE_DAYS)
    if start < earliest:
        start = earliest
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    return start.strftime(fmt), end.strftime(fmt)


def pull_nvd(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    net: Any,
    notes: list[str],
    sleep_seconds: float,
    fresh: list[tuple[str, str]] | None = None,
) -> int:
    seen = state["seen"]["nvd"]
    if bootstrap:
        for row in software:
            for item in row["cves"]:
                key = f"{item['id']}|{row['label']}"
                if key not in seen:
                    seen.append(key)
        return 0
    cve_mod = _software_cve()
    added = 0
    start, end = _nvd_window(str(state.get("last_pull_utc") or ""), now)
    failed = False
    checked = 0
    for row in software:
        if checked >= NVD_PRODUCT_CAP:
            break
        cpe = row["cpe"] or cve_mod.build_cpe23(row["product"], row["version"]) or ""
        if not cpe:
            continue
        checked += 1
        params = urllib.parse.urlencode(
            {
                "virtualMatchString": cpe,
                "lastModStartDate": start,
                "lastModEndDate": end,
                "resultsPerPage": "50",
            }
        )
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        api_key = _key("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key
        payload = net.get_json(f"{cve_mod.NVD_CVE_API}?{params}", headers)
        if not isinstance(payload, dict):
            failed = True
            continue
        for wrapped in payload.get("vulnerabilities") or []:
            cve = wrapped.get("cve") if isinstance(wrapped, dict) else None
            if not isinstance(cve, dict):
                continue
            if not cve_mod.cve_version_fits(cpe, cve):
                continue
            cve_id = str(cve.get("id") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            summary = ""
            for desc in cve.get("descriptions") or []:
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    summary = str(desc.get("value") or "")
                    break
            published = str(cve.get("published") or "")
            if published.endswith("+00:00"):
                published = published.replace("+00:00", "Z")
            item = make_alert(
                source="nvd",
                kind="cve",
                external_id=cve_id,
                software_label=row["label"],
                title=cve_id,
                summary=summary,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_utc=published,
                now=now,
            )
            got = consider(
                bootstrap=False,
                seen=seen,
                seen_key=f"{cve_id}|{row['label']}",
                alerts=alerts,
                known_ids=known_ids,
                item=item,
            )
            added += got
            if got and fresh is not None:
                fresh.append((cve_id, row["label"]))
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    if failed:
        notes.append("NVD lookup failed for some software.")
    return added


def _cve_priority(software: list[dict[str, Any]]) -> list[tuple[str, str, float]]:
    best: dict[str, tuple[str, float]] = {}
    for row in software:
        for item in row["cves"]:
            current = best.get(item["id"])
            if current is None or item["score"] > current[1]:
                best[item["id"]] = (row["label"], item["score"])
    ranked = [(cve_id, label, score) for cve_id, (label, score) in best.items()]
    ranked.sort(key=lambda row: (-row[2], row[0]))
    return ranked


def pull_github(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    net: Any,
    notes: list[str],
    sleep_seconds: float,
    fresh: list[tuple[str, str]] | None = None,
) -> int:
    if bootstrap or not state.get("github_since"):
        state["github_since"] = now.date().isoformat()
        return 0
    seen = state["seen"]["github"]
    token = _key("GITHUB_TOKEN")
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    added = 0
    failed = False
    since = str(state.get("github_since") or now.date().isoformat())
    # New CVEs and KEV hits from this check, then the highest CVSS already on the report.
    ordered: list[tuple[str, str, float]] = []
    seen_ids: set[str] = set()
    for cve_id, label in fresh or []:
        key = cve_id.upper()
        if not key.startswith("CVE-") or key in seen_ids:
            continue
        seen_ids.add(key)
        ordered.append((key, label, 10.0))
    for cve_id, label, score in _cve_priority(software):
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        ordered.append((cve_id, label, score))
    for cve_id, label, _score in ordered[:GITHUB_CAP]:
        query = urllib.parse.urlencode(
            {
                "q": f'"{cve_id}" fork:false pushed:>={since}',
                "sort": "updated",
                "per_page": "5",
            }
        )
        payload = net.get_json(f"https://api.github.com/search/repositories?{query}", headers)
        if not isinstance(payload, dict):
            failed = True
            break
        for repo in payload.get("items") or []:
            if not isinstance(repo, dict) or not github_is_exploit(repo, cve_id):
                continue
            full = str(repo.get("full_name") or "")
            item = make_alert(
                source="github",
                kind="exploit",
                external_id=f"{full}|{cve_id}",
                software_label=label,
                title=full or cve_id,
                summary=str(repo.get("description") or ""),
                url=str(repo.get("html_url") or ""),
                published_utc=str(repo.get("created_at") or repo.get("pushed_at") or ""),
                now=now,
            )
            added += consider(
                bootstrap=False,
                seen=seen,
                seen_key=f"{full}|{cve_id}",
                alerts=alerts,
                known_ids=known_ids,
                item=item,
            )
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    state["github_since"] = now.date().isoformat()
    if failed:
        notes.append("GitHub search did not finish.")
    return added


def metasploit_metadata_path() -> Path | None:
    """Framework module catalog shipped with Metasploit. Nothing is executed."""
    for path in MSF_METADATA_PATHS:
        if path.is_file():
            return path
    which = shutil.which("msfconsole")
    if not which:
        return None
    for parent in Path(which).resolve().parents:
        for relative in (
            Path("embedded/framework/db/modules_metadata_base.json"),
            Path("opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json"),
            Path("share/metasploit-framework/db/modules_metadata_base.json"),
            Path("db/modules_metadata_base.json"),
        ):
            candidate = parent / relative
            if candidate.is_file():
                return candidate
    return None


def _msf_published(disclosure: str, modified: str) -> str:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", disclosure):
        return disclosure + "T00:00:00Z"
    text = modified.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return iso_z(parsed)
    return ""


def load_metasploit_index(path: Path) -> dict[str, list[dict[str, str]]]:
    """Map a CVE id to exploit modules. Auxiliary, payload, and post modules stay out."""
    raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    index: dict[str, list[dict[str, str]]] = {}
    if not isinstance(raw, dict):
        return index
    for entry in raw.values():
        if not isinstance(entry, dict) or entry.get("type") != "exploit":
            continue
        fullname = str(entry.get("fullname") or "").strip()
        if not fullname.startswith("exploit/"):
            continue
        refs = []
        for ref in entry.get("references") or []:
            match = CVE_RE.search(str(ref))
            if match:
                refs.append(match.group(0).upper())
        if not refs:
            continue
        module = {
            "fullname": fullname,
            "name": str(entry.get("name") or "").strip(),
            "description": str(entry.get("description") or "").strip(),
            "published": _msf_published(
                str(entry.get("disclosure_date") or ""),
                str(entry.get("mod_time") or ""),
            ),
        }
        for cve_id in dict.fromkeys(refs):
            index.setdefault(cve_id, []).append(module)
    for modules in index.values():
        modules.sort(key=lambda item: item["fullname"])
    return index


def _cve_targets(
    software: list[dict[str, Any]], fresh: list[tuple[str, str]] | None
) -> list[tuple[str, str]]:
    ordered: list[tuple[str, str]] = []
    seen_ids: set[str] = set()
    for cve_id, label in fresh or []:
        key = str(cve_id or "").upper()
        if not key.startswith("CVE-") or key in seen_ids:
            continue
        seen_ids.add(key)
        ordered.append((key, label))
    for cve_id, label, _score in _cve_priority(software):
        if cve_id in seen_ids:
            continue
        seen_ids.add(cve_id)
        ordered.append((cve_id, label))
    return ordered


def pull_metasploit(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    notes: list[str],
    fresh: list[tuple[str, str]] | None = None,
    metadata_path: Path | None = None,
) -> int:
    path = metadata_path if metadata_path is not None else metasploit_metadata_path()
    if path is None or not path.is_file():
        notes.append("Metasploit was skipped. It is not installed.")
        return 0
    try:
        index = load_metasploit_index(path)
    except (OSError, json.JSONDecodeError):
        notes.append("Metasploit metadata could not be read.")
        return 0
    seen_map = state["seen"]
    ready = isinstance(seen_map.get("metasploit"), list)
    if not ready:
        seen_map["metasploit"] = []
    seen = seen_map["metasploit"]
    # An engagement that already has a baseline records the current modules once.
    record_only = bootstrap or not ready
    added = 0
    for cve_id, label in _cve_targets(software, fresh):
        for module in index.get(cve_id) or []:
            fullname = module["fullname"]
            item = make_alert(
                source="metasploit",
                kind="exploit",
                external_id=f"{fullname}|{cve_id}",
                software_label=label,
                title=module["name"] or fullname,
                summary=module["description"] or fullname,
                url="https://www.rapid7.com/db/modules/" + fullname,
                published_utc=module["published"],
                now=now,
            )
            added += consider(
                bootstrap=record_only,
                seen=seen,
                seen_key=f"{fullname}|{cve_id}",
                alerts=alerts,
                known_ids=known_ids,
                item=item,
            )
    if record_only and not bootstrap:
        notes.append("Metasploit modules already installed were recorded.")
    return added


def pull_x(
    software: list[dict[str, Any]],
    state: dict[str, Any],
    alerts: list[dict[str, Any]],
    known_ids: set[str],
    *,
    bootstrap: bool,
    now: datetime,
    net: Any,
    notes: list[str],
) -> int:
    token = _key("X_API_KEY")
    cfg = _config()
    accounts = cfg.read_x_accounts()
    if not token:
        notes.append("X was skipped. Add a bearer token in Config.")
        return 0
    if not accounts:
        notes.append("X was skipped. Add accounts in Config.")
        return 0
    headers = {"User-Agent": USER_AGENT, "Authorization": "Bearer " + token}
    seen = state["seen"]["x"]
    cursors = state["x_since"]
    added = 0
    limit = X_BOOTSTRAP_POSTS if bootstrap else X_POLL_POSTS
    failed = False
    for handle in accounts:
        user = net.get_json(
            f"https://api.x.com/2/users/by/username/{urllib.parse.quote(handle)}",
            headers,
        )
        user_id = ""
        if isinstance(user, dict) and isinstance(user.get("data"), dict):
            user_id = str(user["data"].get("id") or "")
        if not user_id:
            failed = True
            continue
        params = {
            "exclude": "retweets,replies",
            "max_results": str(limit),
            "tweet.fields": "created_at",
        }
        since = str(cursors.get(handle) or "")
        if since and not bootstrap:
            params["since_id"] = since
        query = urllib.parse.urlencode(params)
        payload = net.get_json(
            f"https://api.x.com/2/users/{urllib.parse.quote(user_id)}/tweets?{query}",
            headers,
        )
        posts = []
        if isinstance(payload, dict) and isinstance(payload.get("data"), list):
            posts = [post for post in payload["data"] if isinstance(post, dict)]
        elif payload is None:
            failed = True
        newest = since
        for post in posts:
            post_id = str(post.get("id") or "")
            text = str(post.get("text") or "")
            if not post_id:
                continue
            if not newest or post_id > newest:
                newest = post_id
            kind, labels = x_matches(software, text)
            if not labels:
                consider(
                    bootstrap=True,
                    seen=seen,
                    seen_key=post_id,
                    alerts=alerts,
                    known_ids=known_ids,
                    item=None,
                )
                continue
            for label in labels:
                item = make_alert(
                    source="x",
                    kind=kind,
                    external_id=post_id,
                    software_label=label,
                    title="@" + handle,
                    summary=text,
                    url=f"https://x.com/{handle}/status/{post_id}",
                    published_utc=str(post.get("created_at") or ""),
                    now=now,
                )
                added += consider(
                    bootstrap=bootstrap,
                    seen=seen,
                    seen_key=f"{post_id}|{label}",
                    alerts=alerts,
                    known_ids=known_ids,
                    item=item,
                )
        if newest:
            cursors[handle] = newest
    if failed:
        notes.append("X did not return every account.")
    return added


def x_progress_line(count: int) -> str:
    """Status line for the X step. The count is the configured account list."""
    try:
        count = int(count)
    except (TypeError, ValueError):
        count = 0
    if count < 0:
        count = 0
    noun = "account" if count == 1 else "accounts"
    return f"[*] Checking {count} X {noun}."


def progress_line_ok(line: str) -> bool:
    return line in CHECK_PROGRESS or bool(X_PROGRESS_RE.fullmatch(line))


def note_progress(report: Path, state: dict[str, Any], line: str) -> None:
    """Append one check line and write it so the Alerts modal can show it."""
    if not progress_line_ok(line):
        return
    progress = state.get("progress")
    if not isinstance(progress, list):
        progress = []
    if line not in progress:
        progress.append(line)
    state["progress"] = progress
    _write_json(state_path(report), state)


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def check_running(report: Path) -> bool:
    raw = _read_json(running_path(report))
    if not isinstance(raw, dict):
        return False
    try:
        pid = int(raw.get("pid") or 0)
    except (TypeError, ValueError):
        return False
    if pid_alive(pid):
        return True
    try:
        running_path(report).unlink()
    except OSError:
        pass
    return False


def run_check(
    report: Path,
    *,
    force: bool = False,
    now: datetime | None = None,
    net: Any | None = None,
    sleep_seconds: float | None = None,
) -> dict[str, Any]:
    moment = now or _now()
    net = net or UrlNet()
    if check_running(report) and os.getpid() != _running_pid(report):
        return {"ok": True, "running": True, "added": 0, "notes": []}
    feed_dir(report).mkdir(parents=True, exist_ok=True)
    _write_json(running_path(report), {"pid": os.getpid(), "started_utc": iso_z(moment)})
    notes: list[str] = []
    try:
        state = load_state(report)
        alerts = load_alerts(report)
        known_ids = {str(item.get("id") or "") for item in alerts}
        software = load_software(report)
        bootstrap = not bool(state.get("bootstrapped"))
        if not software:
            notes.append("No software versions to watch.")
        catalog = _read_json(Path(_software_cve().cisa_kev_catalog_path()))
        added = 0
        fresh: list[tuple[str, str]] = []
        state["progress"] = []
        if sleep_seconds is None:
            sleep_seconds = 0.7 if _key("NVD_API_KEY") else 6.5
        note_progress(report, state, "[*] Checking NVD.")
        added += pull_nvd(
            software,
            state,
            alerts,
            known_ids,
            bootstrap=bootstrap,
            now=moment,
            net=net,
            notes=notes,
            sleep_seconds=sleep_seconds,
            fresh=fresh,
        )
        note_progress(report, state, "[*] Checking KEV.")
        added += pull_kev(
            software,
            state,
            alerts,
            known_ids,
            bootstrap=bootstrap,
            now=moment,
            catalog=catalog if isinstance(catalog, dict) else None,
            fresh=fresh,
        )
        note_progress(report, state, "[*] Checking advisories.")
        added += pull_feeds(
            software, state, alerts, known_ids, bootstrap=bootstrap, now=moment, net=net, notes=notes
        )
        github_sleep = 2.0 if _key("GITHUB_TOKEN") else 6.5
        if sleep_seconds == 0:
            github_sleep = 0
        note_progress(report, state, "[*] Checking GitHub.")
        added += pull_github(
            software,
            state,
            alerts,
            known_ids,
            bootstrap=bootstrap,
            now=moment,
            net=net,
            notes=notes,
            sleep_seconds=github_sleep,
            fresh=fresh,
        )
        note_progress(report, state, "[*] Checking Metasploit.")
        added += pull_metasploit(
            software,
            state,
            alerts,
            known_ids,
            bootstrap=bootstrap,
            now=moment,
            notes=notes,
            fresh=fresh,
        )
        note_progress(report, state, x_progress_line(len(_config().read_x_accounts())))
        added += pull_x(
            software, state, alerts, known_ids, bootstrap=bootstrap, now=moment, net=net, notes=notes
        )
        state["bootstrapped"] = True
        state["last_pull_utc"] = iso_z(moment)
        cfg = _config()
        zone = cfg.read_timezone() or "UTC"
        try:
            local_day = moment.astimezone(ZoneInfo(zone)).date().isoformat()
        except Exception:
            local_day = moment.date().isoformat()
        state["last_scheduled_date"] = local_day
        alerts.sort(key=lambda item: str(item.get("seen_at_utc") or ""), reverse=True)
        save_alerts(report, alerts)
        # Notes can repeat once per failed feed. Keep one of each.
        unique_notes = []
        for note in notes:
            if note not in unique_notes:
                unique_notes.append(note)
        state["last_added"] = added
        state["last_notes"] = unique_notes
        _write_json(state_path(report), state)
        return {
            "ok": True,
            "running": False,
            "bootstrapped": bootstrap,
            "added": added,
            "notes": unique_notes,
        }
    except Exception:
        failed = load_state(report)
        failed["last_added"] = 0
        failed["last_notes"] = ["The check did not finish."]
        try:
            _write_json(state_path(report), failed)
        except OSError:
            pass
        return {
            "ok": False,
            "running": False,
            "bootstrapped": bool(failed.get("bootstrapped")),
            "added": 0,
            "notes": ["The check did not finish."],
        }
    finally:
        try:
            running_path(report).unlink()
        except OSError:
            pass


def _running_pid(report: Path) -> int:
    raw = _read_json(running_path(report))
    if not isinstance(raw, dict):
        return 0
    try:
        return int(raw.get("pid") or 0)
    except (TypeError, ValueError):
        return 0


def is_due(report: Path, now: datetime | None = None) -> bool:
    """A check starts only when the operator clicks Check now."""
    del report, now
    return False


def mark_reviewed(report: Path, alert_id_value: str) -> bool:
    alerts = load_alerts(report)
    found = False
    for item in alerts:
        if str(item.get("id") or "") == alert_id_value:
            item["state"] = "reviewed"
            found = True
            break
    if found:
        save_alerts(report, alerts)
    return found


def public_status(report: Path, now: datetime | None = None) -> dict[str, Any]:
    cfg = _config()
    alerts = load_alerts(report)
    unreviewed = sum(1 for item in alerts if item.get("state") != "reviewed")
    state = load_state(report)
    schedule = ""
    try:
        last_added = int(state.get("last_added") or 0)
    except (TypeError, ValueError):
        last_added = 0
    raw_notes = state.get("last_notes")
    last_notes = []
    if isinstance(raw_notes, list):
        for note in raw_notes:
            text = str(note or "").strip()
            if text and text not in last_notes:
                last_notes.append(text)
    raw_progress = state.get("progress")
    progress = []
    if isinstance(raw_progress, list):
        for item in raw_progress:
            text = str(item or "").strip()
            if progress_line_ok(text) and text not in progress:
                progress.append(text)
    return {
        "ok": True,
        "alerts": alerts,
        "unreviewed": unreviewed,
        "running": check_running(report),
        "schedule": schedule,
        "timezone": cfg.read_timezone() or "UTC",
        "last_pull_utc": state.get("last_pull_utc") or "",
        "bootstrapped": bool(state.get("bootstrapped")),
        "last_added": last_added,
        "last_notes": last_notes,
        "progress": progress,
        "due": is_due(report, now),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Discover threat intel feed")
    parser.add_argument("action", choices=("status", "check", "review"))
    parser.add_argument("--report", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--id", default="")
    args = parser.parse_args(argv)
    report = Path(args.report).expanduser().resolve()
    if args.action == "status":
        payload = public_status(report)
    elif args.action == "review":
        if not args.id:
            payload = {"ok": False, "error": "Missing alert id."}
            print(json.dumps(payload))
            return 2
        found = mark_reviewed(report, args.id)
        payload = {"ok": found, "saved": found}
        if not found:
            payload["error"] = "Alert not found."
    else:
        payload = run_check(report, force=args.force)
    print(json.dumps(payload))
    return 0 if payload.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
