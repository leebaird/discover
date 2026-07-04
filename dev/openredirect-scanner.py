#!/usr/bin/env python3

# by ibrahimsql - openredirect-scanner
# Engine for dev/open-redirect.sh

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PAYLOAD_FILE = SCRIPT_DIR / "data" / "openredirect-payloads.txt"
CONFIRM_CANARY = "confirm-canary.invalid"

REQUEST_TIMEOUT = 10
MAX_RETRIES = 2
BATCH_SIZE = 150
REDIRECT_CODES = {301, 302, 303, 307, 308}

REDIRECT_PARAMS_FULL = [
    "redirect", "redirect_to", "redirecturi", "redirect_uri", "redirectUrl", "RedirectUrl",
    "return", "returnurl", "returnUri", "return_url", "returnURL", "ReturnURL",
    "return_to", "returnTo", "returnto", "url", "next", "nextUrl", "next_url",
    "link", "goto", "to", "out", "view", "login_url", "loginurl", "continue",
    "dest", "destination", "redir", "redirect_url", "ReturnUrl", "forward",
    "forward_url", "forwardurl", "location", "exit_url", "exiturl", "target",
    "navigate", "return_path", "returnpath", "retUrl", "returl", "rurl", "r_url",
    "u", "uri", "relaystate", "relayState", "RelayState", "redirectback",
    "redirect_back", "redirectBack", "checkout_url", "checkouturl", "checkout",
    "ref", "reference", "path", "file", "site", "page", "src", "source",
    "callback", "callbackurl", "callback_url", "go", "go_to", "move", "nav",
    "jump", "jump_to", "rpath", "redirect_uri_path", "success_url", "successurl",
    "success", "login", "logto", "logon", "loginto", "openid_url", "openidurl",
    "idp", "idp_uri", "referer", "redirect_from", "successURL", "nextURL", "home",
    "homepage", "landingpage", "login_success", "return_after_login",
]

REDIRECT_PARAMS_QUICK = REDIRECT_PARAMS_FULL[:25]
REDIRECT_PARAM_SET = {p.lower() for p in REDIRECT_PARAMS_FULL}

FULL_PATH_SUFFIXES = [
    "", "/login", "/signin", "/auth", "/oauth", "/redirect", "/logout", "/account",
]

HEADER_PROBE_NAMES = [
    "Referer", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]

SCAN_DIR_URL_FILES = [
    "api_scanner/found_api_endpoints.txt",
    "api_scanner/endpoints_html.txt",
    "api_scanner/openapi_endpoints.txt",
    "targets.txt",
    "urls.txt",
]

stop_scanning = False
quiet_mode = False
results_lock = threading.Lock()
rate_lock = threading.Lock()
vulnerabilities: list[dict] = []
tested_keys: set[str] = set()
seen_vulns: set[str] = set()
total_tested = 0
max_requests = 0
request_delay = 0.0
requests_per_second = 0.0
_last_request_ts = 0.0
engine_dir = ""
canary_host = "evil-canary.invalid"
confirm_enabled = True
results_saved = False


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def log(msg: str) -> None:
    line = f"[{now_iso()}] {msg}"
    if not quiet_mode:
        print(line)
    if engine_dir:
        with open(os.path.join(engine_dir, "engine.log"), "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def stable_id(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def test_key(method: str, test_type: str, url: str, param: str, payload: str) -> str:
    return stable_id(method, test_type, url, param, payload)


def rate_wait() -> None:
    global _last_request_ts
    if request_delay <= 0 and requests_per_second <= 0:
        return
    with rate_lock:
        now = time.monotonic()
        if requests_per_second > 0:
            min_gap = 1.0 / requests_per_second
            wait = min_gap - (now - _last_request_ts)
            if wait > 0:
                time.sleep(wait)
        elif request_delay > 0:
            time.sleep(request_delay)
        _last_request_ts = time.monotonic()


def bump_test_count() -> bool:
    global total_tested
    with results_lock:
        total_tested += 1
        if max_requests > 0 and total_tested > max_requests:
            return False
    return True


def load_payload_templates(canary: str, mode: str, payload_file: Path | None) -> list[str]:
    path = payload_file or DEFAULT_PAYLOAD_FILE
    templates: list[str] = []
    if path.is_file():
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                templates.append(line.replace("{canary}", canary))
    if not templates:
        templates = [
            f"https://{canary}", f"//{canary}", f"/{canary}", canary,
            f"javascript:alert(1)", f"data:text/html,<script>location='https://{canary}'</script>",
        ]
    templates = list(dict.fromkeys(templates))
    if mode == "quick":
        return templates[:15]
    return templates


def load_wordlist(path: str) -> list[str]:
    params: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                params.append(line)
    log(f"Loaded {len(params)} parameters from wordlist")
    return params


def load_urls_from_file(path: str) -> list[str]:
    urls: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().split()[0] if line.strip() else ""
            if line and not line.startswith("#"):
                if not line.startswith(("http://", "https://")):
                    line = "https://" + line
                urls.append(line)
    log(f"Loaded {len(urls)} URLs from {path}")
    return urls


def collect_scan_dir_urls(scan_dir: str) -> list[str]:
    urls: list[str] = []
    base = Path(scan_dir)
    if not base.is_dir():
        return urls
    for rel in SCAN_DIR_URL_FILES:
        path = base / rel
        if not path.is_file():
            continue
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                token = line.strip().split()[0] if line.strip() else ""
                if token.startswith(("http://", "https://")):
                    urls.append(token)
                elif token.startswith("/") and (base / "api_scanner").is_dir():
                    pass
    crawl_html = base / "api_scanner/crawl/index.html"
    if crawl_html.is_file():
        try:
            html = crawl_html.read_text(encoding="utf-8", errors="ignore")
            parser = LinkExtractor()
            parser.feed(html)
            seed = urls[0] if urls else None
            for href in parser.links:
                if href.startswith(("http://", "https://")):
                    urls.append(href)
                elif seed and href.startswith("/"):
                    urls.append(urljoin(seed, href))
        except Exception as exc:
            log(f"Crawl HTML parse error: {exc}")
    urls = list(dict.fromkeys(urls))
    log(f"Collected {len(urls)} URLs from scan dir {scan_dir}")
    return urls


def crawl_seed_urls(session: requests.Session, seeds: list[str], limit: int = 40) -> list[str]:
    found: list[str] = []
    for seed in seeds[:5]:
        if stop_scanning:
            break
        try:
            rate_wait()
            resp = session.get(seed, timeout=REQUEST_TIMEOUT, verify=False)
            parser = LinkExtractor()
            parser.feed(resp.text[:50000])
            for href in parser.links:
                if href.startswith(("http://", "https://")):
                    found.append(href)
                elif href.startswith("/"):
                    found.append(urljoin(seed, href))
                if len(found) >= limit:
                    break
        except Exception as exc:
            log(f"Crawl failed for {seed}: {exc}")
    found = list(dict.fromkeys(found))
    log(f"Crawl discovered {len(found)} links")
    return found


def expand_domain_targets(domain: str) -> list[str]:
    domain = domain.strip().lower()
    domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]
    hosts = [domain]
    if not domain.startswith("www."):
        hosts.append(f"www.{domain}")
    urls: list[str] = []
    for host in hosts:
        for scheme in ("https", "http"):
            urls.append(f"{scheme}://{host}/")
    return list(dict.fromkeys(urls))


def expand_targets(targets: list[str], mode: str) -> list[str]:
    expanded: list[str] = []
    for target in targets:
        parsed = urlparse(target)
        suffixes = FULL_PATH_SUFFIXES if mode == "full" else [""]
        for suffix in suffixes:
            path = suffix or parsed.path or "/"
            if not path.startswith("/"):
                path = "/" + path
            expanded.append(urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, "")))
    return list(dict.fromkeys(expanded))


def prioritize_urls(urls: list[str]) -> list[str]:
    def score(url: str) -> tuple[int, str]:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        param_hits = sum(1 for k in qs if k.lower() in REDIRECT_PARAM_SET)
        return (-param_hits, -len(qs), url)

    return sorted(dict.fromkeys(urls), key=score)


def build_test_url(base_url: str, param: str, payload: str, mutate: bool) -> str:
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    if mutate and param not in query_params:
        return base_url
    query_params[param] = [payload]
    new_query = urlencode(query_params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def target_domain(url: str) -> str:
    return urlparse(url).netloc or "unknown"


def location_points_to_canary(location: str, canary: str, base_url: str) -> bool:
    if not location or not location.strip():
        return False
    loc = location.strip()
    c = canary.lower()
    base_host = urlparse(base_url).netloc.lower()

    if loc.lower().startswith(("javascript:", "data:")):
        return True

    if loc.startswith("//"):
        host = loc[2:].split("/")[0].split("@")[-1].split(":")[0].lower()
        return c == host or host.endswith("." + c)

    parsed = urlparse(urljoin(base_url, loc))
    host = parsed.netloc.lower()
    if not host:
        return False
    if c == host or host.endswith("." + c):
        return True
    if host != base_host and c in host:
        return True
    return False


def body_indicates_redirect(body: str, canary: str) -> tuple[bool, str]:
    if not body:
        return False, ""
    lower = body.lower()
    c = re.escape(canary.lower())

    meta = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\']+)',
        lower,
        re.I,
    )
    if meta and canary.lower() in meta.group(1).lower():
        return True, f"meta refresh to {meta.group(1)[:200]}"

    patterns = [
        (rf'window\.location(?:\.href)?\s*=\s*["\'][^"\']*{c}', "JavaScript window.location redirect"),
        (rf'location\.href\s*=\s*["\'][^"\']*{c}', "JavaScript location.href redirect"),
        (rf'href=["\']https?://{c}', "href link to canary host"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, lower):
            return True, label

    return False, ""


def classify_severity(detail: str, payload: str) -> str:
    d = (detail + " " + payload).lower()
    if "javascript" in d or "data:" in d:
        return "critical"
    return "high"


def analyze_response(
    response: requests.Response,
    payload: str,
    canary: str,
    base_url: str,
    *,
    require_redirect_status_for_header: bool = True,
) -> tuple[bool, str, str]:
    location = response.headers.get("Location", "")

    if location and location_points_to_canary(location, canary, base_url):
        if response.status_code in REDIRECT_CODES or not require_redirect_status_for_header:
            return True, "redirect_header", f"HTTP {response.status_code} Location: {location}"
        if response.status_code < 400:
            return True, "redirect_header_soft", f"Location header with status {response.status_code}: {location}"

    if location and location.lower().startswith(("javascript:", "data:")):
        return True, "redirect_header_dangerous", f"Dangerous Location: {location[:200]}"

    body = ""
    try:
        body = response.text[:12000]
    except Exception:
        body = ""

    ok, detail = body_indicates_redirect(body, canary)
    if ok and response.status_code in REDIRECT_CODES | {200, 201, 202}:
        if re.search(r"(invalid|error|denied|forbidden)", body.lower()) and "location" not in body.lower():
            if response.status_code == 200 and "refresh" not in body.lower():
                return False, "", ""
        return True, "body_redirect", detail

    return False, "", ""


def follow_one_hop(
    session: requests.Session,
    response: requests.Response,
    payload: str,
    canary: str,
    base_url: str,
) -> tuple[bool, str, str]:
    location = response.headers.get("Location", "")
    if response.status_code not in REDIRECT_CODES or not location:
        return False, "", ""
    next_url = urljoin(base_url, location)
    if urlparse(next_url).netloc == urlparse(base_url).netloc and canary.lower() not in location.lower():
        try:
            rate_wait()
            hop = session.get(next_url, allow_redirects=False, timeout=REQUEST_TIMEOUT, verify=False)
            return analyze_response(hop, payload, canary, base_url, require_redirect_status_for_header=False)
        except Exception:
            return False, "", ""
    return False, "", ""


def confirm_finding(session: requests.Session, case: dict, confirm_canary: str) -> bool:
    method = case["method"]
    test_type = case["test_type"]
    url = case["base_url"]
    param = case["parameter"]
    mutate = test_type == "mutate"
    payload = case["payload"].replace(canary_host, confirm_canary)
    test_url = build_test_url(url, param, payload, mutate)

    try:
        rate_wait()
        if method == "POST":
            resp = session.post(test_url, data={param: payload}, allow_redirects=False, timeout=REQUEST_TIMEOUT, verify=False)
        elif test_type == "header":
            headers = {param: payload}
            resp = session.get(url, headers=headers, allow_redirects=False, timeout=REQUEST_TIMEOUT, verify=False)
        else:
            resp = session.get(test_url, allow_redirects=False, timeout=REQUEST_TIMEOUT, verify=False)
        ok, _, _ = analyze_response(resp, payload, confirm_canary, url)
        if ok:
            return True
        ok2, _, _ = follow_one_hop(session, resp, payload, confirm_canary, url)
        return ok2
    except Exception:
        return False


def record_vulnerability(result: dict) -> None:
    vid = result.get("id") or stable_id(
        result.get("method", "GET"),
        result.get("test_type", ""),
        result.get("base_url", ""),
        result.get("parameter", ""),
        result.get("payload", ""),
    )
    with results_lock:
        if vid in seen_vulns:
            return
        seen_vulns.add(vid)
        result["id"] = vid
        vulnerabilities.append(result)


def save_evidence(result: dict, content: str) -> str:
    eid = result["id"]
    rel = f"openredirect_engine/evidence/{eid}.txt"
    path = os.path.join(engine_dir, "evidence", f"{eid}.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return rel


def execute_test(session: requests.Session, case: dict, canary: str) -> dict | None:
    if stop_scanning:
        return None

    key = case["key"]
    with results_lock:
        if key in tested_keys:
            return None

    if not bump_test_count():
        stop_scanning_global()
        return None

    method = case["method"]
    test_type = case["test_type"]
    url = case["base_url"]
    param = case["parameter"]
    payload = case["payload"]
    mutate = test_type == "mutate"

    try:
        rate_wait()
        if method == "POST":
            test_url = build_test_url(url, param, payload, mutate)
            response = session.post(
                test_url,
                data={param: payload},
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        elif test_type == "header":
            test_url = url
            response = session.get(
                url,
                headers={param: payload},
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )
        else:
            test_url = build_test_url(url, param, payload, mutate)
            response = session.get(
                test_url,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                verify=False,
            )

        with results_lock:
            tested_keys.add(key)

        is_vuln, check, detail = analyze_response(response, payload, canary, url)
        if not is_vuln:
            is_vuln, check, detail = follow_one_hop(session, response, payload, canary, url)

        if not is_vuln:
            return None

        dom = target_domain(url)
        vid = stable_id(method, test_type, url, param, payload)
        evidence_body = (
            f"method={method}\n"
            f"test_type={test_type}\n"
            f"url={test_url}\n"
            f"status={response.status_code}\n"
            f"location={response.headers.get('Location', '')}\n"
            f"detail={detail}\n"
            f"{response.text[:4000]}"
        )
        confirmed = True
        if confirm_enabled and canary != CONFIRM_CANARY:
            confirmed = confirm_finding(session, case, CONFIRM_CANARY)

        result = {
            "id": vid,
            "severity": classify_severity(detail, payload),
            "domain": dom,
            "resource": f"{dom}/{param}",
            "check": check if confirmed else "open_redirect_unconfirmed",
            "detail": f"{detail} (param={param}, type={test_type}, confirmed={confirmed})",
            "evidence": "",
            "url": test_url,
            "base_url": url,
            "parameter": param,
            "payload": payload,
            "method": method,
            "test_type": test_type,
            "status_code": response.status_code,
            "location": response.headers.get("Location", ""),
            "confirmed": confirmed,
            "timestamp": now_iso(),
        }
        if not confirmed:
            result["severity"] = "warning"
        result["evidence"] = save_evidence(result, evidence_body)
        record_vulnerability(result)
        log(f"VULNERABLE: {url} [{test_type}] param={param} confirmed={confirmed}")
        return result
    except requests.exceptions.Timeout:
        log(f"Timeout: {url} param={param}")
    except requests.exceptions.RequestException as exc:
        log(f"Request failed {url}: {exc}")
    except Exception as exc:
        log(f"Unexpected error {url}: {exc}")
    finally:
        with results_lock:
            tested_keys.add(key)
    return None


def stop_scanning_global() -> None:
    global stop_scanning
    stop_scanning = True


def generate_cases(
    url: str,
    parameters: list[str],
    payloads: list[str],
    mode: str,
) -> list[dict]:
    cases: list[dict] = []
    parsed = urlparse(url)
    existing = list(parse_qs(parsed.query, keep_blank_values=True).keys())

    for param in parameters:
        for payload in payloads:
            key = test_key("GET", "inject", url, param, payload)
            cases.append({
                "key": key,
                "method": "GET",
                "test_type": "inject",
                "base_url": url,
                "parameter": param,
                "payload": payload,
            })

    for param in existing:
        if mode == "quick" and param.lower() not in REDIRECT_PARAM_SET:
            continue
        for payload in payloads:
            key = test_key("GET", "mutate", url, param, payload)
            cases.append({
                "key": key,
                "method": "GET",
                "test_type": "mutate",
                "base_url": url,
                "parameter": param,
                "payload": payload,
            })

    if mode == "full":
        post_params = parameters[:12]
        for param in post_params:
            for payload in payloads[:8]:
                key = test_key("POST", "post", url, param, payload)
                cases.append({
                    "key": key,
                    "method": "POST",
                    "test_type": "post",
                    "base_url": url,
                    "parameter": param,
                    "payload": payload,
                })
        for header in HEADER_PROBE_NAMES:
            for payload in payloads[:5]:
                key = test_key("GET", "header", url, header, payload)
                cases.append({
                    "key": key,
                    "method": "GET",
                    "test_type": "header",
                    "base_url": url,
                    "parameter": header,
                    "payload": payload,
                })

    return cases


def scan_url(session: requests.Session, base_url: str, parameters: list[str], payloads: list[str], workers: int, canary: str, mode: str):
    cases = generate_cases(base_url, parameters, payloads, mode)
    pending = [c for c in cases if c["key"] not in tested_keys]
    log(f"Scanning {base_url}: {len(pending)}/{len(cases)} pending tests")
    completed = 0

    for batch_start in range(0, len(pending), BATCH_SIZE):
        if stop_scanning:
            break
        batch = pending[batch_start:batch_start + BATCH_SIZE]
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(execute_test, session, case, canary) for case in batch]
            for future in as_completed(futures):
                if stop_scanning:
                    break
                completed += 1
                try:
                    future.result()
                except Exception as exc:
                    log(f"Worker error: {exc}")
                if completed % 100 == 0 or completed == len(pending):
                    log(f"Progress {base_url}: {completed}/{len(pending)}")


def load_checkpoint(path: Path) -> None:
    global tested_keys, vulnerabilities, seen_vulns, total_tested
    if not path.is_file():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        tested_keys = set(data.get("tested_keys", []))
        vulnerabilities = data.get("vulnerabilities", [])
        seen_vulns = {v.get("id", stable_id(v.get("method", ""), v.get("test_type", ""), v.get("base_url", ""), v.get("parameter", ""), v.get("payload", ""))) for v in vulnerabilities}
        total_tested = int(data.get("tests_performed", 0))
        log(f"Resumed checkpoint: {len(tested_keys)} tested keys, {len(vulnerabilities)} findings")
    except Exception as exc:
        log(f"Checkpoint load failed: {exc}")


def save_checkpoint(path: Path, scan_info: dict) -> None:
    data = {
        "tests_performed": total_tested,
        "tested_keys": sorted(tested_keys),
        "vulnerabilities": vulnerabilities,
        "scan_info": scan_info,
        "completed": not stop_scanning and scan_info.get("targets_completed", 0) >= scan_info.get("targets", 0),
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_results(scan_info: dict) -> None:
    global results_saved
    if not engine_dir or results_saved:
        return
    os.makedirs(engine_dir, exist_ok=True)
    results_path = os.path.join(engine_dir, "results.json")
    payload = {"scan_info": scan_info, "vulnerabilities": vulnerabilities}
    with open(results_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    summary_path = os.path.join(engine_dir, "scan_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write("Open Redirect Scan Summary\n")
        for k, v in scan_info.items():
            fh.write(f"{k}: {v}\n")
        fh.write(f"vulnerabilities: {len(vulnerabilities)}\n")
        fh.write("=" * 60 + "\n\n")
        for i, v in enumerate(vulnerabilities, 1):
            fh.write(f"#{i} [{v.get('severity')}] confirmed={v.get('confirmed')} {v.get('detail')}\n")
            fh.write(f"    URL: {v.get('url')}\n\n")

    save_checkpoint(Path(engine_dir) / "checkpoint.json", scan_info)
    results_saved = True
    log(f"Saved {len(vulnerabilities)} findings to {results_path}")


def create_session() -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(total=MAX_RETRIES, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })
    return session


def signal_handler(_sig, _frame) -> None:
    log("Interrupted — saving partial results")
    stop_scanning_global()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Open Redirect Scanner engine")
    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument("-u", "--url")
    target.add_argument("-d", "--domain")
    target.add_argument("-f", "--file")
    parser.add_argument("--targets-file", action="append", default=[], help="Additional URL list files")
    parser.add_argument("--scan-dir", action="append", default=[], help="Prior scan output directory")
    parser.add_argument("-w", "--wordlist")
    parser.add_argument("-o", "--output-dir", required=True)
    parser.add_argument("--mode", choices=["quick", "full"], default="full")
    parser.add_argument("--canary-host", default="evil-canary.invalid")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds between requests")
    parser.add_argument("--rps", type=float, default=0.0, help="Max requests per second")
    parser.add_argument("--max-requests", type=int, default=0, help="Stop after N tests (0=unlimited)")
    parser.add_argument("--crawl", action="store_true", help="Crawl links from seed URLs")
    parser.add_argument("--no-confirm", action="store_true", help="Skip second-canary confirmation")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--payload-file")
    return parser.parse_args()


def main() -> int:
    global engine_dir, canary_host, stop_scanning, quiet_mode, confirm_enabled
    global request_delay, requests_per_second, max_requests, results_saved

    args = parse_args()
    quiet_mode = args.quiet
    confirm_enabled = not args.no_confirm
    request_delay = max(0.0, args.delay)
    requests_per_second = max(0.0, args.rps)
    max_requests = max(0, args.max_requests)
    engine_dir = os.path.join(args.output_dir, "openredirect_engine")
    canary_host = args.canary_host
    os.makedirs(engine_dir, exist_ok=True)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    checkpoint_path = Path(engine_dir) / "checkpoint.json"
    if args.resume:
        load_checkpoint(checkpoint_path)
        if checkpoint_path.is_file():
            try:
                prev = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                vulnerabilities[:] = prev.get("vulnerabilities", vulnerabilities)
            except Exception:
                pass

    targets: list[str] = []
    if args.url:
        u = args.url if args.url.startswith(("http://", "https://")) else "https://" + args.url
        targets.append(u)
    if args.domain:
        targets.extend(expand_domain_targets(args.domain))
    if args.file:
        targets.extend(load_urls_from_file(args.file))
    for tf in args.targets_file:
        targets.extend(load_urls_from_file(tf))
    for sd in args.scan_dir:
        targets.extend(collect_scan_dir_urls(sd))

    if not targets:
        log("No target specified. Use -u, -d, -f, --targets-file, or --scan-dir.")
        return 1

    targets = list(dict.fromkeys(targets))
    session = create_session()
    if args.crawl:
        targets.extend(crawl_seed_urls(session, targets))
    targets = prioritize_urls(list(dict.fromkeys(targets)))
    targets = expand_targets(targets, args.mode)

    parameters = list(REDIRECT_PARAMS_QUICK if args.mode == "quick" else REDIRECT_PARAMS_FULL)
    if args.wordlist:
        parameters.extend(load_wordlist(args.wordlist))
    parameters = list(dict.fromkeys(parameters))

    payload_path = Path(args.payload_file) if args.payload_file else None
    payloads = load_payload_templates(canary_host, args.mode, payload_path)
    workers = max(1, min(args.workers, 32))

    scan_info = {
        "generated": now_iso(),
        "mode": args.mode,
        "canary_host": canary_host,
        "confirm_canary": CONFIRM_CANARY if confirm_enabled else "",
        "targets": len(targets),
        "targets_completed": 0,
        "parameters": len(parameters),
        "payloads": len(payloads),
        "tests_performed": total_tested,
        "crawl": args.crawl,
        "max_requests": max_requests,
    }

    log(
        f"Starting: {len(targets)} URLs, {len(parameters)} params, {len(payloads)} payloads, "
        f"workers={workers}, delay={request_delay}, rps={requests_per_second}"
    )
    start = time.time()

    for i, target in enumerate(targets, 1):
        if stop_scanning:
            break
        log(f"[{i}/{len(targets)}] {target}")
        scan_url(session, target, parameters, payloads, workers, canary_host, args.mode)
        scan_info["targets_completed"] = i
        save_checkpoint(checkpoint_path, scan_info)

    scan_info["tests_performed"] = total_tested
    scan_info["duration_seconds"] = round(time.time() - start, 2)
    scan_info["vulnerabilities"] = len(vulnerabilities)
    scan_info["completed"] = scan_info["targets_completed"] >= len(targets) and not stop_scanning
    save_results(scan_info)

    log(f"Done in {scan_info['duration_seconds']}s — {total_tested} tests, {len(vulnerabilities)} vulnerabilities")
    if scan_info.get("completed"):
        return 0
    if max_requests > 0 and total_tested >= max_requests:
        return 0
    if stop_scanning:
        return 130
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        stop_scanning_global()
        sys.exit(130)