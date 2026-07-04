#!/usr/bin/env python3
"""Parallel web sensitive-path probing engine for dev/sensitive-scanner.sh."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEV_DIR = Path(__file__).resolve().parent.parent.parent
FILESCAN = Path(__file__).resolve().parent / "filescan.py"
DEFAULT_QUICK = DEV_DIR / "data" / "sensitive-web-paths-quick.txt"
DEFAULT_FULL = DEV_DIR / "data" / "sensitive-web-paths-full.txt"

SENSITIVE_LINE_RE = re.compile(
    r"(api[-_]?key|password|secret|token|credential|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.)",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HEADER_RE = re.compile(r"^(server|x-powered-by|x-aspnet|x-generator):", re.IGNORECASE)
ROBOTS_DISALLOW_RE = re.compile(
    r"(admin|backup|config|db|database|auth|password|user|login|private|secret|key)",
    re.IGNORECASE,
)
DIR_LISTING_RE = re.compile(r"<title>Index of |Directory listing for", re.IGNORECASE)

SCAN_DIR_PATH_FILES = [
    "api_scanner/found_api_endpoints.txt",
    "api_scanner/openapi_endpoints.txt",
    "api_scanner/endpoints_html.txt",
]

USER_AGENT = "Mozilla/5.0 (compatible; DiscoverSensitiveScanner/2.0)"


class RateLimiter:
    def __init__(self, rps: float):
        self.rps = rps
        self.lock = threading.Lock()
        self.next_time = 0.0

    def wait(self) -> None:
        if self.rps <= 0:
            return
        interval = 1.0 / self.rps
        with self.lock:
            now = time.monotonic()
            if now < self.next_time:
                time.sleep(self.next_time - now)
            self.next_time = max(now, self.next_time) + interval


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def path_hash(path: str) -> str:
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def load_wordlist(path: Path) -> list[str]:
    paths = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        paths.append(line)
    return paths


def extract_robots_paths(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        if "disallow:" not in line.lower():
            continue
        part = line.split(":", 1)[-1].strip()
        if not part or part == "/":
            continue
        if ROBOTS_DISALLOW_RE.search(part):
            if not part.startswith("/"):
                part = "/" + part
            out.append(part)
    return out


def extract_sitemap_paths(base_url: str, text: str) -> list[str]:
    paths = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return paths
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    for loc in root.findall(".//sm:loc", ns):
        if loc.text:
            u = urlparse(loc.text.strip())
            if u.path:
                paths.append(u.path)
    if not paths:
        for loc in root.findall(".//loc"):
            if loc.text:
                u = urlparse(loc.text.strip())
                if u.path:
                    paths.append(u.path)
    return paths


def paths_from_scan_dir(scan_dir: Path, base_url: str) -> list[str]:
    paths = []
    for rel in SCAN_DIR_PATH_FILES:
        fpath = scan_dir / rel
        if not fpath.is_file():
            continue
        for line in fpath.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            url = line.split()[0] if " " in line else line
            if not url.startswith("http"):
                continue
            u = urlparse(url)
            if u.path and u.path != "/":
                paths.append(u.path)
    return paths


def build_session(insecure: bool, bearer: str) -> requests.Session:
    sess = requests.Session()
    sess.verify = not insecure
    sess.headers.update({"User-Agent": USER_AGENT})
    if bearer:
        sess.headers["Authorization"] = f"Bearer {bearer}"
    return sess


def is_soft_404(content_type: str, body: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct and re.search(r"(not found|404|page not found|error)", body[:2000], re.I):
        return True
    return False


def deep_scan_content(content_path: Path, url: str, out_dir: Path, domain: str, mode: str) -> list[dict]:
    slug = path_hash(url)
    scan_out = out_dir / "deep_scan" / slug
    import subprocess

    cmd = [
        sys.executable, str(FILESCAN),
        "--file", str(content_path),
        "--output-dir", str(scan_out),
        "--domain", domain,
        "--mode", mode,
        "--evidence-prefix", f"web_sensitive/deep_scan/{slug}",
        "--hits-out", str(scan_out / "hits.jsonl"),
    ]
    subprocess.run(cmd, check=False, capture_output=True)
    hits = []
    hits_file = scan_out / "hits.jsonl"
    if hits_file.is_file():
        for line in hits_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                hits.append(json.loads(line))
    return hits


def probe_path(
    base_url: str,
    path: str,
    sess: requests.Session,
    out_dir: Path,
    domain: str,
    args: argparse.Namespace,
    limiter: RateLimiter,
) -> dict:
    limiter.wait()
    if args.delay > 0:
        time.sleep(args.delay)

    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    result = {
        "path": path,
        "url": url,
        "status": 0,
        "findings": [],
    }
    try:
        head = sess.head(url, timeout=15, allow_redirects=True)
        status = head.status_code
        if status in {405, 501} or status == 0:
            resp = sess.get(url, timeout=15, allow_redirects=True)
            status = resp.status_code
            content_type = resp.headers.get("Content-Type", "")
            body = resp.text[:50000] if resp.text else ""
        else:
            content_type = head.headers.get("Content-Type", "")
            body = ""
            if status == 200 and not args.no_store_content:
                resp = sess.get(url, timeout=15, allow_redirects=True)
                status = resp.status_code
                content_type = resp.headers.get("Content-Type", "")
                body = resp.text[:500000] if resp.text else ""
    except requests.RequestException:
        return result

    result["status"] = status
    if status not in {200, 401, 403}:
        return result

    result["findings"].append({
        "severity": "warning",
        "domain": domain,
        "resource": path,
        "check": "exposed_path",
        "detail": f"Sensitive path returned HTTP {status}",
        "evidence": "web_sensitive/found_paths.txt",
    })

    if status != 200:
        return result

    if is_soft_404(content_type, body):
        return result

    slug = path_hash(path)
    if DIR_LISTING_RE.search(body[:5000]):
        result["findings"].append({
            "severity": "info",
            "domain": domain,
            "resource": path,
            "check": "directory_listing",
            "detail": "Possible directory listing exposed",
            "evidence": "web_sensitive/found_paths.txt",
        })

    if args.no_store_content:
        if SENSITIVE_LINE_RE.search(body):
            result["findings"].append({
                "severity": "high",
                "domain": domain,
                "resource": path,
                "check": "sensitive_content",
                "detail": "Sensitive patterns detected (content not stored)",
                "evidence": "web_sensitive/sensitive_data_files.txt",
            })
        return result

    content_file = out_dir / f"content_{slug}.txt"
    content_file.write_text(body, encoding="utf-8", errors="replace")

    sens_file = out_dir / f"sensitive_content_{slug}.txt"
    matches = [ln for ln in body.splitlines() if SENSITIVE_LINE_RE.search(ln)]
    if matches:
        sens_file.write_text("\n".join(matches[:50]), encoding="utf-8")
        with (out_dir / "sensitive_data_files.txt").open("a", encoding="utf-8") as sdf:
            sdf.write(url + "\n")
        result["findings"].append({
            "severity": "high",
            "domain": domain,
            "resource": path,
            "check": "sensitive_content",
            "detail": matches[0][:300],
            "evidence": f"web_sensitive/sensitive_content_{slug}.txt",
        })
        result["findings"].extend(deep_scan_content(content_file, url, out_dir, domain, args.mode))

    if args.shred_content:
        content_file.unlink(missing_ok=True)

    return result


def load_checkpoint(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("completed", []))
    except json.JSONDecodeError:
        return set()


def save_checkpoint(path: Path, completed: set[str]) -> None:
    path.write_text(json.dumps({"completed": sorted(completed), "updated": now_iso()}, indent=2), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Sensitive web scanner engine")
    ap.add_argument("--url", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--wordlist", default="")
    ap.add_argument("--scan-dir", default="")
    ap.add_argument("--mode", choices=("quick", "full"), default="full")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--delay", type=float, default=0)
    ap.add_argument("--rps", type=float, default=0)
    ap.add_argument("--max-paths", type=int, default=0)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--bearer-token", default="")
    ap.add_argument("--no-store-content", action="store_true")
    ap.add_argument("--shred-content", action="store_true")
    ap.add_argument("--resume", action="store_true")
    args = ap.parse_args()

    base_url = args.url if re.match(r"^https?://", args.url) else f"https://{args.url}"
    domain = urlparse(base_url).netloc
    out_dir = Path(args.output_dir)
    engine_dir = out_dir / "engine"
    engine_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = engine_dir / "checkpoint.json"

    wordlist_path = Path(args.wordlist) if args.wordlist else (DEFAULT_QUICK if args.mode == "quick" else DEFAULT_FULL)
    paths = load_wordlist(wordlist_path)

    sess = build_session(args.insecure, args.bearer_token)

    # robots.txt
    robots_findings = []
    try:
        r = sess.get(urljoin(base_url, "/robots.txt"), timeout=15)
        if r.status_code == 200 and r.text:
            (out_dir / "robots.txt").write_text(r.text, encoding="utf-8")
            robot_paths = extract_robots_paths(r.text)
            paths.extend(robot_paths)
            if robot_paths:
                with (out_dir / "sensitive_paths.txt").open("w", encoding="utf-8") as rf:
                    for rp in robot_paths:
                        rf.write(f"Disallow: {rp}\n")
            for line in r.text.splitlines():
                if "disallow:" in line.lower() and ROBOTS_DISALLOW_RE.search(line):
                    robots_findings.append({
                        "severity": "info",
                        "domain": domain,
                        "resource": "robots.txt",
                        "check": "robots_disallow",
                        "detail": line.strip()[:300],
                        "evidence": "web_sensitive/sensitive_paths.txt",
                    })
    except requests.RequestException:
        pass

    # sitemap.xml
    for sm in ("/sitemap.xml", "/sitemap_index.xml"):
        try:
            r = sess.get(urljoin(base_url, sm), timeout=15)
            if r.status_code == 200 and r.text:
                paths.extend(extract_sitemap_paths(base_url, r.text))
                break
        except requests.RequestException:
            continue

    if args.scan_dir:
        paths.extend(paths_from_scan_dir(Path(args.scan_dir), base_url))

    # dedupe preserve order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    paths = unique_paths

    if args.max_paths > 0:
        paths = paths[: args.max_paths]

    completed = load_checkpoint(checkpoint_path) if args.resume else set()
    pending = [p for p in paths if path_hash(p) not in completed]

    all_findings = list(robots_findings)
    found_paths = []
    limiter = RateLimiter(args.rps)

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(probe_path, base_url, p, sess, out_dir, domain, args, limiter): p
            for p in pending
        }
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                res = fut.result()
            except Exception as exc:
                res = {"path": p, "url": "", "status": 0, "findings": [], "error": str(exc)}
            completed.add(path_hash(p))
            if res.get("status") in {200, 401, 403}:
                found_paths.append(f"{res.get('url', p)} ({res['status']})")
            all_findings.extend(res.get("findings", []))
            if len(completed) % 25 == 0:
                save_checkpoint(checkpoint_path, completed)

    save_checkpoint(checkpoint_path, completed)

    if found_paths:
        with (out_dir / "found_paths.txt").open("a", encoding="utf-8") as fh:
            for line in found_paths:
                fh.write(line + "\n")

    # headers + homepage
    try:
        hr = sess.head(base_url, timeout=15, allow_redirects=True)
        header_text = "\n".join(f"{k}: {v}" for k, v in hr.headers.items())
        (out_dir / "http_headers.txt").write_text(header_text, encoding="utf-8")
        for line in header_text.splitlines():
            if HEADER_RE.match(line):
                all_findings.append({
                    "severity": "info",
                    "domain": domain,
                    "resource": base_url,
                    "check": "header_disclosure",
                    "detail": line,
                    "evidence": "web_sensitive/http_headers.txt",
                })
    except requests.RequestException:
        pass

    try:
        ir = sess.get(base_url, timeout=15, allow_redirects=True)
        if ir.status_code == 200 and ir.text and not args.no_store_content:
            index_path = out_dir / "index.html"
            index_path.write_text(ir.text[:500000], encoding="utf-8")
            emails = sorted(set(EMAIL_RE.findall(ir.text)))
            if emails:
                (out_dir / "emails.txt").write_text("\n".join(emails), encoding="utf-8")
                for email in emails:
                    all_findings.append({
                        "severity": "warning",
                        "domain": domain,
                        "resource": base_url,
                        "check": "exposed_email",
                        "detail": email,
                        "evidence": "web_sensitive/emails.txt",
                    })
            all_findings.extend(deep_scan_content(index_path, base_url, out_dir, domain, args.mode))
            if args.shred_content:
                index_path.unlink(missing_ok=True)
    except requests.RequestException:
        pass

    findings_path = engine_dir / "findings.jsonl"
    with findings_path.open("w", encoding="utf-8") as fh:
        for f in all_findings:
            fh.write(json.dumps(f, ensure_ascii=False) + "\n")

    results = {
        "generated": now_iso(),
        "target": base_url,
        "paths_total": len(paths),
        "paths_probed": len(pending),
        "findings": len(all_findings),
    }
    (engine_dir / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())