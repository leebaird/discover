#!/usr/bin/env python3
"""Discover social profile URLs from a company homepage and fetch follower counts."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
INSTAGRAM_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

BLOCKED_HOME_MARKERS = (
    "access denied",
    "sec-if-cpt-container",
    "please enable javascript",
    "just a moment",
    "cf-browser-verification",
    "errors.edgesuite.net",
)

PLATFORM_ORDER = ("facebook", "Instagram", "Linkedin", "X", "YouTube")

PLATFORM_RULES = (
    ("facebook", re.compile(r"(?:^|\.)facebook\.com$", re.I), re.compile(r"facebook\.com/(?:pages/|pg/|profile\.php\?id=|people/|[A-Za-z0-9._-]+/?$)", re.I)),
    ("Instagram", re.compile(r"(?:^|\.)instagram\.com$", re.I), re.compile(r"instagram\.com/(?:_u/)?[A-Za-z0-9._-]+/?$", re.I)),
    ("Linkedin", re.compile(r"(?:^|\.)linkedin\.com$", re.I), re.compile(r"linkedin\.com/company/[A-Za-z0-9._-]+/?$", re.I)),
    ("X", re.compile(r"(?:^|\.)(?:twitter|x)\.com$", re.I), re.compile(r"(?:twitter|x)\.com/(?!home|search|intent|share|i/)[A-Za-z0-9_]+/?$", re.I)),
    ("YouTube", re.compile(r"(?:^|\.)youtube\.com$", re.I), re.compile(r"youtube\.com/(?:channel/|c/|user/|@)[A-Za-z0-9._-]+/?$", re.I)),
)

SKIP_PATH_PARTS = (
    "/watch",
    "/playlist",
    "/shorts/",
    "/status/",
    "/hashtag/",
    "/login",
    "/signup",
    "/sharer",
    "/share",
    "/intent/",
    "/home",
)


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


def fetch_url(url: str, timeout: int = 25, user_agent: str = USER_AGENT) -> str:
    result = subprocess.run(
        [
            "curl",
            "-ksL",
            "--compressed",
            "-A",
            user_agent,
            "--max-time",
            str(timeout),
            url,
        ],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode == 0 and result.stdout:
        return result.stdout

    wget = subprocess.run(
        [
            "wget",
            "-q",
            "-U",
            user_agent,
            f"--timeout={timeout}",
            "-O",
            "-",
            url,
        ],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return wget.stdout if wget.returncode == 0 else ""


def homepage_blocked(html: str) -> bool:
    if not html or len(html) < 800:
        return True
    lowered = html.lower()
    return any(marker in lowered for marker in BLOCKED_HOME_MARKERS)


def lowercase_url(url: str) -> str:
    result = subprocess.run(
        ["tr", "[:upper:]", "[:lower:]"],
        input=url.strip(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout:
        return result.stdout.strip()
    return url.strip().lower()


def normalize_url(raw: str, base: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:")):
        return None

    joined = urllib.parse.urljoin(base, raw)
    parsed = urllib.parse.urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return None

    path = parsed.path or "/"
    for skip in SKIP_PATH_PARTS:
        if skip in path.lower():
            return None

    cleaned = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path.rstrip("/") or "/", "", "", ""))
    return lowercase_url(cleaned.rstrip("/"))


def classify_url(url: str) -> str | None:
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]

    target = f"{host}{parsed.path}"
    for label, host_re, path_re in PLATFORM_RULES:
        if not host_re.search(host):
            continue
        if path_re.search(target):
            return label
    return None


def extract_links(html: str, base_url: str) -> dict[str, str]:
    found: dict[str, str] = {}

    parser = LinkExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass

    candidates = list(parser.links)
    for block in re.findall(r"<script[^>]+type=[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", html, re.I | re.S):
        try:
            payload = json.loads(block)
        except json.JSONDecodeError:
            continue
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            same_as = item.get("sameAs")
            if isinstance(same_as, str):
                candidates.append(same_as)
            elif isinstance(same_as, list):
                candidates.extend(str(entry) for entry in same_as)

    for raw in candidates:
        url = normalize_url(raw, base_url)
        if not url:
            continue
        label = classify_url(url)
        if not label:
            continue
        found.setdefault(label, url)

    return found


def parse_count(raw: str) -> str | None:
    raw = raw.strip().replace(",", "")
    if not raw:
        return None

    match = re.fullmatch(r"([\d.]+)\s*([KMB])?", raw, re.I)
    if not match:
        return None

    value = float(match.group(1))
    suffix = (match.group(2) or "").upper()
    if suffix == "K":
        value *= 1_000
    elif suffix == "M":
        value *= 1_000_000
    elif suffix == "B":
        value *= 1_000_000_000

    if value >= 1_000_000:
        scaled = value / 1_000_000
        if scaled.is_integer():
            return f"{int(scaled)}M"
        text = f"{scaled:.2f}".rstrip("0").rstrip(".")
        return f"{text}M"
    if value >= 10_000:
        scaled = value / 1_000
        if scaled.is_integer():
            return f"{int(scaled)}K"
        text = f"{scaled:.2f}".rstrip("0").rstrip(".")
        return f"{text}K"
    if value >= 1_000:
        scaled = value / 1_000
        text = f"{scaled:.2f}".rstrip("0").rstrip(".")
        return f"{text}K"
    return str(int(value))


def format_count(value: int | float | str) -> str:
    if isinstance(value, str):
        parsed = parse_count(value)
        return parsed if parsed else value
    return parse_count(str(int(value))) or str(int(value))


def fetch_followers(label: str, url: str) -> str:
    agent = INSTAGRAM_USER_AGENT if label == "Instagram" else USER_AGENT
    html = fetch_url(url, user_agent=agent)
    if not html or len(html) < 400:
        return "Blocked"

    if label == "YouTube":
        match = re.search(r'"subscriberCountText":\{.*?"simpleText":"([^"]+)"', html, re.S)
        if match:
            text = match.group(1).replace(" subscribers", "").strip()
            parsed = parse_count(text)
            return parsed or text
        match = re.search(r'"subscriberCount":"(\d+)"', html)
        if match:
            return format_count(int(match.group(1)))

    if label == "Linkedin":
        match = re.search(r"([\d,.]+[KMB]?)\s+followers on LinkedIn", html, re.I)
        if match:
            parsed = parse_count(match.group(1))
            return parsed or match.group(1)
        match = re.search(r'"followersCount":(\d+)', html)
        if match:
            return format_count(int(match.group(1)))

    if label == "Instagram":
        match = re.search(
            r'<meta[^>]+property="og:description"[^>]+content="([^"]+)"|content="([^"]+)"[^>]+property="og:description"|property="og:description"\s+content="([^"]+)"',
            html,
            re.I,
        )
        if match:
            desc = next(group for group in match.groups() if group)
            count_match = re.search(r"([\d,.]+[KMB]?)\s+Followers", desc, re.I)
            if count_match:
                parsed = parse_count(count_match.group(1))
                return parsed or count_match.group(1)
        match = re.search(r'"edge_followed_by":\{"count":(\d+)', html)
        if match:
            return format_count(int(match.group(1)))

    if label == "facebook":
        for pattern in (
            r'"follower_count":(\d+)',
            r'"followers_count":(\d+)',
            r'([\d,.]+[KMB]?)\s+followers',
        ):
            match = re.search(pattern, html, re.I)
            if match:
                token = match.group(1)
                if token.isdigit():
                    return format_count(int(token))
                parsed = parse_count(token)
                if parsed:
                    return parsed

    if label == "X":
        for pattern in (
            r'"followers_count":(\d+)',
            r"followers_count&quot;:(\d+)",
            r">([\d,.]+[KMB]?)\s+Followers<",
        ):
            match = re.search(pattern, html)
            if match:
                token = match.group(1)
                if token.isdigit():
                    return format_count(int(token))
                parsed = parse_count(token)
                if parsed:
                    return parsed

    return "Blocked"


def load_manual(path: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    if not path.is_file():
        return found

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        label, url = parts[0].strip(), parts[1].strip()
        if label and url:
            found[label] = lowercase_url(url)
    return found


def format_block(rows: list[tuple[str, str, str]]) -> str:
    label_width = 16
    followers_gap = 5
    max_url_len = max((len(url) for _, url, _ in rows), default=len("URL"))

    lines = [
        f"{'Social Media':<{label_width}} {'URL':<{max_url_len}}{' ' * followers_gap}Followers",
        "",
    ]
    if not rows:
        lines.append("(none found)")
    else:
        for label, url, followers in rows:
            lines.append(
                f"{label:<{label_width}} {url:<{max_url_len}}{' ' * followers_gap}{followers}"
            )
    lines.append("=" * 127)
    return "\n".join(lines)


def patch_summary(page: Path, block: str) -> None:
    text = page.read_text(encoding="utf-8", errors="replace")
    start = "<!-- INC_SOCIAL_START -->"
    end = "<!-- INC_SOCIAL_END -->"
    if start not in text or end not in text:
        raise SystemExit(f"summary markers missing in {page}")

    updated = re.sub(
        rf"{re.escape(start)}.*?{re.escape(end)}",
        f"{start}{block}{end}",
        text,
        count=1,
        flags=re.S,
    )
    page.write_text(updated, encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <domain> <tools_dir> [summary.htm]", file=sys.stderr)
        return 1

    domain = sys.argv[1].strip().lower()
    tools_dir = Path(sys.argv[2])
    tools_dir.mkdir(parents=True, exist_ok=True)

    homepage_path = tools_dir / "homepage.html"
    social_path = tools_dir / "social.tsv"
    manual_path = tools_dir / "social-manual.tsv"

    homepage_html = ""
    homepage_url = ""
    for candidate in (f"https://www.{domain}", f"https://{domain}"):
        homepage_html = fetch_url(candidate)
        if homepage_html and not homepage_blocked(homepage_html):
            homepage_url = candidate
            break

    if homepage_html:
        homepage_path.write_text(homepage_html, encoding="utf-8", errors="replace")

    profiles: dict[str, str] = {}
    if homepage_html and not homepage_blocked(homepage_html):
        profiles.update(extract_links(homepage_html, homepage_url or f"https://www.{domain}"))
    profiles.update(load_manual(manual_path))

    rows: list[tuple[str, str, str]] = []
    ordered_labels = [label for label in PLATFORM_ORDER if label in profiles]
    for label in sorted(profiles.keys()):
        if label not in ordered_labels:
            ordered_labels.append(label)

    for index, label in enumerate(ordered_labels):
        url = lowercase_url(profiles[label])
        followers = fetch_followers(label, url)
        rows.append((label, url, followers))
        if index + 1 < len(ordered_labels):
            time.sleep(2)

    with social_path.open("w", encoding="utf-8", newline="\n") as handle:
        for label, url, followers in rows:
            handle.write(f"{label}\t{url}\t{followers}\n")

    if len(sys.argv) >= 4:
        patch_summary(Path(sys.argv[3]), format_block(rows))

    for label, url, followers in rows:
        print(f"{label}\t{url}\t{followers}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())