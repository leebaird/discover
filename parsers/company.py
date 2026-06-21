#!/usr/bin/env python3
"""Discover corporate HQ address and phone for the Summary page."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

SEC_USER_AGENT = "Discover Script discover@example.com"
WEB_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

BLOCKED_HOME_MARKERS = (
    "access denied",
    "sec-if-cpt-container",
    "please enable javascript",
    "just a moment",
    "cf-browser-verification",
    "errors.edgesuite.net",
)

DEI_FIELDS = (
    "dei:EntityAddressAddressLine1",
    "dei:EntityAddressAddressLine2",
    "dei:EntityAddressCityOrTown",
    "dei:EntityAddressStateOrProvince",
    "dei:EntityAddressPostalZipCode",
    "dei:EntityAddressCountry",
    "dei:CityAreaCode",
    "dei:LocalPhoneNumber",
)

PHONE_RE = re.compile(
    r"(?:\+?1[-.\s]?)?(?:\(\s*\d{3}\s*\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}"
)
US_ZIP_RE = re.compile(r"\b\d{5}(?:-\d{4})?\b")
CA_POSTAL_RE = re.compile(r"\b[A-Z]\d[A-Z][ -]?\d[A-Z]\d\b", re.I)
STREET_HINT_RE = re.compile(
    r"\b(?:street|st\.?|avenue|ave\.?|road|rd\.?|boulevard|blvd\.?|drive|dr\.?|lane|ln\.?|way|court|ct\.?|place|pl\.?|highway|hwy\.?|route|suite|floor|ste\.?)\b",
    re.I,
)


def fetch_url(url: str, timeout: int = 25, user_agent: str = WEB_USER_AGENT) -> str:
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
        ["wget", "-q", "-U", user_agent, f"--timeout={timeout}", "-O", "-", url],
        capture_output=True,
        text=True,
        errors="replace",
    )
    return wget.stdout if wget.returncode == 0 else ""


def html_to_lines(html: str) -> list[str]:
    text = re.sub(r"<(script|style|noscript)[^>]*>[\s\S]*?</\1>", " ", html, flags=re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</(p|div|li|tr|h[1-6])>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", "\n", text)
    lines: list[str] = []
    for raw in text.split("\n"):
        line = re.sub(r"\s+", " ", raw).strip()
        if line:
            lines.append(line)
    return lines


def extract_footer_html(html: str) -> str:
    match = re.search(r"<footer\b[\s\S]*?</footer>", html, re.I)
    if match:
        return match.group(0)
    return html[-20000:]


def normalize_name(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def company_name_tokens(company: str, domain: str) -> list[str]:
    tokens = [normalize_name(company)]
    base = domain.split(".", 1)[0]
    if base:
        tokens.append(normalize_name(base))
    return tokens


def find_cik(company: str, domain: str, cache_path: Path) -> str | None:
    if cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = None
    else:
        payload = None

    if not isinstance(payload, dict):
        raw = fetch_url(
            "https://www.sec.gov/files/company_tickers.json",
            user_agent=SEC_USER_AGENT,
        )
        if not raw or not raw.lstrip().startswith("{"):
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        cache_path.write_text(json.dumps(payload), encoding="utf-8")

    tokens = company_name_tokens(company, domain)
    best: tuple[int, str] | None = None
    for entry in payload.values():
        title = normalize_name(str(entry.get("title", "")))
        cik = str(entry.get("cik_str", "")).strip()
        if not title or not cik:
            continue
        for token in tokens:
            if not token:
                continue
            if title == token or token in title or title in token:
                score = 100 if title == token else 80 if title.startswith(token) else 60
                if best is None or score > best[0]:
                    best = (score, cik.zfill(10))
    return best[1] if best else None


def latest_10k_url(cik: str) -> str | None:
    cik_num = str(int(cik))
    raw = fetch_url(
        f"https://data.sec.gov/submissions/CIK{cik.zfill(10)}.json",
        user_agent=SEC_USER_AGENT,
    )
    if not raw:
        return None

    data = json.loads(raw)
    recent = data.get("filings", {}).get("recent", {})
    forms = recent.get("form", [])
    for index, form in enumerate(forms):
        if form != "10-K":
            continue
        accession = recent["accessionNumber"][index].replace("-", "")
        primary = recent["primaryDocument"][index]
        return f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{accession}/{primary}"
    return None


def parse_dei_fields(html: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for field in DEI_FIELDS:
        match = re.search(rf'name="{re.escape(field)}"[^>]*>([^<]+)<', html)
        if match:
            value = re.sub(r"\s+", " ", match.group(1)).strip()
            if value:
                found[field] = value
    return found


def format_phone(area: str, local: str) -> str:
    area = re.sub(r"\D", "", area)
    local = local.strip()
    if area and local:
        return f"({area}) {local}"
    return local or area


def sec_contact(company: str, domain: str, tools_dir: Path) -> tuple[list[str], str, str] | None:
    cache_path = tools_dir / "sec-company-tickers.json"
    cik = find_cik(company, domain, cache_path)
    if not cik:
        return None

    filing_url = latest_10k_url(cik)
    if not filing_url:
        return None

    html = fetch_url(filing_url, timeout=45, user_agent=SEC_USER_AGENT)
    if not html:
        return None

    dei = parse_dei_fields(html)
    if not dei.get("dei:EntityAddressAddressLine1"):
        return None

    lines: list[str] = [dei["dei:EntityAddressAddressLine1"]]
    if dei.get("dei:EntityAddressAddressLine2"):
        lines.append(dei["dei:EntityAddressAddressLine2"])

    city = dei.get("dei:EntityAddressCityOrTown", "")
    state = dei.get("dei:EntityAddressStateOrProvince", "")
    postal = dei.get("dei:EntityAddressPostalZipCode", "")
    country = dei.get("dei:EntityAddressCountry", "")

    city_parts = [part for part in (city, state) if part]
    city_line = ", ".join(city_parts)
    if postal:
        city_line = f"{city_line} {postal}".strip()
    if country and country.lower() not in {"us", "usa", "united states", "united states of america"}:
        city_line = f"{city_line}, {country}".strip(", ")
    if city_line:
        lines.append(city_line)

    phone = ""
    if dei.get("dei:CityAreaCode") and dei.get("dei:LocalPhoneNumber"):
        phone = format_phone(dei["dei:CityAreaCode"], dei["dei:LocalPhoneNumber"])

    return lines, phone, "sec-10k"


def normalize_phone(value: str) -> str:
    value = value.strip()
    value = re.sub(r"^tel:", "", value, flags=re.I)
    match = PHONE_RE.search(value)
    if not match:
        return ""
    phone = match.group(0)
    phone = re.sub(r"^\+?1[-.\s]?", "", phone)
    phone = re.sub(r"^\((\d{3})\)\s*", r"(\1) ", phone)
    return phone.strip()


def looks_like_address(line: str) -> bool:
    if len(line) < 8 or len(line) > 120:
        return False
    if PHONE_RE.search(line):
        return False
    if US_ZIP_RE.search(line) or CA_POSTAL_RE.search(line):
        return True
    if STREET_HINT_RE.search(line) and re.search(r"\d", line):
        return True
    return False


def extract_contact_from_html(html: str) -> tuple[list[str], str] | None:
    if not html or any(marker in html.lower() for marker in BLOCKED_HOME_MARKERS):
        return None

    footer_lines = html_to_lines(extract_footer_html(html))
    phone = ""
    for line in reversed(footer_lines):
        candidate = normalize_phone(line)
        if candidate:
            phone = candidate
            break

    address_lines: list[str] = []
    for index, line in enumerate(footer_lines):
        if US_ZIP_RE.search(line) or CA_POSTAL_RE.search(line):
            block = footer_lines[max(0, index - 2) : index + 1]
            block = [entry for entry in block if looks_like_address(entry) or entry == line]
            if block:
                address_lines = block
                break

    if not address_lines:
        for line in footer_lines:
            if looks_like_address(line):
                address_lines.append(line)

    address_lines = [line for line in address_lines if not PHONE_RE.search(line)]
    if not address_lines and not phone:
        return None
    return address_lines, phone


def website_contact(domain: str, tools_dir: Path) -> tuple[list[str], str, str] | None:
    candidates: list[str] = []
    homepage_path = tools_dir / "homepage.html"
    if homepage_path.exists():
        candidates.append(homepage_path.read_text(encoding="utf-8", errors="replace"))

    for path in ("", "/contact", "/contact-us", "/about/contact"):
        for prefix in (f"https://www.{domain}", f"https://{domain}"):
            url = urllib.parse.urljoin(f"{prefix}/", path.lstrip("/"))
            html = fetch_url(url)
            if html:
                candidates.append(html)

    seen: set[str] = set()
    for html in candidates:
        digest = html[:5000]
        if digest in seen:
            continue
        seen.add(digest)
        parsed = extract_contact_from_html(html)
        if parsed:
            lines, phone = parsed
            if lines or phone:
                return lines, phone, "website-footer"
    return None


def load_manual(path: Path) -> tuple[list[str], str] | None:
    if not path.exists():
        return None

    lines: list[str] = []
    phone = ""
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            key, value = (part.strip() for part in line.split("\t", 1))
            if key.lower() == "phone":
                phone = value
            elif key.lower() in {"line", "address", "address_line"}:
                lines.append(value)
        else:
            lines.append(line)

    if lines and not phone and PHONE_RE.search(lines[-1]):
        phone = normalize_phone(lines[-1])
        lines = lines[:-1]

    if not lines and not phone:
        return None
    return lines, phone


def choose_contact(
    company: str,
    domain: str,
    tools_dir: Path,
) -> tuple[list[str], str, str]:
    manual = load_manual(tools_dir / "company-manual.tsv")
    if manual:
        lines, phone = manual
        return lines, phone, "manual"

    sec = sec_contact(company, domain, tools_dir)
    if sec and (sec[0] or sec[1]):
        return sec

    web = website_contact(domain, tools_dir)
    if web:
        return web

    return [], "", ""


def format_block(lines: list[str], phone: str) -> str:
    output: list[str] = []
    if lines:
        output.extend(lines)
    else:
        output.extend(["Address", "City, State Zip"])

    if phone:
        output.append(phone)
    else:
        output.append("Phone")

    return "\n".join(output)


def patch_summary(page: Path, block: str) -> None:
    text = page.read_text(encoding="utf-8", errors="replace")
    start = "<!-- INC_COMPANY_START -->"
    end = "<!-- INC_COMPANY_END -->"
    if start not in text or end not in text:
        raise SystemExit(f"summary company markers missing in {page}")

    updated = re.sub(
        rf"{re.escape(start)}.*?{re.escape(end)}",
        f"{start}{block}{end}",
        text,
        count=1,
        flags=re.S,
    )
    page.write_text(updated, encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 4:
        print(
            f"usage: {sys.argv[0]} <company> <domain> <tools_dir> [summary.htm]",
            file=sys.stderr,
        )
        return 1

    company = sys.argv[1].strip()
    domain = sys.argv[2].strip().lower()
    tools_dir = Path(sys.argv[3])
    tools_dir.mkdir(parents=True, exist_ok=True)

    manual_path = tools_dir / "company-manual.tsv"
    if not manual_path.exists():
        manual_path.write_text(
            "\n".join(
                [
                    "# Manual HQ address — tab-separated: Field, Value",
                    "# Use when SEC/website discovery is wrong or blocked.",
                    "# Example:",
                    "# address_line\t1350 René-Lévesque Blvd West",
                    "# address_line\t20th floor",
                    "# address_line\tMontréal, Quebec, Canada",
                    "# address_line\tH3G 1T4",
                    "# phone\t514-841-3200",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    lines, phone, source = choose_contact(company, domain, tools_dir)
    block = format_block(lines, phone)

    result = {
        "source": source or "none",
        "address_lines": lines,
        "phone": phone,
    }
    (tools_dir / "company.json").write_text(
        json.dumps(result, indent=2) + "\n",
        encoding="utf-8",
    )

    if len(sys.argv) >= 5:
        patch_summary(Path(sys.argv[4]), block)

    for line in lines:
        print(line)
    if phone:
        print(phone)
    if source:
        print(f"# source: {source}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())