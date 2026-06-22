#!/usr/bin/env python3
"""Shared SEC EDGAR helpers for Discover parsers."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

SEC_USER_AGENT = "research@example.com"
WEB_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
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


def normalize_company_name(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def company_name_tokens(company: str, domain: str) -> list[str]:
    tokens = [normalize_company_name(company)]
    base = domain.split(".", 1)[0]
    if base:
        tokens.append(normalize_company_name(base))
    return tokens


def find_cik(company: str, domain: str, cache_path: Path) -> str | None:
    payload: dict | None = None
    if cache_path.exists():
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
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
        title = normalize_company_name(str(entry.get("title", "")))
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


def load_submissions(cik: str) -> dict | None:
    raw = fetch_url(
        f"https://data.sec.gov/submissions/CIK{cik.zfill(10)}.json",
        user_agent=SEC_USER_AGENT,
    )
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def filing_url(cik: str, accession: str, primary_document: str) -> str:
    cik_num = str(int(cik))
    accession_clean = accession.replace("-", "")
    return f"https://www.sec.gov/Archives/edgar/data/{cik_num}/{accession_clean}/{primary_document}"


def recent_filings(cik: str, forms: tuple[str, ...], limit: int = 1) -> list[dict[str, str]]:
    data = load_submissions(cik)
    if not data:
        return []

    recent = data.get("filings", {}).get("recent", {})
    form_values = recent.get("form", [])
    wanted = {form.upper(): form for form in forms}
    results: list[dict[str, str]] = []

    for index, form in enumerate(form_values):
        key = str(form).upper()
        if key not in wanted:
            continue
        results.append(
            {
                "form": wanted[key],
                "filing_date": recent["filingDate"][index],
                "accession": recent["accessionNumber"][index],
                "primary_document": recent["primaryDocument"][index],
                "url": filing_url(cik, recent["accessionNumber"][index], recent["primaryDocument"][index]),
            }
        )
        if len(results) >= limit:
            break
    return results


def latest_filing_url(cik: str, forms: tuple[str, ...]) -> str | None:
    filings = recent_filings(cik, forms, limit=1)
    return filings[0]["url"] if filings else None