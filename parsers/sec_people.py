#!/usr/bin/env python3
"""Discover executives and directors from SEC EDGAR filings."""

from __future__ import annotations

import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sec_common import SEC_USER_AGENT, fetch_url, find_cik, recent_filings

TITLE_KEYWORDS = re.compile(
    r"\b(?:Chief|Chair|President|Officer|Director|SVP|EVP|VP|CFO|CEO|COO|CTO|CISO|"
    r"Head|Managing|General Counsel|Secretary|Treasurer|Controller|Accounting|Senior|"
    r"Technical|Engineering|Automotive|Operations|Energy|Powertrain)\b",
    re.I,
)
HONORIFIC_RE = re.compile(r"^(?:Mr\.|Ms\.|Mrs\.|Dr\.)\s+", re.I)
ROLE_SUFFIX_RE = re.compile(r"\s*\((?:Chair|Director|Lead Independent Director|Independent Director)\)\s*$", re.I)
HTML_ENTITY_RE = re.compile(r"&[a-z#0-9]+;")

PROSE_PATTERNS = (
    re.compile(
        r"([A-Z][a-z]+(?:\s+[A-Z][a-z'\.-]+){1,3}),\s*our\s+((?:Chief|Chair|Senior|President|Managing|General)[^,;.<]{2,80})",
        re.I,
    ),
    re.compile(
        r"Mr\.\s+([A-Z][a-z]+)\s+\([^)]*\),\s*our\s+((?:Chief|Chair|Senior|President|Managing)[^,;.<]{2,80})",
        re.I,
    ),
    re.compile(
        r"Ms\.\s+([A-Z][a-z]+)\s+\([^)]*\),\s*our\s+((?:Chief|Chair|Senior|President|Managing)[^,;.<]{2,80})",
        re.I,
    ),
)

TITLE_EXPANSIONS = {
    "ceo": "Chief Executive Officer",
    "cfo": "Chief Financial Officer",
    "coo": "Chief Operating Officer",
    "cto": "Chief Technical Officer",
    "ciso": "Chief Information Security Officer",
    "svp": "Senior Vice President",
    "evp": "Executive Vice President",
    "vp": "Vice President",
}

NAME_PATTERN = re.compile(
    r"^[A-Z][a-z]+(?:['-][A-Z][a-z]+)?(?:\s+[A-Z][a-z'\.-]+){1,2}(?:\s*\((?:Chair|Director|Lead Independent Director|Independent Director)\))?$"
)
BLOCKED_NAME_RE = re.compile(
    r"\b(?:Agreement|Amount|Assumptions|Awards|Audit|Beneficially|Capitalization|"
    r"Committee|Compensation|Controls|Corp|Date|Directors|Disposition|EBITDA|"
    r"Expiration|Governance|Group|Information|Issuance|Item|Law|Leadership|"
    r"Matter|Matters|Milestones|Officer|Officers|Owner|Period|Person|Planning|"
    r"Pledging|Price|Principles|Product|Proposal|Proposals|Related|Requested|"
    r"Required|Requirement|Resolution|Restriction|Rights|Service|Skills|Summary|"
    r"Terms|Tranches|Transaction|Transactions|Type|Value|Vesting|Vote|Withholding|"
    r"Year|Market|Offset|Voting|Broker|Shares|Class|Structure|Other|Development|"
    r"Strategic|Shareholder|Frequently|Proposed|Holding|Performance|Recommendation|"
    r"Fiscal|NVIDIA|Tesla|Total|Option|Stock|Equity|Report|Analysis|Appendix|"
    r"Information|Allowed|Orderly|Double|Dip|Goals|Achieved|Targets|Adjustment|"
    r"Comparison|Executive|Agenda|Owned|Name|Cap|Discretionary|Considerations|"
    r"Eligibility|Key|Assumptions|Expiration|Purchase|FairValue|Forfeiture|"
    r"Grant|Share|Offset|Vesting|Withholding|Operational|Performance|Limited|"
    r"Retention|Principles|Succession|Structure|Matters)\b",
    re.I,
)


class _TableParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tables: list[list[list[str]]] = []
        self._in_table = False
        self._in_row = False
        self._in_cell = False
        self._cell_chunks: list[str] = []
        self._current_row: list[str] = []
        self._current_table: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "table":
            self._in_table = True
            self._current_table = []
        elif self._in_table and tag == "tr":
            self._in_row = True
            self._current_row = []
        elif self._in_row and tag in {"td", "th"}:
            self._in_cell = True
            self._cell_chunks = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"td", "th"} and self._in_cell:
            text = self._clean("".join(self._cell_chunks))
            if text:
                self._current_row.append(text)
            self._in_cell = False
            self._cell_chunks = []
        elif tag == "tr" and self._in_row:
            if self._current_row:
                self._current_table.append(self._current_row)
            self._in_row = False
            self._current_row = []
        elif tag == "table" and self._in_table:
            if self._current_table:
                self.tables.append(self._current_table)
            self._in_table = False
            self._current_table = []

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_chunks.append(data)

    @staticmethod
    def _clean(value: str) -> str:
        value = HTML_ENTITY_RE.sub(" ", value)
        return re.sub(r"\s+", " ", value).strip()


def strip_html(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    value = HTML_ENTITY_RE.sub(" ", value)
    return re.sub(r"\s+", " ", value).strip()


def normalize_person_name(raw: str, *, swap_last_first: bool = False) -> str:
    raw = HONORIFIC_RE.sub("", raw.strip())
    raw = ROLE_SUFFIX_RE.sub("", raw)
    raw = re.sub(r"\s+", " ", raw).strip(" ,.")
    if not raw:
        return ""

    parts = raw.split()
    suffixes = {"JR", "SR", "II", "III", "IV", "V"}
    parts = [part for part in parts if part.upper() not in suffixes]
    if not parts:
        return ""

    if raw == raw.upper():
        parts = [part.title() for part in parts]
        swap_last_first = True

    if len(parts) == 2:
        if swap_last_first:
            return f"{parts[1]} {parts[0]}"
        return f"{parts[0]} {parts[1]}"

    if len(parts) >= 3:
        if swap_last_first:
            first = parts[1]
            last = parts[0]
            middle = [part for part in parts[2:] if len(part) > 1]
            if middle:
                return f"{first} {' '.join(middle)} {last}".strip()
            return f"{first} {last}".strip()
        return " ".join(parts)

    return raw


def merge_key(name: str) -> str:
    clean = normalize_person_name(name)
    tokens = [token for token in re.split(r"\s+", clean.lower()) if token]
    if len(tokens) == 2:
        return " ".join(sorted(tokens))
    return re.sub(r"[^a-z0-9]+", " ", clean.lower()).strip()


def looks_like_person_name(name: str) -> bool:
    if not name or len(name) > 80:
        return False
    if "@" in name or "http" in name.lower():
        return False
    if re.search(r"\d", name):
        return False
    if BLOCKED_NAME_RE.search(name):
        return False
    if not NAME_PATTERN.match(name.strip()):
        return False
    words = [word for word in re.split(r"\s+", ROLE_SUFFIX_RE.sub("", name).strip()) if word]
    return len(words) >= 2


def clean_title(title: str) -> str:
    title = strip_html(title)
    title = re.sub(r"\s+", " ", title).strip(" ,.;")
    title = re.sub(r"\s+and a director.*$", "", title, flags=re.I)
    title = re.sub(r"\s+received approximately.*$", "", title, flags=re.I)
    if not title:
        return ""
    lowered = title.lower()
    if lowered in TITLE_EXPANSIONS:
        return TITLE_EXPANSIONS[lowered]
    return title


def upsert(
    store: dict[str, dict[str, str]],
    name: str,
    title: str,
    source: str,
    *,
    swap_last_first: bool = False,
) -> None:
    name = normalize_person_name(name, swap_last_first=swap_last_first)
    title = clean_title(title)
    if not looks_like_person_name(name):
        return
    if title and not TITLE_KEYWORDS.search(title):
        return

    key = merge_key(name)
    row = store.setdefault(key, {"name": name, "title": "", "source": source})
    if source.startswith("def14a"):
        row["name"] = name
        row["source"] = source
    elif not row["name"]:
        row["name"] = name

    if title and (not row["title"] or len(title) > len(row["title"])):
        row["title"] = title


def load_manual(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    store: dict[str, dict[str, str]] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" not in line:
            continue
        name, title, *rest = [part.strip() for part in line.split("\t")]
        phone = rest[0] if rest else ""
        if not name:
            continue
        key = merge_key(name)
        store[key] = {
            "name": normalize_person_name(name),
            "title": clean_title(title),
            "source": "manual",
            "phone": phone,
        }
    return store


def parse_def14a_roles(html: str, store: dict[str, dict[str, str]]) -> None:
    for pattern in PROSE_PATTERNS:
        for match in pattern.finditer(html):
            upsert(store, match.group(1), match.group(2), "def14a-prose")

    for match in re.finditer(
        r"([A-Z][a-z]+(?:[-'][A-Z][a-z]+)?(?:\s+[A-Z][a-z'\.-]+){1,2})\s*\(([^)]+)\)",
        html,
    ):
        name = match.group(1).strip()
        role = match.group(2).strip().lower()
        if role not in {"chair", "lead independent director", "independent director", "director"}:
            continue
        title = "Chair of the Board" if role == "chair" else role.title()
        upsert(store, name, title, "def14a-board")

    parser = _TableParser()
    parser.feed(html)
    for table in parser.tables:
        for row in table:
            name_cells = [cell.strip() for cell in row if looks_like_person_name(cell)]
            if len(name_cells) < 2:
                continue
            for cell in name_cells:
                role_match = re.search(r"\(([^)]+)\)\s*$", cell)
                name = ROLE_SUFFIX_RE.sub("", cell).strip()
                title = "Director"
                if role_match:
                    role = role_match.group(1).strip().lower()
                    if role == "chair":
                        title = "Chair of the Board"
                    elif "director" in role:
                        title = role.title()
                upsert(store, name, title, "def14a-board")


def parse_form4_html(html: str, store: dict[str, dict[str, str]]) -> None:
    name = ""
    for pattern in (
        r"1\.\s*Name and Address of Reporting Person[\s\S]{0,400}?<a[^>]*>([^<]+)</a>",
        r"1\.\s*Name and Address of Reporting Person[\s\S]{0,400}?<span class=\"FormData\">([^<]+)</span>",
    ):
        match = re.search(pattern, html, re.I)
        if match:
            name = match.group(1).strip()
            break
    if not name:
        return

    title = ""
    title_match = re.search(
        r"Officer \(give title below\)[\s\S]{0,500}?style=\"color: blue\">([^<]+)<",
        html,
        re.I,
    )
    if title_match:
        title = title_match.group(1).strip()

    if not title and re.search(r">\s*X\s*<[\s\S]{0,120}?Director", html, re.I):
        title = "Director"

    expanded = TITLE_EXPANSIONS.get(title.lower())
    if expanded:
        title = expanded

    upsert(store, name, title, "form4", swap_last_first=True)


def discover_sec_people(company: str, domain: str, tools_dir: Path) -> tuple[list[dict[str, str]], dict]:
    cache_path = tools_dir / "sec-company-tickers.json"
    cik = find_cik(company, domain, cache_path)
    meta: dict = {"cik": cik, "sources": []}
    store: dict[str, dict[str, str]] = {}

    if not cik:
        return [], meta

    def14a = recent_filings(cik, ("DEF 14A",), limit=1)
    if def14a:
        filing = def14a[0]
        html = fetch_url(filing["url"], timeout=60, user_agent=SEC_USER_AGENT)
        if html:
            parse_def14a_roles(html, store)
            meta["sources"].append(
                {"type": "def14a", "filing_date": filing["filing_date"], "url": filing["url"]}
            )

    form4_filings = recent_filings(cik, ("4",), limit=25)
    seen_docs: set[str] = set()
    for filing in form4_filings:
        if filing["primary_document"] in seen_docs:
            continue
        seen_docs.add(filing["primary_document"])
        html = fetch_url(filing["url"], timeout=20, user_agent=SEC_USER_AGENT)
        if html:
            parse_form4_html(html, store)

    if form4_filings:
        meta["sources"].append({"type": "form4", "count": len(seen_docs)})

    rows = sorted(store.values(), key=lambda row: row["name"].lower())
    return rows, meta


def write_tsv(path: Path, rows: list[dict[str, str]]) -> None:
    lines = []
    for row in rows:
        phone = row.get("phone", "")
        lines.append(f"{row['name']}\t{row['title']}\t{phone}")
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 5:
        print(
            f"usage: {sys.argv[0]} <company> <domain> <tools_dir> <output_tsv>",
            file=sys.stderr,
        )
        return 1

    company = sys.argv[1].strip()
    domain = sys.argv[2].strip().lower()
    tools_dir = Path(sys.argv[3])
    output_path = Path(sys.argv[4])
    tools_dir.mkdir(parents=True, exist_ok=True)

    manual_path = tools_dir / "sec-people-manual.tsv"
    if not manual_path.exists():
        manual_path.write_text(
            "\n".join(
                [
                    "# Manual SEC leadership — tab-separated: Name, Title, Phone",
                    "# Example:",
                    "# Robyn Denholm\tChair of the Board\t",
                    "",
                ]
            ),
            encoding="utf-8",
        )

    manual = load_manual(manual_path)
    if manual:
        rows = sorted(manual.values(), key=lambda row: row["name"].lower())
        meta = {"source": "manual", "count": len(rows)}
    else:
        rows, meta = discover_sec_people(company, domain, tools_dir)
        meta["source"] = "sec"
        meta["count"] = len(rows)

    write_tsv(output_path, rows)
    (tools_dir / "sec-people.json").write_text(
        json.dumps({"people": rows, "meta": meta}, indent=2) + "\n",
        encoding="utf-8",
    )

    for row in rows:
        print(f"{row['name']}\t{row['title']}")
    print(f"# {meta.get('count', 0)} leadership rows ({meta.get('source', 'sec')})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())