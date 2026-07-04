#!/usr/bin/env python3
"""Single-pass sensitive file scanner for dev/sensitive-scanner.sh."""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEV_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_PATTERNS = DEV_DIR / "data" / "sensitive-patterns.tsv"
DEFAULT_DENYLIST = DEV_DIR / "data" / "sensitive-denylist.txt"
DEFAULT_SKIP = DEV_DIR / "data" / "sensitive-skip-paths.txt"

INCLUDE_PROFILES = {
    "common": {
        ".js", ".jsx", ".ts", ".tsx", ".php", ".py", ".rb", ".java", ".json", ".xml",
        ".yaml", ".yml", ".conf", ".config", ".env", ".ini", ".properties", ".sh",
        ".tf", ".vue", ".cs", ".go", ".gradle", ".kt", ".swift", ".rs", ".toml",
        ".dockerfile", ".md", ".cfg", ".cnf",
    },
    "web": {
        ".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".php", ".json", ".xml",
        ".yaml", ".yml", ".css", ".vue",
    },
    "token": {
        ".log", ".txt", ".json", ".env", ".sh", ".py", ".js", ".ts",
    },
    "all": None,
    "config": {
        ".env", ".conf", ".config", ".ini", ".properties", ".yaml", ".yml", ".json",
        ".tf", ".toml", ".cfg", ".cnf",
    },
}

CONFIG_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development", ".htpasswd",
    ".htaccess", "credentials", "kubeconfig", "terraform.tfstate",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "dist", "build", ".cache", ".venv",
    "__pycache__", ".tox", ".mypy_cache", "target",
}

BUCKET_MAP = {
    "api_credential": "api_keys.txt",
    "aws_key": "aws_keys.txt",
    "service_token": "service_tokens.txt",
    "google_api_key": "google_api_keys.txt",
    "db_connection": "db_connections.txt",
    "gcp_credential": "gcp_credentials.txt",
    "auth_token": "auth_tokens.txt",
    "framework_secret": "framework_secrets.txt",
    "infra_secret": "infra_secrets.txt",
    "vcs_exposure": "vcs_exposure.txt",
    "email": "emails.txt",
    "credit_card": "credit_cards.txt",
    "ssn": "ssn.txt",
    "tc_kimlik": "tc_kimlik.txt",
    "private_key": "private_keys.txt",
    "crypto_secret": "crypto_secrets.txt",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def load_patterns(path: Path, quick: bool) -> list[dict]:
    patterns = []
    for line in load_lines(path):
        if "\t" not in line:
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        pid, severity, check, regex, profile, quick_flag = parts[:6]
        entropy = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
        if quick and quick_flag != "1":
            continue
        patterns.append({
            "id": pid,
            "severity": severity,
            "check": check,
            "regex": re.compile(regex, re.IGNORECASE | re.MULTILINE),
            "profile": profile,
            "entropy": bool(entropy),
        })
    return patterns


def load_regex_list(path: Path) -> list[re.Pattern[str]]:
    return [re.compile(p, re.IGNORECASE) for p in load_lines(path)]


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_assignment_value(line: str) -> str:
    m = re.search(r"=\s*['\"]?([^'\"#\s]{8,})", line)
    return m.group(1) if m else ""


def luhn_valid(digits: str) -> bool:
    digits = "".join(c for c in digits if c.isdigit())
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    rev = digits[::-1]
    for i, ch in enumerate(rev):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def ssn_valid(line: str) -> bool:
    m = re.search(r"([0-9]{3})[-:\ ]([0-9]{2})[-:\ ]([0-9]{4})", line)
    if not m:
        return False
    a, b, c = m.group(1), m.group(2), m.group(3)
    if a in {"000", "666"} or a.startswith("9"):
        return False
    if b == "00" or c == "0000":
        return False
    return True


def tc_kimlik_valid(num: str) -> bool:
    if len(num) != 11 or not num.isdigit() or num[0] == "0":
        return False
    d = [int(x) for x in num]
    if ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def path_skipped(rel: str, skip_globs: list[str]) -> bool:
    norm = rel.replace("\\", "/")
    for pat in skip_globs:
        if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(f"**/{norm}", pat):
            return True
    return False


def profile_allows(path: Path, profile: str) -> bool:
    exts = INCLUDE_PROFILES.get(profile)
    if exts is None:
        return True
    name = path.name.lower()
    if name in CONFIG_NAMES or name.startswith(".env"):
        return True
    if name in {"dockerfile", "makefile", "gemfile"}:
        return True
    suffix = path.suffix.lower()
    return suffix in exts or suffix == ""


def iter_files(root: Path, max_size: int) -> list[Path]:
    files = []
    if root.is_file():
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            try:
                if p.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            files.append(p)
    return files


def normalize_resource(path: Path, line_no: int | None) -> str:
    if line_no is not None:
        return f"{path}:{line_no}"
    return str(path)


def denied(line: str, denylist: list[re.Pattern[str]]) -> bool:
    return any(r.search(line) for r in denylist)


def validate_hit(check: str, line: str, match_text: str) -> bool:
    if check == "credit_card_raw":
        return luhn_valid(line)
    if check == "ssn_raw":
        return ssn_valid(line)
    if check == "tc_kimlik_raw":
        for num in re.findall(r"\b[1-9][0-9]{10}\b", line):
            if tc_kimlik_valid(num):
                return True
        return False
    return True


def bucket_for(check: str) -> str:
    if check == "credit_card_raw":
        return "credit_card"
    if check == "ssn_raw":
        return "ssn"
    if check == "tc_kimlik_raw":
        return "tc_kimlik"
    return check


def scan_file(
    path: Path,
    patterns: list[dict],
    denylist: list[re.Pattern[str]],
    entropy_min: float,
) -> list[dict]:
    hits = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits

    lines = text.splitlines()
    for pat in patterns:
        if not profile_allows(path, pat["profile"]):
            continue
        for match in pat["regex"].finditer(text):
            start = match.start()
            line_no = text.count("\n", 0, start) + 1
            line = lines[line_no - 1] if 0 < line_no <= len(lines) else match.group(0)
            if denied(line, denylist):
                continue
            if pat["entropy"]:
                val = extract_assignment_value(line) or match.group(0)
                if len(val) >= 12 and shannon_entropy(val) < entropy_min:
                    continue
            if not validate_hit(pat["check"], line, match.group(0)):
                continue
            check = bucket_for(pat["check"])
            hits.append({
                "severity": pat["severity"],
                "check": check,
                "resource": normalize_resource(path, line_no),
                "detail": line.strip()[:500],
                "line": line_no,
            })
    return hits


def find_config_files(root: Path) -> list[str]:
    found = []
    if root.is_file():
        name = root.name.lower()
        if name in CONFIG_NAMES or name.startswith(".env") or root.suffix in {".conf", ".config", ".env", ".ini"}:
            found.append(str(root))
        return found
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            low = fname.lower()
            if low in CONFIG_NAMES or low.startswith(".env") or p.suffix in {".conf", ".config", ".env", ".ini"}:
                found.append(str(p))
    return found


def write_buckets(out_dir: Path, hits: list[dict], append: bool) -> None:
    buckets: dict[str, list[str]] = defaultdict(list)
    for h in hits:
        fname = BUCKET_MAP.get(h["check"], f"{h['check']}.txt")
        buckets[fname].append(f"{h['resource']}:{h['line']}:{h['detail']}")
    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, lines in buckets.items():
        dest = out_dir / fname
        mode = "a" if append else "w"
        with dest.open(mode, encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Sensitive file scanner engine")
    ap.add_argument("--root", help="Directory or file to scan")
    ap.add_argument("--file", help="Single file (api-scanner hook)")
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--domain", default="local")
    ap.add_argument("--patterns", default=str(DEFAULT_PATTERNS))
    ap.add_argument("--denylist", default=str(DEFAULT_DENYLIST))
    ap.add_argument("--skip-paths", default=str(DEFAULT_SKIP))
    ap.add_argument("--mode", choices=("quick", "full"), default="full")
    ap.add_argument("--max-file-size", type=int, default=5 * 1024 * 1024)
    ap.add_argument("--entropy-min", type=float, default=3.5)
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--evidence-prefix", default="sensitive_info")
    ap.add_argument("--hits-out", help="JSONL findings output path")
    ap.add_argument("--sensitive-out", help="Write matching lines for api-scanner (.sensitive)")
    args = ap.parse_args()

    if not args.root and not args.file:
        print("error: --root or --file required", file=sys.stderr)
        return 2

    quick = args.mode == "quick"
    patterns = load_patterns(Path(args.patterns), quick)
    denylist = load_regex_list(Path(args.denylist))
    skip_globs = load_lines(Path(args.skip_paths))

    roots = [Path(args.file)] if args.file else [Path(args.root)]
    all_hits: list[dict] = []
    config_files: list[str] = []

    for root in roots:
        if not root.exists():
            continue
        config_files.extend(find_config_files(root))
        for fpath in iter_files(root, args.max_file_size):
            rel = str(fpath)
            if path_skipped(rel, skip_globs):
                continue
            all_hits.extend(scan_file(fpath, patterns, denylist, args.entropy_min))

    out_dir = Path(args.output_dir)
    write_buckets(out_dir, all_hits, args.append)

    if config_files:
        cfg_dest = out_dir / "config_files.txt"
        mode = "a" if args.append else "w"
        with cfg_dest.open(mode, encoding="utf-8") as fh:
            for c in sorted(set(config_files)):
                fh.write(c + "\n")

    jsonl_path = Path(args.hits_out) if args.hits_out else out_dir / "hits.jsonl"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a" if args.append else "w", encoding="utf-8") as fh:
        for h in all_hits:
            bucket = BUCKET_MAP.get(h["check"], f"{h['check']}.txt")
            record = {
                "severity": h["severity"],
                "domain": args.domain,
                "resource": h["resource"],
                "check": h["check"],
                "detail": h["detail"],
                "evidence": f"{args.evidence_prefix}/{bucket}",
            }
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        for cfg in sorted(set(config_files)):
            record = {
                "severity": "warning",
                "domain": args.domain,
                "resource": cfg,
                "check": "config_file",
                "detail": f"Sensitive configuration file: {cfg}",
                "evidence": f"{args.evidence_prefix}/config_files.txt",
            }
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    if args.sensitive_out and all_hits:
        with open(args.sensitive_out, "w", encoding="utf-8") as fh:
            for h in all_hits:
                fh.write(h["detail"] + "\n")

    summary = {
        "generated": now_iso(),
        "files_scanned": len(list(iter_files(roots[0], args.max_file_size))) if roots else 0,
        "hits": len(all_hits),
        "config_files": len(set(config_files)),
    }
    (out_dir / "scan_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())