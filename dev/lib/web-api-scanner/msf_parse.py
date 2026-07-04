#!/usr/bin/env python3
"""Parse Metasploit spool output into structured hits JSONL."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

PLUS_RE = re.compile(r"^\[\+\]\s*(.*)")
STAR_RE = re.compile(r"^\[\*\]\s+(Running|Using|Scanned)\b", re.I)
VULN_RE = re.compile(r"vulnerable|exploit|credential|password|token|RCE|shell", re.I)
RECON_RE = re.compile(r"version|header|robots|ssl|Apache|nginx|Tomcat", re.I)


def classify(detail: str) -> tuple[str, str]:
    if VULN_RE.search(detail) and re.search(r"exploit|RCE|shell|VULNERABLE", detail, re.I):
        return "high", "msf_exploit_signal"
    if VULN_RE.search(detail):
        return "high", "msf_credential_signal"
    if RECON_RE.search(detail):
        return "info", "msf_recon_signal"
    return "warning", "msf_finding"


def parse_spool(
    spool_path: Path,
    *,
    phase: str,
    phase_label: str,
    domain: str,
    target: str,
) -> list[dict]:
    if not spool_path.is_file():
        return []

    hits: list[dict] = []
    seen: set[str] = set()
    current_module = ""

    for raw in spool_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or STAR_RE.match(line):
            continue
        if line.startswith("[*]") and ":" in line:
            current_module = line.split(":", 1)[0].replace("[*]", "").strip()
            continue

        candidates: list[str] = []
        plus = PLUS_RE.match(line)
        if plus:
            candidates.append(plus.group(1).strip())
        elif re.search(r"vulnerable|credential|password.*found", line, re.I):
            candidates.append(line)

        for detail in candidates:
            if not detail or detail in seen:
                continue
            low = detail.lower()
            if any(x in low for x in ("found 0", "not vulnerable", "not found", "failed to", "error:")):
                continue
            seen.add(detail)
            severity, check = classify(detail)
            hits.append(
                {
                    "phase": phase,
                    "phase_label": phase_label,
                    "domain": domain,
                    "target": target,
                    "module": current_module,
                    "severity": severity,
                    "check": check,
                    "detail": f"{phase_label} | {detail}",
                    "evidence": f"msf_engine/spool/{phase}.txt",
                }
            )
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description="Parse MSF spool to JSONL hits")
    parser.add_argument("spool")
    parser.add_argument("--phase", required=True)
    parser.add_argument("--phase-label", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()

    hits = parse_spool(
        Path(args.spool),
        phase=args.phase,
        phase_label=args.phase_label,
        domain=args.domain,
        target=args.target,
    )
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for hit in hits:
            fh.write(json.dumps(hit, ensure_ascii=False) + "\n")
    print(len(hits))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())