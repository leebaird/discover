#!/usr/bin/env python3

import csv
import re
import sys
from pathlib import Path

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def load_rules(path):
    rules = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            category, pattern = line.split("\t", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            category, pattern = parts
        category = category.strip()
        pattern = pattern.strip().lower()
        if category and pattern:
            rules.append((category, pattern))
    return rules


def label_matches(label, pattern):
    if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
        return pattern[1:-1] in label
    if pattern.startswith("*"):
        return label.endswith(pattern[1:])
    if pattern.endswith("*"):
        return label.startswith(pattern[:-1])
    if pattern.startswith("-"):
        return label.endswith(pattern)
    return label == pattern


def categorize_host(host, rules):
    host = host.strip().lower()
    labels = host.split(".")
    for category, pattern in rules:
        if "." in pattern:
            if pattern in host:
                return category
            continue
        for label in labels:
            if label_matches(label, pattern):
                return category
    return ""


def parse_input_row(raw):
    raw = raw.strip()
    if not raw:
        return None

    if "\t" in raw:
        row = next(csv.reader([raw], delimiter="\t"))
        while len(row) < 2:
            row.append("")
        host = row[0].strip()
        ip = row[1].strip()
        category = row[2].strip() if len(row) > 2 else ""
    else:
        parts = raw.split()
        if not parts:
            return None
        if len(parts) == 1:
            host, ip, category = parts[0], "", ""
        elif IPV4_RE.match(parts[-1]):
            host, ip, category = " ".join(parts[:-1]), parts[-1], ""
        else:
            host, ip, category = parts[0], parts[1], parts[2] if len(parts) > 2 else ""

    if not host:
        return None
    return host, ip, category


def main():
    if len(sys.argv) != 3:
        print("usage: subdomain-categorize.py RULES.tsv INPUT.tsv", file=sys.stderr)
        sys.exit(1)

    rules_path = Path(sys.argv[1])
    input_path = Path(sys.argv[2])
    rules = load_rules(rules_path)

    rows = []
    for raw in input_path.read_text().splitlines():
        parsed = parse_input_row(raw)
        if not parsed:
            continue
        host, ip, _ = parsed
        if not ip:
            continue
        category = categorize_host(host, rules)
        rows.append((host, ip, category))

    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    for row in sorted(rows, key=lambda item: item[0].lower()):
        writer.writerow(row)


if __name__ == "__main__":
    main()