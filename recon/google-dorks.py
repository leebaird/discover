#!/usr/bin/env python3
"""Run the Discover Google dorks through the Serply search API.

Takes the same Google search URLs that ``recon/domain.sh`` opens in Firefox,
pulls the ``q`` value out of each one, queries the Serply search API, and
writes every hit to ``google-dorks.txt`` in the engagement directory. The
operator reads one file instead of triaging 14 browser tabs by hand.

SERPLY_API_KEY is required. Discover checks, in order:
  1. Existing shell environment (export SERPLY_API_KEY=...)
  2. Private key file: ~/.discover/api-keys

Free key: https://serply.io

Usage:
  python3 recon/google-dorks.py --domain <domain> <google search url> [...]
  python3 recon/google-dorks.py --have-key
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

SERPLY_SEARCH_API = "https://api.serply.io/v1/search"
# Serply is behind Cloudflare, which blocks the default urllib User-Agent.
FALLBACK_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
)
DEFAULT_NUM = 20
DEFAULT_SLEEP = 1.0
MEDIUM = "=" * 66


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def discover_root() -> str:
    explicit = (os.environ.get("DISCOVER") or "").strip()
    if explicit:
        return explicit
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_software_cve_module() -> Any | None:
    """Load recon/software-cve.py (hyphenated filename) when available."""
    module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "software-cve.py")
    if not os.path.isfile(module_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location("software_cve", module_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def load_discover_env_files() -> None:
    """Load ~/.discover/api-keys into the environment (shell exports win).

    Reuses software-cve.py's loader so every key follows one path. Without
    that module only shell exports are visible.
    """
    module = load_software_cve_module()
    if module is not None and hasattr(module, "load_discover_env_files"):
        try:
            module.load_discover_env_files()
        except Exception:
            pass


def get_serply_api_key() -> str:
    key = (os.environ.get("SERPLY_API_KEY") or "").strip()
    if key:
        return key
    load_discover_env_files()
    return (os.environ.get("SERPLY_API_KEY") or "").strip()


def user_agent() -> str:
    """Discover's scanner User-Agent, same source as the shell scripts."""
    exported = (os.environ.get("USER_AGENT") or "").strip()
    if exported.startswith("Mozilla/"):
        return exported
    ua_file = os.path.join(discover_root(), "resource", "user-agent.txt")
    try:
        with open(ua_file, encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if line.startswith("Mozilla/"):
                    return line
    except OSError:
        pass
    return FALLBACK_USER_AGENT


def dork_query(url: str) -> str:
    """Return the decoded q= value of a Google search URL."""
    query = urllib.parse.urlparse(url).query
    values = urllib.parse.parse_qs(query, keep_blank_values=False).get("q") or []
    return values[0].strip() if values else ""


def serply_search(query: str, api_key: str, num: int, timeout: float) -> list[dict[str, Any]]:
    """Query the Serply search API and return the organic results."""
    url = SERPLY_SEARCH_API + "?" + urllib.parse.urlencode({"q": query, "num": num})
    request = urllib.request.Request(url)
    request.add_header("X-Api-Key", api_key)
    request.add_header("User-Agent", user_agent())
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", "replace"))
    results = payload.get("results")
    return results if isinstance(results, list) else []


def format_section(position: int, total: int, query: str, results: list[dict[str, Any]]) -> str:
    lines = [f"[{position}/{total}] {query}", "-" * 66, ""]

    if not results:
        lines.append("No results.")
        lines.append("")
        return "\n".join(lines)

    for index, result in enumerate(results, start=1):
        title = str(result.get("title") or "").strip() or "(no title)"
        link = str(result.get("link") or "").strip()
        description = " ".join(str(result.get("description") or "").split())
        lines.append(f"{index:>3}. {title}")

        if link:
            lines.append(f"     {link}")

        if description:
            lines.append(f"     {description[:200]}")

        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Discover Google dorks through Serply.")
    parser.add_argument("urls", nargs="*", help="Google search URLs from recon/domain.sh")
    parser.add_argument("--domain", default="", help="Engagement domain (output directory name)")
    parser.add_argument("--out-dir", default="", help="Output directory (default ~/data/<domain>)")
    parser.add_argument("--num", type=int, default=DEFAULT_NUM, help="Results per dork")
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP, help="Pause between dorks")
    parser.add_argument("--timeout", type=float, default=30.0, help="Request timeout in seconds")
    parser.add_argument(
        "--have-key",
        action="store_true",
        help="Exit 0 when a key is configured, 1 when it is not. Prints nothing.",
    )
    args = parser.parse_args()

    api_key = get_serply_api_key()

    if args.have_key:
        return 0 if api_key else 1

    if not api_key:
        eprint("[!] SERPLY_API_KEY not set.")
        eprint("    export SERPLY_API_KEY=... or put it in ~/.discover/api-keys")
        eprint("    Template: $DISCOVER/resource/api-keys.example")
        return 1

    if not args.domain:
        eprint("[!] A domain is required.")
        return 1

    queries = [query for query in (dork_query(url) for url in args.urls) if query]

    if not queries:
        eprint("[!] No dork queries were provided.")
        return 1

    out_dir = args.out_dir or os.path.join(os.path.expanduser("~"), "data", args.domain)

    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as error:
        eprint(f"[!] Cannot create {out_dir} ({error.__class__.__name__}).")
        return 1

    out_file = os.path.join(out_dir, "google-dorks.txt")
    stamp = datetime.now(timezone.utc).strftime("%m/%d/%Y - %H:%M Z")
    sections = [
        "Google dorks",
        "",
        f"Domain:    {args.domain}",
        f"Created:   {stamp}",
        "Source:    Serply search API (https://serply.io)",
        "",
        MEDIUM,
        "",
    ]
    total = len(queries)
    hits = 0

    for position, query in enumerate(queries, start=1):
        print(f"[{position}/{total}] {query}")

        try:
            results = serply_search(query, api_key, args.num, args.timeout)
        except urllib.error.HTTPError as error:
            if error.code in (401, 403):
                eprint("[!] Serply rejected the key (HTTP %d)." % error.code)
                return 1

            eprint(f"    Request failed (HTTP {error.code}).")
            sections.append(format_section(position, total, query, []))
            continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            eprint(f"    Request failed ({error.__class__.__name__}).")
            sections.append(format_section(position, total, query, []))
            continue

        hits += len(results)
        print(f"      {len(results)} results.")
        sections.append(format_section(position, total, query, results))

        if position < total and args.sleep > 0:
            time.sleep(args.sleep)

    try:
        with open(out_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(sections).rstrip() + "\n")
    except OSError as error:
        eprint(f"[!] Cannot write {out_file} ({error.__class__.__name__}).")
        return 1

    print()
    print(f"{hits} results from {total} dorks.")
    print(f"Saved to {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
