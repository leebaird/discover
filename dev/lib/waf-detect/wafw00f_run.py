#!/usr/bin/env python3
"""Run wafw00f with optional TLS verify skip, proxy, and no-redirect."""

from __future__ import annotations

import argparse
import ssl
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover wafw00f wrapper")
    parser.add_argument("target")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-a", "--findall", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--no-redirect", action="store_true")
    parser.add_argument("--proxy", default="")
    args, extra = parser.parse_known_args()

    if args.insecure:
        ssl._create_default_https_context = ssl._create_unverified_context  # type: ignore[attr-defined]
        try:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    argv = ["wafw00f", args.target, "-f", "json", "-o", args.output]
    if args.findall:
        argv.append("-a")
    if args.no_redirect:
        argv.append("-r")
    if args.proxy:
        argv.extend(["-p", args.proxy])
    argv.extend(extra)

    sys.argv = argv
    try:
        from wafw00f.main import main as wafw00f_main
    except ImportError:
        print("error: wafw00f Python package not installed", file=sys.stderr)
        return 1

    try:
        wafw00f_main()
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())