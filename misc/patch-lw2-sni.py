#!/usr/bin/env python3
"""Patch libwhisker2 (LW2.pm) to send TLS SNI during HTTPS connect.

Nikto 2.1.x uses LW2/Net::SSLeay without Server Name Indication. Many modern
front ends (Azure Application Gateway / AGC, Cloudflare, etc.) require SNI and
fail the handshake without it — Nikto then reports "No web server found" even
when curl works.

Usage:
  patch-lw2-sni.py <src-LW2.pm> <dst-LW2.pm>
  patch-lw2-sni.py --in-place <LW2.pm>

Exit 0 if already patched or newly patched; 1 on error; 2 if marker pattern missing.
"""
from __future__ import annotations

import sys
from pathlib import Path

MARKER = "Discover: TLS SNI"
# Insert SNI immediately after set_fd, before set_session / connect.
OLD = (
    "    Net::SSLeay::set_fd( $xr->{sslobj}, fileno( $xr->{sock} ) );\n"
    "    Net::SSLeay::set_session( $xr->{sslobj}, $xr->{sslsession} )\n"
)
NEW = (
    "    Net::SSLeay::set_fd( $xr->{sslobj}, fileno( $xr->{sock} ) );\n"
    "    # Discover: TLS SNI (required by Azure ALB / modern HTTPS front ends)\n"
    "    if ( defined $W->{host} && exists &Net::SSLeay::set_tlsext_host_name ) {\n"
    "        Net::SSLeay::set_tlsext_host_name( $xr->{sslobj}, $W->{host} );\n"
    "    }\n"
    "    Net::SSLeay::set_session( $xr->{sslobj}, $xr->{sslsession} )\n"
)


def patch_text(text: str) -> tuple[str, str]:
    """Return (new_text, status) where status is already|patched|missing."""
    if MARKER in text or "set_tlsext_host_name( $xr->{sslobj}" in text:
        return text, "already"
    if OLD not in text:
        return text, "missing"
    return text.replace(OLD, NEW, 1), "patched"


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--in-place":
        path = Path(argv[2])
        src = dst = path
    elif len(argv) == 3:
        src = Path(argv[1])
        dst = Path(argv[2])
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    if not src.is_file():
        print(f"[!] LW2 not found: {src}", file=sys.stderr)
        return 1

    text = src.read_text(encoding="utf-8", errors="replace")
    new_text, status = patch_text(text)
    if status == "missing":
        print(
            f"[!] Could not locate SSL set_fd/set_session block in {src} "
            "(unexpected LW2 version).",
            file=sys.stderr,
        )
        return 2
    if status == "already" and src.resolve() == dst.resolve():
        print(f"[*] LW2 already has SNI: {dst}")
        return 0

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(new_text, encoding="utf-8")
    if status == "already":
        print(f"[*] Copied SNI-ready LW2 → {dst}")
    else:
        print(f"[+] Patched LW2 for TLS SNI → {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
