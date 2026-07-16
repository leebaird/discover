#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Localhost-only status helper for Discover host-scan live UI.

Usage:
  host-scan-statusd.py <report_root> [port]

Binds 127.0.0.1 only. Serves:
  GET /status  -> tools/host-scans/status.json
  GET /mode    -> assets/report-mode.json
  GET /health  -> ok
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: host-scan-statusd.py <report_root> [port]", file=sys.stderr)
        return 2

    report_root = Path(argv[1]).resolve()
    port = int(argv[2]) if len(argv) > 2 else 17322
    status_path = report_root / "tools" / "host-scans" / "status.json"
    mode_path = report_root / "assets" / "report-mode.json"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(self, code: int, body: bytes, content_type: str = "application/json"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/health", "/"):
                self._send(200, b'{"ok":true}\n')
                return
            if path == "/mode":
                if mode_path.is_file():
                    self._send(200, mode_path.read_bytes())
                else:
                    self._send(
                        200,
                        b'{"mode":"operator","launches":true}\n',
                    )
                return
            if path == "/status":
                if status_path.is_file():
                    self._send(200, status_path.read_bytes())
                else:
                    self._send(200, b'{"running":false,"hosts":{}}\n')
                return
            self._send(404, b'{"error":"not found"}\n')

    # Bind localhost only
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # Write port file for the report UI
    port_file = report_root / "tools" / "host-scans" / "statusd.port"
    port_file.parent.mkdir(parents=True, exist_ok=True)
    port_file.write_text(str(port) + "\n", encoding="utf-8")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            port_file.unlink()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
