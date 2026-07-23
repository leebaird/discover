#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Localhost-only status helper + static report server for host-scan UI.

Usage:
  host-scan-statusd.py <report_root> [port]

Binds 127.0.0.1 only. Serves:
  GET /status  -> tools/host-scans/status.json
  GET /mode    -> assets/report-mode.json
  GET /health  -> ok
  GET /*       -> files under report_root (operator browser via http://127.0.0.1:port/)

Host-scan chevrons only appear when the report is opened through this server
(Import report / Active), not via file:// manual open.
"""

from __future__ import annotations

import mimetypes
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: host-scan-statusd.py <report_root> [port]", file=sys.stderr)
        return 2

    report_root = Path(argv[1]).resolve()
    if not report_root.is_dir():
        print(f"Not a directory: {report_root}", file=sys.stderr)
        return 2

    port = int(argv[2]) if len(argv) > 2 else 17322
    status_path = report_root / "tools" / "host-scans" / "status.json"
    mode_path = report_root / "assets" / "report-mode.json"

    def safe_report_file(url_path: str) -> Path | None:
        """Map URL path to a file under report_root, or None."""
        rel = unquote(url_path).split("?", 1)[0]
        rel = rel.lstrip("/")
        if not rel:
            # Prefer index.htm at report root
            for name in ("index.htm", "index.html"):
                cand = report_root / name
                if cand.is_file():
                    return cand
            return None
        parts = Path(rel).parts
        if any(p == ".." or p.startswith("/") for p in parts):
            return None
        candidate = (report_root / rel).resolve()
        try:
            candidate.relative_to(report_root)
        except ValueError:
            return None
        if candidate.is_file():
            return candidate
        return None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def _send(
            self,
            code: int,
            body: bytes,
            content_type: str = "application/json",
            cache: str = "no-store",
        ):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", cache)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path or "/"

            if path == "/health":
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

            # Static report files (operator UI over http://127.0.0.1)
            if path == "/":
                path = "/index.htm"
            fpath = safe_report_file(path)
            if fpath is None:
                self._send(404, b'{"error":"not found"}\n')
                return
            try:
                body = fpath.read_bytes()
            except OSError:
                self._send(404, b'{"error":"not found"}\n')
                return
            ctype, _enc = mimetypes.guess_type(str(fpath))
            if not ctype:
                if fpath.suffix.lower() in {".htm", ".html"}:
                    ctype = "text/html; charset=utf-8"
                elif fpath.suffix.lower() == ".js":
                    ctype = "application/javascript; charset=utf-8"
                elif fpath.suffix.lower() == ".css":
                    ctype = "text/css; charset=utf-8"
                elif fpath.suffix.lower() == ".json":
                    ctype = "application/json"
                else:
                    ctype = "application/octet-stream"
            # HTML/JS need revalidation so host-scan cache-busts work
            cache = "no-cache" if fpath.suffix.lower() in {
                ".htm",
                ".html",
                ".js",
                ".css",
                ".json",
            } else "private, max-age=3600"
            self._send(200, body, content_type=ctype, cache=cache)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
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
