#!/usr/bin/env python3
# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
"""Localhost-only status helper + static report server for Discover operator UI.

Usage:
  host-scan-statusd.py <report_root> [port]

Binds 127.0.0.1 only. Serves:
  GET /status  -> tools/host-scans/status.json
  GET /mode    -> assets/report-mode.json
  GET /health  -> ok
  GET /shodan-status -> {"ok":true,"api_key":true|false} (never returns the key)
  POST /export -> run recon/export-report.sh (JSON body: {"kind":"client"|"defender"|"operator"})
  POST /import-operator-package -> merge another operator report
      (JSON: {"source":"/path/to/unpacked-report","operator":"Bob"})
  POST /shodan-refresh -> force-refresh one IP via recon/shodan-enrich.py --ip (JSON: {"ip":"..."})
  POST /shodan-refresh-all -> force Shodan enrich all public IPs (--force --json-summary)
  POST /software-cve-refresh -> force NVD software CVEs + rebuild active.htm
  GET  /config -> operator config (api keys values for edit, name, view timezone)
  POST /config/api-keys -> save NVD/SHODAN/WPSCAN keys to ~/.discover/api-keys
  POST /config/operator-name -> set name; rewrite this report audit log; rebuild Audit
  POST /config/timezone -> set display timezone only (does not change written stamps)
  GET /*       -> files under report_root (operator browser via http://127.0.0.1:port/)

Host-scan chevrons, Export, Import/Config (Audit), Shodan Update, and Active Update only appear when
the report is opened through this server (Import report / Active), not file://.
"""

from __future__ import annotations

import importlib.util
import json
import mimetypes
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


def shodan_api_key_configured(discover_root: Path) -> bool:
    """True when SHODAN_API_KEY is set in the environment or private key files.

    Does not return or log the key value.
    """
    # Prefer enricher's loader (api-keys + legacy .env migration).
    enrich = discover_root / "recon" / "shodan-enrich.py"
    if enrich.is_file():
        try:
            spec = importlib.util.spec_from_file_location(
                "discover_shodan_enrich", str(enrich)
            )
            if spec is not None and spec.loader is not None:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "get_shodan_api_key"):
                    return bool((mod.get_shodan_api_key() or "").strip())
        except Exception:
            pass
    return bool((os.environ.get("SHODAN_API_KEY") or "").strip())


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

    # Discover install root (…/discover) from this script: misc/ → parent
    discover_root = Path(__file__).resolve().parent.parent
    export_script = discover_root / "recon" / "export-report.sh"
    import_operator_script = discover_root / "recon" / "import-operator-package.py"
    config_script = discover_root / "recon" / "discover-config.py"
    shodan_enrich = discover_root / "recon" / "shodan-enrich.py"
    active_tech = discover_root / "recon" / "active-tech.py"

    def safe_report_file(url_path: str) -> Path | None:
        """Map URL path to a file under report_root, or None."""
        rel = unquote(url_path).split("?", 1)[0]
        rel = rel.lstrip("/")
        if not rel:
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
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Cache-Control", cache)
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self._send(204, b"")

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path or "/"
            if path not in {
                "/export",
                "/import-operator-package",
                "/shodan-refresh",
                "/shodan-refresh-all",
                "/software-cve-refresh",
                "/config/api-keys",
                "/config/operator-name",
                "/config/timezone",
            }:
                self._send(404, b'{"ok":false,"error":"not found"}\n')
                return

            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._send(400, b'{"ok":false,"error":"invalid JSON"}\n')
                return

            env = os.environ.copy()
            env["DISCOVER"] = str(discover_root)
            env["HOME"] = str(Path.home())

            def _parse_json_stdout(stdout: str) -> dict | None:
                for ln in reversed(
                    [x.strip() for x in (stdout or "").splitlines() if x.strip()]
                ):
                    try:
                        cand = json.loads(ln)
                        if isinstance(cand, dict):
                            return cand
                    except json.JSONDecodeError:
                        continue
                return None

            if path == "/shodan-refresh-all":
                if not shodan_enrich.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"shodan-enrich missing: {shodan_enrich}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                try:
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(shodan_enrich),
                            str(report_root),
                            "--force",
                            "--json-summary",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=7200,
                        env=env,
                        cwd=str(discover_root),
                    )
                except subprocess.TimeoutExpired:
                    self._send(
                        504,
                        b'{"ok":false,"error":"Shodan bulk refresh timed out"}\n',
                    )
                    return
                except OSError as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return
                result = _parse_json_stdout(proc.stdout or "")
                if not isinstance(result, dict):
                    err = (proc.stderr or proc.stdout or "shodan bulk failed").strip()
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": err[:500]
                                or f"shodan-enrich exit {proc.returncode}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                code = 200 if result.get("ok") else 400
                self._send(code, json.dumps(result).encode() + b"\n")
                return

            if path == "/software-cve-refresh":
                if not active_tech.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"active-tech missing: {active_tech}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                force_all = bool(body.get("force_all"))
                cmd = [
                    sys.executable,
                    str(active_tech),
                    str(report_root),
                    "--refresh-cves",
                    "--json",
                ]
                if force_all:
                    cmd.append("--force-all")
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=3600,
                        env=env,
                        cwd=str(discover_root),
                    )
                except subprocess.TimeoutExpired:
                    self._send(
                        504,
                        b'{"ok":false,"error":"Software CVE refresh timed out"}\n',
                    )
                    return
                except OSError as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return
                result = _parse_json_stdout(proc.stdout or "")
                if not isinstance(result, dict):
                    err = (proc.stderr or proc.stdout or "cve refresh failed").strip()
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": err[:500]
                                or f"active-tech exit {proc.returncode}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                code = 200 if result.get("ok") else 400
                self._send(code, json.dumps(result).encode() + b"\n")
                return

            if path == "/shodan-refresh":
                ip = str(body.get("ip") or "").strip()
                if not ip:
                    self._send(400, b'{"ok":false,"error":"ip is required"}\n')
                    return
                if not shodan_enrich.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"shodan-enrich missing: {shodan_enrich}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                try:
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(shodan_enrich),
                            str(report_root),
                            "--ip",
                            ip,
                            "--json",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=90,
                        env=env,
                        cwd=str(discover_root),
                    )
                except subprocess.TimeoutExpired:
                    self._send(
                        504,
                        b'{"ok":false,"error":"Shodan refresh timed out"}\n',
                    )
                    return
                except OSError as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return

                result = None
                for ln in reversed(
                    [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]
                ):
                    try:
                        cand = json.loads(ln)
                        if isinstance(cand, dict):
                            result = cand
                            break
                    except json.JSONDecodeError:
                        continue

                if not isinstance(result, dict):
                    err = (proc.stderr or proc.stdout or "shodan refresh failed").strip()
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": err[:500]
                                or f"shodan-enrich exit {proc.returncode}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return

                code = 200 if result.get("ok") else 400
                if proc.returncode != 0 and result.get("ok"):
                    result["ok"] = False
                    result.setdefault(
                        "error", f"shodan-enrich exit {proc.returncode}"
                    )
                    code = 500
                self._send(code, json.dumps(result).encode() + b"\n")
                return

            # --- /config/* (operator machine settings under ~/.discover) ---
            if path in {
                "/config/api-keys",
                "/config/operator-name",
                "/config/timezone",
            }:
                if not config_script.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"config script missing: {config_script}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                try:
                    if path == "/config/api-keys":
                        proc = subprocess.run(
                            [
                                sys.executable,
                                str(config_script),
                                "set-api-keys",
                                "--json",
                                "--body",
                                json.dumps(body),
                            ],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            env=env,
                            cwd=str(discover_root),
                        )
                    elif path == "/config/operator-name":
                        name = str(
                            body.get("name") or body.get("operator") or ""
                        ).strip()
                        proc = subprocess.run(
                            [
                                sys.executable,
                                str(config_script),
                                "set-operator-name",
                                "--json",
                                "--name",
                                name,
                                "--report",
                                str(report_root),
                            ],
                            capture_output=True,
                            text=True,
                            timeout=120,
                            env=env,
                            cwd=str(discover_root),
                        )
                    else:
                        tz = str(body.get("timezone") or body.get("tz") or "").strip()
                        proc = subprocess.run(
                            [
                                sys.executable,
                                str(config_script),
                                "set-timezone",
                                "--json",
                                "--tz",
                                tz,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            env=env,
                            cwd=str(discover_root),
                        )
                except subprocess.TimeoutExpired:
                    self._send(
                        504,
                        b'{"ok":false,"error":"config update timed out"}\n',
                    )
                    return
                except OSError as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return
                result = _parse_json_stdout(proc.stdout or "")
                if not isinstance(result, dict):
                    err = (proc.stderr or proc.stdout or "config failed").strip()
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": err[:800]
                                or f"config exit {proc.returncode}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                code = 200 if result.get("ok") and proc.returncode == 0 else 400
                if proc.returncode != 0 and result.get("ok"):
                    result["ok"] = False
                    result.setdefault("error", f"config exit {proc.returncode}")
                    code = 500
                self._send(code, json.dumps(result).encode() + b"\n")
                return

            # --- /import-operator-package ---
            if path == "/import-operator-package":
                source = str(body.get("source") or body.get("path") or "").strip()
                operator = str(body.get("operator") or "").strip()
                if not source:
                    self._send(
                        400,
                        b'{"ok":false,"error":"source path is required"}\n',
                    )
                    return
                if not operator:
                    self._send(
                        400,
                        b'{"ok":false,"error":"operator name is required"}\n',
                    )
                    return
                if not import_operator_script.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"import script missing: {import_operator_script}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                try:
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(import_operator_script),
                            "--dest",
                            str(report_root),
                            "--source",
                            source,
                            "--operator",
                            operator,
                            "--json",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=3600,
                        env=env,
                        cwd=str(discover_root),
                    )
                except subprocess.TimeoutExpired:
                    self._send(
                        504,
                        b'{"ok":false,"error":"import timed out"}\n',
                    )
                    return
                except OSError as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return
                result = _parse_json_stdout(proc.stdout or "")
                if not isinstance(result, dict):
                    err = (proc.stderr or proc.stdout or "import failed").strip()
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": err[:800]
                                or f"import exit {proc.returncode}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                code = 200 if result.get("ok") and proc.returncode == 0 else 400
                if proc.returncode != 0 and result.get("ok"):
                    result["ok"] = False
                    result.setdefault(
                        "error", f"import exit {proc.returncode}"
                    )
                    code = 500
                if not result.get("ok") and proc.stderr:
                    result.setdefault(
                        "error_detail", (proc.stderr or "")[:400]
                    )
                self._send(code, json.dumps(result).encode() + b"\n")
                return

            # --- /export ---
            kind = str(body.get("kind") or "").strip().lower()
            if kind not in {"client", "defender", "operator"}:
                self._send(
                    400,
                    b'{"ok":false,"error":"kind must be client, defender, or operator"}\n',
                )
                return

            if not export_script.is_file():
                self._send(
                    500,
                    json.dumps(
                        {"ok": False, "error": f"export script missing: {export_script}"}
                    ).encode()
                    + b"\n",
                )
                return

            out_dir = Path.home() / "data"
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                self._send(
                    500,
                    json.dumps({"ok": False, "error": f"out dir: {exc}"}).encode()
                    + b"\n",
                )
                return

            try:
                proc = subprocess.run(
                    [
                        "bash",
                        str(export_script),
                        "--kind",
                        kind,
                        "--report",
                        str(report_root),
                        "--out-dir",
                        str(out_dir),
                        "--quiet",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=3600,
                    env=env,
                    cwd=str(discover_root),
                )
            except subprocess.TimeoutExpired:
                self._send(504, b'{"ok":false,"error":"export timed out"}\n')
                return
            except OSError as exc:
                self._send(
                    500,
                    json.dumps({"ok": False, "error": str(exc)}).encode() + b"\n",
                )
                return

            # Last non-empty line should be JSON from export-report.sh
            lines = [
                ln.strip()
                for ln in (proc.stdout or "").splitlines()
                if ln.strip()
            ]
            result = None
            for ln in reversed(lines):
                try:
                    result = json.loads(ln)
                    if isinstance(result, dict):
                        break
                except json.JSONDecodeError:
                    continue

            if not isinstance(result, dict):
                err = (proc.stderr or proc.stdout or "export failed").strip()
                self._send(
                    500 if proc.returncode else 500,
                    json.dumps(
                        {
                            "ok": False,
                            "error": err[:500] or f"export exit {proc.returncode}",
                        }
                    ).encode()
                    + b"\n",
                )
                return

            code = 200 if result.get("ok") and proc.returncode == 0 else 400
            if proc.returncode != 0 and result.get("ok"):
                result["ok"] = False
                result.setdefault("error", f"export exit {proc.returncode}")
                code = 500
            self._send(code, json.dumps(result).encode() + b"\n")

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
            if path == "/shodan-status":
                # Presence only — never return the key material.
                configured = shodan_api_key_configured(discover_root)
                self._send(
                    200,
                    json.dumps(
                        {
                            "ok": True,
                            "api_key": configured,
                            "path": str(Path.home() / ".discover" / "api-keys"),
                        }
                    ).encode()
                    + b"\n",
                )
                return
            if path == "/config":
                if not config_script.is_file():
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": f"config script missing: {config_script}",
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                try:
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(config_script),
                            "get-all",
                            "--json",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        env={**os.environ, "HOME": str(Path.home())},
                        cwd=str(discover_root),
                    )
                except (subprocess.TimeoutExpired, OSError) as exc:
                    self._send(
                        500,
                        json.dumps({"ok": False, "error": str(exc)}).encode()
                        + b"\n",
                    )
                    return
                result = None
                for ln in reversed(
                    [x.strip() for x in (proc.stdout or "").splitlines() if x.strip()]
                ):
                    try:
                        cand = json.loads(ln)
                        if isinstance(cand, dict):
                            result = cand
                            break
                    except json.JSONDecodeError:
                        continue
                if not isinstance(result, dict):
                    self._send(
                        500,
                        json.dumps(
                            {
                                "ok": False,
                                "error": (proc.stderr or "config get failed")[:400],
                            }
                        ).encode()
                        + b"\n",
                    )
                    return
                self._send(200, json.dumps(result).encode() + b"\n")
                return

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
