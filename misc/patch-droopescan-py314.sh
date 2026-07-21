#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Make pipx-installed droopescan work on Python 3.12+:
#   - cement still imports removed stdlib 'imp' → patch to importlib
#   - droopescan uses distutils.util.strtobool → ensure setuptools
#
# Quiet when already patched (safe to run every Update).
# Usage: patch-droopescan-py314.sh [-v] [venv_root]
# Default: /opt/pipx/venvs/droopescan

set -euo pipefail

VERBOSE=0
if [ "${1:-}" = "-v" ] || [ "${1:-}" = "--verbose" ]; then
    VERBOSE=1
    shift
fi

VENV="${1:-/opt/pipx/venvs/droopescan}"

log(){
    if [ "$VERBOSE" -eq 1 ]; then
        echo "$*"
    fi
}

if [ ! -d "$VENV" ]; then
    echo "[!] droopescan venv not found: $VENV"
    exit 1
fi

PY="$VENV/bin/python"
if [ ! -x "$PY" ]; then
    echo "[!] python not found in $VENV"
    exit 1
fi

CEMENT=$(find "$VENV/lib" -type d -path '*/site-packages/cement' 2>/dev/null | head -1)
if [ -z "$CEMENT" ]; then
    echo "[!] cement package not found under $VENV"
    exit 1
fi

SITE=$(dirname "$CEMENT")
FOUNDATION="$SITE/cement/core/foundation.py"
EXTENSION="$SITE/cement/core/extension.py"
PLUGIN="$SITE/cement/ext/ext_plugin.py"

# Already fully patched?
need_setuptools=0
need_cement=0
if ! "$PY" -c 'from distutils.util import strtobool' 2>/dev/null; then
    need_setuptools=1
fi
if [ ! -f "$FOUNDATION" ] || ! grep -q 'Discover patch: Python 3.12+ removed imp' "$FOUNDATION" 2>/dev/null; then
    need_cement=1
fi
if [ ! -f "$EXTENSION" ] || ! grep -q 'Discover patch: Python 3.12+ removed imp' "$EXTENSION" 2>/dev/null; then
    need_cement=1
fi
if [ -f "$PLUGIN" ] && grep -qE '^import imp$' "$PLUGIN" 2>/dev/null \
    && ! grep -q 'class _ImpShim' "$PLUGIN" 2>/dev/null; then
    need_cement=1
fi

if [ "$need_setuptools" -eq 0 ] && [ "$need_cement" -eq 0 ]; then
    # Smoke-test quietly; only noise on failure
    if [ -x "$VENV/bin/droopescan" ] && ! "$VENV/bin/droopescan" --help >/dev/null 2>&1; then
        echo "[!] droopescan present but --help failed ($VENV)"
        "$VENV/bin/droopescan" --help 2>&1 | head -15 || true
        exit 1
    fi
    log "[*] droopescan already patched ($VENV)"
    exit 0
fi

if [ "$need_setuptools" -eq 1 ]; then
    log "[*] Ensuring setuptools in $VENV"
    "$PY" -m pip install -q setuptools >/dev/null
fi

if [ "$need_cement" -eq 1 ]; then
    log "[*] Patching cement under $SITE"
    python3 - "$SITE" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
changed = []

FOUNDATION_HEADER = '''"""Cement core foundation module."""

import re
import os
import sys
import signal
from ..core import backend, exc, handler, hook, log, config, plugin, interface
from ..core import output, extension, arg, controller, meta, cache, mail
from ..utils.misc import is_true, minimal_logger
from ..utils import fs

# Discover patch: Python 3.12+ removed imp
try:
    from imp import reload  # type: ignore
except ImportError:  # pragma: no cover
    from importlib import reload  # noqa: F401
try:
    from io import StringIO  # pragma: nocover
except ImportError:  # pragma: no cover
    from StringIO import StringIO  # type: ignore

LOG = minimal_logger(__name__)


'''

EXTENSION_HEADER = '''"""Cement core extensions module."""

import sys
from ..core import exc, interface, handler
from ..utils.misc import minimal_logger

# Discover patch: Python 3.12+ removed imp
try:
    from imp import reload  # type: ignore
except ImportError:  # pragma: no cover
    from importlib import reload  # noqa: F401

LOG = minimal_logger(__name__)


'''

PLUGIN_SHIM = '''# Discover patch: Python 3.12+ removed imp
try:
    import imp  # type: ignore
except ImportError:  # pragma: no cover
    import importlib.util
    import os as _os

    class _ImpShim(object):
        @staticmethod
        def find_module(name, path=None):
            if not path:
                raise ImportError(name)
            for base in path:
                full = _os.path.join(base, name + ".py")
                if _os.path.isfile(full):
                    return (full, full, ("", "r", 1))
            raise ImportError(name)

        @staticmethod
        def load_module(name, file, pathname, description):
            path = pathname if isinstance(pathname, str) else file
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                raise ImportError(name)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            return mod

    imp = _ImpShim()

'''


def rest_from(text: str, marker: str) -> str:
    i = text.find(marker)
    if i < 0:
        raise SystemExit(f"marker not found: {marker!r}")
    return text[i:]


fp = root / "cement/core/foundation.py"
ft = fp.read_text(encoding="utf-8", errors="replace")
ft = "".join(ch for ch in ft if ch == "\n" or ch == "\t" or (ord(ch) >= 32))
if "Discover patch: Python 3.12+ removed imp" not in ft:
    rest = rest_from(ft, "class NullOut")
    fp.write_text(FOUNDATION_HEADER + rest, encoding="utf-8")
    changed.append("cement/core/foundation.py")

ep = root / "cement/core/extension.py"
et = ep.read_text(encoding="utf-8", errors="replace")
et = "".join(ch for ch in et if ch == "\n" or ch == "\t" or (ord(ch) >= 32))
if "Discover patch: Python 3.12+ removed imp" not in et:
    rest = rest_from(et, "def extension_validator")
    ep.write_text(EXTENSION_HEADER + rest, encoding="utf-8")
    changed.append("cement/core/extension.py")

pp = root / "cement/ext/ext_plugin.py"
if pp.is_file():
    pt = pp.read_text(encoding="utf-8", errors="replace")
    if "class _ImpShim" not in pt and "import imp\n" in pt:
        pt2 = pt.replace("import imp\n", PLUGIN_SHIM, 1)
        pp.write_text(pt2, encoding="utf-8")
        changed.append("cement/ext/ext_plugin.py")

for c in changed:
    print(f"  patched {c}")
if not changed:
    print("  (cement already current)")
PY
fi

if [ -x "$VENV/bin/droopescan" ]; then
    if ! "$VENV/bin/droopescan" --help >/dev/null 2>&1; then
        echo "[!] droopescan still failing after patch ($VENV):"
        "$VENV/bin/droopescan" --help 2>&1 | head -25 || true
        exit 1
    fi
fi

# One line when we actually did work (non-verbose)
if [ "$VERBOSE" -eq 0 ]; then
    echo "[+] droopescan patched ($VENV)"
else
    echo "[+] droopescan OK ($VENV/bin/droopescan)"
fi
