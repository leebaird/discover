#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Make pipx-installed droopescan work on Python 3.12+:
#   - cement still imports removed stdlib 'imp' → patch to importlib
#   - droopescan uses distutils.util.strtobool → ensure setuptools
#
# Safe to run multiple times. Rewrites cement module headers cleanly
# (avoids leftover else:/broken indentation from partial patches).
#
# Usage: patch-droopescan-py314.sh [venv_root]
# Default: /opt/pipx/venvs/droopescan
# User:    ~/.local/pipx/venvs/droopescan

set -euo pipefail

VENV="${1:-/opt/pipx/venvs/droopescan}"

if [ ! -d "$VENV" ]; then
    echo "[!] droopescan venv not found: $VENV"
    exit 1
fi

PY="$VENV/bin/python"
if [ ! -x "$PY" ]; then
    echo "[!] python not found in $VENV"
    exit 1
fi

echo "[*] Ensuring setuptools (distutils) in droopescan venv"
"$PY" -m pip install -q setuptools >/dev/null

CEMENT=$(find "$VENV/lib" -type d -path '*/site-packages/cement' 2>/dev/null | head -1)
if [ -z "$CEMENT" ]; then
    echo "[!] cement package not found under $VENV"
    exit 1
fi

SITE=$(dirname "$CEMENT")
echo "[*] Patching cement under $SITE (imp → importlib)"

python3 - "$SITE" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])

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


# --- foundation.py: replace entire header through LOG ---
fp = root / "cement/core/foundation.py"
ft = fp.read_text(encoding="utf-8", errors="replace")
# Drop any non-printable garbage from prior bad patches
ft = "".join(ch for ch in ft if ch == "\n" or ch == "\t" or (ord(ch) >= 32))
rest = rest_from(ft, "class NullOut")
fp.write_text(FOUNDATION_HEADER + rest, encoding="utf-8")
print("  patched cement/core/foundation.py")

# --- extension.py ---
ep = root / "cement/core/extension.py"
et = ep.read_text(encoding="utf-8", errors="replace")
et = "".join(ch for ch in et if ch == "\n" or ch == "\t" or (ord(ch) >= 32))
rest = rest_from(et, "def extension_validator")
ep.write_text(EXTENSION_HEADER + rest, encoding="utf-8")
print("  patched cement/core/extension.py")

# --- ext_plugin.py ---
pp = root / "cement/ext/ext_plugin.py"
if pp.is_file():
    pt = pp.read_text(encoding="utf-8", errors="replace")
    if "class _ImpShim" in pt:
        print("  ok cement/ext/ext_plugin.py (already patched)")
    elif "import imp\n" in pt:
        # strip prior discover shims if re-running
        if "Discover patch: Python 3.12+ removed imp" in pt and "import imp" in pt:
            # rewrite from original-style start
            pass
        pt2 = pt
        # If already has try/import imp shim from us, leave
        if "class _ImpShim" not in pt2:
            pt2 = pt2.replace("import imp\n", PLUGIN_SHIM, 1)
            pp.write_text(pt2, encoding="utf-8")
            print("  patched cement/ext/ext_plugin.py")
    else:
        print("  ok cement/ext/ext_plugin.py")
else:
    print("  missing cement/ext/ext_plugin.py")

print("[*] cement patch complete")
PY

BIN=""
if [ -x "$VENV/bin/droopescan" ]; then
    BIN="$VENV/bin/droopescan"
fi

if [ -n "$BIN" ]; then
    if "$BIN" --help >/dev/null 2>&1; then
        echo "[+] droopescan OK ($BIN)"
    else
        echo "[!] droopescan still failing:"
        "$BIN" --help 2>&1 | head -25 || true
        exit 1
    fi
fi
