#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Make pipx-installed droopescan work on Python 3.12+:
#   - cement still imports removed stdlib 'imp' → patch to importlib
#   - droopescan uses distutils.util.strtobool → ensure setuptools
#
# Safe to run multiple times.
#
# Usage: patch-droopescan-py314.sh [venv_root]
# Default: /opt/pipx/venvs/droopescan (system Update install)
# User install: ~/.local/pipx/venvs/droopescan

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

# distutils was removed from the stdlib; setuptools provides it.
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

RELOAD_BLOCK = """# Discover patch: Python 3.12+ removed imp
try:
    from imp import reload  # type: ignore
except ImportError:  # pragma: no cover
    from importlib import reload  # noqa: F401
try:
    from io import StringIO  # pragma: nocover
except ImportError:  # pragma: no cover
    from StringIO import StringIO  # type: ignore
"""

RELOAD_BLOCK_EXT = """# Discover patch: Python 3.12+ removed imp
try:
    from imp import reload  # type: ignore
except ImportError:  # pragma: no cover
    from importlib import reload  # noqa: F401
"""


def strip_imp_reload_blocks(text: str) -> str:
    """Remove existing imp.reload imports / Discover shims so we can re-apply cleanly."""
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "Discover patch: Python 3.12+ removed imp" in line:
            # skip until blank line after try/except block
            i += 1
            while i < len(lines) and lines[i].strip() != "":
                i += 1
            if i < len(lines) and lines[i].strip() == "":
                i += 1
            continue
        if "from imp import reload" in line:
            if out and "sys.version_info" in out[-1] and out[-1].lstrip().startswith("if "):
                out.pop()
            i += 1
            # skip a simple else: StringIO branch that only existed for py2
            if i < len(lines) and lines[i].lstrip().startswith("else:"):
                i += 1
                while i < len(lines) and (lines[i].startswith(" ") or lines[i].startswith("\t")):
                    i += 1
            continue
        if "from StringIO import StringIO" in line and "Discover patch" not in "".join(out[-8:]):
            # drop bare py2-only import if orphaned
            i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)


def patch_reload_file(path: Path, with_stringio: bool) -> None:
    if not path.is_file():
        print(f"  missing {path}")
        return
    text = path.read_text(encoding="utf-8", errors="replace")
    text = strip_imp_reload_blocks(text)
    block = RELOAD_BLOCK if with_stringio else RELOAD_BLOCK_EXT
    # Insert after standard imports (after first blank line following imports)
    lines = text.splitlines(keepends=True)
    insert_at = 0
    for i, line in enumerate(lines):
        if line.startswith("import ") or line.startswith("from "):
            insert_at = i + 1
        elif insert_at and line.strip() == "":
            insert_at = i + 1
            break
    new_lines = lines[:insert_at] + [block if block.endswith("\n") else block + "\n", "\n"] + lines[insert_at:]
    path.write_text("".join(new_lines), encoding="utf-8")
    print(f"  patched {path.relative_to(root)}")


patch_reload_file(root / "cement/core/foundation.py", with_stringio=True)
patch_reload_file(root / "cement/core/extension.py", with_stringio=False)

plugin = root / "cement/ext/ext_plugin.py"
if plugin.is_file():
    text = plugin.read_text(encoding="utf-8", errors="replace")
    if "class _ImpShim" in text:
        print("  ok cement/ext/ext_plugin.py (already patched)")
    elif "import imp" in text:
        shim = '''# Discover patch: Python 3.12+ removed imp
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
        text = text.replace("import imp\n", shim, 1)
        plugin.write_text(text, encoding="utf-8")
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
elif command -v droopescan >/dev/null 2>&1; then
    BIN=$(command -v droopescan)
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
