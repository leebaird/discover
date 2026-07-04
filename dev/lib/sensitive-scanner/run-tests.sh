#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="${ROOT}/lib/sensitive-scanner"
FIX="${LIB}/fixtures"
FAIL=0

pass(){ echo "[PASS] $*"; }
fail(){ echo "[FAIL] $*"; FAIL=1; }

echo "=== sensitive-scanner tests ==="

bash -n "${ROOT}/sensitive-scanner.sh" && pass "sensitive-scanner.sh syntax"
bash -n "${LIB}/common.sh" && pass "common.sh syntax"
bash -n "${LIB}/files.sh" && pass "files.sh syntax"
bash -n "${LIB}/web.sh" && pass "web.sh syntax"

"${ROOT}/sensitive-scanner.sh" --help >/dev/null && pass "--help"

OUT=$(mktemp -d)
python3 "${LIB}/filescan.py" \
    --root "$FIX" \
    --output-dir "$OUT" \
    --domain fixtures \
    --mode full \
    --hits-out "$OUT/hits.jsonl"
[ -s "$OUT/hits.jsonl" ] && pass "filescan produces hits" || fail "filescan produces hits"
grep -q 'ghp_' "$OUT/hits.jsonl" && pass "detects github token" || fail "detects github token"
grep -q 'PRIVATE KEY' "$OUT/hits.jsonl" && pass "detects private key" || fail "detects private key"
grep -q 'your-api-key' "$OUT/hits.jsonl" && fail "denylist allows placeholder" || pass "denylist filters placeholder"
grep -q 'user@example.com' "$OUT/hits.jsonl" && fail "denylist allows example email" || pass "denylist filters example email"

OUT2=$(mktemp -d)
"${ROOT}/sensitive-scanner.sh" --path "$FIX/secrets.env" --files --quick --output-dir "$OUT2" --quiet
[ -f "$OUT2/findings.json" ] && pass "CLI file scan report" || fail "CLI file scan report"
TOTAL=$(jq -r '.summary.total' "$OUT2/findings.json")
[ "${TOTAL:-0}" -gt 0 ] && pass "CLI findings recorded" || fail "CLI findings recorded"

OUT3=$(mktemp -d)
"${ROOT}/sensitive-scanner.sh" --url https://example.com --web --quick --max-paths 3 --workers 2 --output-dir "$OUT3" --quiet
[ -f "$OUT3/web_sensitive/engine/results.json" ] && pass "web engine results" || fail "web engine results"
[ -f "$OUT3/findings.json" ] && pass "web findings json" || fail "web findings json"

rm -rf "$OUT" "$OUT2" "$OUT3"

if [ "$FAIL" -eq 0 ]; then
    echo "=== all tests passed ==="
    exit 0
fi
echo "=== tests failed ==="
exit 1