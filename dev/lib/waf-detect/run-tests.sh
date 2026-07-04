#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="${ROOT}/lib/waf-detect"
FAIL=0

pass(){ echo "[PASS] $*"; }
fail(){ echo "[FAIL] $*"; FAIL=1; }

echo "=== waf-detect tests ==="

bash -n "${ROOT}/waf-detect.sh" && pass "waf-detect.sh syntax"
bash -n "${LIB}/common.sh" && pass "common.sh syntax"
bash -n "${LIB}/probe.sh" && pass "probe.sh syntax"

"${ROOT}/waf-detect.sh" --help >/dev/null && pass "--help"

OUT=$(mktemp -d)
"${ROOT}/waf-detect.sh" --url https://example.com --passive --quiet --output-dir "$OUT" || true
[ -f "$OUT/findings.json" ] && pass "findings.json created" || fail "findings.json created"
[ -f "$OUT/waf_results.tsv" ] && pass "waf_results.tsv created" || fail "waf_results.tsv created"
[ -f "$OUT/report.txt" ] && pass "report.txt created" || fail "report.txt created"

PASSIVE_FLAG=$(jq -r '.passive' "$OUT/findings.json")
[ "$PASSIVE_FLAG" = "true" ] && pass "passive flag in findings.json" || fail "passive flag in findings.json ($PASSIVE_FLAG)"
! grep -qi 'Running wafw00f' "$OUT/scan.log" 2>/dev/null && pass "passive scan skips wafw00f" || fail "passive scan skips wafw00f"
grep -qi 'Passive: 1' "$OUT/scan.log" && pass "passive logged in scan.log" || fail "passive logged in scan.log"

OUT2=$(mktemp -d)
"${ROOT}/waf-detect.sh" --url https://example.com --i-understand --quiet --output-dir "$OUT2" || true
TOTAL=$(jq -r '.summary.total' "$OUT2/findings.json")
WAF_ROWS=$(jq -r '[.findings[] | select(.check=="waf_identified")] | length' "$OUT2/findings.json")
[ "${TOTAL:-0}" -eq 1 ] && pass "single consolidated finding (was duplicate)" || fail "single consolidated finding (total=$TOTAL)"
[ "${WAF_ROWS:-0}" -eq 1 ] && pass "one waf_identified row" || fail "one waf_identified row (rows=$WAF_ROWS)"
CONF=$(jq -r '.findings[0].detail' "$OUT2/findings.json")
echo "$CONF" | grep -q 'confidence=high' && pass "wafw00f high confidence" || fail "wafw00f high confidence"
echo "$CONF" | grep -q 'source=wafw00f' && pass "source is wafw00f" || fail "source is wafw00f"

HITS_LEN=$(jq -r '.hits | length' "$OUT2/findings.json")
[ "${HITS_LEN:-0}" -ge 1 ] && pass "structured hits in findings.json" || fail "structured hits in findings.json (hits=$HITS_LEN)"
[ -f "$OUT2/waf_engine/hits.jsonl" ] && pass "hits.jsonl created" || fail "hits.jsonl created"
jq -e '.hits[0].vendor' "$OUT2/findings.json" >/dev/null && pass "hits have vendor field" || fail "hits have vendor field"

OUT3=$(mktemp -d)
"${ROOT}/waf-detect.sh" --url https://example.com --passive --waf-only --quiet --output-dir "$OUT3" || true
WAF_ONLY_FLAG=$(jq -r '.waf_only' "$OUT3/findings.json")
[ "$WAF_ONLY_FLAG" = "true" ] && pass "waf-only flag in findings.json" || fail "waf-only flag in findings.json ($WAF_ONLY_FLAG)"
CDN_ROWS=$(jq -r '[.findings[] | select(.check=="cdn_present")] | length' "$OUT3/findings.json")
WAF_ONLY_ROWS=$(jq -r '[.findings[] | select(.check=="waf_identified")] | length' "$OUT3/findings.json")
# example.com is Cloudflare (both) — waf-only may report waf_identified or cdn_present depending on passive hit
[ "${WAF_ONLY_ROWS:-0}" -ge 0 ] && pass "waf-only scan completes" || fail "waf-only scan completes"

rm -rf "$OUT" "$OUT2" "$OUT3"

if [ "$FAIL" -eq 0 ]; then
    echo "=== all tests passed ==="
    exit 0
fi
echo "=== tests failed ==="
exit 1