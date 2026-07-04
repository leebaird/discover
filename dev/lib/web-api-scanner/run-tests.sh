#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="${ROOT}/lib/web-api-scanner"
FIX="${LIB}/fixtures"
FAIL=0

pass(){ echo "[PASS] $*"; }
fail(){ echo "[FAIL] $*"; FAIL=1; }

echo "=== web-api-scanner tests ==="

bash -n "${ROOT}/web-api-scanner.sh" && pass "web-api-scanner.sh syntax"
bash -n "${LIB}/common.sh" && pass "common.sh syntax"
bash -n "${LIB}/phases.sh" && pass "phases.sh syntax"
bash -n "${LIB}/waf.sh" && pass "waf.sh syntax"
bash -n "${LIB}/targets.sh" && pass "targets.sh syntax"
bash -n "${LIB}/msf.sh" && pass "msf.sh syntax"
bash -n "${LIB}/probe.sh" && pass "probe.sh syntax"

"${ROOT}/web-api-scanner.sh" --help >/dev/null && pass "--help"
"${ROOT}/web-api-scanner.sh" --help 2>&1 | grep -q -- '--quick' && pass "help documents --quick" || fail "help documents --quick"
"${ROOT}/web-api-scanner.sh" --help 2>&1 | grep -q -- '--tier' && pass "help documents --tier" || fail "help documents --tier"

OUT=$(mktemp -d)
"${ROOT}/web-api-scanner.sh" --url https://example.com --passive --dry-run --skip-msf-db --quiet --output-dir "$OUT" || true
PHASES=$(jq -r 'length' "$OUT/msf_engine/phases.json")
[ "${PHASES:-0}" -eq 1 ] && pass "passive tier one phase" || fail "passive tier phases ($PHASES)"
TIER=$(jq -r '.tier' "$OUT/findings.json")
[ "$TIER" = "passive" ] && pass "findings tier passive" || fail "findings tier ($TIER)"
[ ! -d "$OUT/msf_engine/resources" ] && pass "resources cleaned by default" || fail "resources cleaned"

OUTQ=$(mktemp -d)
"${ROOT}/web-api-scanner.sh" --url https://example.com --quick --dry-run --skip-msf-db --quiet --output-dir "$OUTQ" || true
QPHASES=$(jq -r 'length' "$OUTQ/msf_engine/phases.json")
[ "${QPHASES:-0}" -gt 1 ] && pass "quick tier multiple phases" || fail "quick tier phases ($QPHASES)"
! grep -q 'sql_injection' "$OUTQ/msf_engine/session_web_recon.rc" 2>/dev/null && \
  ! grep -qr 'sql_injection' "$OUTQ/msf_engine/" 2>/dev/null && pass "quick skips sqli" || \
  ! grep -q 'sql_injection' "$OUTQ/msf_engine/session_sqli_security.rc" 2>/dev/null && pass "quick skips sqli" || fail "quick skips sqli"

OUT2=$(mktemp -d)
"${ROOT}/web-api-scanner.sh" --url https://example.com --tier exploit --i-understand --dry-run --skip-msf-db --quiet --output-dir "$OUT2" || true
[ -f "$OUT2/msf_engine/session_web_exploit_checks.rc" ] && pass "exploit tier session files" || fail "exploit tier session files"
grep -q 'jenkins_script_console' "$OUT2/msf_engine/session_web_exploit_checks.rc" && pass "exploit phase content" || fail "exploit phase content"

OUT3=$(mktemp -d)
"${ROOT}/web-api-scanner.sh" --url https://example.com --tier intrusive --quiet --dry-run --skip-msf-db --output-dir "$OUT3" 2>/dev/null && fail "intrusive requires consent" || pass "intrusive requires consent"

# msf_parse.py fixture
PARSE_OUT=$(mktemp -d)
COUNT=$(python3 "${LIB}/msf_parse.py" "${FIX}/msf_spool_sample.txt" \
    --phase web_recon --phase-label "Web Recon" --domain example.com --target https://example.com \
    -o "${PARSE_OUT}/hits.jsonl")
[ "${COUNT:-0}" -ge 2 ] && pass "msf_parse extracts hits" || fail "msf_parse extracts hits ($COUNT)"
grep -q 'nginx' "${PARSE_OUT}/hits.jsonl" && pass "msf_parse nginx hit" || fail "msf_parse nginx hit"

# Technology fixtures
OUT4=$(mktemp -d)
mkdir -p "$OUT4/msf_engine/fingerprint"
cp "$FIX/wordpress_page.html" "$OUT4/msf_engine/fingerprint/page.html"
printf 'HTTP/1.1 200 OK\nServer: nginx\n' > "$OUT4/msf_engine/fingerprint/headers.txt"
bash -c "
    WEBAPI_ROOT='${ROOT}' WEBAPI_TECH_MIN_SCORE=3 WEBAPI_TIER=passive OUTPUT_DIR='${OUT4}'
    WEBAPI_PAGE_FILE='${OUT4}/msf_engine/fingerprint/page.html'
    WEBAPI_HEADERS_FILE='${OUT4}/msf_engine/fingerprint/headers.txt'
    source '${LIB}/common.sh'
    source '${LIB}/phases.sh'
    source '${LIB}/probe.sh'
    f_webapi_load_tech_signatures 'https://fixture.test'
    [ \"\${WEBAPI_TECH_SCORE[wordpress]:-0}\" -ge 3 ] || exit 1
" && pass "wordpress tech score" || fail "wordpress tech score"

OUT5=$(mktemp -d)
mkdir -p "$OUT5/msf_engine/fingerprint"
cp "$FIX/swagger_page.html" "$OUT5/msf_engine/fingerprint/page.html"
printf 'HTTP/1.1 200 OK\nContent-Type: application/json\n' > "$OUT5/msf_engine/fingerprint/headers.txt"
bash -c "
    WEBAPI_ROOT='${ROOT}' WEBAPI_TECH_MIN_SCORE=3 WEBAPI_TIER=standard OUTPUT_DIR='${OUT5}'
    WEBAPI_PAGE_FILE='${OUT5}/msf_engine/fingerprint/page.html'
    WEBAPI_HEADERS_FILE='${OUT5}/msf_engine/fingerprint/headers.txt'
    source '${LIB}/common.sh'
    source '${LIB}/phases.sh'
    source '${LIB}/probe.sh'
    f_webapi_load_tech_signatures 'https://fixture.test'
    [ \"\${WEBAPI_TECH_SCORE[swagger]:-0}\" -ge 3 ] || exit 1
" && pass "swagger body tech score" || fail "swagger body tech score"

# WAF skips brute phases
OUT6=$(mktemp -d)
bash -c "
    WEBAPI_ROOT='${ROOT}' WEBAPI_TIER=intrusive WEBAPI_WAF_PRESENT=1 WEBAPI_WAF_AWARE=1 OUTPUT_DIR='${OUT6}'
    mkdir -p '${OUT6}/msf_engine'
    source '${LIB}/common.sh'
    source '${LIB}/phases.sh'
    source '${LIB}/waf.sh'
    source '${LIB}/msf.sh'
    source '${LIB}/probe.sh'
    WEBAPI_TECH_SCORE[wordpress]=5
    phases=()
    f_webapi_build_phase_plan phases
    for p in \"\${phases[@]}\"; do [ \"\$p\" = web_auth_brute ] && exit 1; done
    exit 0
" && pass "waf skips brute phases" || fail "waf skips brute phases"

# api-scanner endpoint formats
OUT7=$(mktemp -d)
mkdir -p "$OUT7/api_scanner"
printf '%s\n' 'https://app.example.com/api/v1/users' 'https://app.example.com/api/v2/items' > "$OUT7/api_scanner/all_endpoints.txt"
bash -c "
    WEBAPI_ROOT='${ROOT}' WEBAPI_SCAN_DIR='${OUT7}' OUTPUT_DIR='${OUT7}'
    source '${LIB}/common.sh'
    source '${LIB}/msf.sh'
    WEBAPI_MSF_WORDLIST_RESOLVED='/tmp/directory.txt'
    f_webapi_load_api_path_formats 'https://app.example.com'
    [ \"\${#WEBAPI_API_FORMATS[@]}\" -ge 5 ] || exit 1
    printf '%s\n' \"\${WEBAPI_API_FORMATS[@]}\" | grep -q '/api/v1/%s' || exit 1
" && pass "api-scanner endpoint formats" || fail "api-scanner endpoint formats"

env -i HOME="$HOME" PATH="$PATH" TERM="${TERM:-xterm}" \
    bash "${ROOT}/web-api-scanner.sh" --help >/dev/null 2>&1 && pass "standalone --help" || fail "standalone --help"

if [ "${WEBAPI_RUN_LIVE_MSF:-0}" = "1" ] && command -v msfconsole >/dev/null 2>&1; then
    OUTL=$(mktemp -d)
    "${ROOT}/web-api-scanner.sh" --url https://example.com --passive --skip-msf-db --quiet --output-dir "$OUTL" --phase-timeout 120 || true
    [ -s "$OUTL/msf_engine/spool/web_recon.txt" ] && pass "live msf passive spool" || fail "live msf passive spool"
    rm -rf "$OUTL"
else
    pass "live msf test skipped (set WEBAPI_RUN_LIVE_MSF=1)"
fi

rm -rf "$OUT" "$OUTQ" "$OUT2" "$OUT3" "$PARSE_OUT" "$OUT4" "$OUT5" "$OUT6" "$OUT7"

if [ "$FAIL" -eq 0 ]; then
    echo "=== all tests passed ==="
    exit 0
fi
echo "=== tests failed ==="
exit 1