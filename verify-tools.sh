#!/bin/bash
################################################################################
# ARISE Tool Verification Script
# Checks all external tools used by easm-pipeline.sh for availability and basic
# functionality. Reports pass/fail for each tool with version/banner info.
################################################################################

set -o pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NORMAL='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0

# Output formatting
log_pass() {
    echo -e "${GREEN}[✓ PASS]${NORMAL} $1"
    ((PASS++))
}

log_fail() {
    echo -e "${RED}[✗ FAIL]${NORMAL} $1"
    ((FAIL++))
}

log_warn() {
    echo -e "${YELLOW}[⚠ WARN]${NORMAL} $1"
    ((WARN++))
}

log_section() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NORMAL}"
    echo -e "${CYAN}  $1${NORMAL}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NORMAL}"
}

# Directories where Go-installed tools may actually live
GO_BIN_DIRS=(
    "$HOME/go/bin"
    "$HOME/.pdtm/go/bin"
    "$HOME/.local/bin"
    "/usr/local/bin"
    "/usr/local/go/bin"
)

# Track every Go tool name we test, so the PATH/hash consistency
# section can re-check them all in one pass.
GO_TOOL_NAMES=()

# Find every real, executable copy of a tool across known install dirs.
# Prints one path per line (may be zero, one, or several).
find_go_tool_copies() {
    local tool_name="$1"
    for dir in "${GO_BIN_DIRS[@]}"; do
        if [ -x "$dir/$tool_name" ]; then
            echo "$dir/$tool_name"
        fi
    done
}

# Test a Go-installed tool. Verifies:
#   1. A real binary exists somewhere in known install dirs
#   2. `command -v` (PATH resolution) actually finds a *working* copy
#   3. Bash's hashed command cache isn't pointing at a dead path
#   4. The binary responds and (optionally) supports an expected flag
test_go_tool() {
    local tool_name="$1"
    local expected_flag="$2"
    GO_TOOL_NAMES+=("$tool_name")

    local real_copies
    real_copies=$(find_go_tool_copies "$tool_name")

    if [ -z "$real_copies" ]; then
        log_fail "$tool_name - NOT FOUND in any of: ${GO_BIN_DIRS[*]}"
        return 1
    fi

    local first_copy
    first_copy=$(echo "$real_copies" | head -1)
    local copy_count
    copy_count=$(echo "$real_copies" | wc -l | tr -d ' ')

    # What does PATH resolution (as bash would use it right now) find?
    local path_resolved
    path_resolved=$(command -v "$tool_name" 2>/dev/null)

    if [ -z "$path_resolved" ]; then
        log_fail "$tool_name - binary exists at $first_copy but is NOT on PATH (command -v found nothing). Add its directory to \$PATH."
        return 1
    elif [ ! -x "$path_resolved" ]; then
        log_fail "$tool_name - PATH resolves to $path_resolved which is stale/broken (no such file). Run 'hash -r' or fix \$PATH ordering."
        return 1
    fi

    # Bash caches resolved paths per-session; a stale hash entry can
    # point at a binary that was since moved/deleted even though a
    # fresh `command -v` (which bypasses the hash table) works fine.
    local hashed_path=""
    if hash -t "$tool_name" &>/dev/null; then
        hashed_path=$(hash -t "$tool_name" 2>/dev/null)
        if [ -n "$hashed_path" ] && [ ! -x "$hashed_path" ]; then
            log_warn "$tool_name - bash has a STALE hash entry pointing to $hashed_path (does not exist). Run 'hash -r' to clear it."
        fi
    fi

    if [ "$copy_count" -gt 1 ]; then
        log_warn "$tool_name - multiple copies found (${real_copies//$'\n'/, }); PATH is using $path_resolved. Remove duplicates to avoid confusion."
    fi

    # Get version/banner (try -v, --version, -h, --help in order)
    local version_output
    version_output=$("$path_resolved" -version 2>&1 || "$path_resolved" --version 2>&1 || "$path_resolved" -h 2>&1 | head -3 || echo "OK")

    # Check for expected flag if provided
    if [ -n "$expected_flag" ]; then
        if "$path_resolved" -h 2>&1 | grep -q "^\s*$expected_flag"; then
            log_pass "$tool_name - $(echo "$version_output" | head -1) [$path_resolved]"
            return 0
        else
            log_warn "$tool_name - found but missing expected flag $expected_flag [$path_resolved]"
            return 0
        fi
    else
        log_pass "$tool_name - $(echo "$version_output" | head -1) [$path_resolved]"
        return 0
    fi
}

# Test CLI tools (apt/manual install)
test_cli_tool() {
    local tool_name="$1"
    local expected_flag="$2"

    if ! command -v "$tool_name" &>/dev/null; then
        log_fail "$tool_name - NOT FOUND"
        return 1
    fi

    local version_output
    version_output=$("$tool_name" -h 2>&1 | head -1 || "$tool_name" --version 2>&1 | head -1 || echo "OK")

    if [ -n "$expected_flag" ]; then
        if "$tool_name" -h 2>&1 | grep -q "$expected_flag"; then
            log_pass "$tool_name - found"
            return 0
        else
            log_warn "$tool_name - found but missing expected flag $expected_flag"
            return 0
        fi
    else
        log_pass "$tool_name - found"
        return 0
    fi
}

# Test Python packages
test_python_package() {
    local pkg_name="$1"

    if python3 -c "import $pkg_name" 2>/dev/null; then
        log_pass "Python: $pkg_name"
        return 0
    else
        log_fail "Python: $pkg_name - NOT INSTALLED"
        return 1
    fi
}

################################################################################
# START VERIFICATION
################################################################################

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          ARISE Tool & Dependency Verification Script           ║"
echo "║     Checking all external tools for availability & function    ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log_section "SYSTEM INFO"
echo "Go version: $(go version)"
echo "Python3: $(python3 --version)"
echo "Bash: $(bash --version | head -1)"
echo "User: $(whoami)"
echo "PATH: $PATH"

log_section "GO-INSTALLED RECONNAISSANCE TOOLS"
test_go_tool "subfinder" "-d"
test_go_tool "puredns" "bruteforce"
test_go_tool "dnsx" "-l"
test_go_tool "naabu" "-l"
test_go_tool "httpx" "-l"
test_go_tool "nuclei" "-l"
test_go_tool "gau" "--subs"
test_go_tool "gospider" "-s"
test_go_tool "katana" "-list"

log_section "GO-INSTALLED FUZZING & EXPLOITATION TOOLS"
test_go_tool "ffuf" "-w"
test_go_tool "dalfox" "file"
test_go_tool "crlfuzz" "-u"
test_go_tool "bhedak" "-l"
test_go_tool "qsreplace" ""

log_section "GO-INSTALLED UTILITY TOOLS"
test_go_tool "anew" ""
test_go_tool "gf" "-l"
test_go_tool "interactsh-client" ""

log_section "GO-INSTALLED SECRET SCANNING"
test_go_tool "trufflehog" "filesystem"

log_section "SYSTEM TOOLS"
test_cli_tool "nmap" "-sV"
test_cli_tool "curl" "-I"
test_cli_tool "wget" "-O"
test_cli_tool "jq" "."
test_cli_tool "grep" "-E"
test_cli_tool "awk" ""
test_cli_tool "sed" ""
test_cli_tool "sort" ""
test_cli_tool "uniq" ""

log_section "PYTHON PACKAGES (Core)"
test_python_package "requests"
test_python_package "json"
test_python_package "sys"
test_python_package "urllib"

log_section "PYTHON PACKAGES (Optional/Extended)"
test_python_package "sqlmap" || true
test_python_package "wafw00f" || true
test_python_package "dirsearch" || true
test_python_package "cloud_enum" || true

log_section "PATH & HASH CONSISTENCY CHECK (ALL GO TOOLS)"
echo "Re-checking every Go tool tested above for PATH/hash-cache issues"
echo "that only show up in an interactive shell (the class of bug that"
echo "broke httpx on EC2: binary present, but PATH/hash pointed at nothing)."
echo ""

hash -r  # clear stale cache before re-checking, mirrors what the fix requires

PATH_ISSUES=0
for tool in "${GO_TOOL_NAMES[@]}"; do
    copies=$(find_go_tool_copies "$tool")
    [ -z "$copies" ] && continue  # already reported as FAIL above

    resolved=$(command -v "$tool" 2>/dev/null)
    copy_count=$(echo "$copies" | wc -l | tr -d ' ')

    if [ -z "$resolved" ]; then
        log_fail "$tool - installed at $(echo "$copies" | head -1) but NOT resolvable via \$PATH"
        ((PATH_ISSUES++))
    elif [ "$copy_count" -gt 1 ]; then
        echo -e "  ${YELLOW}note${NORMAL}: $tool has $copy_count copies, PATH picks: $resolved"
    fi
done

if [ "$PATH_ISSUES" -eq 0 ]; then
    log_pass "No PATH resolution issues found for any Go tool"
else
    log_fail "$PATH_ISSUES Go tool(s) have PATH resolution issues - see above"
fi

echo ""
echo "Directories currently searched for Go tools: ${GO_BIN_DIRS[*]}"
echo "Directories actually present in \$PATH:"
for dir in "${GO_BIN_DIRS[@]}"; do
    if [[ ":$PATH:" == *":$dir:"* ]]; then
        echo -e "  ${GREEN}[in PATH]${NORMAL}    $dir"
    elif [ -d "$dir" ]; then
        echo -e "  ${RED}[NOT in PATH]${NORMAL} $dir (exists on disk, has tools, but PATH doesn't include it)"
    fi
done

log_section "CRITICAL FEATURE TESTS"

# Resolve httpx via PATH (not a hardcoded ~/go/bin guess) so this test
# reflects reality on machines using pdtm, apt, or manual installs.
HTTPX_BIN=$(command -v httpx 2>/dev/null)
if [ -z "$HTTPX_BIN" ]; then
    HTTPX_BIN=$(find_go_tool_copies "httpx" | head -1)
fi

# Test httpx -l flag specifically (the one that failed on EC2)
echo -n "Testing httpx -l flag: "
if [ -n "$HTTPX_BIN" ] && "$HTTPX_BIN" -h 2>&1 | grep -q -- "-l"; then
    log_pass "httpx supports -l flag (list input) [$HTTPX_BIN]"
else
    log_fail "httpx does NOT support -l flag, or httpx not resolvable - upgrade Go, reinstall httpx, and fix PATH"
fi

# Test httpx can read from file
echo -n "Testing httpx file input: "
if [ -n "$HTTPX_BIN" ] && echo "google.com" > /tmp/test_hosts.txt && \
   timeout 5 "$HTTPX_BIN" -l /tmp/test_hosts.txt -silent -nc -timeout 3 2>/dev/null | grep -q "google"; then
    log_pass "httpx can probe from file"
else
    log_warn "httpx file input test inconclusive (network may be blocking, or httpx not resolvable)"
fi
rm -f /tmp/test_hosts.txt

# Test nuclei templates
echo -n "Checking nuclei templates: "
TMPL_DIR="$HOME/nuclei-templates"
if [ ! -d "$TMPL_DIR" ]; then
    TMPL_DIR="$HOME/recon/nuclei-templates"
fi
if [ -d "$TMPL_DIR" ]; then
    TMPL_COUNT=$(find "$TMPL_DIR" -name "*.yaml" 2>/dev/null | wc -l)
    log_pass "nuclei templates found ($TMPL_COUNT YAML files in $TMPL_DIR)"
else
    log_warn "nuclei templates directory not found - run 'git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates'"
fi

# Test wordlists
echo -n "Checking wordlists: "
WL_DIR="$PWD/lists"
if [ ! -d "$WL_DIR" ]; then
    WL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lists"
fi
if [ -d "$WL_DIR" ]; then
    WL_COUNT=$(find "$WL_DIR" -type f 2>/dev/null | wc -l)
    log_pass "wordlists found ($WL_COUNT files in $WL_DIR)"
else
    log_warn "wordlists directory not found at $WL_DIR"
fi

log_section "ENVIRONMENT & CONFIG"
echo "GOPATH: $GOPATH"
echo "GOROOT: $GOROOT"
echo "GO111MODULE: ${GO111MODULE:-not set}"
echo "CGO_ENABLED: ${CGO_ENABLED:-not set}"

# Check if ARISE env vars are set
echo ""
echo "ARISE-specific env vars:"
echo "  NAABU_RATE: ${NAABU_RATE:-not set}"
echo "  NAABU_THREADS: ${NAABU_THREADS:-not set}"
echo "  PORT_SCAN_MODE: ${PORT_SCAN_MODE:-not set (defaults: Mac=fast, Linux=full)}"
echo "  PUREDNS_ENABLED: ${PUREDNS_ENABLED:-not set (default=true)}"

log_section "SUMMARY"
echo ""
echo -e "Results:"
echo -e "  ${GREEN}Passed:  $PASS${NORMAL}"
echo -e "  ${YELLOW}Warnings: $WARN${NORMAL}"
echo -e "  ${RED}Failed:  $FAIL${NORMAL}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}✓ All critical tools are available!${NORMAL}"
    echo ""
    echo "Next steps:"
    echo "  1. Run: cd /home/ubuntu/ARISEv2.1 && bash easm-pipeline.sh jungleerummy.com"
    echo "  2. Logs will be in: scans/jungleerummy.com-TIMESTAMP/logs/"
    echo "  3. Tool-specific logs: scans/jungleerummy.com-TIMESTAMP/logs/tools/"
    exit 0
else
    echo -e "${RED}✗ Some critical tools are missing or misconfigured!${NORMAL}"
    echo ""
    if [ "${PATH_ISSUES:-0}" -gt 0 ]; then
        echo "FIX (PATH/hash issues): binaries exist but aren't resolvable in this shell."
        echo "  1. Run: hash -r"
        echo "  2. Make sure the missing directory is exported in THIS shell, e.g.:"
        echo "     export PATH=\$PATH:\$HOME/.pdtm/go/bin"
        echo "  3. Persist it for future shells: add the export to ~/.bashrc (or"
        echo "     ~/.profile / /etc/environment for non-interactive/cron use)."
        echo "  4. Re-run this script in a FRESH shell to confirm the fix sticks."
        echo ""
    fi
    if ! command -v httpx &>/dev/null || ! command -v httpx | xargs -I{} {} -h 2>&1 | grep -q -- "-l"; then
        echo "FIX (httpx -l flag missing/broken): Upgrade Go to 1.21+ and reinstall httpx:"
        echo "  sudo apt-get update && sudo apt-get install -y golang-go"
        echo "  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        echo "  go version  # verify 1.21+"
    fi
    exit 1
fi
