#!/usr/bin/env bash
# ARISE Setup Script — Cross-Platform (Linux / macOS / WSL / Docker)
# "Summon Every Hidden Exposure."
#
# Installs everything ARISE needs to run the dashboard + the full easm-pipeline:
#   - system packages (nmap, libpcap, git, jq, sqlmap, dnsutils, chromium deps…)
#   - Go + the Go security tool suite (nuclei v3, httpx, subfinder, naabu, …)
#   - the exact Python dependencies the code imports (flask, apscheduler,
#     scikit-learn, playwright, phonenumbers, …) — not a partial guess
#   - git-cloned Python tools (jwt_tool, SSTImap, graphw00f, smuggler, cloud_enum)
#   - wordlists + nuclei templates
#
# Design goals for this rewrite:
#   * Works unattended in a Docker base image (root, no sudo, non-interactive apt,
#     PEP-668 pip, PATH persisted globally via /etc/profile.d).
#   * Never aborts on an OPTIONAL tool failure; aborts ONLY when a CRITICAL
#     dependency is missing. Failures are collected and summarised at the end.
#   * Idempotent — safe to re-run.
#   * Correct Go PATH + Python PATH setup for both interactive shells and Docker.
#
# Environment toggles:
#   ARISE_MINIMAL=1     skip heavy optional extras (prowler/scoutsuite/playwright browser)
#   ARISE_SKIP_GO=1     skip Go + Go tools (assume already on PATH)
#   ARISE_SKIP_PY=1     skip Python deps
#   ARISE_NO_BROWSER=1  skip the Playwright/Chromium browser download
#   GOPATH, GOBIN       respected if already set

# NOTE: intentionally NOT using `set -e`. This installer is designed to continue
# past optional-tool failures; we track and report them explicitly instead. We do
# enable pipefail + a soft ERR trap for diagnostics only.
set -o pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''   # no color when piped (e.g. Docker build logs)
fi
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC} $1"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Failure accounting — reported in the final summary.
FAILED_OPTIONAL=()
FAILED_CRITICAL=()
note_optional() { FAILED_OPTIONAL+=("$1"); log_warn "$1"; }
note_critical() { FAILED_CRITICAL+=("$1"); log_error "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# ─────────────────────────────────────────────────────────────────────────────
# Platform / privilege detection
# ─────────────────────────────────────────────────────────────────────────────
detect_platform() {
    OS="$(uname -s)"; ARCH="$(uname -m)"
    case "$OS" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="darwin" ;;
        *)      log_error "Unsupported OS: $OS"; exit 1 ;;
    esac
    case "$ARCH" in
        x86_64|amd64)  GOARCH="amd64" ;;
        aarch64|arm64) GOARCH="arm64" ;;
        armv7l|armv6l) GOARCH="armv6l" ;;
        *)             log_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    # Running inside a container?
    IS_DOCKER=0
    if [ -f /.dockerenv ] || grep -qaE '(docker|containerd|kubepods)' /proc/1/cgroup 2>/dev/null; then
        IS_DOCKER=1
    fi

    # Privilege: prefer running as root (Docker); otherwise use sudo if present.
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command_exists sudo; then
        SUDO="sudo"
    else
        SUDO=""
        log_warn "Not root and no sudo — system package installs may fail."
    fi

    # Package manager
    PKG_MGR=""
    for m in apt-get dnf yum pacman brew; do
        if command_exists "$m"; then
            case "$m" in apt-get) PKG_MGR="apt" ;; *) PKG_MGR="$m" ;; esac
            break
        fi
    done

    # Shell rc (best effort; Docker also gets a global /etc/profile.d file)
    USER_SHELL="$(basename "${SHELL:-/bin/bash}")"
    case "$USER_SHELL" in
        zsh)  SHELL_RC="$HOME/.zshrc" ;;
        fish) SHELL_RC="$HOME/.config/fish/config.fish" ;;
        *)    SHELL_RC="$HOME/.bashrc" ;;
    esac

    export DEBIAN_FRONTEND=noninteractive
    log_info "Platform: $PLATFORM/$GOARCH  Pkg: ${PKG_MGR:-none}  Docker: $IS_DOCKER  Root: $([ -z "$SUDO" ] && echo yes || echo no)"
}

# Persist an env line both globally (/etc/profile.d, if writable) and to the
# user's shell rc — so PATH works in Docker layers AND interactive shells.
persist_env() {
    local line="$1" marker="$2"
    # Global (root only) — makes PATH work in non-login Docker shells / layers.
    if [ -z "$SUDO" ]; then
        local global="/etc/profile.d/arise.sh"
        grep -qsF "$marker" "$global" 2>/dev/null || echo "$line" >> "$global" 2>/dev/null || true
    fi
    # Per-user rc — for interactive shells.
    touch "$SHELL_RC" 2>/dev/null || true
    grep -qsF "$marker" "$SHELL_RC" 2>/dev/null || echo "$line" >> "$SHELL_RC" 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# System packages
# ─────────────────────────────────────────────────────────────────────────────
install_core_utils() {
    log_step "Installing core system packages..."
    case "$PKG_MGR" in
        apt)
            $SUDO apt-get update -y || note_optional "apt-get update failed"
            # build tools + runtime libs + the CLI tools the pipeline shells out to
            $SUDO apt-get install -y --no-install-recommends \
                build-essential ca-certificates wget curl git jq unzip \
                python3 python3-pip python3-venv python3-dev \
                libpcap-dev nmap dnsutils sqlmap \
                || note_critical "core apt packages failed to install"
            ;;
        dnf|yum)
            $SUDO "$PKG_MGR" install -y \
                gcc gcc-c++ make ca-certificates wget curl git jq unzip \
                python3 python3-pip python3-devel \
                libpcap-devel nmap bind-utils \
                || note_critical "core $PKG_MGR packages failed to install"
            # sqlmap not always packaged on RHEL — pip fallback handled later
            ;;
        pacman)
            $SUDO pacman -Sy --noconfirm \
                base-devel ca-certificates wget curl git jq unzip \
                python python-pip libpcap nmap bind sqlmap \
                || note_critical "core pacman packages failed to install"
            ;;
        brew)
            brew install wget curl git jq libpcap nmap bind sqlmap python@3.12 2>/dev/null \
                || note_optional "some brew packages failed"
            ;;
        *)
            note_critical "No supported package manager found — install core tools manually."
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# Go toolchain
# ─────────────────────────────────────────────────────────────────────────────
_configure_go_env() {
    export GOROOT="${GOROOT:-/usr/local/go}"
    export GOPATH="${GOPATH:-$HOME/go}"
    export GOBIN="${GOBIN:-$GOPATH/bin}"
    export PATH="$GOROOT/bin:$GOBIN:$PATH"
    mkdir -p "$GOBIN" 2>/dev/null || true

    persist_env "export GOROOT=\"$GOROOT\"" "ARISE_GOROOT"
    persist_env "export GOPATH=\"\$HOME/go\"" "ARISE_GOPATH"
    persist_env 'export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"' "ARISE_GOPATH_PATH"
}

install_go() {
    [ "${ARISE_SKIP_GO:-0}" = "1" ] && { log_info "ARISE_SKIP_GO=1 — skipping Go"; _configure_go_env; return 0; }
    log_step "Installing Go (>= 1.21)..."

    if command_exists go; then
        local ver major minor
        ver=$(go version 2>/dev/null | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
        major=${ver%%.*}; minor=${ver##*.}
        if [ -n "$major" ] && [ "$major" -ge 1 ] && [ "${minor:-0}" -ge 21 ]; then
            log_info "Go $ver already sufficient"
            _configure_go_env
            return 0
        fi
        log_info "Go ${ver:-unknown} too old — upgrading"
    fi

    if [ "$PLATFORM" = "darwin" ] && [ "$PKG_MGR" = "brew" ]; then
        brew install go 2>/dev/null && { _configure_go_env; command_exists go && { log_info "Go: $(go version)"; return 0; }; }
    fi

    local latest tarball url tmp size
    latest=$(curl -fsSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -1)
    [ -z "$latest" ] && { latest="go1.23.4"; log_warn "Could not detect latest Go; using $latest"; }
    tarball="${latest}.${PLATFORM}-${GOARCH}.tar.gz"
    url="https://go.dev/dl/${tarball}"
    tmp="$(mktemp)"
    log_info "Downloading $url"
    if ! curl -fsSL "$url" -o "$tmp"; then
        rm -f "$tmp"; note_critical "Go download failed"; return 1
    fi
    size=$(wc -c < "$tmp" | tr -d ' ')
    if [ "${size:-0}" -lt 10000000 ]; then
        rm -f "$tmp"; note_critical "Go tarball too small ($size bytes)"; return 1
    fi
    $SUDO rm -rf /usr/local/go
    $SUDO tar -C /usr/local -xzf "$tmp" || { rm -f "$tmp"; note_critical "Go extract failed"; return 1; }
    rm -f "$tmp"
    _configure_go_env
    if command_exists go; then log_info "Go installed: $(go version)"; else note_critical "'go' not found after install"; fi
}

install_go_tools() {
    [ "${ARISE_SKIP_GO:-0}" = "1" ] && return 0
    command_exists go || { note_critical "Go missing — cannot install Go tools"; return 1; }
    log_step "Installing Go security tools..."
    export GO111MODULE=on CGO_ENABLED=0

    # nuclei MUST be v3 — the code uses -jsonl / -dast / -validate (v3 flags).
    local -a tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/jaeles-project/gospider@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        "github.com/trufflesecurity/trufflehog/v3@latest"
        "github.com/d3mondev/puredns/v2@latest"
    )
    local total=${#tools[@]} i=0 name
    for tool in "${tools[@]}"; do
        i=$((i+1))
        name="${tool##*/}"; name="${name%%@*}"; name="${name%%/*}"
        printf "  [%d/%d] %-16s\n" "$i" "$total" "$name"
        go install -v "$tool" >/dev/null 2>&1 || note_optional "go tool '$name' failed to install"
    done

    # naabu needs CGO + libpcap
    log_info "Installing naabu (CGO/libpcap)..."
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest >/dev/null 2>&1 \
        || note_optional "naabu install failed (need libpcap-dev)"

    # Make Go-installed tools available system-wide inside containers, so the
    # pipeline finds them even in a non-login shell.
    if [ -z "$SUDO" ] && [ -d "$GOBIN" ]; then
        for b in "$GOBIN"/*; do
            [ -x "$b" ] || continue
            ln -sf "$b" "/usr/local/bin/$(basename "$b")" 2>/dev/null || true
        done
    fi

    local -a critical=(subfinder httpx nuclei katana)
    local miss=0
    for t in "${critical[@]}"; do command_exists "$t" || { note_optional "critical Go tool missing: $t"; miss=$((miss+1)); }; done
    [ "$miss" -eq 0 ] && log_info "Core Go tools verified"
}

# ─────────────────────────────────────────────────────────────────────────────
# Python dependencies
# ─────────────────────────────────────────────────────────────────────────────
_pip_flags() {
    # PEP-668 (Debian/Ubuntu externally-managed) needs --break-system-packages.
    local flags=("--disable-pip-version-check")
    [ "$IS_DOCKER" = "1" ] && flags+=("--no-cache-dir")
    if python3 -m pip install --help 2>&1 | grep -q "break-system-packages"; then
        flags+=("--break-system-packages")
    fi
    if [ -n "$SUDO" ] || [ "$(id -u)" -ne 0 ]; then
        # non-root: install into the user site unless we're actually root
        [ "$(id -u)" -ne 0 ] && flags+=("--user")
    fi
    echo "${flags[@]}"
}

pip_install() {
    # shellcheck disable=SC2046
    PIP_ROOT_USER_ACTION=ignore python3 -m pip install $(_pip_flags) "$@"
}

_configure_python_path() {
    # Ensure user-site + common script dirs are on PATH (dirsearch, wafw00f, etc.)
    local usb; usb="$(python3 -m site --user-base 2>/dev/null)/bin"
    export PATH="$usb:$HOME/.local/bin:$PATH"
    persist_env 'export PATH="$HOME/.local/bin:$PATH"' "ARISE_PY_LOCALBIN"
}

install_python_deps() {
    [ "${ARISE_SKIP_PY:-0}" = "1" ] && { log_info "ARISE_SKIP_PY=1 — skipping Python deps"; return 0; }
    log_step "Installing Python dependencies..."
    _configure_python_path
    pip_install --upgrade pip setuptools wheel >/dev/null 2>&1 || log_warn "pip self-upgrade skipped"

    # CORE — the dashboard + pipeline WILL NOT run without these.
    local -a core=(
        flask flask-cors werkzeug waitress # web dashboard (waitress = prod WSGI server for non-loopback hosts)
        apscheduler                        # recurring-scan scheduler (arise_jobs)
        cryptography                       # secret vault / session signing
        requests urllib3 certifi           # HTTP everywhere
        python-dateutil pytz               # time handling
        beautifulsoup4 lxml                # HTML/XML parsing
        PyYAML python-dotenv validators    # config / .env / input validation
        colorama tqdm rich                 # CLI output
        tldextract phonenumbers            # domain + PII (phone) analysis
        websocket-client                   # wss_agent / protocol_exec
        pypdf                              # report/PDF handling
        numpy scikit-learn                 # arise_nlp vectorize/similarity
        dirsearch                          # content discovery (invoked as a CLI too)
        scapy                              # low-level packet ops
        anthropic                          # AI analyst (Claude provider)
        dnstwist                           # OSINT: brand/typosquat monitoring (Module 18)
    )
    if ! pip_install "${core[@]}"; then
        note_critical "core Python dependencies failed — retrying individually"
        for pkg in "${core[@]}"; do
            pip_install "$pkg" >/dev/null 2>&1 || note_critical "python core dep failed: $pkg"
        done
    fi

    # wafw00f is used by the WAF-detection module (CLI + import)
    pip_install wafw00f >/dev/null 2>&1 || note_optional "wafw00f install failed (WAF detection degraded)"

    # OPTIONAL heavy cloud auditors — skipped in minimal mode.
    if [ "${ARISE_MINIMAL:-0}" != "1" ]; then
        pip_install s3scanner  >/dev/null 2>&1 || note_optional "s3scanner failed (cloud bucket enum degraded)"
        pip_install prowler    >/dev/null 2>&1 || note_optional "prowler failed (cloud compliance audit unavailable)"
        pip_install scoutsuite >/dev/null 2>&1 || note_optional "scoutsuite failed (multi-cloud audit unavailable)"
    else
        log_info "ARISE_MINIMAL=1 — skipping prowler/scoutsuite/s3scanner"
    fi

    log_info "Python dependencies installed"
}

install_playwright() {
    [ "${ARISE_SKIP_PY:-0}" = "1" ] && return 0
    log_step "Installing Playwright (headless browser automation)..."
    pip_install playwright >/dev/null 2>&1 || { note_optional "playwright pip install failed (input discovery / WSS degraded)"; return 0; }

    if [ "${ARISE_NO_BROWSER:-0}" = "1" ] || [ "${ARISE_MINIMAL:-0}" = "1" ]; then
        log_info "Skipping Chromium download (ARISE_NO_BROWSER/ARISE_MINIMAL); a system chromium will be used if present"
        return 0
    fi
    # --with-deps needs root/apt; fall back to a plain browser download otherwise.
    if [ -z "$SUDO" ] && [ "$PKG_MGR" = "apt" ]; then
        python3 -m playwright install --with-deps chromium >/dev/null 2>&1 \
            || python3 -m playwright install chromium >/dev/null 2>&1 \
            || note_optional "playwright chromium install failed"
    else
        python3 -m playwright install chromium >/dev/null 2>&1 \
            || note_optional "playwright chromium install failed (install a system chromium instead)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Additional security tools (source builds + git-cloned python tools)
# ─────────────────────────────────────────────────────────────────────────────
# Where launcher shims + built binaries go. Prefer a PATH dir writable now.
_bin_dir() {
    if [ -z "$SUDO" ] && [ -w /usr/local/bin ]; then echo "/usr/local/bin";
    else mkdir -p "${GOBIN:-$HOME/go/bin}" 2>/dev/null; echo "${GOBIN:-$HOME/go/bin}"; fi
}

install_security_tools() {
    log_step "Installing additional security tools..."
    local bindir; bindir="$(_bin_dir)"

    # massdns (used by puredns for fast DNS brute force)
    if ! command_exists massdns; then
        log_info "Building massdns from source..."
        local tmp; tmp=$(mktemp -d)
        if git clone --depth 1 --quiet https://github.com/blechschmidt/massdns.git "$tmp" 2>/dev/null \
            && make -C "$tmp" >/dev/null 2>&1; then
            $SUDO cp "$tmp/bin/massdns" /usr/local/bin/ 2>/dev/null \
                || cp "$tmp/bin/massdns" "$bindir/" 2>/dev/null \
                || note_optional "massdns copy failed"
            command_exists massdns && log_info "massdns installed"
        else
            note_optional "massdns build failed (puredns brute force degraded)"
        fi
        rm -rf "$tmp"
    fi

    # sqlmap fallback if the OS package wasn't available (RHEL/older distros)
    if ! command_exists sqlmap; then
        log_info "sqlmap not packaged — installing via pip"
        pip_install sqlmap >/dev/null 2>&1 || note_optional "sqlmap install failed (SQLi module unavailable)"
    fi

    pip_install tldextract >/dev/null 2>&1 || true
}

install_extended_tools() {
    log_step "Installing extended verification tools (git-cloned)..."
    local rdir="${ARISE_RECON_DIR:-$HOME/recon}"; mkdir -p "$rdir"
    local bindir; bindir="$(_bin_dir)"; mkdir -p "$bindir"

    _clone_tool() {
        local url="$1" dir="$2" entry="$3" cmd="$4"
        if [ ! -d "$rdir/$dir/.git" ]; then
            git clone --depth 1 --quiet "$url" "$rdir/$dir" 2>/dev/null || { note_optional "$cmd clone failed"; return; }
        fi
        [ -f "$rdir/$dir/requirements.txt" ] && pip_install -r "$rdir/$dir/requirements.txt" >/dev/null 2>&1 || true
        cat > "$bindir/$cmd" <<EOF
#!/usr/bin/env bash
exec python3 "$rdir/$dir/$entry" "\$@"
EOF
        chmod +x "$bindir/$cmd"
        log_info "  $cmd installed"
    }

    _clone_tool https://github.com/ticarpi/jwt_tool.git        jwt_tool  jwt_tool.py jwt_tool
    _clone_tool https://github.com/vladimirbutuzov/SSTImap.git SSTImap   sstimap.py  sstimap
    _clone_tool https://github.com/dolevf/graphw00f.git        graphw00f main.py     graphw00f
    _clone_tool https://github.com/defparam/smuggler.git       smuggler  smuggler.py smuggler

    # JWT weak-secret wordlist
    if [ ! -f "$rdir/lists/jwt-secrets.txt" ]; then
        mkdir -p "$rdir/lists"
        curl -fsSL https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list \
            -o "$rdir/lists/jwt-secrets.txt" 2>/dev/null || note_optional "jwt-secrets wordlist download failed"
    fi
}

install_cloud_enum() {
    [ "${ARISE_MINIMAL:-0}" = "1" ] && { log_info "ARISE_MINIMAL=1 — skipping cloud_enum"; return 0; }
    log_step "Installing cloud_enum..."
    local rdir="${ARISE_RECON_DIR:-$HOME/recon}"
    local ce_dir="$rdir/cloud_enum"
    if [ ! -d "$ce_dir/.git" ]; then
        git clone --depth 1 --quiet https://github.com/initstring/cloud_enum.git "$ce_dir" 2>/dev/null \
            || { note_optional "cloud_enum clone failed"; return; }
    fi
    pip_install -r "$ce_dir/requirements.txt" >/dev/null 2>&1 || true
    local bindir; bindir="$(_bin_dir)"
    cat > "$bindir/cloud_enum" <<EOF
#!/usr/bin/env bash
exec python3 "$ce_dir/cloud_enum.py" "\$@"
EOF
    chmod +x "$bindir/cloud_enum"
    log_info "cloud_enum installed"
}

# ─────────────────────────────────────────────────────────────────────────────
# Wordlists + nuclei templates
# ─────────────────────────────────────────────────────────────────────────────
setup_directories() {
    log_step "Setting up wordlists + nuclei templates..."
    local rdir="${ARISE_RECON_DIR:-$HOME/recon}"
    mkdir -p "$rdir/lists"

    _dl() { local url="$1" dest="$2"; [ -f "$dest" ] && return 0
            curl -fsSL "$url" -o "$dest" 2>/dev/null || note_optional "download failed: $(basename "$dest")"; }

    # Also seed the project-local lists/ dir the pipeline uses at runtime.
    local proj_lists="$SCRIPT_DIR/lists"; mkdir -p "$proj_lists"
    for d in "$rdir/lists" "$proj_lists"; do
        _dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" "$d/subdomains-top1million-110000.txt"
        _dl "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" "$d/resolvers.txt"
        _dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" "$d/common.txt"
        _dl "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" "$d/LFI-Jhaddix.txt"
    done

    # Nuclei templates — let the binary manage its own default template dir.
    if command_exists nuclei; then
        log_info "Updating nuclei templates..."
        nuclei -update-templates -silent >/dev/null 2>&1 || note_optional "nuclei template update failed (will retry at first run)"
    fi

    # gf patterns
    mkdir -p "$HOME/.gf"
    if [ -z "$(ls -A "$HOME/.gf" 2>/dev/null)" ]; then
        local tmp; tmp="$(mktemp -d)"
        if git clone --depth 1 --quiet https://github.com/1ndianl33t/Gf-Patterns "$tmp" 2>/dev/null; then
            cp "$tmp"/*.json "$HOME/.gf/" 2>/dev/null || true
        fi
        rm -rf "$tmp"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# macOS quarantine cleanup (no-op on Linux/Docker)
# ─────────────────────────────────────────────────────────────────────────────
fix_macos_xattr() {
    [ "$PLATFORM" = "darwin" ] || return 0
    command_exists xattr || return 0
    log_step "Clearing macOS extended attributes..."
    local src_dirs=(. recon ports discovery tls api_security api_security/api_logic \
        offensive offensive/legacy evidence cloud intel ai history core tools)
    for d in "${src_dirs[@]}"; do
        [ -d "$SCRIPT_DIR/$d" ] || continue
        find "$SCRIPT_DIR/$d" -maxdepth 1 -name "*.py" -type f -exec xattr -c {} \; 2>/dev/null || true
    done
    log_info "macOS extended attributes cleared"
}

# ─────────────────────────────────────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────────────────────────────────────
verify_install() {
    log_step "Verifying installation..."
    echo ""
    local -a bins=(
        "go:Go compiler" "python3:Python 3" "nmap:Network scanning" "dig:DNS lookups"
        "sqlmap:SQL injection" "subfinder:Subdomain enum" "httpx:HTTP probing"
        "nuclei:Vuln scanning" "naabu:Port scanning" "katana:Crawling"
        "dnsx:DNS toolkit" "ffuf:Fuzzing" "gau:URL harvest" "trufflehog:Secret scan"
        "dalfox:XSS" "crlfuzz:CRLF" "gf:Pattern grep" "massdns:DNS brute"
        "dirsearch:Dir brute" "wafw00f:WAF detect"
    )
    local pass=0 fail=0 cmd desc
    for c in "${bins[@]}"; do
        cmd="${c%%:*}"; desc="${c##*:}"
        if command_exists "$cmd"; then printf "  ${GREEN}✓${NC} %-16s %s\n" "$cmd" "$desc"; pass=$((pass+1))
        else printf "  ${RED}✗${NC} %-16s %s\n" "$cmd" "$desc"; fail=$((fail+1)); fi
    done

    echo ""
    log_step "Verifying the app's Python imports actually resolve..."
    if python3 - <<'PY' 2>/dev/null
import importlib, sys
core = ["flask", "flask_cors", "waitress", "apscheduler", "cryptography",
        "requests", "bs4", "yaml", "dotenv", "sklearn", "numpy",
        "phonenumbers", "websocket", "dateutil", "anthropic"]
missing = [m for m in core if importlib.util.find_spec(m) is None]
if missing:
    print("MISSING:" + ",".join(missing)); sys.exit(1)
print("ok")
PY
    then log_info "Core Python imports OK"
    else note_critical "some core Python imports are missing (dashboard may not boot)"; fi

    echo ""
    log_info "Binary check: $pass present, $fail missing"
}

print_summary() {
    echo ""
    log_info "========================================"
    if [ "${#FAILED_CRITICAL[@]}" -gt 0 ]; then
        log_error "Setup completed WITH CRITICAL FAILURES:"
        for f in "${FAILED_CRITICAL[@]}"; do echo "    - $f"; done
    else
        log_info "ARISE Setup Complete!"
    fi
    if [ "${#FAILED_OPTIONAL[@]}" -gt 0 ]; then
        log_warn "Optional components skipped/failed (features degrade, not fatal):"
        for f in "${FAILED_OPTIONAL[@]}"; do echo "    - $f"; done
    fi
    log_info "========================================"
    [ "$IS_DOCKER" = "1" ] || log_info "Reload your shell:  source $SHELL_RC"
    log_info "Start the dashboard:  python3 dashboard.py"
    log_info "Run a scan:           bash easm-pipeline.sh <target_domain>"
    log_info "========================================"
    # Fail the script (non-zero) only on CRITICAL failures — so Docker builds stop.
    [ "${#FAILED_CRITICAL[@]}" -eq 0 ]
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
main() {
    echo "========================================"
    echo "  ARISE Setup — Cross-Platform"
    echo "  Summon Every Hidden Exposure."
    echo "========================================"
    detect_platform
    fix_macos_xattr
    install_core_utils
    install_go
    install_go_tools
    install_security_tools
    install_python_deps
    install_playwright
    install_cloud_enum
    install_extended_tools
    setup_directories
    verify_install
    print_summary
}

main "$@"
