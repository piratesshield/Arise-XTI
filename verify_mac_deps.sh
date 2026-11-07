#!/usr/bin/env bash
# verify_mac_deps.sh
# macOS Dependency Verifier & Installer for ARISE

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}========================================${NC}"
echo -e "${BOLD}${BLUE}  ARISE Dependency Verifier (macOS)     ${NC}"
echo -e "${BOLD}${BLUE}========================================${NC}"

# Counters
TOTAL_TOOLS=0
FOUND_TOOLS=0
TOTAL_PY=0
FOUND_PY=0

# Helper function to check command line tools
check_tool() {
    local name=$1
    local category=$2
    ((TOTAL_TOOLS++))
    if command -v "$name" &> /dev/null; then
        local path
        path=$(command -v "$name")
        echo -e "  [${GREEN}OK${NC}] Tool ${BOLD}$name${NC} ($category) -> $path"
        ((FOUND_TOOLS++))
        return 0
    else
        echo -e "  [${RED}MISSING${NC}] Tool ${BOLD}$name${NC} ($category)"
        return 1
    fi
}

# Helper function to check python package
check_py_pkg() {
    local pip_name=$1
    local import_name=$2
    local category=$3
    ((TOTAL_PY++))
    if python3 -c "import $import_name" &> /dev/null; then
        local version
        version=$(python3 -c "import $import_name; print(getattr($import_name, '__version__', 'unknown'))" 2>/dev/null)
        echo -e "  [${GREEN}OK${NC}] Python ${BOLD}$pip_name${NC} ($category) -> v$version"
        ((FOUND_PY++))
        return 0
    else
        echo -e "  [${RED}MISSING${NC}] Python ${BOLD}$pip_name${NC} ($category)"
        return 1
    fi
}

echo -e "\n${BOLD}${CYAN}--- Checking System & Platform Tools ---${NC}"
check_tool "go" "Platform"
check_tool "git" "Platform"
check_tool "curl" "Platform"
check_tool "jq" "Platform"
check_tool "bash" "Platform"
check_tool "nmap" "Port Scanning"
check_tool "massdns" "DNS Resolution"

echo -e "\n${BOLD}${CYAN}--- Checking Go Recon & Vulnerability Tools ---${NC}"
check_tool "subfinder" "Recon"
check_tool "puredns" "Recon"
check_tool "dnsx" "Recon"
check_tool "anew" "Recon"
check_tool "naabu" "Port Scanning"
check_tool "httpx" "HTTP Probing"
check_tool "katana" "Crawling"
check_tool "gospider" "Crawling"
check_tool "gau" "Crawling"
check_tool "ffuf" "Fuzzing"
check_tool "gf" "Pattern Matching"
check_tool "nuclei" "Vulnerability"
check_tool "dalfox" "XSS Scanner"
check_tool "sqlmap" "SQLi Scanner"
check_tool "trufflehog" "Secret Scanner"
check_tool "wafw00f" "WAF Fingerprinting"
check_tool "interactsh-client" "OOB Verification"
check_tool "crlfuzz" "CRLF Injection"

echo -e "\n${BOLD}${CYAN}--- Checking Python Packages ---${NC}"
check_py_pkg "requests" "requests" "HTTP/API"
check_py_pkg "urllib3" "urllib3" "HTTP/API"
check_py_pkg "pyOpenSSL" "OpenSSL" "Security"
check_py_pkg "cryptography" "cryptography" "Security"
check_py_pkg "scapy" "scapy" "Security"
check_py_pkg "beautifulsoup4" "bs4" "Web Scraping"
check_py_pkg "lxml" "lxml" "Web Scraping"
check_py_pkg "html5lib" "html5lib" "Web Scraping"
check_py_pkg "pandas" "pandas" "Data"
check_py_pkg "python-dateutil" "dateutil" "Data"
check_py_pkg "pytz" "pytz" "Data"
check_py_pkg "tabulate" "tabulate" "Data"
check_py_pkg "matplotlib" "matplotlib" "Visualization"
check_py_pkg "colorama" "colorama" "CLI"
check_py_pkg "tqdm" "tqdm" "CLI"
check_py_pkg "rich" "rich" "CLI"
check_py_pkg "PyYAML" "yaml" "Config"
check_py_pkg "python-dotenv" "dotenv" "Config"
check_py_pkg "flask" "flask" "Dashboard"
check_py_pkg "flask-cors" "flask_cors" "Dashboard"
check_py_pkg "anthropic" "anthropic" "AI"
check_py_pkg "scikit-learn" "sklearn" "AI"
check_py_pkg "python-magic" "magic" "Utilities"
check_py_pkg "filetype" "filetype" "Utilities"
check_py_pkg "validators" "validators" "Utilities"
check_py_pkg "dirsearch" "dirsearch" "Utilities"
check_py_pkg "boto3" "boto3" "Cloud/AWS"
check_py_pkg "botocore" "botocore" "Cloud/AWS"
check_py_pkg "s3transfer" "s3transfer" "Cloud/AWS"
check_py_pkg "jmespath" "jmespath" "Cloud/AWS"
check_py_pkg "gevent" "gevent" "Concurrency"
check_py_pkg "greenlet" "greenlet" "Concurrency"
check_py_pkg "pydantic" "pydantic" "Validation"
check_py_pkg "pydantic-settings" "pydantic_settings" "Validation"
check_py_pkg "pymongo" "pymongo" "Storage"
check_py_pkg "tinydb" "tinydb" "Storage"
check_py_pkg "slack-sdk" "slack_sdk" "Notifications"

echo -e "\n${BOLD}${BLUE}========================================${NC}"
echo -e "${BOLD}${BLUE}  Readiness Summary                     ${NC}"
echo -e "${BOLD}${BLUE}========================================${NC}"
echo -e "  External Tools:  ${BOLD}$FOUND_TOOLS / $TOTAL_TOOLS${NC}"
echo -e "  Python Packages: ${BOLD}$FOUND_PY / $TOTAL_PY${NC}"

# Calculate percentages
TOOL_PCT=$(( FOUND_TOOLS * 100 / TOTAL_TOOLS ))
PY_PCT=$(( FOUND_PY * 100 / TOTAL_PY ))

if [ "$FOUND_TOOLS" -eq "$TOTAL_TOOLS" ]; then
    echo -e "  Tools Status:    ${GREEN}All installed ($TOOL_PCT%)${NC}"
else
    echo -e "  Tools Status:    ${RED}Missing some tools ($TOOL_PCT%)${NC}"
fi

if [ "$FOUND_PY" -eq "$TOTAL_PY" ]; then
    echo -e "  Python Status:   ${GREEN}All installed ($PY_PCT%)${NC}"
else
    echo -e "  Python Status:   ${YELLOW}Missing some packages ($PY_PCT%)${NC}"
fi

echo -e "${BOLD}${BLUE}========================================${NC}"

if [ "$FOUND_PY" -lt "$TOTAL_PY" ]; then
    echo -e "\n${BOLD}${YELLOW}Would you like to install the missing Python packages? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo -e "\n${BOLD}${CYAN}Installing missing Python packages...${NC}"
        python3 -m pip install boto3 botocore s3transfer jmespath gevent greenlet slack-sdk pymongo tinydb python-magic filetype pydantic-settings matplotlib html5lib
    else
        echo -e "\nSkip installing Python packages."
    fi
fi
