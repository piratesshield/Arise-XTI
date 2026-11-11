###############################################################################
#  AriseXTI — Production Docker Image
#  Multi-stage: Go tools → Python app → slim runtime
###############################################################################

# ── Stage 1: Build Go security tools ────────────────────────────────────────
FROM golang:1.26-bookworm AS go-builder

ENV CGO_ENABLED=0 GO111MODULE=on GOTOOLCHAIN=auto

# ProjectDiscovery suite
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# Community tools
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install -v github.com/d3mondev/puredns/v2@latest

# Trufflehog (has replace directives, must build from source)
RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && \
    cd /tmp/trufflehog && go build -o /go/bin/trufflehog . && \
    rm -rf /tmp/trufflehog

# naabu needs CGO + libpcap
RUN apt-get update -qq && apt-get install -y --no-install-recommends libpcap-dev && \
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    rm -rf /var/lib/apt/lists/*

# Build massdns from source
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns && \
    make -C /tmp/massdns && \
    cp /tmp/massdns/bin/massdns /go/bin/ && \
    rm -rf /tmp/massdns

# ── Stage 2: Python dependencies ────────────────────────────────────────────
FROM python:3.12-slim-bookworm AS py-builder

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt && \
    pip install --no-cache-dir --prefix=/install wafw00f

# ── Stage 3: Runtime image ──────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

LABEL maintainer="piratesshield" \
      description="AriseXTI — External Threat Intelligence & Attack Surface Management"

# System deps the app + tools need at runtime
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nmap dnsutils curl wget jq unzip git ca-certificates \
        libpcap0.8 sqlmap chromium && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy Go tools from builder
COPY --from=go-builder /go/bin/ /usr/local/bin/

# Copy Python packages from builder
COPY --from=py-builder /install /usr/local

# Update nuclei templates
RUN nuclei -update-templates -silent 2>/dev/null || true

# gf patterns
RUN mkdir -p /root/.gf && \
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf && \
    cp /tmp/gf/*.json /root/.gf/ 2>/dev/null || true && \
    rm -rf /tmp/gf

# Clone extended tools
RUN mkdir -p /opt/tools && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool && \
    git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/tools/SSTImap && \
    git clone --depth 1 https://github.com/dolevf/graphw00f.git /opt/tools/graphw00f && \
    git clone --depth 1 https://github.com/defparam/smuggler.git /opt/tools/smuggler && \
    printf '#!/bin/bash\nexec python3 /opt/tools/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    printf '#!/bin/bash\nexec python3 /opt/tools/SSTImap/sstimap.py "$@"\n' > /usr/local/bin/sstimap && \
    printf '#!/bin/bash\nexec python3 /opt/tools/graphw00f/main.py "$@"\n' > /usr/local/bin/graphw00f && \
    printf '#!/bin/bash\nexec python3 /opt/tools/smuggler/smuggler.py "$@"\n' > /usr/local/bin/smuggler && \
    chmod +x /usr/local/bin/jwt_tool /usr/local/bin/sstimap /usr/local/bin/graphw00f /usr/local/bin/smuggler && \
    rm -rf /opt/tools/*/.git

# Download essential wordlists
RUN mkdir -p /app/lists && \
    curl -fsSL -o /app/lists/subdomains-top1million-110000.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt && \
    curl -fsSL -o /app/lists/resolvers.txt \
        https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt && \
    curl -fsSL -o /app/lists/common.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    curl -fsSL -o /app/lists/LFI-Jhaddix.txt \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt && \
    mkdir -p /opt/tools/jwt-secrets && \
    curl -fsSL -o /opt/tools/jwt-secrets/jwt.secrets.list \
        https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list || true

# Set Playwright to use system Chromium
ENV PLAYWRIGHT_BROWSERS_PATH=0 \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# ── Application code ───────────────────────────────────────────────────────
WORKDIR /app
COPY . /app/

# Ensure lists from build context merge with downloaded ones
RUN cp -n /app/lists/* /app/lists/ 2>/dev/null || true

# Create runtime directories
RUN mkdir -p /app/scans /app/logs /app/outputs /app/jobs /app/state

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${ARISE_DASHBOARD_PORT:-5059}/api/health || exit 1

# Default env
ENV ARISE_DASHBOARD_PORT=5059 \
    ARISE_DASHBOARD_HOST=0.0.0.0

EXPOSE 5059

# Volumes for persistent data
VOLUME ["/app/scans", "/app/logs", "/app/state"]

# Default: run the dashboard
CMD ["python3", "dashboard.py"]
