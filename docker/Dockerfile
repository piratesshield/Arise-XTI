# ARISE EASM — full product image.
# Build context is the REPO ROOT (source is COPIED in, never moved):
#   docker build -f docker/Dockerfile -t arise:local .
#
# The image installs everything via the project's own setup.sh, so the container
# gets the exact toolchain the pipeline expects (Go tools, nmap, sqlmap, nuclei
# v3, playwright/chromium, and the full Python dependency set).

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.title="ARISE EASM" \
      org.opencontainers.image.description="Summon Every Hidden Exposure — EASM dashboard + pipeline" \
      org.opencontainers.image.source="https://github.com/"

# Runtime + build environment. Admin creds and port are baked as requested for a
# local deploy (override with -e at run time for anything non-local).
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    DEBIAN_FRONTEND=noninteractive \
    GOROOT=/usr/local/go \
    GOPATH=/root/go \
    PATH=/usr/local/go/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin \
    ARISE_DASHBOARD_PORT=3333 \
    ARISE_ADMIN_USER=admin \
    ARISE_ADMIN_PASSWORD=admin

WORKDIR /app

# Tiny bootstrap so setup.sh can run; setup.sh installs the full toolchain itself.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl bash git \
    && rm -rf /var/lib/apt/lists/*

# Copy the source (respects .dockerignore — no scans/, no secrets).
COPY . /app

# Provision the whole product. setup.sh exits non-zero ONLY on critical failures
# (core apt + core python), so the build fails loudly if the dashboard couldn't
# possibly boot, but tolerates optional-tool hiccups.
RUN chmod +x setup.sh docker/entrypoint.sh \
    && bash setup.sh

EXPOSE 3333

# Persist vault keys + scans across restarts when a volume is mounted here.
VOLUME ["/app/scans"]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["dashboard"]
