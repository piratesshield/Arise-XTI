#!/usr/bin/env python3
"""ARISE Cloud Asset Intelligence — Module 17b.

External, unauthenticated cloud attack-surface classification.

This engine performs no cloud-API calls and needs no credentials. It ingests
the recon data the earlier pipeline modules already collected on disk —

    * 03b_dns_discovery/dns_all_records.json   (CNAME / A record chains)
    * 03b_dns_discovery/cloud_storage_targets.json
    * 04_http_discovery/http_confirmed.json     (httpx tech/webserver/cdn/cname)
    * 14_port_scan/all_ports.jsonl              (open ports)
    * 02_subdomain_enum/all_subdomains.txt      (naming heuristics)
    * manifest.json                             (per-host resolved/cdn/waf/ports)

— and classifies every discovered asset into the cloud service taxonomy below,
attaching to each hit: the provider, the region/hosted-zone, a risk rating, the
concrete evidence that triggered it, a black-box **enumeration recipe**, and an
**exploitation playbook** describing how an attacker would probe/abuse it (for
authorised external attack-surface testing).

Taxonomy (16 categories):
    provider · storage · cdn · load_balancer · api_gateway · serverless ·
    kubernetes · registry · database · cache · queue · object_website ·
    app_service · bastion · vpn · cloud_dns

Output:
    17_cloud_exposure/cloud_asset_map.jsonl     (one finding per line)
    17_cloud_exposure/cloud_asset_summary.json  (counts + matrix)

Design notes
------------
The single richest signal is the **CNAME / A-record chain** — a subdomain whose
CNAME resolves to `kong-public-alb-...us-west-1.elb.amazonaws.com` reveals an
AWS ALB, a Kong API gateway, and the us-west-1 region in one string, with zero
packets sent to the target. Port data corroborates managed-DB/cache/queue/k8s
exposure. Naming heuristics (vpn.*, bastion.*, k8s.*) are last-resort, low
confidence, and only ever *raise* — never fabricate — a finding.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
    _HAS_REQUESTS = True
except ImportError:                                   # pragma: no cover
    _HAS_REQUESTS = False
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Taxonomy + risk model
# ---------------------------------------------------------------------------

CATEGORIES = [
    "provider", "compute", "storage", "origin_exposure", "cdn", "load_balancer",
    "api_gateway", "serverless", "kubernetes", "registry", "database", "cache",
    "queue", "object_website", "app_service", "bastion", "vpn", "cloud_dns",
]

CATEGORY_LABELS = {
    "provider": "Cloud Provider",
    # Split out from the old catch-all "provider" bucket: EC2/GCE/Azure-VM
    # compute signatures were previously tagged "provider" alongside the
    # unrelated origin-exposure finding below, so a real EC2 asset (a handful
    # of hits on a typical scan) was buried under dozens of "exposed origin"
    # rows sharing the same category — neither was individually filterable.
    "compute": "Compute (EC2 / GCE / Azure VM)",
    "origin_exposure": "Exposed Origin (CDN/WAF Bypass)",
    "storage": "Object Storage",
    "cdn": "CDN / Edge",
    "load_balancer": "Load Balancer",
    "api_gateway": "API Gateway",
    "serverless": "Serverless / Functions",
    "kubernetes": "Kubernetes",
    "registry": "Container Registry",
    "database": "Managed Database",
    "cache": "Managed Cache",
    "queue": "Message Queue",
    "object_website": "Static Website Hosting",
    "app_service": "App Service / PaaS",
    "bastion": "Bastion / SSH Gateway",
    "vpn": "VPN Portal",
    "cloud_dns": "Cloud DNS",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------------------
# Region / hosted-zone extraction
# ---------------------------------------------------------------------------

# Generic AWS region token, e.g. us-east-1, ap-south-1, eu-central-2, us-gov-west-1
_AWS_REGION_RE = re.compile(
    r"\b((?:us|eu|ap|ca|sa|me|af|il|cn)-(?:gov-)?"
    r"(?:east|west|south|southeast|northeast|central|north)-[1-9])\b",
    re.IGNORECASE,
)
# Azure region tokens embedded in FQDNs, e.g. eastus2, westeurope, centralindia
_AZURE_REGION_RE = re.compile(
    r"\b(eastus2?|westus[23]?|centralus|northcentralus|southcentralus|westcentralus"
    r"|northeurope|westeurope|uksouth|ukwest|francecentral|germanywestcentral"
    r"|switzerlandnorth|norwayeast|swedencentral|centralindia|southindia|westindia"
    r"|eastasia|southeastasia|japaneast|japanwest|koreacentral|australiaeast"
    r"|australiasoutheast|brazilsouth|canadacentral|southafricanorth|uaenorth)\b",
    re.IGNORECASE,
)
# GCP region tokens, e.g. us-central1, asia-south1, europe-west1
_GCP_REGION_RE = re.compile(
    r"\b((?:us|europe|asia|australia|northamerica|southamerica|me)-"
    r"(?:central|east|west|south|southeast|northeast|north)[1-9])\b",
    re.IGNORECASE,
)


def extract_region(text: str) -> str:
    """Pull the first cloud region token out of any FQDN / URL / blob."""
    if not text:
        return ""
    for rx in (_AWS_REGION_RE, _GCP_REGION_RE, _AZURE_REGION_RE):
        m = rx.search(text)
        if m:
            return m.group(1).lower()
    return ""


# ---------------------------------------------------------------------------
# Fingerprint database — the core intelligence
# ---------------------------------------------------------------------------

@dataclass
class Signature:
    category: str
    service: str
    provider: str
    risk: str
    severity: str
    # regexes matched against any candidate hostname / CNAME / A-FQDN / tech blob
    patterns: List[str]
    enumerate: str
    attack: str
    tools: List[str] = field(default_factory=list)
    takeover_prone: bool = False        # dangling CNAME here => takeover candidate
    port_hints: List[int] = field(default_factory=list)

    def __post_init__(self):
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def match(self, text: str) -> Optional[str]:
        for rx in self._compiled:
            m = rx.search(text)
            if m:
                return m.group(0)
        return None


# Ordered so the most specific service wins first within a category.
SIGNATURES: List[Signature] = [

    # ─── STORAGE ────────────────────────────────────────────────────────────
    Signature(
        "storage", "AWS S3", "aws", "Public data / bucket exposure", "high",
        [r"[.\-/]s3[.\-]", r"\.s3\.amazonaws\.com", r"\.s3-[a-z0-9-]+\.amazonaws\.com",
         r"\.s3\.[a-z0-9-]+\.amazonaws\.com", r"s3-accelerate\.amazonaws\.com"],
        "aws s3 ls s3://<bucket> --no-sign-request  |  "
        "curl -s 'https://<bucket>.s3.amazonaws.com/?list-type=2'  |  "
        "s3scanner scan -b <bucket>",
        "Enumerate ACL for public LIST/READ/WRITE. If NoSuchBucket on a live "
        "CNAME → bucket takeover (re-create bucket, serve content). Check for "
        "readable backups/.env/DB dumps; test anonymous PutObject for defacement "
        "and supply-chain (upload malicious JS served from the origin).",
        ["s3scanner", "cloud_enum", "awscli"], takeover_prone=True,
    ),
    Signature(
        "storage", "Azure Blob", "azure", "Public data / container exposure", "high",
        [r"\.blob\.core\.windows\.net"],
        "az storage blob list --account-name <acct> --container-name <c> --auth-mode login  |  "
        "curl -s 'https://<acct>.blob.core.windows.net/<container>?restype=container&comp=list'",
        "Test anonymous container listing (?comp=list). Dangling blob CNAME → "
        "takeover by claiming the storage account name. Look for SAS tokens in "
        "JS/HTML granting broader access.",
        ["cloud_enum", "azure-cli"], takeover_prone=True,
    ),
    Signature(
        "storage", "Google Cloud Storage", "gcp", "Public data / bucket exposure", "high",
        [r"storage\.googleapis\.com", r"\.storage\.googleapis\.com",
         r"\.storage\.cloud\.google\.com"],
        "gsutil ls -r gs://<bucket>  |  "
        "curl -s 'https://storage.googleapis.com/<bucket>?list-type=2'  |  "
        "curl -s 'https://www.googleapis.com/storage/v1/b/<bucket>/o'",
        "Check allUsers/allAuthenticatedUsers IAM on the bucket. Test "
        "storage.objects.list / storage.objects.get anonymously. Misconfigured "
        "bucket IAM often allows public read of PII exports.",
        ["cloud_enum", "gsutil"], takeover_prone=True,
    ),
    Signature(
        "storage", "DigitalOcean Spaces", "digitalocean", "Public data exposure", "high",
        [r"\.digitaloceanspaces\.com"],
        "s3cmd --host=<region>.digitaloceanspaces.com ls s3://<space>",
        "Spaces speaks the S3 API — test anonymous LIST/GET, same playbook as S3.",
        ["s3scanner"], takeover_prone=True,
    ),
    Signature(
        "storage", "Cloudflare R2", "cloudflare", "Public data exposure", "medium",
        [r"\.r2\.cloudflarestorage\.com", r"\.r2\.dev"],
        "curl -s 'https://<account>.r2.cloudflarestorage.com/<bucket>'",
        "Public r2.dev buckets serve objects anonymously — enumerate object keys "
        "leaked in HTML/JS.",
        [],
    ),
    Signature(
        "storage", "Backblaze B2 / Wasabi", "other", "Public data exposure", "medium",
        [r"\.backblazeb2\.com", r"\.wasabisys\.com"],
        "s3cmd --host=<endpoint> ls s3://<bucket>",
        "S3-compatible — anonymous LIST/GET enumeration.",
        ["s3scanner"],
    ),
    Signature(
        "storage", "MinIO (self-hosted)", "other", "Public data exposure", "medium",
        [r"\bminio\b"],
        "mc alias set t http://<host>:9000 '' '' --api s3v4; mc ls t  |  "
        "curl -s http://<host>:9000/minio/health/live",
        "Check for default minioadmin:minioadmin console (:9001), anonymous bucket "
        "policy, and the unauthenticated /minio/health & metrics endpoints.",
        [], port_hints=[9000, 9001],
    ),

    # ─── CDN ────────────────────────────────────────────────────────────────
    Signature(
        "cdn", "Amazon CloudFront", "aws", "Origin exposure / CDN bypass", "medium",
        [r"\.cloudfront\.net", r"amazon cloudfront"],
        "dig +short <host>  |  curl -sI https://<host> (look for X-Amz-Cf-Id, "
        "X-Amz-Cf-Pop, Via: CloudFront)  |  find origin: censys/shodan same "
        "TLS-cert hash, or historical DNS (SecurityTrails).",
        "Bypass the CDN/WAF by hitting the origin IP directly with a spoofed Host "
        "header. Dangling CloudFront alias (CNAME to a deleted distribution) → "
        "takeover. Test cache poisoning via unkeyed headers.",
        ["httpx"], takeover_prone=True,
    ),
    Signature(
        "cdn", "Azure CDN / Front Door", "azure", "Origin exposure", "medium",
        [r"\.azureedge\.net", r"\.azurefd\.net"],
        "curl -sI https://<host> (X-Azure-Ref, X-Cache)  |  resolve origin via "
        "cert transparency + historical DNS.",
        "Dangling azureedge/azurefd endpoint → takeover. Locate and hit the "
        "origin directly to bypass WAF policy applied only at the edge.",
        ["httpx"], takeover_prone=True,
    ),
    Signature(
        "cdn", "Fastly", "fastly", "Origin exposure", "medium",
        [r"\.fastly\.net", r"\.fastlylb\.net"],
        "curl -sI https://<host> (X-Served-By, X-Cache, Fastly-Debug)",
        "Find origin to bypass edge WAF. Historic Fastly shared-IP host-header "
        "confusion; test cache poisoning.",
        ["httpx"],
    ),
    Signature(
        "cdn", "Akamai", "akamai", "Origin exposure", "medium",
        [r"\.akamaiedge\.net", r"\.akamai\.net", r"\.akamaized\.net",
         r"\.edgesuite\.net", r"\.edgekey\.net", r"akamaighost"],
        "curl -sI https://<host> (X-Akamai-*, server: AkamaiGHost)  |  origin "
        "discovery via cert transparency.",
        "Origin-IP discovery to bypass Akamai WAF/Kona. Test for "
        "X-Akamai-Debug / pragma header info-leak.",
        ["httpx"],
    ),
    Signature(
        "cdn", "Cloudflare", "cloudflare", "Origin exposure", "medium",
        [r"\.cloudflare\.net", r"\bcloudflare\b"],
        "curl -sI https://<host> (CF-Ray, server: cloudflare)  |  origin via "
        "crimeflare / historical DNS / SSL cert SAN / SPF records.",
        "Discover the real origin IP (crt.sh, historical A records, mail servers) "
        "and hit it directly to bypass Cloudflare WAF & rate-limits.",
        ["httpx"],
    ),

    # ─── LOAD BALANCER ──────────────────────────────────────────────────────
    Signature(
        "load_balancer", "AWS ELB/ALB/NLB", "aws", "Internet-facing service", "low",
        [r"\.elb\.amazonaws\.com", r"\.elb\.[a-z0-9-]+\.amazonaws\.com",
         r"[a-z0-9-]+\.[a-z0-9-]+\.elb\.amazonaws\.com", r"awselb"],
        "dig +short <host>  |  curl -sI https://<host> (AWSALB/AWSALBCORS cookie, "
        "server: awselb/2.0)  |  nmap -sV -p443 <ip>.",
        "ALB by itself is expected, but: enumerate host-based routing rules by "
        "fuzzing Host headers; a mis-scoped listener rule can expose internal "
        "vhosts. Dangling ELB CNAME → takeover. Check for open non-TLS listeners.",
        ["httpx", "nmap"], takeover_prone=True,
    ),
    Signature(
        "load_balancer", "AWS Global Accelerator", "aws", "Internet-facing service", "low",
        [r"\.awsglobalaccelerator\.com"],
        "dig +short <host>  |  the two anycast IPs front backend endpoints.",
        "Map the backend endpoint groups; GA forwards raw TCP/UDP so backend "
        "services (not just HTTP) may be reachable.",
        ["httpx"],
    ),
    Signature(
        "load_balancer", "Azure Load Balancer / Traffic Manager", "azure",
        "Internet-facing service", "low",
        [r"\.cloudapp\.azure\.com", r"\.trafficmanager\.net"],
        "dig +short <host>  |  Traffic Manager returns the active endpoint FQDN.",
        "Traffic Manager profile enumeration reveals all backend endpoints incl. "
        "staging. Dangling trafficmanager.net endpoint → takeover.",
        ["httpx"], takeover_prone=True,
    ),

    # ─── API GATEWAY ────────────────────────────────────────────────────────
    Signature(
        "api_gateway", "AWS API Gateway", "aws", "Public API surface", "medium",
        [r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com"],
        "curl -s https://<id>.execute-api.<region>.amazonaws.com/<stage>/  |  "
        "enumerate stages (dev/test/prod/v1) and resources; check "
        "X-Amzn-RequestId / x-amz-apigw-id headers.",
        "Brute stage & resource names; look for authorizer bypass (missing "
        "AWS_IAM/Cognito on some routes), verbose IAM error leaks, and the "
        "default {api-id} endpoint left enabled alongside the custom domain. "
        "Feed discovered routes to the API Intelligence Engine.",
        ["apisec.py", "ffuf"],
    ),
    Signature(
        "api_gateway", "AWS AppSync (GraphQL)", "aws", "Public GraphQL API", "medium",
        [r"\.appsync-api\.[a-z0-9-]+\.amazonaws\.com", r"\.appsync-realtime-api\."],
        "curl -s -X POST https://<id>.appsync-api.<region>.amazonaws.com/graphql "
        "-d '{\"query\":\"{__schema{types{name}}}\"}'",
        "Run GraphQL introspection; enumerate queries/mutations. Test API-key-only "
        "auth (x-api-key) and IAM-signed vs. unauthenticated access.",
        ["apisec.py"],
    ),
    Signature(
        "api_gateway", "Azure API Management", "azure", "Public API surface", "medium",
        [r"\.azure-api\.net"],
        "curl -sI https://<host> (Ocp-Apim-*)  |  GET /  and probe common APIM "
        "paths; check the developer portal at /developer.",
        "Test subscription-key enforcement per product; some operations are "
        "left open. Enumerate the APIM developer portal for API definitions.",
        ["apisec.py"],
    ),
    Signature(
        "api_gateway", "GCP API Gateway", "gcp", "Public API surface", "medium",
        [r"\.gateway\.dev", r"\.apigateway\.[a-z0-9-]+\.cloud\.goog"],
        "curl -s https://<gw>.gateway.dev/  |  enumerate configured routes.",
        "Probe for routes missing an API key/JWT requirement; inspect the "
        "OpenAPI config exposure.",
        ["apisec.py"],
    ),
    Signature(
        "api_gateway", "Kong Gateway", "other", "Public API surface", "medium",
        [r"\bkong[.\-]", r"kong-[a-z0-9-]*(alb|proxy|public|gateway)"],
        "curl -sI https://<host> (Via: kong/*, X-Kong-*)  |  probe :8001 admin "
        "API  |  curl http://<host>:8001/routes  http://<host>:8001/services.",
        "The prize is the Kong Admin API (:8001/:8444) — if internet-exposed it "
        "lists every route/service/consumer and lets you add routes or strip "
        "auth plugins. Test for the unauthenticated admin API and default creds.",
        ["apisec.py", "nmap"], port_hints=[8001, 8444],
    ),

    # ─── SERVERLESS ─────────────────────────────────────────────────────────
    Signature(
        "serverless", "AWS Lambda Function URL", "aws", "Unauthenticated function", "high",
        [r"\.lambda-url\.[a-z0-9-]+\.on\.aws"],
        "curl -s https://<id>.lambda-url.<region>.on.aws/  |  fuzz methods & "
        "query/body params.",
        "Function URLs with AuthType=NONE run the function for anyone. Test SSRF "
        "(read the 169.254.169.254 credentials via the function), command/proto "
        "injection into event fields, and IAM over-privilege of the exec role.",
        ["apisec.py"],
    ),
    Signature(
        "serverless", "GCP Cloud Run", "gcp", "Unauthenticated service", "high",
        [r"\.run\.app", r"\.a\.run\.app"],
        "curl -s https://<svc>-<hash>-<region>.run.app/  |  probe common paths.",
        "allUsers-invoker Cloud Run services are fully public — enumerate the app, "
        "test metadata SSRF (metadata.google.internal), and mine the container for "
        "GOOGLE_APPLICATION_CREDENTIALS / service-account token.",
        ["apisec.py"],
    ),
    Signature(
        "serverless", "GCP Cloud Functions", "gcp", "Unauthenticated function", "high",
        [r"\.cloudfunctions\.net", r"[a-z0-9-]+-[a-z0-9-]+\.cloudfunctions\.net"],
        "curl -s https://<region>-<project>.cloudfunctions.net/<fn>",
        "allUsers-invoker functions run unauthenticated. Test event-field "
        "injection and metadata SSRF; enumerate sibling functions by name.",
        ["apisec.py"],
    ),
    Signature(
        "serverless", "Cloudflare Workers", "cloudflare", "Public function", "medium",
        [r"\.workers\.dev"],
        "curl -s https://<name>.<sub>.workers.dev/",
        "Enumerate routes; Workers often proxy to internal APIs — test for SSRF "
        "and secret leakage via env bindings reflected in responses.",
        ["apisec.py"],
    ),
    Signature(
        "serverless", "Vercel / Netlify Functions", "other", "Public function", "low",
        [r"\.vercel\.app", r"\.netlify\.app"],
        "curl -s https://<app>/api/  |  enumerate /api/* serverless routes.",
        "Probe /api/* handlers for injection and leaked build-time env vars. "
        "Dangling vercel/netlify subdomain → takeover.",
        ["apisec.py"], takeover_prone=True,
    ),

    # ─── KUBERNETES ─────────────────────────────────────────────────────────
    Signature(
        "kubernetes", "AWS EKS", "aws", "Cluster control-plane exposure", "high",
        [r"\.eks\.amazonaws\.com", r"\.gr[0-9]\.[a-z0-9-]+\.eks\.amazonaws\.com"],
        "curl -sk https://<eks-endpoint>/version  |  "
        "curl -sk https://<endpoint>/api/v1/namespaces (expect 401/403 if locked).",
        "Public EKS API servers accept anonymous /version & /healthz. Test "
        "system:anonymous RBAC (some clusters bind it to view), leaked "
        "kubeconfig, and the AWS IAM authenticator webhook.",
        ["kube-hunter", "nmap"], port_hints=[6443, 443],
    ),
    Signature(
        "kubernetes", "Azure AKS", "azure", "Cluster control-plane exposure", "high",
        [r"\.azmk8s\.io", r"\.hcp\.[a-z0-9-]+\.azmk8s\.io"],
        "curl -sk https://<aks-fqdn>:443/version",
        "AKS API servers reachable publicly unless an authorized-IP range is set. "
        "Test anonymous RBAC and leaked cluster admin kubeconfig.",
        ["kube-hunter"], port_hints=[443],
    ),
    Signature(
        "kubernetes", "Exposed Kubernetes API/kubelet", "other",
        "Cluster control-plane exposure", "critical",
        [r"\bk8s\b", r"\bkube(rnetes)?\b"],
        "nmap -p6443,10250,10255,2379,2380 <ip>  |  "
        "curl -sk https://<ip>:6443/version  |  curl -sk https://<ip>:10250/pods "
        "(kubelet — read-only or exec).",
        "6443 = API server (test anonymous), 10250 = kubelet (unauth /pods, /run "
        "→ RCE in pods), 10255 = read-only kubelet, 2379/2380 = etcd (full secret "
        "store, often no auth). etcd exposure = game over.",
        ["kube-hunter", "nmap"], port_hints=[6443, 10250, 10255, 2379, 2380],
    ),

    # ─── CONTAINER REGISTRY ─────────────────────────────────────────────────
    Signature(
        "registry", "AWS ECR", "aws", "Container image leakage", "high",
        [r"\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com", r"public\.ecr\.aws"],
        "aws ecr describe-repositories  |  for PUBLIC: "
        "curl -s https://public.ecr.aws/v2/<alias>/<repo>/tags/list",
        "ECR Public galleries are anonymously pullable — pull images and scan "
        "layers for hard-coded secrets, private source, and .git dirs. Private "
        "ECR with a permissive repo policy may allow cross-account pull.",
        ["trivy", "dive"],
    ),
    Signature(
        "registry", "Azure Container Registry", "azure", "Container image leakage", "high",
        [r"\.azurecr\.io"],
        "curl -s https://<acr>.azurecr.io/v2/_catalog  |  "
        "az acr repository list -n <acr>",
        "Test anonymous pull (some ACRs enable it). /v2/_catalog with no auth = "
        "full repo list. Pull & scan images for secrets and internal code.",
        ["trivy"],
    ),
    Signature(
        "registry", "Google Artifact/Container Registry", "gcp",
        "Container image leakage", "high",
        [r"\.pkg\.dev", r"[a-z0-9-]+-docker\.pkg\.dev", r"gcr\.io", r"\.gcr\.io"],
        "curl -s https://<region>-docker.pkg.dev/v2/_catalog  |  "
        "curl -s https://gcr.io/v2/<project>/<image>/tags/list",
        "allUsers-reader GAR/GCR repos are public — enumerate tags, pull, scan "
        "layers for GCP service-account keys and source.",
        ["trivy"],
    ),
    Signature(
        "registry", "Self-hosted registry (Harbor/Quay/Docker)", "other",
        "Container image leakage", "medium",
        [r"\b(harbor|quay|registry)\b"],
        "curl -s https://<host>/v2/_catalog  |  curl -s https://<host>/api/v2.0/projects",
        "Docker Registry v2 API /v2/_catalog often unauthenticated. Harbor: test "
        "default admin/Harbor12345, public projects. Pull & scan for secrets.",
        ["trivy"], port_hints=[5000],
    ),

    # ─── MANAGED DATABASE ───────────────────────────────────────────────────
    Signature(
        "database", "AWS RDS / Aurora", "aws", "Public database exposure", "critical",
        [r"\.rds\.amazonaws\.com", r"\.[a-z0-9]+\.[a-z0-9-]+\.rds\.amazonaws\.com"],
        "nmap -sV -p3306,5432,1433,1521 <rds-endpoint>  |  attempt anon/default "
        "login with mysql/psql/sqsh.",
        "Publicly-accessible RDS is critical. Test default & weak creds, and any "
        "creds harvested from exposed .env/S3. An open 3306/5432 with a valid "
        "cred = full data exfiltration.",
        ["nmap", "sqlmap"], port_hints=[3306, 5432, 1433, 1521],
    ),
    Signature(
        "database", "AWS Redshift / DocumentDB / Neptune", "aws",
        "Public database exposure", "critical",
        [r"\.redshift\.amazonaws\.com", r"\.docdb\.amazonaws\.com",
         r"\.neptune\.amazonaws\.com"],
        "nmap -sV -p5439,27017,8182 <endpoint>",
        "Redshift 5439, DocumentDB 27017, Neptune 8182 exposed publicly → test "
        "default/harvested creds and unauthenticated access.",
        ["nmap"], port_hints=[5439, 27017, 8182],
    ),
    Signature(
        "database", "Azure SQL / Cosmos DB", "azure", "Public database exposure", "critical",
        [r"\.database\.windows\.net", r"\.documents\.azure\.com",
         r"\.cosmos\.azure\.com", r"\.mysql\.database\.azure\.com",
         r"\.postgres\.database\.azure\.com"],
        "nmap -sV -p1433,3306,5432 <host>  |  Cosmos: probe REST API with "
        "leaked master/resource keys.",
        "Azure SQL firewall set to 0.0.0.0 (Allow Azure services / all) exposes "
        "1433. Cosmos DB keys leaked in JS grant full DB access via REST. Test "
        "harvested connection strings.",
        ["nmap"], port_hints=[1433, 3306, 5432],
    ),
    Signature(
        "database", "MongoDB Atlas", "other", "Public database exposure", "high",
        [r"\.mongodb\.net"],
        "nmap -sV -p27017 <host>  |  mongosh 'mongodb+srv://<host>' --username ...",
        "Atlas with 0.0.0.0/0 network access + weak/leaked creds = full read. "
        "Test SRV enumeration and harvested connection strings.",
        ["nmap"], port_hints=[27017],
    ),

    # ─── MANAGED CACHE ──────────────────────────────────────────────────────
    Signature(
        "cache", "AWS ElastiCache (Redis/Memcached)", "aws", "Internet cache exposure",
        "critical",
        [r"\.cache\.amazonaws\.com"],
        "nmap -sV -p6379,11211 <endpoint>  |  redis-cli -h <host> INFO  |  "
        "echo 'stats' | nc <host> 11211.",
        "Unauthenticated Redis (6379) → read/write all keys, often session tokens "
        "and cache-stored PII; CONFIG SET can write a webshell/SSH key on some "
        "builds. Memcached (11211) → dump keys + UDP amplification abuse.",
        ["nmap", "redis-cli"], port_hints=[6379, 11211],
    ),
    Signature(
        "cache", "Azure Cache for Redis", "azure", "Internet cache exposure", "critical",
        [r"\.redis\.cache\.windows\.net"],
        "nmap -sV -p6379,6380 <host>  |  redis-cli -h <host> -p 6380 --tls -a <key>",
        "Non-TLS 6379 may be enabled; test the access key (often leaked in "
        "app config / JS). Dump keys for sessions & secrets.",
        ["nmap"], port_hints=[6379, 6380],
    ),
    Signature(
        "cache", "Exposed Redis/Memcached (self-hosted)", "other",
        "Internet cache exposure", "critical",
        [r"\bredis\b", r"\bmemcached\b"],
        "redis-cli -h <host> ping  |  redis-cli -h <host> INFO  |  "
        "nc <host> 11211 <<< stats",
        "Unauth Redis → KEYS *, CONFIG GET, and RCE via CONFIG SET dir/dbfilename "
        "to write cron/authorized_keys/webshell. Classic critical.",
        ["nmap", "redis-cli"], port_hints=[6379, 11211],
    ),

    # ─── MESSAGE QUEUE ──────────────────────────────────────────────────────
    Signature(
        "queue", "AWS SQS / SNS", "aws", "Queue / topic exposure", "medium",
        [r"sqs\.[a-z0-9-]+\.amazonaws\.com", r"sns\.[a-z0-9-]+\.amazonaws\.com"],
        "aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy",
        "A wildcard SQS/SNS resource policy lets anyone SendMessage/ReceiveMessage "
        "or Subscribe — test message injection & exfiltration of queued data.",
        ["awscli"],
    ),
    Signature(
        "queue", "Azure Service Bus / Event Hub", "azure", "Queue exposure", "medium",
        [r"\.servicebus\.windows\.net"],
        "Probe with any leaked SAS connection string; check shared-access policy scope.",
        "Leaked SAS tokens (often in mobile apps / JS) grant Send/Listen. "
        "Enumerate queues/topics and test message injection.",
        [],
    ),
    Signature(
        "queue", "AWS MSK / Kafka / RabbitMQ", "other", "Broker exposure", "high",
        [r"\.kafka\.[a-z0-9-]+\.amazonaws\.com", r"\b(kafka|rabbitmq|amqp)\b"],
        "nmap -sV -p9092,9094,5672,15672 <host>  |  RabbitMQ mgmt UI :15672.",
        "Open Kafka 9092 with no SASL = read/write all topics. RabbitMQ :15672 "
        "test guest/guest; :5672 AMQP anonymous. Message injection & data theft.",
        ["nmap"], port_hints=[9092, 9094, 5672, 15672],
    ),

    # ─── STATIC WEBSITE HOSTING ─────────────────────────────────────────────
    Signature(
        "object_website", "AWS S3 Website", "aws", "Static site / data leakage", "medium",
        [r"\.s3-website[.\-][a-z0-9-]+\.amazonaws\.com", r"\.s3-website\."],
        "curl -sI http://<bucket>.s3-website-<region>.amazonaws.com/",
        "S3 website endpoints have no HTTPS and reveal the bucket name → pivot to "
        "the S3 REST endpoint for ACL/LIST testing. Dangling → takeover.",
        ["s3scanner"], takeover_prone=True,
    ),
    Signature(
        "object_website", "Azure Static Website", "azure", "Static site / data leakage",
        "medium", [r"\.web\.core\.windows\.net", r"\.z[0-9]+\.web\.core\.windows\.net"],
        "curl -sI https://<acct>.z<n>.web.core.windows.net/",
        "Reveals the storage account → test the sibling blob endpoint "
        "(<acct>.blob.core.windows.net) for anonymous container listing.",
        [], takeover_prone=True,
    ),
    Signature(
        "object_website", "Firebase Hosting", "gcp", "Static site / data leakage",
        "medium", [r"\.web\.app", r"\.firebaseapp\.com"],
        "curl -s https://<app>.firebaseapp.com/__/firebase/init.json  |  "
        "test RTDB: curl https://<app>.firebaseio.com/.json",
        "init.json leaks the Firebase config → test the Realtime DB `/.json` for "
        "public read/write, and Firestore rules for open access. Dangling → takeover.",
        [], takeover_prone=True,
    ),

    # ─── APP SERVICE / PaaS ─────────────────────────────────────────────────
    Signature(
        "app_service", "AWS Elastic Beanstalk", "aws", "Public application", "low",
        [r"\.elasticbeanstalk\.com", r"\.[a-z0-9-]+\.elasticbeanstalk\.com"],
        "curl -sI https://<env>.<region>.elasticbeanstalk.com/",
        "Predictable EB bucket: elasticbeanstalk-<region>-<accountid> — the "
        "account ID leaks here. Dangling EB env CNAME → takeover.",
        ["httpx"], takeover_prone=True,
    ),
    Signature(
        "app_service", "Azure App Service / Functions", "azure", "Public application", "low",
        [r"\.azurewebsites\.net"],
        "curl -sI https://<app>.azurewebsites.net/  |  probe /.env, "
        "/.git, and the Kudu console at <app>.scm.azurewebsites.net.",
        "The SCM/Kudu site (<app>.scm.azurewebsites.net) is a huge target — if "
        "reachable it gives filesystem + env vars. Dangling azurewebsites → "
        "takeover. x-functions-key in JS = function invoke.",
        ["httpx"], takeover_prone=True,
    ),
    Signature(
        "app_service", "GCP App Engine", "gcp", "Public application", "low",
        [r"\.appspot\.com", r"\.[a-z0-9-]+\.r\.appspot\.com"],
        "curl -sI https://<project>.appspot.com/  |  probe /_ah/ admin endpoints.",
        "Test the /_ah/ App Engine admin & health endpoints, default service "
        "enumeration, and metadata SSRF from any app-side request feature.",
        ["httpx"],
    ),
    Signature(
        "app_service", "Heroku", "other", "Public application", "low",
        [r"\.herokuapp\.com"],
        "curl -sI https://<app>.herokuapp.com/",
        "Dangling herokuapp CNAME (No such app) → takeover. Probe for leaked "
        "config vars reflected in errors.",
        ["httpx"], takeover_prone=True,
    ),

    # ─── BASTION / SSH ──────────────────────────────────────────────────────
    Signature(
        "bastion", "Bastion / SSH gateway", "other", "Administrative access", "medium",
        [r"\bbastion\b", r"\bjump(box|host|server)?\b", r"^ssh[.\-]", r"[.\-]ssh[.\-]"],
        "nmap -sV -p22,2222 <host>  |  ssh -v <host> (banner, auth methods, "
        "host-key age).",
        "Fingerprint SSH version for CVEs; enumerate auth methods (password vs "
        "key). Password auth on an internet bastion = spray/brute target. Check "
        "for exposed 2FA-less jump host and old OpenSSH (regreSSHion CVE-2024-6387).",
        ["nmap"], port_hints=[22, 2222],
    ),

    # ─── VPN PORTAL ─────────────────────────────────────────────────────────
    Signature(
        "vpn", "SSL VPN portal", "other", "Remote access gateway", "medium",
        [r"\bvpn\b", r"\bsslvpn\b", r"\bglobalprotect\b", r"\banyconnect\b",
         r"\bpulsesecure\b", r"\bfortigate\b", r"\bfortinet\b"],
        "curl -sk https://<host>/remote/login (Fortinet)  |  "
        "/global-protect/login.esp (Palo Alto)  |  /+CSCOE+/logon.html (Cisco)  |  "
        "/dana-na/ (Ivanti)  |  /vpn/index.html (Citrix).",
        "Fingerprint the VPN vendor/version via login-page paths & favicon hash, "
        "then map to CVEs (Fortinet CVE-2024-21762, Ivanti CVE-2024-21887, "
        "Citrix Bleed CVE-2023-4966, PAN GlobalProtect CVE-2024-3400). These are "
        "the #1 initial-access vector — prioritise version disclosure.",
        ["nmap", "nuclei"], port_hints=[443, 10443, 4433],
    ),

    # ─── CLOUD DNS ──────────────────────────────────────────────────────────
    Signature(
        "cloud_dns", "AWS Route 53", "aws", "Asset mapping / zone exposure", "info",
        [r"\bawsdns-[0-9]+\b", r"\.awsdns-[0-9]+\."],
        "dig NS <domain>  |  attempt AXFR: dig AXFR <domain> @<ns>.",
        "Route53 rarely allows AXFR, but NS records confirm the AWS account "
        "hosts DNS → pivot to other AWS assets. Check for dangling delegation "
        "(NS to a hosted zone that no longer exists) → zone takeover.",
        ["dnsrecon"], takeover_prone=True,
    ),
    Signature(
        "cloud_dns", "Azure DNS", "azure", "Asset mapping", "info",
        [r"\.azure-dns\.(com|net|org|info)"],
        "dig NS <domain>",
        "Confirms Azure-hosted DNS. Dangling Azure DNS zone delegation → "
        "subdomain/zone takeover by claiming the zone in another subscription.",
        ["dnsrecon"], takeover_prone=True,
    ),
    Signature(
        "cloud_dns", "Google Cloud DNS", "gcp", "Asset mapping", "info",
        [r"ns-cloud-[a-z0-9]+\.googledomains\.com"],
        "dig NS <domain>",
        "Confirms GCP-hosted DNS. Enumerate sibling zones; check delegation "
        "hygiene.",
        ["dnsrecon"],
    ),

    # ─── PROVIDER (rDNS / generic compute) — lowest priority, catch-all ──────
    Signature(
        "compute", "AWS EC2 / compute", "aws", "Cloud footprint", "info",
        [r"\.compute\.amazonaws\.com", r"\.compute-1\.amazonaws\.com",
         r"ec2-[0-9-]+\.[a-z0-9-]*\.?amazonaws\.com"],
        "dig -x <ip>  |  whois <ip> (AS16509/AS14618)  |  nmap -sV <ip>.",
        "Direct EC2 exposure — full port scan for non-web services, check IMDSv1 "
        "reachability via any SSRF, and security-group over-permissiveness.",
        ["nmap"],
    ),
    Signature(
        "compute", "GCP Compute", "gcp", "Cloud footprint", "info",
        [r"\.bc\.googleusercontent\.com", r"\.googleusercontent\.com"],
        "dig -x <ip>  |  whois <ip> (AS15169)  |  nmap -sV <ip>.",
        "Direct GCE exposure — port scan, test metadata SSRF, firewall rules.",
        ["nmap"],
    ),
    Signature(
        "compute", "Azure Compute", "azure", "Cloud footprint", "info",
        [r"\.cloudapp\.net"],
        "dig -x <ip>  |  whois <ip> (AS8075)  |  nmap -sV <ip>.",
        "Direct Azure VM exposure — port scan, NSG review, IMDS SSRF test.",
        ["nmap"],
    ),
]


# ---------------------------------------------------------------------------
# Port → managed-service risk map (corroborating / standalone signal)
# ---------------------------------------------------------------------------

SENSITIVE_PORTS: Dict[int, Tuple[str, str, str, str]] = {
    # port: (category, service, severity, note)
    3306:  ("database", "MySQL / RDS / Aurora", "critical", "MySQL wire protocol"),
    5432:  ("database", "PostgreSQL / RDS", "critical", "PostgreSQL wire protocol"),
    1433:  ("database", "MSSQL / Azure SQL", "critical", "MSSQL / TDS"),
    1521:  ("database", "Oracle DB", "critical", "Oracle TNS listener"),
    5439:  ("database", "AWS Redshift", "critical", "Redshift"),
    27017: ("database", "MongoDB", "critical", "MongoDB wire protocol"),
    27018: ("database", "MongoDB (shard)", "critical", "MongoDB shard"),
    9200:  ("database", "Elasticsearch / OpenSearch", "critical", "ES/OpenSearch HTTP"),
    9300:  ("database", "Elasticsearch (transport)", "high", "ES transport"),
    5984:  ("database", "CouchDB", "high", "CouchDB HTTP"),
    8182:  ("database", "AWS Neptune", "high", "Neptune Gremlin"),
    6379:  ("cache", "Redis / ElastiCache", "critical", "Redis (often no auth)"),
    6380:  ("cache", "Redis TLS / Azure Cache", "high", "Redis over TLS"),
    11211: ("cache", "Memcached / ElastiCache", "critical", "Memcached (no auth, amplification)"),
    9092:  ("queue", "Kafka / MSK", "high", "Kafka broker"),
    9094:  ("queue", "Kafka (TLS)", "high", "Kafka TLS"),
    5672:  ("queue", "RabbitMQ / AMQP", "high", "AMQP broker"),
    15672: ("queue", "RabbitMQ mgmt UI", "high", "RabbitMQ management (guest/guest)"),
    6443:  ("kubernetes", "Kubernetes API server", "critical", "kube-apiserver"),
    10250: ("kubernetes", "Kubelet API", "critical", "kubelet (RCE via /run)"),
    10255: ("kubernetes", "Kubelet read-only", "high", "read-only kubelet"),
    2379:  ("kubernetes", "etcd (client)", "critical", "etcd — full secret store"),
    2380:  ("kubernetes", "etcd (peer)", "high", "etcd peer"),
    2375:  ("kubernetes", "Docker API (plain)", "critical", "Docker daemon — RCE"),
    2376:  ("kubernetes", "Docker API (TLS)", "high", "Docker daemon TLS"),
    5000:  ("registry", "Docker Registry", "medium", "registry v2 API"),
    8500:  ("kubernetes", "Consul", "high", "Consul HTTP API"),
    5601:  ("database", "Kibana", "high", "Kibana dashboard"),
    22:    ("bastion", "SSH", "low", "SSH — bastion/jump candidate"),
    2222:  ("bastion", "SSH (alt)", "low", "alt SSH"),
    3389:  ("bastion", "RDP", "medium", "Windows RDP"),
    9000:  ("storage", "MinIO", "medium", "MinIO API"),
    9001:  ("storage", "MinIO Console", "medium", "MinIO console"),
}


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class CloudFinding:
    host: str
    category: str
    category_label: str
    service: str
    provider: str
    risk: str
    severity: str
    region: str
    evidence: str
    matched: str
    enumerate: str
    attack: str
    tools: List[str]
    source: str                 # dns | httpx | ports | naming
    takeover_candidate: bool = False
    ip: str = ""
    port: Optional[int] = None
    confidence: str = "medium"  # high (FQDN/port) | medium | low (naming only)
    # W1 unified exposure ladder shared with cloud_storage_enum:
    #   referenced        — name/heuristic only, existence unconfirmed
    #   exists            — FQDN/port reachable, auth/anon state unknown
    #   anon_accessible   — confirmed reachable AND unauthenticated
    #   sensitive_confirmed — confirmed unauth AND sensitive (secret store/RCE)
    exposure_state: str = "exists"
    probe_result: str = ""      # active-probe outcome, when --active is used

    def key(self) -> str:
        return f"{self.host}|{self.category}|{self.service}"


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class CloudAssetClassifier:
    def __init__(self, scan_dir: Path, active: bool = False, verbose: bool = False):
        self.scan_dir = Path(scan_dir)
        self.active = active
        self.verbose = verbose
        self.findings: Dict[str, CloudFinding] = {}
        # host -> {hostnames:set, tech:str, ip:str, cdn:bool, waf:str, ports:set,
        #          status:int, cnames:set, takeover_hint:bool}
        self.assets: Dict[str, dict] = {}
        self._resolve_cache: Dict[str, bool] = {}   # fqdn -> resolves?
        self._dns_zones_emitted: Set[Tuple[str, str, str]] = set()
        self._origin_ips_emitted: Set[str] = set()   # W3: dedup origin exposure
        self._ptr_map: Dict[str, List[str]] = {}     # ip -> [reverse-dns fqdns]
        if active and _HAS_REQUESTS:
            # Active probes hit services by raw IP with the wrong TLS SNI on
            # purpose; silence the noisy per-request warning.
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore
            except Exception:
                pass

    # -- logging ----------------------------------------------------------
    def log(self, *a):
        if self.verbose:
            print("[cloud-intel]", *a, file=sys.stderr)

    # -- ingest -----------------------------------------------------------
    def _load_json(self, rel: str):
        p = self.scan_dir / rel
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(errors="ignore"))
        except Exception as e:
            self.log(f"failed to parse {rel}: {e}")
            return None

    def _asset(self, host: str) -> dict:
        host = host.strip().rstrip(".").lower()
        if host not in self.assets:
            self.assets[host] = {
                "hostnames": set(), "cnames": set(), "tech": "", "ip": "",
                "ips": set(), "cdn": False, "waf": "", "ports": set(),
                "status": None, "takeover_hint": False,
            }
        return self.assets[host]

    def ingest(self):
        self._ingest_manifest()
        self._ingest_dns_records()
        self._ingest_cloud_storage_targets()
        self._ingest_httpx()
        self._ingest_ports()
        self._ingest_subdomains()
        self._ingest_ptr_records()
        self._apply_ptr_records()
        self.log(f"assets assembled: {len(self.assets)}")

    def _ingest_ptr_records(self):
        """Reverse-DNS (PTR) reveals the cloud provider + region even when a host
        resolves to a bare IP — e.g. 13.235.201.63 →
        ec2-13-235-201-63.ap-south-1.compute.amazonaws.com. Read from the DNS
        resolution module's IP annotations and results."""
        for rel in ("03_dns_resolution/ip_annotations.json",
                    "03_dns_resolution/dns_results.json"):
            p = self.scan_dir / rel
            if not p.exists():
                continue
            for line in p.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                ip = str(e.get("host", "")).strip()
                ptrs = e.get("ptr") or []
                if _is_ip(ip) and ptrs:
                    fqdns = [str(x).strip().rstrip(".").lower()
                             for x in ptrs if str(x).strip()]
                    if fqdns:
                        self._ptr_map.setdefault(ip, [])
                        for f in fqdns:
                            if f not in self._ptr_map[ip]:
                                self._ptr_map[ip].append(f)

    def _apply_ptr_records(self):
        """Fold each asset's reverse-DNS names into its searchable hostname set so
        the signature engine can fingerprint provider/region from the PTR."""
        if not self._ptr_map:
            return
        for a in self.assets.values():
            ips = set(a.get("ips") or set())
            if a.get("ip"):
                ips.add(a["ip"])
            for ip in ips:
                for fqdn in self._ptr_map.get(ip, []):
                    a["hostnames"].add(fqdn)

    def _ingest_manifest(self):
        man = self._load_json("manifest.json")
        if not man or "hosts" not in man:
            return
        for host, h in man["hosts"].items():
            a = self._asset(host)
            a["hostnames"].add(host.lower())
            if h.get("ip"):
                a["ip"] = a["ip"] or h["ip"]
                if _is_ip(h["ip"]):
                    a["ips"].add(h["ip"])
            a["cdn"] = a["cdn"] or bool(h.get("cdn"))
            if h.get("waf_vendor"):
                a["waf"] = h["waf_vendor"]
            for p in (h.get("ports_open") or []):
                try:
                    a["ports"].add(int(p))
                except Exception:
                    pass
            if h.get("http_status") not in (None, ""):
                try:
                    a["status"] = int(h["http_status"])
                except Exception:
                    pass

    def _ingest_dns_records(self):
        rec = self._load_json("03b_dns_discovery/dns_all_records.json")
        if not isinstance(rec, dict):
            return
        for host, records in rec.items():
            a = self._asset(host)
            a["hostnames"].add(host.lower())
            if not isinstance(records, dict):
                continue
            for rtype, values in records.items():
                if not isinstance(values, list):
                    continue
                for v in values:
                    v = str(v).strip().rstrip(".").lower()
                    if not v:
                        continue
                    # FQDN targets (CNAME/A that resolve to cloud service names)
                    if re.search(r"[a-z]", v) and "." in v and not _is_ip(v):
                        a["hostnames"].add(v)
                        if rtype == "CNAME":
                            a["cnames"].add(v)
                    elif _is_ip(v):
                        a["ips"].add(v)
                        if not a["ip"]:
                            a["ip"] = v

    def _ingest_cloud_storage_targets(self):
        data = self._load_json("03b_dns_discovery/cloud_storage_targets.json")
        if not isinstance(data, dict):
            return
        for hit in data.get("hits", []):
            host = (hit.get("host") or "").lower()
            if not host:
                continue
            a = self._asset(host)
            cname = (hit.get("cname") or "").lower().rstrip(".")
            if cname:
                a["hostnames"].add(cname)
                a["cnames"].add(cname)

    def _ingest_httpx(self):
        p = self.scan_dir / "04_http_discovery/http_confirmed.json"
        if not p.exists():
            return
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            host = (e.get("host") or e.get("input") or "").lower()
            if not host:
                continue
            a = self._asset(host)
            a["hostnames"].add(host)
            blob = " ".join([
                " ".join(e.get("tech", []) or []),
                e.get("webserver", "") or "",
                e.get("cdn_name", "") or "",
            ])
            a["tech"] = (a["tech"] + " " + blob).strip()
            for c in (e.get("cname") or []):
                c = str(c).strip().rstrip(".").lower()
                if c:
                    a["hostnames"].add(c)
                    a["cnames"].add(c)
            for ipv in (e.get("a") or []):
                ipv = str(ipv).strip().rstrip(".").lower()
                if _is_ip(ipv):
                    a["ips"].add(ipv)
                    if not a["ip"]:
                        a["ip"] = ipv
                elif re.search(r"[a-z]", ipv) and "." in ipv:
                    a["hostnames"].add(ipv)
            if e.get("cdn"):
                a["cdn"] = True
            if e.get("status_code") not in (None, ""):
                try:
                    a["status"] = int(e["status_code"])
                except Exception:
                    pass
            # dangling / takeover hint from httpx body markers
            title = (e.get("title") or "").lower()
            if any(m in title for m in ("nosuchbucket", "no such app",
                                        "there isn't a github", "not found - request id",
                                        "do not exist", "domain not found")):
                a["takeover_hint"] = True

    def _ingest_ports(self):
        p = self.scan_dir / "14_port_scan/all_ports.jsonl"
        if not p.exists():
            return
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            host = (e.get("host") or "").lower()
            if not host:
                continue
            a = self._asset(host)
            try:
                a["ports"].add(int(e.get("port")))
            except Exception:
                pass
            if _is_ip(e.get("ip", "")):
                a["ips"].add(e["ip"])
                if not a["ip"]:
                    a["ip"] = e["ip"]

    def _ingest_subdomains(self):
        p = self.scan_dir / "02_subdomain_enum/all_subdomains.txt"
        if not p.exists():
            return
        for line in p.read_text(errors="ignore").splitlines():
            host = line.strip().lower()
            if host and not host.startswith("#"):
                self._asset(host)["hostnames"].add(host)

    # -- classify ---------------------------------------------------------
    def classify(self):
        for host, a in self.assets.items():
            self._classify_host(host, a)
        self._classify_ports()
        self._classify_origin_exposure()

    def _classify_host(self, host: str, a: dict):
        # Build the searchable candidate set: the host, all resolved hostnames,
        # CNAME targets, and the tech/webserver/cdn blob.
        candidates = set(a["hostnames"]) | {a["tech"]}
        region = ""
        for c in candidates:
            region = region or extract_region(c)

        # A host can legitimately match several categories (LB + API GW, etc.).
        matched_cats: Set[str] = set()
        for sig in SIGNATURES:
            hit = None
            hit_str = ""
            for cand in candidates:
                m = sig.match(cand)
                if m:
                    hit, hit_str = m, cand
                    break
            if not hit:
                continue

            # Compute catch-alls only fire if nothing more specific in that
            # provider matched (avoid EC2-compute noise when we already
            # identified S3/ELB/etc for the same host).
            if sig.category == "compute" and matched_cats - {"compute", "cloud_dns"}:
                continue

            # Cloud DNS is a zone-level fact (every host's NS records list the
            # same nameservers) — collapse to one finding per apex domain so the
            # nameserver provider doesn't repeat for all 100+ subdomains.
            if sig.category == "cloud_dns":
                apex = _apex(host)
                zkey = (apex, sig.provider, sig.service)
                if zkey in self._dns_zones_emitted:
                    continue
                self._dns_zones_emitted.add(zkey)

            matched_cats.add(sig.category)
            confidence = self._confidence(sig, hit_str, a)

            # Takeover requires a *dangling* resource, proven one of two ways:
            #   (a) httpx saw a service "not-claimed" marker (NoSuchBucket, etc.), or
            #   (b) the CNAME target FQDN no longer resolves (NXDOMAIN).
            # A plain 404 from a live endpoint is NOT sufficient (an ALB can 404).
            #
            # The dangling check is only meaningful against a genuine CNAME the
            # target's own DNS zone points *to* (a["cnames"]). a["hostnames"]
            # also carries reverse-DNS (PTR) labels folded in by
            # _apply_ptr_records for provider/region fingerprinting — e.g. a
            # CloudFront edge node's rDNS "server-1-2-3-4.popNN.r.cloudfront.net".
            # Those are per-edge-node, shared across every CloudFront customer,
            # and by design never have a forward A record — so they always look
            # "dangling" regardless of whether any distribution is actually
            # decommissioned. Checking them would flag every CDN-fronted host
            # as a takeover unconditionally; restrict to confirmed CNAME hits.
            takeover = bool(
                sig.takeover_prone and (
                    a.get("takeover_hint") or
                    (hit_str in a["cnames"] and _looks_like_fqdn(hit_str)
                     and self._is_dangling(hit_str))
                )
            )

            sev = "critical" if takeover else sig.severity
            # W1/W3 exposure state + naming-heuristic gate.
            # A naming-only match (confidence "low": a hostname merely CONTAINS
            # "k8s"/"redis"/"vpn") is NOT evidence the service exists — the notes
            # are explicit that asserting a service from a name is a false
            # positive. Unless a port corroborates it (which lifts confidence to
            # "high"), such a match is downgraded to an INFO breadcrumb with
            # exposure_state "referenced", not a medium finding. Confirmed FQDN
            # matches and port-corroborated hits are "exists".
            naming_only = (not takeover and confidence == "low")
            if naming_only:
                exposure_state = "referenced"
                sev = "info"
                risk = sig.risk + " (naming heuristic — unconfirmed)"
            else:
                exposure_state = "exists"
                risk = ("Subdomain takeover — dangling " + sig.service
                        if takeover else sig.risk)

            self._add(CloudFinding(
                host=_apex(host) if sig.category == "cloud_dns" else host,
                category=sig.category,
                category_label=CATEGORY_LABELS[sig.category],
                service=sig.service, provider=sig.provider,
                risk=risk, severity=sev,
                region=extract_region(hit_str) or region,
                evidence=f"matched '{hit}' in {_short(hit_str)}",
                matched=hit, enumerate=sig.enumerate, attack=sig.attack,
                tools=sig.tools, source="dns" if hit_str in a["cnames"] or
                hit_str in a["hostnames"] else "httpx",
                takeover_candidate=takeover, ip=a.get("ip", ""),
                confidence="high" if takeover else confidence,
                exposure_state=exposure_state,
            ))

    def _is_dangling(self, fqdn: str) -> bool:
        """True if the CNAME-target FQDN no longer resolves (NXDOMAIN) — the
        strong, accurate signal for a subdomain-takeover candidate. Cached and
        bounded; failures other than NXDOMAIN are treated as 'resolves' to avoid
        false positives on transient/network errors."""
        fqdn = fqdn.strip().rstrip(".").lower()
        if fqdn in self._resolve_cache:
            return not self._resolve_cache[fqdn]
        resolves = True
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(fqdn, None)
            resolves = True
        except socket.gaierror as e:
            # NXDOMAIN / name-not-known => dangling. Other gaierrors are ambiguous.
            resolves = e.errno not in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5))
        except Exception:
            resolves = True   # be conservative
        self._resolve_cache[fqdn] = resolves
        return not resolves

    def _confidence(self, sig: Signature, hit_str: str, a: dict) -> str:
        # FQDN suffix match = high; naming-only heuristic (\bword\b) = low
        if any(tok in sig.patterns[0] for tok in
               (r"\.", "amazonaws", "windows.net", "googleapis", "cloud")):
            return "high"
        # port corroboration lifts confidence
        if sig.port_hints and (set(sig.port_hints) & a.get("ports", set())):
            return "high"
        # pure naming heuristic
        if sig.patterns and sig.patterns[0].startswith(r"\b"):
            return "low"
        return "medium"

    def _classify_ports(self):
        for host, a in self.assets.items():
            ports = a.get("ports", set())
            if not ports:
                continue
            # W4/memory-note: a port seen on a CDN/WAF-fronted host belongs to the
            # edge, not the origin service — scanning it produces false "exposed
            # database/cache" findings. Skip those hosts entirely for port class.
            if a.get("cdn") or a.get("waf"):
                self.log(f"skip port-class on CDN/WAF host {host}")
                continue
            for port in sorted(ports):
                if port not in SENSITIVE_PORTS:
                    continue
                cat, service, table_sev, note = SENSITIVE_PORTS[port]

                # W4 core: an OPEN port proves REACHABILITY, not that the service
                # is unauthenticated/exploitable. The notes are explicit — a
                # kubelet on 10250 that answers 401 is auth working correctly, an
                # RDS port needs a credential, Redis may have AUTH. So by default
                # we DOWNGRADE the table severity ("critical") to at most "high"
                # and mark exposure_state="exists" (reachable, auth unknown).
                sev = table_sev
                exposure_state = "exists"
                confidence = "medium"
                probe_result = ""
                evidence = f"port {port}/tcp open ({note})"

                if SEVERITY_RANK[sev] > SEVERITY_RANK["high"]:
                    sev = "high"

                # W4 active mode: a read-only banner probe upgrades reachable →
                # confirmed. open+unauth restores the true (critical) severity;
                # an auth-required response is the documented FP → drop to low.
                if self.active:
                    target = a.get("ip") or (sorted(a.get("ips") or [""])[0]) or host
                    outcome, detail = self._probe_service(port, target, cat)
                    probe_result = f"{outcome}: {detail}" if detail else outcome
                    if outcome == "open_unauth":
                        sev = table_sev
                        exposure_state = ("sensitive_confirmed"
                                          if cat in ("kubernetes", "cache")
                                          or port in (2375, 2379, 10250)
                                          else "anon_accessible")
                        confidence = "high"
                        evidence = (f"port {port}/tcp open + UNAUTHENTICATED "
                                    f"({note}; {detail})")
                    elif outcome == "auth_required":
                        sev = "low"
                        exposure_state = "exists"
                        confidence = "high"
                        evidence = (f"port {port}/tcp open but authentication "
                                    f"ENFORCED ({note}; {detail}) — not anon-"
                                    f"exposed")

                self._add(CloudFinding(
                    host=host, category=cat,
                    category_label=CATEGORY_LABELS[cat],
                    service=service, provider=self._guess_provider(a),
                    risk=self._port_risk(cat),
                    severity=sev,
                    region=extract_region(" ".join(a["hostnames"])),
                    evidence=evidence,
                    matched=str(port),
                    enumerate=self._port_enum(port, host, a.get("ip", "")),
                    attack=self._port_attack(cat, port),
                    tools=["nmap"], source="ports",
                    ip=a.get("ip", ""), port=port, confidence=confidence,
                    exposure_state=exposure_state, probe_result=probe_result,
                ))

    # ── W4: read-only service banner probes (only in --active mode) ──────────
    def _probe_service(self, port: int, target: str, cat: str) -> Tuple[str, str]:
        """Confirm whether a reachable sensitive port is actually
        UNAUTHENTICATED. Returns (outcome, detail) where outcome is one of:
          open_unauth   — service answered a privileged request with no auth
          auth_required — service demanded auth (401/403/NOAUTH/handshake) — FP
          unreachable   — could not connect (stale port record)
          unknown       — reachable but auth state not determinable here
        All probes are read-only (PING / GET / version); none mutate state."""
        if not target:
            return "unknown", ""
        try:
            if port in (6379,):                       # Redis — PING
                return self._probe_redis(target, port)
            if port in (11211,):                      # Memcached — stats
                return self._probe_memcached(target)
            if port in (10250, 10255):                # kubelet — /pods
                scheme = "https" if port == 10250 else "http"
                return self._probe_http(f"{scheme}://{target}:{port}/pods",
                                        good=("kind", "PodList", "containers"))
            if port == 6443:                          # kube-apiserver — /api
                return self._probe_http(f"https://{target}:6443/api",
                                        good=("versions", "serverAddress", "APIVersions"))
            if port in (2379,):                       # etcd — /version
                return self._probe_http(f"http://{target}:2379/version",
                                        good=("etcdserver", "etcdcluster"))
            if port in (2375,):                       # Docker API — /version
                return self._probe_http(f"http://{target}:2375/version",
                                        good=("ApiVersion", "GitCommit", "Docker"))
            if port in (9200,):                       # Elasticsearch/OpenSearch
                return self._probe_http(f"http://{target}:9200/",
                                        good=("cluster_name", "lucene_version", "You Know, for"))
            if port in (5984,):                       # CouchDB
                return self._probe_http(f"http://{target}:5984/",
                                        good=("couchdb", "Welcome"))
            if port in (5601,):                       # Kibana
                return self._probe_http(f"http://{target}:5601/api/status",
                                        good=("version", "status", "kibana"))
            if port in (15672,):                      # RabbitMQ mgmt
                return self._probe_http(f"http://{target}:15672/api/overview",
                                        good=("management_version", "rabbitmq_version"))
            if port in (8500,):                       # Consul
                return self._probe_http(f"http://{target}:8500/v1/agent/self",
                                        good=("Config", "Member", "Consul"))
        except Exception as e:                        # pragma: no cover
            return "unknown", str(e)[:60]
        # DBs (3306/5432/1433/1521/5439/27017), SSH, RDP: a bare TCP connect only
        # confirms reachability, not auth state — do not over-claim.
        return self._probe_tcp(target, port)

    def _probe_tcp(self, target: str, port: int) -> Tuple[str, str]:
        try:
            with socket.create_connection((target, port), timeout=4):
                return "unknown", "reachable (auth state not probed)"
        except OSError:
            return "unreachable", ""

    def _probe_redis(self, target: str, port: int) -> Tuple[str, str]:
        try:
            with socket.create_connection((target, port), timeout=4) as s:
                s.sendall(b"PING\r\n")
                data = s.recv(256)
        except OSError:
            return "unreachable", ""
        low = data.lower()
        if b"+pong" in low:
            return "open_unauth", "PING→PONG (no auth)"
        if b"noauth" in low or b"authentication" in low or b"-err" in low:
            return "auth_required", "requires AUTH"
        return "unknown", ""

    def _probe_memcached(self, target: str) -> Tuple[str, str]:
        try:
            with socket.create_connection((target, 11211), timeout=4) as s:
                s.sendall(b"stats\r\n")
                data = s.recv(512)
        except OSError:
            return "unreachable", ""
        if b"STAT " in data:
            return "open_unauth", "stats readable (no auth)"
        return "unknown", ""

    def _probe_http(self, url: str, good: Tuple[str, ...]) -> Tuple[str, str]:
        if not _HAS_REQUESTS:
            return "unknown", "requests unavailable"
        try:
            r = requests.get(url, timeout=5, verify=False,
                             headers={"User-Agent": "ARISE-cloud-intel/1.0"})
        except RequestException as e:
            return "unreachable", str(e)[:50]
        if r.status_code in (401, 403):
            return "auth_required", f"HTTP {r.status_code}"
        body = (r.text or "")[:4000]
        if r.status_code == 200 and any(g in body for g in good):
            return "open_unauth", f"HTTP 200, unauth data ({r.status_code})"
        return "unknown", f"HTTP {r.status_code}"

    def _classify_origin_exposure(self):
        """A resolved host on a cloud provider that is NOT behind a CDN/WAF is a
        direct-origin / CDN-bypass candidate.

        W3 noise controls:
          * Dedup by origin IP — a 200-subdomain estate on one ALB IP is ONE
            origin, not 200 findings (the single biggest noise source before).
          * Skip WAF-fronted hosts (edge protection present).
          * Corroboration gate — a bare cloud-hosted origin is only an INFO
            breadcrumb; it is a MEDIUM 'origin exposure' finding only when the
            same IP also exposes a sensitive service port (a concrete thing to
            bypass to)."""
        for host, a in self.assets.items():
            ip = a.get("ip")
            if a.get("cdn") or a.get("waf") or not ip:
                continue
            if a.get("status") is None:
                continue
            prov = self._guess_provider(a)
            if not prov:
                continue
            if ip in self._origin_ips_emitted:
                continue                              # one finding per origin IP
            self._origin_ips_emitted.add(ip)

            has_sensitive_port = bool(a.get("ports", set()) & set(SENSITIVE_PORTS))
            if has_sensitive_port:
                sev, exposure_state, conf = "medium", "exists", "medium"
                risk = "Origin exposure — WAF/CDN bypass to an exposed service"
            else:
                sev, exposure_state, conf = "info", "exists", "low"
                risk = "Cloud-hosted origin (no CDN/WAF) — informational"

            self._add(CloudFinding(
                host=host, category="origin_exposure",
                category_label=CATEGORY_LABELS["origin_exposure"],
                service="Exposed origin (no CDN/WAF edge)",
                provider=prov, risk=risk,
                severity=sev, region=extract_region(" ".join(a["hostnames"])),
                evidence=f"resolves to {ip} on {prov} with no CDN/WAF fronting"
                         + (" and an open sensitive port" if has_sensitive_port else ""),
                matched=ip,
                enumerate=f"nmap -sV {ip}  |  curl -H 'Host: {host}' "
                          f"https://{ip}/ -k  (confirm origin serves the app)",
                attack="Hit the origin IP directly with the real Host header to "
                       "bypass any edge WAF/rate-limiting. Add to Shodan/Censys "
                       "monitoring for exposed services on this IP.",
                tools=["httpx", "nmap"], source="httpx",
                ip=ip, confidence=conf, exposure_state=exposure_state,
            ))

    # -- helpers ----------------------------------------------------------
    def _guess_provider(self, a: dict) -> str:
        blob = " ".join(a["hostnames"]) + " " + a.get("tech", "")
        blob = blob.lower()
        if any(t in blob for t in ("amazonaws", "cloudfront", "aws", "ec2", "elb")):
            return "aws"
        if any(t in blob for t in ("azure", "windows.net", "azureedge", "cloudapp")):
            return "azure"
        if any(t in blob for t in ("google", "gcp", "appspot", "run.app", "goog")):
            return "gcp"
        if "cloudflare" in blob:
            return "cloudflare"
        return ""

    @staticmethod
    def _port_risk(cat: str) -> str:
        return {
            "database": "Public database exposure",
            "cache": "Internet cache exposure",
            "queue": "Broker / queue exposure",
            "kubernetes": "Cluster control-plane exposure",
            "registry": "Container image leakage",
            "bastion": "Administrative access",
            "storage": "Storage service exposure",
        }.get(cat, "Service exposure")

    @staticmethod
    def _port_enum(port: int, host: str, ip: str) -> str:
        tgt = ip or host
        return f"nmap -sV -Pn -p{port} {tgt}  |  probe service banner & default creds"

    @staticmethod
    def _port_attack(cat: str, port: int) -> str:
        return {
            "database": "Attempt anonymous/default/harvested credentials; a "
                        "reachable DB port + one valid cred = full data exfiltration.",
            "cache": "Test unauthenticated access (Redis PING/INFO, Memcached "
                     "stats); Redis CONFIG SET can achieve RCE.",
            "queue": "Test anonymous broker access; enumerate topics/queues and "
                     "inject/exfiltrate messages.",
            "kubernetes": "Probe anonymous API/kubelet/etcd; etcd or kubelet /run "
                          "exposure leads to cluster-wide RCE and secret theft.",
            "registry": "Pull images anonymously via /v2/_catalog; scan layers "
                        "for secrets and private source.",
            "bastion": "Fingerprint SSH/RDP version for CVEs; test password auth "
                       "for spray/brute and missing MFA.",
            "storage": "Test anonymous bucket/console access and default creds.",
        }.get(cat, "Investigate the exposed service for authentication weaknesses.")

    def _add(self, f: CloudFinding):
        k = f.key()
        cur = self.findings.get(k)
        if cur is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.severity]:
            self.findings[k] = f

    # -- output -----------------------------------------------------------
    def write(self) -> Tuple[int, dict]:
        out_dir = self.scan_dir / "17_cloud_exposure"
        out_dir.mkdir(parents=True, exist_ok=True)
        findings = sorted(
            self.findings.values(),
            key=lambda f: (-SEVERITY_RANK[f.severity], f.category, f.host),
        )
        map_path = out_dir / "cloud_asset_map.jsonl"
        with open(map_path, "w") as w:
            for f in findings:
                w.write(json.dumps(asdict(f)) + "\n")

        summary = self._summary(findings)
        with open(out_dir / "cloud_asset_summary.json", "w") as w:
            json.dump(summary, w, indent=2)
        return len(findings), summary

    def _summary(self, findings: List[CloudFinding]) -> dict:
        by_cat: Dict[str, dict] = {}
        by_prov: Dict[str, int] = {}
        by_sev: Dict[str, int] = {s: 0 for s in SEVERITY_RANK}
        by_state: Dict[str, int] = {}
        takeovers = []
        for f in findings:
            by_state[f.exposure_state] = by_state.get(f.exposure_state, 0) + 1
            c = by_cat.setdefault(f.category, {
                "label": f.category_label, "count": 0, "services": {},
                "max_severity": "info", "risk": f.risk,
            })
            c["count"] += 1
            c["services"][f.service] = c["services"].get(f.service, 0) + 1
            if SEVERITY_RANK[f.severity] > SEVERITY_RANK[c["max_severity"]]:
                c["max_severity"] = f.severity
            if f.provider:
                by_prov[f.provider] = by_prov.get(f.provider, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            if f.takeover_candidate:
                takeovers.append({"host": f.host, "service": f.service,
                                  "provider": f.provider})
        return {
            "total": len(findings),
            "categories": by_cat,
            "by_provider": by_prov,
            "by_severity": by_sev,
            "by_exposure_state": by_state,
            "takeover_candidates": takeovers,
            "category_order": [c for c in CATEGORIES if c in by_cat],
        }

    # -- orchestration ----------------------------------------------------
    def run(self) -> int:
        self.log(f"scan dir: {self.scan_dir}")
        self.ingest()
        self.classify()
        n, summary = self.write()
        self.log(f"wrote {n} cloud asset findings across "
                 f"{len(summary['categories'])} categories")
        if not self.verbose:
            # concise stdout for pipeline logs
            cats = ", ".join(f"{c}:{d['count']}"
                             for c, d in summary["categories"].items())
            print(f"[cloud-intel] {n} findings — {cats}")
            if summary["takeover_candidates"]:
                print(f"[cloud-intel] ⚠ {len(summary['takeover_candidates'])} "
                      f"subdomain-takeover candidate(s)")
        return n


# ---------------------------------------------------------------------------
# small utilities
# ---------------------------------------------------------------------------

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip().rstrip("."))
        return True
    except Exception:
        return False


def _short(s: str, n: int = 80) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def _apex(host: str) -> str:
    """Best-effort registrable apex (last two labels). Good enough for grouping
    zone-level facts; not a public-suffix-list implementation."""
    parts = (host or "").strip().rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _looks_like_fqdn(s: str) -> bool:
    """A dotted, resolvable-looking hostname (not an IP, not a tech blob)."""
    s = (s or "").strip().rstrip(".")
    if not s or " " in s or _is_ip(s):
        return False
    return "." in s and bool(re.match(r"^[a-z0-9.\-]+$", s, re.IGNORECASE))


def main():
    ap = argparse.ArgumentParser(
        description="ARISE Cloud Asset Intelligence — external cloud attack-surface "
                    "classification over existing scan data.")
    ap.add_argument("scan_dir", help="path to a scan output directory")
    ap.add_argument("--active", action="store_true",
                    help="allow lightweight live probes (VPN paths, bucket ACLs)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.exists():
        print(f"scan dir not found: {scan_dir}", file=sys.stderr)
        return 2

    clf = CloudAssetClassifier(scan_dir, active=args.active, verbose=args.verbose)
    clf.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
