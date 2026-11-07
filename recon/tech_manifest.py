#!/usr/bin/env python3
"""
Build a per-scan technology manifest from Module 4 httpx output.

httpx already runs tech-detect on every confirmed root and writes a list of
detected fingerprints per host into http_confirmed.json. That signal is
currently thrown away — every downstream vuln scanner (nuclei, apisec, cloud
recon) has to guess or re-detect the same tech stack.

This script collapses httpx's per-host tech into:

  tech_manifest.jsonl  — one row per host:
                          {host, techs: [...], nuclei_tags: [...],
                           methods_hint: [...]}

The nuclei_tags column is the practical payoff: nuclei's template metadata
uses vendor names as tags (`wordpress`, `apache`, `nginx`, `tomcat`, …), so
mapping httpx's detected techs onto that vocabulary lets a caller do
`nuclei -tags "$(jq -r ...)"` and get a targeted scan instead of the whole
template shelf. On big scans this can cut nuclei runtime substantially
because -as (automatic scan) still loads a broad base set.

We deliberately don't emit an "aggregate" list across hosts — a mixed-tech
target should scan each host with its own tag set, otherwise a nginx-only
subdomain gets Apache templates and a WordPress subdomain misses its own.

Usage:
    python3 tech_manifest.py <scan_dir>
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import sys
from pathlib import Path
from typing import List, Set

# httpx tech -> nuclei template tag(s). Only the mappings we're confident
# about; unknowns are passed through unchanged so nuclei still gets the raw
# tech name as a tag (it uses fuzzy matching internally, so this often works).
TECH_TO_NUCLEI_TAG = {
    "wordpress": ["wordpress"],
    "wp": ["wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    "prestashop": ["prestashop"],
    "typo3": ["typo3"],
    "apache": ["apache"],
    "apache http server": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis"],
    "microsoft-iis": ["iis"],
    "tomcat": ["tomcat", "apache-tomcat"],
    "jboss": ["jboss"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "kibana": ["kibana"],
    "elasticsearch": ["elasticsearch"],
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker"],
    "consul": ["consul", "hashicorp"],
    "vault": ["vault", "hashicorp"],
    "prometheus": ["prometheus"],
    "spring": ["spring", "springboot"],
    "spring boot": ["springboot", "spring"],
    "laravel": ["laravel"],
    "django": ["django"],
    "rails": ["rails", "ruby-on-rails"],
    "express": ["express", "nodejs"],
    "next.js": ["nextjs"],
    "react": ["react"],
    "vue.js": ["vuejs"],
    "angular": ["angular"],
    "confluence": ["confluence", "atlassian"],
    "jira": ["jira", "atlassian"],
    "bitbucket": ["bitbucket", "atlassian"],
    "moodle": ["moodle"],
    "phpmyadmin": ["phpmyadmin"],
    "graphql": ["graphql"],
    "swagger": ["swagger", "openapi"],
    "swagger-ui": ["swagger"],
    "openapi": ["openapi", "swagger"],
    "kong": ["kong"],
    "cisco": ["cisco"],
    "fortinet": ["fortinet"],
    "citrix": ["citrix"],
    "vmware": ["vmware"],
    "atlassian": ["atlassian"],
    "aem": ["aem", "adobe"],
    "adobe experience manager": ["aem", "adobe"],
    "coldfusion": ["coldfusion", "adobe"],
    "sharepoint": ["sharepoint", "microsoft"],
    "exchange": ["exchange", "microsoft"],
    "solr": ["solr", "apache-solr"],
    "elk": ["elasticsearch", "kibana"],
    "cloudflare": ["cloudflare"],
    "akamai": ["akamai"],
    "aws": ["aws"],
    "azure": ["azure"],
    "gcp": ["gcp", "google-cloud"],
    "salesforce": ["salesforce"],
    "servicenow": ["servicenow"],
    "sap": ["sap"],
    "oracle": ["oracle"],
    "cassandra": ["cassandra"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "memcached": ["memcached"],
    "postgresql": ["postgresql", "postgres"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb", "mysql"],
    "mssql": ["mssql", "microsoft-sql"],
    "kafka": ["kafka"],
    "rabbitmq": ["rabbitmq"],
}


def _normalize(tech: str) -> str:
    return tech.strip().lower().replace("_", "-")


def _to_nuclei_tags(techs: List[str]) -> List[str]:
    tags: Set[str] = set()
    for t in techs:
        key = _normalize(t)
        mapped = TECH_TO_NUCLEI_TAG.get(key)
        if mapped:
            tags.update(mapped)
        else:
            # Passthrough — nuclei tags are lowercase alphanumeric+dash.
            slug = "".join(c if c.isalnum() or c == "-" else "-" for c in key)
            slug = slug.strip("-")
            if slug and len(slug) <= 40:
                tags.add(slug)
    return sorted(tags)


def build(scan_dir: Path) -> int:
    src = scan_dir / "04_http_discovery" / "http_confirmed.json"
    out = scan_dir / "04_http_discovery" / "tech_manifest.jsonl"
    if not src.is_file() or src.stat().st_size == 0:
        return 0
    seen = set()
    rows_written = 0
    with open(out, "w", encoding="utf-8") as w:
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    host = (e.get("host") or e.get("input") or "").lower()
                    if not host or host in seen:
                        continue
                    seen.add(host)
                    # httpx tech field is either 'tech' or 'technologies'
                    techs = e.get("tech") or e.get("technologies") or []
                    if isinstance(techs, str):
                        techs = [techs]
                    if not isinstance(techs, list):
                        techs = []
                    if not techs:
                        continue
                    tags = _to_nuclei_tags([str(t) for t in techs])
                    if not tags:
                        continue
                    w.write(json.dumps({
                        "host": host,
                        "techs": techs,
                        "nuclei_tags": tags,
                    }) + "\n")
                    rows_written += 1
        except FileNotFoundError:
            return 0
    return rows_written


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: tech_manifest.py <scan_dir>", file=sys.stderr)
        sys.exit(2)
    n = build(Path(sys.argv[1]))
    print(f"[tech-manifest] wrote {n} host row(s)", file=sys.stderr)
