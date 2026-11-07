#!/usr/bin/env python3
"""Extract normalized tech stack from httpx tech-detect output.

Reads http_confirmed.json (or deduped variant) and produces:
  tech_stack.json — normalized tech list with categories, versions, hosts
  tech_by_host.jsonl — one row per host with detected technologies
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import sys
import argparse
from collections import defaultdict

# Rough categorization for dashboard grouping / nuclei template routing.
TECH_CATEGORIES = {
    "web-server": ["nginx", "apache", "iis", "caddy", "litespeed", "openresty"],
    "cdn": ["cloudflare", "akamai", "cloudfront", "fastly", "sucuri",
            "stackpath", "keycdn", "azure cdn"],
    "waf": ["cloudflare", "aws waf", "imperva", "sucuri", "akamai",
            "barracuda", "f5", "fortinet"],
    "framework": ["django", "flask", "rails", "spring", "express",
                  "laravel", "symfony", "asp.net", "next.js", "nuxt",
                  "gatsby", "angular", "react", "vue"],
    "language": ["php", "python", "java", "ruby", "go", "node.js",
                 "typescript"],
    "cms": ["wordpress", "drupal", "joomla", "magento", "shopify",
            "squarespace", "wix", "ghost"],
    "database": ["mysql", "postgresql", "mongodb", "redis", "elasticsearch"],
    "cloud": ["aws", "gcp", "azure", "heroku", "netlify", "vercel"],
    "analytics": ["google analytics", "gtag", "hotjar", "mixpanel",
                  "segment", "amplitude"],
    "js-lib": ["jquery", "bootstrap", "react", "vue", "angular", "lodash",
               "moment", "d3"],
}


def _categorize(name: str) -> list:
    name_l = name.lower()
    cats = []
    for cat, patterns in TECH_CATEGORIES.items():
        for pat in patterns:
            if pat in name_l:
                cats.append(cat)
                break
    return cats or ["other"]


def _parse_tech(entry: dict) -> list:
    """Extract technology names+versions from httpx entry."""
    techs = []
    # httpx uses "tech" (list) or "technologies" (list of dicts)
    for t in (entry.get("tech") or []):
        if isinstance(t, str):
            name = t.strip()
            version = ""
            # httpx string format: "Name:1.2.3"
            if ":" in name:
                name, version = name.split(":", 1)
            techs.append({"name": name.strip(), "version": version.strip()})
        elif isinstance(t, dict):
            techs.append({
                "name": t.get("name", "").strip(),
                "version": t.get("version", "").strip(),
            })
    for t in (entry.get("technologies") or []):
        if isinstance(t, dict) and t.get("name"):
            techs.append({
                "name": t["name"].strip(),
                "version": (t.get("version") or "").strip(),
            })
    return [x for x in techs if x["name"]]


def extract(http_file: str, out_stack: str, out_by_host: str) -> dict:
    if not os.path.exists(http_file):
        return {"error": "http_confirmed.json missing"}

    tech_hosts = defaultdict(lambda: {
        "hosts": set(), "versions": set(), "categories": set()})
    host_tech = defaultdict(list)

    with open(http_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            host = entry.get("host") or entry.get("input") or ""
            techs = _parse_tech(entry)
            for t in techs:
                name = t["name"]
                ver = t["version"]
                tech_hosts[name]["hosts"].add(host)
                if ver:
                    tech_hosts[name]["versions"].add(ver)
                for c in _categorize(name):
                    tech_hosts[name]["categories"].add(c)
                host_tech[host].append(t)

    # tech_stack.json — flat list of technologies with counts
    tech_list = []
    for name, data in tech_hosts.items():
        tech_list.append({
            "name": name,
            "host_count": len(data["hosts"]),
            "versions": sorted(data["versions"]),
            "categories": sorted(data["categories"]),
            "hosts": sorted(data["hosts"])[:50],
        })
    tech_list.sort(key=lambda x: x["host_count"], reverse=True)

    by_category = defaultdict(list)
    for t in tech_list:
        for c in t["categories"]:
            by_category[c].append(t["name"])

    stack_summary = {
        "total_technologies": len(tech_list),
        "total_hosts": len(host_tech),
        "technologies": tech_list,
        "by_category": {k: sorted(set(v)) for k, v in by_category.items()},
    }

    os.makedirs(os.path.dirname(out_stack) or ".", exist_ok=True)
    with open(out_stack, "w") as f:
        json.dump(stack_summary, f, indent=2)

    os.makedirs(os.path.dirname(out_by_host) or ".", exist_ok=True)
    with open(out_by_host, "w") as f:
        for host, techs in host_tech.items():
            # dedup by name within a host
            seen = set()
            uniq = []
            for t in techs:
                if t["name"] not in seen:
                    seen.add(t["name"])
                    uniq.append(t)
            f.write(json.dumps({"host": host, "tech": uniq}) + "\n")

    return {
        "total_technologies": len(tech_list),
        "total_hosts": len(host_tech),
        "categories": len(by_category),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-confirmed", required=True,
                    help="Path to httpx http_confirmed.json (input)")
    ap.add_argument("--out-stack", required=True,
                    help="Path to tech_stack.json (output)")
    ap.add_argument("--out-by-host", required=True,
                    help="Path to tech_by_host.jsonl (output)")
    args = ap.parse_args()

    summary = extract(args.http_confirmed, args.out_stack, args.out_by_host)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
