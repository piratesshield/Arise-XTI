#!/usr/bin/env python3
"""
ARISE — CAPEC Attack-Path Builder  (Layer 6: score & chain)
===========================================================
Findings are dots. This joins them. It loads MITRE CAPEC v3.9 (capec_v3.9/
capec_v3.9.xml) as a directed graph — nodes = attack patterns, edges =
CanPrecede / CanFollow (MITRE's own "this attack enables that attack") — into
arise_autonomous.KnowledgeGraph, maps each CONFIRMED finding onto a CAPEC by
attack-lane and CWE, then walks the precede-edges to chain findings into ranked
attack PATHS gated by each pattern's Prerequisites against what recon actually
found.

  finding ──lane/CWE──▶ CAPEC ──CanPrecede──▶ CAPEC ──▶ … ──▶ impact
                          │
                    Prerequisite ◀─ checked against ─ asset facts

Grounded, not generative: it only chains findings that already exist, and only
along edges MITRE ships. A "realized" hop = a second finding corroborates that
step (the strongest signal); an "open" hop = a reachable next move nobody has
confirmed yet — the exact thing to test next.

Output (per scan, under 25_attack_paths/):
  capec_attack_paths.json   — ranked paths + narratives + the next probe per open hop
  capec_kg.json             — the KnowledgeGraph (findings + CAPEC nodes + edges)

Usage:
    python3 capec_attack_paths.py <scan_dir> [--capec PATH] [--max-depth N] [--summary]
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

NS = {"c": "http://capec.mitre.org/capec-3"}
# capec_v3.9/ (vendored MITRE data) lives at PROJECT_ROOT, shared with
# easm-pipeline.sh (which reads $PROJECT_ROOT/capec_v3.9/... directly) --
# NOT next to this file, which now lives one level down at intel/.
DEFAULT_CAPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "capec_v3.9", "capec_v3.9.xml")

try:
    from core.knowledge_graph import KnowledgeGraph
except Exception:  # pragma: no cover — minimal fallback if import fails
    class KnowledgeGraph:  # type: ignore
        def __init__(self):
            self.nodes, self.edges = {}, []

        def add_node(self, ntype, label, **attrs):
            nid = f"{ntype}:{label}"
            self.nodes.setdefault(nid, {"type": ntype, "label": label, "attrs": {}})
            self.nodes[nid]["attrs"].update({k: v for k, v in attrs.items() if v})
            return nid

        def add_edge(self, src, rel, dst):
            e = {"src": src, "rel": rel, "dst": dst}
            if e not in self.edges:
                self.edges.append(e)

        def summary(self):
            bt = defaultdict(int)
            for n in self.nodes.values():
                bt[n["type"]] += 1
            return {"node_counts": dict(bt), "edge_count": len(self.edges)}

        def to_dict(self):
            return {"nodes": list(self.nodes.values()), "edges": self.edges, "summary": self.summary()}


# ---------------------------------------------------------------------------
# Lane / keyword → CAPEC. The bridge from ARISE's attack lanes to MITRE.
# ---------------------------------------------------------------------------

LANE_CAPEC = {
    "sqli": 66, "sql": 66, "sql-injection": 66,
    "xss": 63, "cross-site-scripting": 63,
    "lfi": 126, "ssti-lfi": 126, "path-traversal": 126, "traversal": 126,
    "ssti": 242, "rce": 248, "code-injection": 242,
    "ssrf": 664,
    "bola": 1, "idor": 1, "authz": 1, "access-control": 1, "broken-access": 1,
    "auth-jwt": 115, "jwt": 593, "auth": 115, "auth-bypass": 115,
    "graphql": 54, "introspection": 54,
    "exposure": 545, "config": 545, "secret": 545, "credentials": 545,
    "disclosure": 118, "sensitive-review": 118, "info-leak": 118,
    "version-swap": 113, "api": 113, "interface": 113,
    "methods": 274, "http-methods": 274, "dangerous-methods": 274, "verb": 274,
    "file-upload": 17, "upload": 17,
    "cloud-review": 545, "open-redirect": 194,
}
KNOWN_LANES = set(LANE_CAPEC)


# ---------------------------------------------------------------------------
# CAPEC catalog → graph
# ---------------------------------------------------------------------------

def load_capec(path):
    """Parse the CAPEC XML into patterns + a global precede-adjacency + CWE index."""
    tree = ET.parse(path)
    root = tree.getroot()
    patterns = {}
    precedes = defaultdict(set)   # A precedes B  (A CanPrecede B, or B CanFollow A)
    parent_of = {}
    cwe_index = defaultdict(set)  # CWE id -> {capec ids}

    for ap in root.iter("{%s}Attack_Pattern" % NS["c"]):
        try:
            cid = int(ap.get("ID"))
        except (TypeError, ValueError):
            continue
        if ap.get("Status") == "Deprecated":
            continue
        rec = {
            "id": cid,
            "name": ap.get("Name", ""),
            "abstraction": ap.get("Abstraction", ""),
            "prereqs": [], "cwes": [], "consequences": [],
            "description": "", "how": [], "mitigations": [], "skill": "",
        }
        d = ap.find("c:Description", NS)
        if d is not None and d.text:
            rec["description"] = " ".join(d.text.split())[:400]
        # Execution_Flow = the actual "how to carry out this attack" steps.
        ef = ap.find("c:Execution_Flow", NS)
        if ef is not None:
            for step in ef.findall("c:Attack_Step", NS):
                ph = step.find("c:Phase", NS)
                sd = step.find("c:Description", NS)
                if sd is not None and sd.text:
                    phase = (ph.text if ph is not None else "").strip()
                    rec["how"].append(f"{phase}: {' '.join(sd.text.split())[:220]}")
        for m in ap.findall("c:Mitigations/c:Mitigation", NS):
            if m.text:
                rec["mitigations"].append(" ".join(m.text.split())[:220])
        sk = ap.find("c:Skills_Required/c:Skill", NS)
        if sk is not None:
            rec["skill"] = (sk.get("Level") or "").strip()
        for pr in ap.findall("c:Prerequisites/c:Prerequisite", NS):
            if pr.text:
                rec["prereqs"].append(pr.text.strip())
        for rw in ap.findall("c:Related_Weaknesses/c:Related_Weakness", NS):
            w = rw.get("CWE_ID")
            if w and w.isdigit():
                rec["cwes"].append(int(w))
                cwe_index[int(w)].add(cid)
        for cons in ap.findall("c:Consequences/c:Consequence", NS):
            scopes = [s.text for s in cons.findall("c:Scope", NS) if s.text]
            impacts = [i.text for i in cons.findall("c:Impact", NS) if i.text]
            if scopes or impacts:
                rec["consequences"].append({"scope": scopes, "impact": impacts})
        for rel in ap.findall("c:Related_Attack_Patterns/c:Related_Attack_Pattern", NS):
            nature = rel.get("Nature")
            tgt = rel.get("CAPEC_ID")
            if not tgt or not tgt.isdigit():
                continue
            tgt = int(tgt)
            if nature == "CanPrecede":
                precedes[cid].add(tgt)
            elif nature == "CanFollow":
                precedes[tgt].add(cid)
            elif nature == "ChildOf":
                parent_of[cid] = tgt
        patterns[cid] = rec

    # ── Domain scoping ────────────────────────────────────────────────────────
    # A remote web/API EASM must not chain into Social-Engineering / Physical /
    # Hardware / Supply-Chain attacks (real MITRE edges, wrong domain). CAPEC's
    # ChildOf hierarchy is by MECHANISM, not domain, so we must NOT expand down
    # it — prune only the DIRECT members of the excluded "Domains of Attack"
    # categories, plus a keyword net for detailed patterns named by their domain.
    DOMAIN_EXCLUDE = {403, 514, 515, 437}  # Social Eng, Physical, Hardware, Supply Chain
    out_of_scope = set()
    for cat in root.iter("{%s}Category" % NS["c"]):
        try:
            catid = int(cat.get("ID"))
        except (TypeError, ValueError):
            continue
        if catid in DOMAIN_EXCLUDE:
            for hm in cat.findall("c:Relationships/c:Has_Member", NS):
                m = hm.get("CAPEC_ID")
                if m and m.isdigit():
                    out_of_scope.add(int(m))
    DENY = re.compile(r"phish|pharm|bluetooth|wi[-]?fi|wireless|rfid|\bnfc\b|\busb\b|"
                      r"firmware|\bhardware\b|software update|social engineer|"
                      r"\bhuman\b|physical|knob|cellular|\bsms\b|postal|"
                      r"deceptive|influence|pretext|counterfeit", re.I)
    for cid, rec in patterns.items():
        if DENY.search(rec["name"]):
            out_of_scope.add(cid)

    return patterns, precedes, parent_of, cwe_index, out_of_scope


def precedes_effective(cid, precedes, parent_of):
    """Successors of a pattern, enriched one level up the ChildOf hierarchy —
    meta/standard patterns often carry the chaining edges a detailed one omits."""
    out = set(precedes.get(cid, ()))
    par = parent_of.get(cid)
    if par:
        out |= set(precedes.get(par, ()))
    out.discard(cid)
    return out


# ---------------------------------------------------------------------------
# Findings loader + mapping
# ---------------------------------------------------------------------------

def _iter_jsonl(path):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
    except OSError:
        return


def _host_only(u):
    """Strip scheme/path/port from a host/url field → bare hostname."""
    import urllib.parse
    u = (u or "").strip().lower()
    if "://" in u:
        try:
            return urllib.parse.urlparse(u).hostname or ""
        except Exception:
            return ""
    return u.split("/")[0].split(":")[0]


# ---------------------------------------------------------------------------
# Host grounding (F02 / §4 in ARISE_REMEDIATION_ROADMAP.md)
#
# Previously a chain hop was marked "realized" the moment ANY finding anywhere
# in the scan matched that CAPEC ID, regardless of which host it was on — a
# chain could link host-A to host-B purely off a coincidental CAPEC-ID
# adjacency. This reads the same host->IP data kaiju_entities.py's
# RESOLVES_TO relation is built from (manifest.json), directly rather than via
# the entities.json cache, so this has no dependency on the Issues tab ever
# having been opened for this scan (the cache may not exist yet).
# ---------------------------------------------------------------------------

def load_host_graph(scan_dir):
    """Return (fqdn_to_ip, ip_to_fqdns) — same shape as before this function
    delegated to intel/evidence_graph.py (attack_chain_v2.ROADMAP.md Phase 1):
    one shared graph instead of this file independently re-reading
    manifest.json, which is exactly the duplication
    ARISE_REMEDIATION_ROADMAP.md's Cluster A/C flagged. Falls back to the
    original direct manifest read if evidence_graph is unavailable for any
    reason — never a hard dependency, matching this file's existing
    fail-open-on-import pattern for KnowledgeGraph itself."""
    try:
        from intel.evidence_graph import build_graph, host_ip_graph
        kg, _counts = build_graph(scan_dir)
        fqdn_to_ip, ip_to_fqdns = host_ip_graph(kg)
        return fqdn_to_ip, {ip: set(hosts) for ip, hosts in ip_to_fqdns.items()}
    except Exception:
        pass

    fqdn_to_ip, ip_to_fqdns = {}, defaultdict(set)
    try:
        manifest = json.load(open(os.path.join(scan_dir, "manifest.json")))
    except Exception:
        return fqdn_to_ip, ip_to_fqdns
    for fqdn, hd in (manifest.get("hosts") or {}).items():
        ip = (hd or {}).get("ip")
        if ip:
            fqdn_to_ip[fqdn.lower()] = ip
            ip_to_fqdns[ip].add(fqdn.lower())
    return fqdn_to_ip, ip_to_fqdns


def same_asset(host_a, host_b, fqdn_to_ip):
    """True if two hosts are the same asset: identical hostname, or both
    resolve to the same IP. This is the check a chain hop must pass to be
    marked 'realized' instead of merely CAPEC-ID-coincidental. With no
    manifest data available, this degrades to exact-hostname matching only
    (stricter than before, never looser — fails safe, not open)."""
    if not host_a or not host_b:
        return False
    host_a, host_b = host_a.lower(), host_b.lower()
    if host_a == host_b:
        return True
    ip_a, ip_b = fqdn_to_ip.get(host_a), fqdn_to_ip.get(host_b)
    return bool(ip_a) and ip_a == ip_b


def load_findings(scan_dir):
    seen, out = set(), []
    for rel in ("12_nuclei_scanning/nuclei_results.txt",
                "12_nuclei_scanning/synth_results.txt",
                "12_nuclei_scanning/full_results.txt",
                "23_internet_intel/intel_findings.jsonl",
                # P6: the adaptive loop's confirmed findings are nuclei-shaped, so
                # they chain here exactly like a template hit (lane tags + CWE).
                "27_adaptive_loop/loop_findings.jsonl"):
        for r in _iter_jsonl(os.path.join(scan_dir, rel)):
            tid = r.get("template-id") or r.get("templateID") or r.get("name") or ""
            host = r.get("host") or r.get("matched-at") or r.get("url") or ""
            key = (tid, host)
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
    return out


SEV_W = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 1}

# An info-severity finding (banner, low-signal disclosure) must not by itself
# stand in as proof that a *different*, more serious attack step was realized
# — the evidence-floor half of F02's fix (severity is what's actually present
# on these records; there's no per-finding evidence rung on nuclei/synth/
# intel-derived findings to gate on instead).
MIN_CORROBORATION_SEVERITY = {"critical", "high", "medium", "low"}


def finding_view(f):
    info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
    tags = info.get("tags") or f.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    cls = info.get("classification") or {}
    cwes = cls.get("cwe-id") or cls.get("cwe_id") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    cwe_ids = []
    for c in cwes:
        m = re.search(r"(\d+)", str(c))
        if m:
            cwe_ids.append(int(m.group(1)))
    # Evidence: the actual data the finding pulled + where it matched.
    extracted = f.get("extracted-results") or f.get("extracted_results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    cve = cls.get("cve-id") or cls.get("cve_id")
    cves = [cve] if isinstance(cve, str) else (cve or [])
    return {
        "ref": f.get("template-id") or f.get("templateID") or info.get("name") or f.get("name") or "?",
        "name": info.get("name") or f.get("name") or "",
        "description": (info.get("description") or "").strip()[:300],
        "host": _host_only(f.get("host") or f.get("matched-at") or f.get("url") or ""),
        "severity": (info.get("severity") or f.get("severity") or "unknown").lower(),
        "tags": [str(t).lower() for t in tags],
        "cwes": cwe_ids,
        # WHERE the data is:
        "location": {
            "url": f.get("url") or "",
            "matched_at": f.get("matched-at") or f.get("matched") or f.get("url") or "",
            "host": f.get("host") or "",
            "port": str(f.get("port") or ""),
            "method": (f.get("type") or "http"),
        },
        # WHAT the data is (evidence):
        "evidence": {
            "extracted": [str(x)[:160] for x in extracted[:8]],
            "matcher": f.get("matcher-name") or f.get("matcher_name") or "",
            "curl": (f.get("curl-command") or f.get("curl_command") or "")[:400],
            "template": f.get("template") or f.get("template-path") or "",
            "template_ref": f.get("template-url") or "",
        },
        "cves": [str(c) for c in cves if c],
    }


def _fdetail(fv):
    """Compact 'what / where / evidence' block for a finding, for the path output."""
    return {
        "ref": fv["ref"], "name": fv["name"], "severity": fv["severity"],
        "description": fv.get("description", ""),
        "location": fv.get("location", {}),
        "evidence": fv.get("evidence", {}),
        "cwes": [f"CWE-{c}" for c in fv.get("cwes", [])],
        "cves": fv.get("cves", []),
    }


def map_to_capec(fv, patterns, cwe_index):
    """Return the set of CAPEC ids a finding maps to, via lane/keyword then CWE."""
    hits = set()
    blob = " ".join(fv["tags"]) + " " + fv["ref"].lower() + " " + fv["name"].lower()
    for lane, cid in LANE_CAPEC.items():
        if lane in fv["tags"] or re.search(r"\b" + re.escape(lane) + r"\b", blob):
            if cid in patterns:
                hits.add(cid)
    for w in fv["cwes"]:
        for cid in cwe_index.get(w, ()):
            hits.add(cid)
    return hits


# ---------------------------------------------------------------------------
# Asset facts (for prerequisite gating / annotation)
# ---------------------------------------------------------------------------

def asset_facts(scan_dir):
    facts = {"hosts": set(), "techs": set(), "has_api": False,
             "has_auth_finding": False, "cloud": False, "services": set()}
    p = os.path.join(scan_dir, "04_http_discovery", "tech_manifest.jsonl")
    for r in _iter_jsonl(p):
        if r.get("host"):
            facts["hosts"].add(r["host"])
        facts["techs"].update(t.lower() for t in (r.get("techs") or []))
    ar = os.path.join(scan_dir, "08_directory_discovery", "attack_routing.jsonl")
    for r in _iter_jsonl(ar):
        if r.get("url_class") == "api":
            facts["has_api"] = True
        if r.get("attack") in ("auth-jwt", "bola"):
            facts["has_auth_finding"] = True
    if os.path.isdir(os.path.join(scan_dir, "17_cloud_exposure")):
        facts["cloud"] = True
    return facts


def _reachability_note(prereqs, facts):
    """Light, honest annotation — never a hard block in a black-box context."""
    txt = " ".join(prereqs).lower()
    if any(k in txt for k in ("authenticat", "valid account", "credential", "logged")) \
            and not facts["has_auth_finding"]:
        return "needs credentials — chain from a credential-exposure finding to reach it"
    if "physical" in txt:
        return "requires physical access — out of scope for remote EASM"
    return None


# ---------------------------------------------------------------------------
# Path building
# ---------------------------------------------------------------------------

def capec_label(cid, patterns):
    return f"CAPEC-{cid}"


def terminal_impact(cid, patterns):
    impacts = []
    for c in patterns.get(cid, {}).get("consequences", []):
        impacts.extend(c.get("impact") or [])
    return sorted(set(impacts))


HIGH_IMPACT = {"Execute Unauthorized Commands", "Gain Privileges", "Bypass Protection Mechanism",
               "Read Data", "Modify Data", "Hide Activities"}


def build_paths(findings, patterns, precedes, parent_of, cwe_index, facts,
                out_of_scope=frozenset(), max_depth=3, fqdn_to_ip=None):
    fqdn_to_ip = fqdn_to_ip or {}
    def _succ(cid):
        return {n for n in precedes_effective(cid, precedes, parent_of)
                if n in patterns and n not in out_of_scope}

    kg = KnowledgeGraph()
    troot = kg.add_node("target", ",".join(sorted(facts["hosts"]))[:60] or "target")

    # index: which CAPECs are realized by a finding (for corroboration)
    capec_findings = defaultdict(list)
    mapped = []
    for f in findings:
        fv = finding_view(f)
        cids = {c for c in map_to_capec(fv, patterns, cwe_index) if c not in out_of_scope}
        if not cids:
            continue
        fnode = kg.add_node("finding", f"{fv['ref']}@{fv['host']}"[:70],
                            severity=fv["severity"], host=fv["host"])
        kg.add_edge(troot, "has", fnode)
        for cid in cids:
            cnode = kg.add_node("capec", capec_label(cid, patterns),
                                name=patterns[cid]["name"], abstraction=patterns[cid]["abstraction"])
            kg.add_edge(fnode, "exploits", cnode)
            capec_findings[cid].append(fv)
        mapped.append((fv, cids))

    # add CAPEC→CAPEC enabling edges (only among in-scope reachable successors)
    for cid in list(capec_findings):
        for nxt in _succ(cid):
            kg.add_edge(kg.add_node("capec", capec_label(cid, patterns), name=patterns[cid]["name"]),
                        "enables",
                        kg.add_node("capec", capec_label(nxt, patterns), name=patterns[nxt]["name"]))

    # walk chains from each mapped finding
    paths = []
    for fv, cids in mapped:
        for entry_cid in cids:
            steps = []
            # Frontier carries the "anchor" host each hop is grounded on —
            # starts at the entry finding's host, and moves to wherever a
            # realized hop's corroborating finding actually was (F02 fix:
            # a hop can only be "realized" by evidence on the SAME asset as
            # where the chain currently stands, not anywhere in the scan).
            frontier = [(entry_cid, 0, fv["host"])]
            visited = {entry_cid}
            realized_hops = 0
            while frontier:
                cur, depth, anchor_host = frontier.pop(0)
                if depth >= max_depth:
                    continue
                for nxt in sorted(_succ(cur)):
                    if nxt in visited:
                        continue
                    visited.add(nxt)
                    candidates = [
                        x for x in capec_findings.get(nxt, [])
                        if x["severity"] in MIN_CORROBORATION_SEVERITY
                        and same_asset(anchor_host, x["host"], fqdn_to_ip)
                    ]
                    realized = bool(candidates)
                    proof = candidates[0] if candidates else None
                    next_anchor = proof["host"] if proof else anchor_host
                    if realized:
                        realized_hops += 1
                    pn = patterns[nxt]
                    note = _reachability_note(pn["prereqs"], facts)
                    steps.append({
                        "capec": capec_label(nxt, patterns),
                        "name": pn["name"],
                        "nature": "CanPrecede",
                        "realized": realized,
                        # WHO proves this hop (enriched: what/where/evidence),
                        # and on which asset that proof was grounded:
                        "by": (_fdetail(proof) if realized else None),
                        "host_grounded": next_anchor if realized else None,
                        # HOW to carry out this attack step + how to defend:
                        "what": pn.get("description", ""),
                        "how_to_attack": pn.get("how", [])[:4],
                        "mitigation": (pn.get("mitigations") or [""])[0],
                        "skill": pn.get("skill", ""),
                        "prerequisite": (pn["prereqs"][0] if pn["prereqs"] else ""),
                        "reachability_note": note,
                        "impact": terminal_impact(nxt, patterns)[:4],
                    })
                    frontier.append((nxt, depth + 1, next_anchor))
            if not steps:
                continue  # a lone finding with no successors is not a "path"
            impacts = sorted({im for s in steps for im in s["impact"]})
            prereq_misses = sum(1 for s in steps
                                if s.get("reachability_note") and not s["realized"])
            sev = SEV_W.get(fv["severity"], 1)
            score = (sev
                     + 2.0 * realized_hops
                     - 1.0 * prereq_misses
                     + (2 if any(im in HIGH_IMPACT for im in impacts) else 0))
            narrative = " → ".join(
                [f"{fv['name'] or fv['ref']} ({capec_label(entry_cid, patterns)})"]
                + [f"{s['name']} ({s['capec']})" for s in steps[:4]])
            # The single concrete next move (for the operator / autonomous engine).
            open_steps = [s for s in steps if not s["realized"]]
            if open_steps:
                ns = open_steps[0]
                nxt_action = f"Attempt {ns['name']} ({ns['capec']}) — " + (
                    ns["how_to_attack"][0] if ns["how_to_attack"] else (ns["what"][:140] or "chain from the entry"))
            else:
                loc = fv.get("location", {}).get("matched_at") or fv["host"]
                nxt_action = f"Re-confirm the entry finding at {loc}, then pivot along the chain."
            ep = patterns[entry_cid]
            paths.append({
                "score": round(score, 2),
                "realized": realized_hops > 0,
                # Always True here: grounding is enforced structurally by the
                # same_asset() check above, not situational — a "realized"
                # hop in this path can only ever be true because it passed it.
                "host_grounded": True,
                "entry": {
                    "capec": capec_label(entry_cid, patterns),
                    "capec_name": ep["name"],
                    "capec_what": ep.get("description", ""),
                    "finding": _fdetail(fv),
                    # flat convenience fields (back-compat with the current GUI)
                    "ref": fv["ref"], "host": fv["host"], "severity": fv["severity"],
                },
                "steps": steps[:8],
                "impact": impacts[:6],
                "narrative": narrative,
                "next_action": nxt_action,
            })

    # dedupe identical narratives, rank
    seen_n, uniq = set(), []
    for p in sorted(paths, key=lambda x: -x["score"]):
        if p["narrative"] in seen_n:
            continue
        seen_n.add(p["narrative"])
        uniq.append(p)
    for i, p in enumerate(uniq, 1):
        p["rank"] = i
    return uniq, kg, mapped


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# C6 — Cloud attack-path edges (recon → cloud takeover)
#
# Three-tier evidence model (strongest → weakest):
#   confirmed  = active exploitation produced differential proof
#                (SSRF fetched IMDS creds, SQLi dumped data)
#   observed   = artifact/credential pattern found but NOT validated
#                (key regex hit in JS bundle, .publishsettings file)
#   recon      = passive infrastructure exists (DNS resolves, MX record)
#
# Each chain declares min_tier — the weakest evidence it accepts for
# `realized`.  A chain triggered by recon-only seeds stays "potential".
# ---------------------------------------------------------------------------

EVIDENCE_TIERS = {"confirmed": 3, "observed": 2, "recon": 1}

CLOUD_CHAINS = [
    {
        "id": "cloud-ssrf-imds-takeover",
        "entry": {"ssrf_to_imds"},
        "min_tier": "confirmed",
        "title": "SSRF → IMDS credential theft → cloud takeover",
        "steps": ["SSRF sink reaches instance metadata (IMDSv1)",
                  "steal IAM/role credentials from metadata",
                  "authenticate to cloud API as the instance role",
                  "enumerate + access data / escalate"],
        "capec": ["CAPEC-664", "CAPEC-115"], "mitre": ["T1552.005", "T1078.004"],
        "impact": ["Gain Privileges", "Read Data"], "base": 95,
    },
    {
        "id": "cloud-leakedkey-snapshot-reuse",
        "entry": {"leaked_cloud_credential"},
        "min_tier": "observed",
        "title": "Leaked key → disk snapshot → offline crack → credential reuse → VM",
        "steps": ["use leaked cloud key against control plane",
                  "snapshot/download VM OS disk (VHD/EBS)",
                  "offline-mount, extract SAM/SYSTEM or /etc/shadow",
                  "crack hashes, reuse creds against live VM (RDP/SSH/WinRM)",
                  "lateral movement"],
        "capec": ["CAPEC-560", "CAPEC-37"], "mitre": ["T1078.004", "T1552", "T1110.002"],
        "impact": ["Gain Privileges", "Read Data", "Execute Unauthorized Commands"],
        "base": 90,
    },
    {
        "id": "cloud-rbac-vm-reset",
        "entry": {"leaked_cloud_credential"},
        "min_tier": "observed",
        "title": "Control-plane RBAC → VM credential reset → VM takeover",
        "steps": ["leaked key grants VM-write/owner RBAC",
                  "reset local admin password / SSH key via control plane "
                  "(no prior cred needed)",
                  "log in to the VM as admin"],
        "capec": ["CAPEC-122"], "mitre": ["T1098.004", "T1078.004"],
        "impact": ["Gain Privileges", "Execute Unauthorized Commands"], "base": 85,
    },
    {
        "id": "cloud-sas-blob-secrets",
        "entry": {"writable_sas", "public_bucket"},
        "min_tier": "observed",
        "title": "Storage key/SAS leak → blob access → secrets → escalate",
        "steps": ["use leaked SAS/storage key or anon bucket",
                  "download objects; find embedded secrets/config",
                  "pivot with recovered secrets"],
        "capec": ["CAPEC-150", "CAPEC-118"], "mitre": ["T1530", "T1552.001"],
        "impact": ["Read Data", "Gain Privileges"], "base": 80,
    },
    {
        "id": "cloud-keyvault-runas",
        "entry": {"leaked_cloud_credential"},
        "min_tier": "observed",
        "title": "Key Vault / Automation RunAs → stored SP creds → privilege escalation",
        "steps": ["access Key Vault / Automation account via leaked key",
                  "read stored service-principal creds / RunAs cert",
                  "assume higher-privileged principal"],
        "capec": ["CAPEC-560"], "mitre": ["T1552.005", "T1078.004"],
        "impact": ["Gain Privileges", "Read Data"], "base": 82,
    },
    {
        "id": "cloud-golden-saml",
        "entry": {"federation_present"},
        "min_tier": "observed",
        "title": "ADFS token-signing cert → Golden SAML → impersonate → bypass MFA",
        "steps": ["compromise ADFS / AAD-Connect sync account",
                  "steal token-signing certificate",
                  "forge SAML tokens for any user",
                  "access federated cloud services, bypassing MFA"],
        "capec": ["CAPEC-21", "CAPEC-473"], "mitre": ["T1606.002", "T1199"],
        "impact": ["Gain Privileges", "Bypass Protection Mechanism"], "base": 88,
    },
    {
        "id": "cloud-onprem-pivot",
        "entry": {"leaked_cloud_credential", "federation_present"},
        "min_tier": "observed",
        "title": "Cloud → on-prem pivot (VPN / Service Bus / Logic Apps / Hybrid Worker)",
        "steps": ["leverage cloud foothold's hybrid connectivity",
                  "reach internal services via VPN gateway / Service Bus relay / "
                  "Logic Apps / Hybrid Runbook Worker",
                  "re-enter on-prem network ('circle of access')"],
        "capec": ["CAPEC-107"], "mitre": ["T1090", "T1021"],
        "impact": ["Execute Unauthorized Commands", "Read Data"], "base": 78,
    },
    {
        "id": "cloud-password-spray",
        "entry": {"federation_present", "mail_provider"},
        "min_tier": "recon",
        "title": "Password spray (low-and-slow) → cloud / VPN initial access",
        "steps": ["enumerate valid users from OSINT/SaaS footprint",
                  "low-and-slow spray common passwords against cloud auth",
                  "obtain a valid session, bypass lockout"],
        "capec": ["CAPEC-49", "CAPEC-565"], "mitre": ["T1110.003", "T1078.004"],
        "impact": ["Gain Privileges"], "base": 60,
    },
]

_CLOUD_SEED_FILES = [
    "cloud_credentials.jsonl", "ssrf_metadata.jsonl", "cloud_buckets.jsonl",
    "presigned_urls.jsonl", "cloud_saas_fingerprint.jsonl", "cloud_posture.jsonl",
]


def _evidence_tier(record, source_file):
    """Classify a cloud finding into confirmed / observed / recon.

    confirmed = the originating module's own differential test proved it
    observed  = artifact found (cred pattern, config file, writable bucket)
    recon     = passive infrastructure lookup (DNS, MX, SaaS attribution)
    """
    conf = (record.get("confidence") or "").lower()
    if conf == "confirmed":
        return "confirmed"
    if source_file == "cloud_saas_fingerprint.jsonl":
        return "recon"
    sev = (record.get("severity") or "").lower()
    if sev in ("critical", "high"):
        return "observed"
    if sev == "medium":
        return "observed"
    return "recon"


def _resolve_cred_host(scan_dir):
    """cloud_cred_scan.py's CredFinding only records a bare staged filename
    (source_file), never a host — reverse-map it back to the real source URL
    via the same index.tsv manifests easm-pipeline.sh's own credential fold
    reads (10_secret_scanning/staged/{js_downloads,http_responses_2xx}/
    index.tsv: url<TAB>filename). This is what CLOUD_CHAINS' host field was
    missing (F02/§4 in ARISE_REMEDIATION_ROADMAP.md)."""
    url_map = {}
    for sub in ("js_downloads", "http_responses_2xx"):
        idx = os.path.join(scan_dir, "10_secret_scanning", "staged", sub, "index.tsv")
        if not os.path.exists(idx):
            continue
        for line in open(idx, errors="ignore"):
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 2:
                url_map[parts[1]] = parts[0]
    return url_map


def load_cloud_seeds(scan_dir):
    """Walk the scan dir for cloud-module outputs and collect present seed
    markers. Returns {seed: {"tier":str, "evidence":str, "count":int, "hosts":[...]}}.
    Tier is the HIGHEST tier seen across all findings for that seed."""
    seeds = {}
    cred_url_map = _resolve_cred_host(scan_dir)

    def _bump(seed, evidence, tier, host=""):
        s = seeds.setdefault(seed, {"tier": "recon", "evidence": "", "count": 0, "hosts": set()})
        s["count"] += 1
        if EVIDENCE_TIERS.get(tier, 0) > EVIDENCE_TIERS.get(s["tier"], 0):
            s["tier"] = tier
        if not s["evidence"]:
            s["evidence"] = evidence[:160]
        if host:
            s["hosts"].add(host)

    for root, _dirs, files in os.walk(scan_dir):
        for fn in files:
            if fn not in _CLOUD_SEED_FILES:
                continue
            for r in _iter_jsonl(os.path.join(root, fn)):
                seed = r.get("attack_path_seed") or r.get("seed") or ""
                tier = _evidence_tier(r, fn)
                host = (r.get("host") or "").strip().lower()
                if not host:
                    for k in ("url", "endpoint"):
                        if r.get(k):
                            host = _host_only(r[k])
                            break
                if not host and fn == "cloud_credentials.jsonl":
                    src = os.path.basename(r.get("source_file") or r.get("file") or "")
                    src_url = cred_url_map.get(src, "")
                    if src_url:
                        host = _host_only(src_url)
                if seed:
                    _bump(seed, r.get("evidence") or r.get("note") or seed, tier, host)
                if fn == "cloud_saas_fingerprint.jsonl":
                    if r.get("category") == "mail":
                        _bump("mail_provider",
                              f"mail provider: {r.get('provider','')}", "recon", host)
                    if r.get("category") == "federation":
                        _bump("federation_present",
                              r.get("note", "federation host live"), "recon", host)
    for s in seeds.values():
        s["hosts"] = sorted(s["hosts"])
    return seeds


def build_cloud_paths(scan_dir):
    """Emit cloud attack-path dicts for chains whose entry seeds are present.
    `realized` requires every entry seed to meet the chain's min_tier."""
    seeds = load_cloud_seeds(scan_dir)
    present = set(seeds)
    paths = []
    seen_entry = {}

    for chain in CLOUD_CHAINS:
        trigger = chain["entry"] & present
        if not trigger:
            continue

        min_tier = chain.get("min_tier", "observed")
        min_val = EVIDENCE_TIERS.get(min_tier, 2)
        entry_tiers = [seeds[s]["tier"] for s in trigger]
        weakest = min(EVIDENCE_TIERS.get(t, 0) for t in entry_tiers)
        realized = weakest >= min_val

        evidence = "; ".join(seeds[s]["evidence"] for s in sorted(trigger))
        tier_label = "/".join(sorted(set(entry_tiers)))
        entry_hosts = sorted({h for s in trigger for h in seeds[s].get("hosts", [])})
        entry_host = entry_hosts[0] if entry_hosts else ""

        if realized:
            tier_bonus = 5
        elif weakest >= EVIDENCE_TIERS["observed"]:
            tier_bonus = -5
        else:
            tier_bonus = -20

        score = chain["base"] + tier_bonus

        ev_key = frozenset(trigger)
        if ev_key in seen_entry and not realized:
            prev = seen_entry[ev_key]
            if score <= prev:
                score = min(score, chain["base"] - 25)
        seen_entry.setdefault(ev_key, score)

        narrative = f"{chain['title']} — " + " → ".join(chain["steps"])
        steps_objs = [{"capec": chain["capec"][0] if chain["capec"] else "",
                       "name": s, "realized": False, "by": None,
                       "what": s, "how_to_attack": [], "mitigation": "",
                       "skill": "", "prerequisite": "",
                       "reachability_note": None, "impact": chain["impact"],
                       "nature": "cloud-chain"} for s in chain["steps"]]
        paths.append({
            "id": chain["id"], "kind": "cloud", "score": round(score, 2),
            "realized": realized, "narrative": narrative,
            "steps": steps_objs, "entry_seed": sorted(trigger),
            "evidence": evidence, "evidence_tier": tier_label,
            "capec": chain["capec"], "mitre": chain["mitre"],
            "terminal_impact": chain["impact"],
            "impact": chain["impact"],
            # False when no seed record carried a resolvable host — honestly
            # flagged rather than silently defaulting to blank (F02/§4).
            "host_grounded": bool(entry_host),
            "entry": {
                "capec": chain["capec"][0] if chain["capec"] else "",
                "capec_name": chain["title"].split(" → ")[0],
                "finding": {"name": chain["title"], "description": evidence,
                            "severity": "critical" if realized else "medium",
                            "location": {"host": entry_host}, "evidence": {"extracted": [evidence[:120]]},
                            "cwes": [], "cves": []},
                "ref": chain["id"], "host": entry_host, "hosts": entry_hosts,
                "severity": "critical" if realized else "medium",
            },
            "next_action": chain["steps"][-1] if chain["steps"] else "",
            "note": (f"exploitation evidence meets {min_tier} threshold"
                     if realized else
                     f"entry evidence is {tier_label} (chain needs {min_tier}) — investigate to confirm"),
        })

    paths.sort(key=lambda p: -p["score"])
    return paths, seeds


def main():
    ap = argparse.ArgumentParser(description="CAPEC Attack-Path Builder (ARISE L6)")
    ap.add_argument("scan_dir")
    ap.add_argument("--capec", default=DEFAULT_CAPEC, help="path to capec_v3.9.xml")
    ap.add_argument("--out", help="output dir (default: <scan_dir>/25_attack_paths)")
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    if not os.path.isdir(args.scan_dir):
        print(f"error: not a directory: {args.scan_dir}", file=sys.stderr)
        return 2
    if not os.path.exists(args.capec):
        print(f"error: CAPEC xml not found: {args.capec}", file=sys.stderr)
        return 2

    patterns, precedes, parent_of, cwe_index, out_of_scope = load_capec(args.capec)
    findings = load_findings(args.scan_dir)
    facts = asset_facts(args.scan_dir)
    fqdn_to_ip, _ip_to_fqdns = load_host_graph(args.scan_dir)
    paths, kg, mapped = build_paths(findings, patterns, precedes, parent_of,
                                    cwe_index, facts, out_of_scope, args.max_depth,
                                    fqdn_to_ip=fqdn_to_ip)

    # C6 — merge cloud attack-path chains (recon → cloud takeover)
    cloud_paths, cloud_seeds = build_cloud_paths(args.scan_dir)
    if cloud_paths:
        paths = paths + cloud_paths
        paths.sort(key=lambda p: -p.get("score", 0))

    out_dir = args.out or os.path.join(args.scan_dir, "25_attack_paths")
    os.makedirs(out_dir, exist_ok=True)
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_dir": os.path.abspath(args.scan_dir),
        # Presence of this key is what the dashboard uses to trust a path's
        # "realized"/"host_grounded" fields — any capec_attack_paths.json on
        # disk from before this fix lacks it and is rendered as unverified
        # regardless of its own realized flag (ARISE_REMEDIATION_ROADMAP.md §4).
        "attack_path_engine": "host-grounded-v2",
        "capec_version": "3.9",
        "capec_patterns_loaded": len(patterns),
        "precede_edges": sum(len(v) for v in precedes.values()),
        "findings_total": len(findings),
        "findings_mapped": len(mapped),
        "asset_facts": {k: (sorted(v) if isinstance(v, set) else v) for k, v in facts.items()},
        "kg_summary": kg.summary(),
        "cloud_seeds_present": sorted(cloud_seeds),
        "cloud_paths_count": len(cloud_paths),
        "paths": paths,
    }
    with open(os.path.join(out_dir, "capec_attack_paths.json"), "w") as fh:
        json.dump(doc, fh, indent=2)
    with open(os.path.join(out_dir, "capec_kg.json"), "w") as fh:
        json.dump(kg.to_dict(), fh, indent=2)

    realized = sum(1 for p in paths if p["realized"])
    print(f"[capec] {len(patterns)} patterns, {doc['precede_edges']} precede-edges | "
          f"{len(mapped)}/{len(findings)} findings mapped → {len(paths)} paths "
          f"({realized} realized) → {out_dir}")
    if args.summary:
        for p in paths[:8]:
            flag = "★ realized" if p["realized"] else "  open"
            print(f"  [{p['score']:>4}] {flag}  {p['narrative'][:120]}")
        if not paths:
            print("  (no chains — either no confirmed findings yet, or none map to a CAPEC with successor edges)")
    return 0


def _selftest() -> int:
    """Host-grounding self-test (F02, ARISE_REMEDIATION_ROADMAP.md) — a chain
    hop must only be 'realized' by evidence on the same or IP-linked host,
    never by a coincidental CAPEC-ID match anywhere else in the scan."""
    # -- same_asset() --
    assert same_asset("a.com", "a.com", {}) is True
    assert same_asset("a.com", "b.com", {}) is False, "no shared-IP data -> must fail safe, not open"
    assert same_asset("a.com", "b.com", {"a.com": "1.1.1.1", "b.com": "1.1.1.1"}) is True
    assert same_asset("a.com", "b.com", {"a.com": "1.1.1.1", "b.com": "2.2.2.2"}) is False
    print("[1] same_asset: exact host, shared-IP linkage, fail-safe with no data  ✓")

    # -- build_paths(): realized-hop requires host grounding --
    patterns = {
        66: {"id": 66, "name": "SQL Injection", "abstraction": "Standard", "prereqs": [],
             "cwes": [], "consequences": [], "description": "", "how": [], "mitigations": [], "skill": ""},
        1: {"id": 1, "name": "Accessing Functionality Not Properly Constrained by ACLs",
            "abstraction": "Standard", "prereqs": [], "cwes": [], "consequences": [],
            "description": "", "how": [], "mitigations": [], "skill": ""},
    }
    precedes = {66: {1}}
    parent_of = {}
    cwe_index = {}
    facts = {"hosts": {"api.target.com", "other.target.com"}, "techs": set(),
            "has_api": True, "has_auth_finding": False, "cloud": False, "services": set()}

    def _nuclei(host, tid, sev="high"):
        return {"template-id": tid, "host": host, "matched-at": f"https://{host}/x",
                "info": {"name": tid, "severity": sev, "tags": [tid]}}

    entry = _nuclei("api.target.com", "sqli")
    same_host_corrob = _nuclei("api.target.com", "bola")
    other_host_corrob = _nuclei("other.target.com", "bola")

    # Case A: corroborating finding on a DIFFERENT, unrelated host -> must NOT realize
    paths_a, _kg_a, _m_a = build_paths([entry, other_host_corrob], patterns, precedes,
                                       parent_of, cwe_index, facts, fqdn_to_ip={})
    realized_a = [p for p in paths_a if p["realized"]]
    assert not realized_a, \
        f"a same-CAPEC-ID finding on an UNRELATED host must not realize a hop, got {realized_a}"

    # Case B: corroborating finding on the SAME host -> must realize
    paths_b, _kg_b, _m_b = build_paths([entry, same_host_corrob], patterns, precedes,
                                       parent_of, cwe_index, facts, fqdn_to_ip={})
    realized_b = [p for p in paths_b if p["realized"]]
    assert realized_b, "a corroborating finding on the SAME host must realize the hop"
    assert all(p.get("host_grounded") for p in paths_b)
    print("[2] build_paths: realized-hop requires same-host/IP grounding, not just CAPEC-ID  ✓")

    # Case C: an info-severity corroborator must not anchor a realized hop
    weak_corrob = _nuclei("api.target.com", "bola", sev="info")
    paths_c, _kg_c, _m_c = build_paths([entry, weak_corrob], patterns, precedes,
                                       parent_of, cwe_index, facts, fqdn_to_ip={})
    assert not [p for p in paths_c if p["realized"]], \
        "an info-severity finding must not be sufficient to realize a hop"
    print("[3] build_paths: info-severity findings can't anchor a realized hop  ✓")

    print("\ncapec_attack_paths host-grounding self-test: ALL PASS")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    raise SystemExit(main())
