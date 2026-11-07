"""
Shared attack-surface knowledge graph.

Neutral home for the asset/finding graph used across ARISE: the AriseAI engine,
the CAPEC chainer (intel/capec_attack_paths.py), and the attack-chain-v2
subsystem (intel/evidence_graph, chain_gate, chain_architect, chain_scoring,
chokepoint). Previously this class lived inside arise_autonomous.py, which forced
every one of those modules to import the whole Autonomous engine just to get a
graph data structure. It now lives here with no engine dependencies; stdlib only,
never raises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class KnowledgeGraph:
    nodes: Dict[str, dict] = field(default_factory=dict)
    edges: List[dict] = field(default_factory=list)

    def add_node(self, ntype: str, label: str, **attrs) -> str:
        nid = f"{ntype}:{label}"
        if nid not in self.nodes:
            self.nodes[nid] = {"type": ntype, "label": label, "attrs": {}}
        self.nodes[nid]["attrs"].update({k: v for k, v in attrs.items() if v})
        return nid

    def add_edge(self, src: str, rel: str, dst: str) -> None:
        e = {"src": src, "rel": rel, "dst": dst}
        if e not in self.edges:
            self.edges.append(e)

    def seed_from_context(self, context: dict) -> None:
        target = context.get("target")
        troot = self.add_node("target", target) if target else None
        for h in (context.get("sensitive_services") or []):
            hn = self.add_node("host", h.get("host", ""))
            pn = self.add_node("port", str(h.get("port", "")), service=h.get("service", ""))
            self.add_edge(hn, "exposes", pn)
            if troot:
                self.add_edge(troot, "owns", hn)
        for v in (context.get("top_vulnerabilities") or []):
            fid = self.add_node("finding", v.get("title", "finding"),
                                severity=v.get("severity", ""), source=v.get("source", ""))
            if v.get("host"):
                self.add_edge(self.add_node("host", v["host"]), "has", fid)
        for c in (context.get("cves") or []):
            cid = c.get("cve") if isinstance(c, dict) else str(c)
            if cid:
                self.add_node("cve", cid)
        for a in (context.get("api_findings") or []):
            ep = a.get("endpoint") or ""
            if ep:
                self.add_node("endpoint", ep, issue=a.get("issue", ""))

    def summary(self) -> dict:
        by_type: Dict[str, int] = {}
        for n in self.nodes.values():
            by_type[n["type"]] = by_type.get(n["type"], 0) + 1
        return {"node_counts": by_type, "edge_count": len(self.edges)}

    def to_dict(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": self.edges, "summary": self.summary()}

    def compact(self, cap: int = 60) -> str:
        """A token-bounded textual view for feeding to specialist workers."""
        lines = [f"- {n['type']}: {n['label']}"
                 + (f" ({', '.join(f'{k}={v}' for k, v in n['attrs'].items())})" if n["attrs"] else "")
                 for n in list(self.nodes.values())[:cap]]
        return "\n".join(lines)
