#!/usr/bin/env python3
"""Regression: discovery/url_classify.py AI/MCP surface tagging (Phase 0 of the
MCP_AI_DISCOVERY roadmap). The ai_surface/ai_flavor/ai_confidence tag is
ORTHOGONAL to url_class — this test asserts (a) every AI/MCP stack is detected
with the right surface, (b) no false positives on look-alike plain URLs, and
(c) the existing url_class / routed_to behaviour of non-AI URLs is unchanged.
Offline — no network.  Run:  python3 tests/test_ai_surface_classify.py
"""
from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import discovery.url_classify as uc

_fail = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {detail}" if detail and not cond else ""))


def surface_of(url, **kw):
    c = uc.classify_url(url, **kw)
    return c["ai_surface"], c["ai_flavor"], c["ai_confidence"]


print("== positive: AI/MCP surfaces are detected ==")
POS = [
    # url, expected surface, expected flavor substring
    ("https://mcp.example.com/mcp", "mcp", "streamable"),
    ("https://example.com/sse", "mcp", "sse"),
    ("https://example.com/.well-known/mcp.json", "mcp", "wellknown"),
    ("https://example.com/.well-known/mcp/server-card.json", "mcp", None),
    ("https://ai.example.com/v1/chat/completions", "llm-api", "openai"),
    ("https://example.com/v1/models", "llm-api", "openai"),
    ("https://example.com/v1/embeddings", "llm-api", "openai"),
    ("https://ollama.example.com/api/tags", "llm-api", "ollama"),
    ("https://example.com/api/ps", "llm-api", "ollama"),
    ("https://example.com/v2/models", "llm-api", "triton"),
    ("https://example.com/input_schema", "ai-agent", "langserve"),
    ("https://example.com/config_schema", "ai-agent", "langserve"),
    ("https://example.com/run/predict", "ai-agent", "gradio"),
    ("https://example.com/api/v1/prediction/abc", "ai-agent", "appflow"),
]
for url, exp_surface, exp_flavor in POS:
    s, f, conf = surface_of(url)
    check(f"{url} -> {exp_surface}", s == exp_surface, f"got surface={s}")
    if exp_flavor:
        check(f"  flavor~{exp_flavor}", bool(f) and exp_flavor in f, f"got flavor={f}")
    check("  confidence is path-hint", conf == "path-hint", f"got {conf}")

print("== host-label is ASSET-level only, NOT per-URL (no inventory flood) ==")
# ai_surface(host_label=True) tags an AI-named host — used at the ASSET level.
for host_url, exp in [("https://copilot.example.com/", "ai-agent"),
                      ("https://vectordb.example.com/x", "vector-db"),
                      ("https://llm.example.com/anything", "llm-api"),
                      ("https://mcp-server.zomato.com/graphql", "mcp")]:
    s, _, _ = uc.ai_surface(host_url, host=uc._host_of(host_url))      # default host_label=True
    check(f"ai_surface() host-label: {host_url} -> {exp}", s == exp, f"got {s}")
# But classify_url (URL-level) must NOT tag these — a plain path on an AI host
# is not itself an AI endpoint (this is the mcp-server.zomato.com flood fix).
for host_url in ["https://copilot.example.com/", "https://mcp-server.zomato.com/graphql",
                 "https://mcp-server.zomato.com/app", "https://llm.example.com/about"]:
    s, _, _ = surface_of(host_url, status=200)
    check(f"classify_url does NOT flood-tag {host_url}", s is None, f"got {s}")
# The actual MCP transport path ON that host still tags (path-based).
s, _, _ = surface_of("https://mcp-server.zomato.com/mcp", status=401)
check("classify_url tags the /mcp path on an MCP host", s == "mcp", f"got {s}")
# public host-label helper
check("ai_host_label(mcp-server.zomato.com) == mcp",
      uc.ai_host_label("mcp-server.zomato.com") == "mcp")
check("ai_host_label(www.zomato.com) is None",
      uc.ai_host_label("www.zomato.com") is None)

print("== fingerprint tier: body/header upgrade confidence ==")
# MCP initialize response body
s, f, conf = surface_of(
    "https://example.com/rpc",
    body='{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
         '"serverInfo":{"name":"x"},"capabilities":{"tools":{}}}}')
check("MCP jsonrpc body -> mcp/fingerprint", s == "mcp" and conf == "fingerprint",
      f"got {s}/{conf}")
# Mcp-Session-Id header
s, _, conf = surface_of("https://example.com/anything",
                        headers={"Mcp-Session-Id": "abc123"})
check("Mcp-Session-Id header -> mcp/fingerprint", s == "mcp" and conf == "fingerprint",
      f"got {s}/{conf}")
# OpenAI model list body on the right path
s, f, conf = surface_of(
    "https://example.com/v1/models",
    body='{"object":"list","data":[{"id":"gpt-4","object":"model"}]}')
check("OpenAI model-list body -> llm-api/fingerprint",
      s == "llm-api" and conf == "fingerprint", f"got {s}/{conf}")
# Ollama /api/tags body
s, f, conf = surface_of("https://example.com/api/tags",
                        body='{"models":[{"name":"llama3"}]}')
check("Ollama tags body -> llm-api/fingerprint",
      s == "llm-api" and conf == "fingerprint", f"got {s}/{conf}")

print("== confirmed override (probe module handshake) ==")
c = uc.classify_url("https://example.com/mcp", ai_surface_override="mcp",
                    ai_flavor_override="mcp-streamable",
                    ai_confidence_override="confirmed")
check("override upgrades to confirmed", c["ai_confidence"] == "confirmed",
      f"got {c['ai_confidence']}")

print("== negative: NO false positives ==")
NEG = [
    "https://mailchimp.com/campaigns",      # 'ai' substring inside mailchimp
    "https://example.com/messages",         # chat inbox, not MCP legacy POST-back
    "https://example.com/api/chat",         # generic chat API, not Ollama
    "https://example.com/v1/users/123",     # versioned API, not inference
    "https://airtable.com/records",         # 'air' substring
    "https://example.com/aircraft/42",      # 'air' substring, path id
    "https://chairman.example.com/",        # 'chair' contains 'ai'? whole-label no
    "https://example.com/assets/app.js",    # static
]
for url in NEG:
    s, _, _ = surface_of(url, status=200)
    check(f"{url} not AI", s is None, f"got surface={s}")

print("== non-regression: non-AI url_class / routing unchanged ==")
c = uc.classify_url("https://api.groww.in/v1/users/12345?sort=asc", status=200)
check("api url still url_class=api", c["url_class"] == "api")
check("api url ai_surface is None", c["ai_surface"] is None)
check("api url has no ai-* lanes",
      not any(r.startswith("ai-") or r.startswith("mcp-") for r in c["routed_to"]))
c = uc.classify_url("https://groww.in/graphql", status=200)
check("graphql lane intact", "graphql" in c["routed_to"])

print("== schema: AI keys always present (uniform record) ==")
c = uc.classify_url("https://example.com/plain-page", status=200)
check("ai_surface key present", "ai_surface" in c)
check("ai_flavor key present", "ai_flavor" in c)
check("ai_confidence key present", "ai_confidence" in c)

print(f"\n{'ALL PASS' if _fail == 0 else str(_fail) + ' FAILED'}")
sys.exit(1 if _fail else 0)
