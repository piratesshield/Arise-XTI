# -*- coding: utf-8 -*-
"""Scoreless counterfactual differential analysis (passive-only, non-destructive).

Ported to standalone stdlib Python 3 from BurpAPISecuritySuite's
`burp_counterfactual_methods.py` (a Jython mixin). The three invariants are
preserved verbatim in intent:

  A  authorization_must_be_representation_invariant
       — auth enforcement must not differ by request representation
         (JSON vs form vs multipart vs xml).
  B  identifier_resolution_must_not_depend_on_source_precedence
       — conflicting identifier values from >1 source must not both succeed.
  C  sensitive_response_redaction_must_be_auth_monotonic
       — a weak/anonymous context must not expose sensitive fields that a
         stronger context redacts.

Entry point:  build_counterfactual_package(data_snapshot) -> dict
`data_snapshot` = { endpoint_key: [entry, ...] } where each entry is the
unified evidence record (method, normalized_path, headers, request_body,
response_body, response_status, content_type, auth_detected, role, parameters).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import re
import time


_SENSITIVE_FIELD_TOKENS = (
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "authorization", "session", "cookie", "ssn", "social",
    "iban", "card", "cvv", "salary", "balance", "credit", "debit", "bank",
    "account_number", "private",
)

_IDENTIFIER_TOKENS = (
    "id", "user_id", "account_id", "owner_id", "tenant_id", "organization_id",
    "org_id", "project_id", "customer_id", "subject", "sub",
)

_WEAK_TOKENS = ("none", "guest", "anonymous", "unauth", "public", "noauth")


def _text(value, lower=False):
    if value is None:
        value = ""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            value = ""
    return value.lower() if lower else value


# --------------------------------------------------------------------------- #
# Per-entry feature extraction
# --------------------------------------------------------------------------- #
def _request_format(entry):
    method = _text((entry or {}).get("method") or "GET").strip().upper() or "GET"
    body_text = _text((entry or {}).get("request_body") or "").strip()
    path_text = _text((entry or {}).get("normalized_path") or (entry or {}).get("path") or "/", lower=True)
    content_type = _text((entry or {}).get("content_type") or "", lower=True).strip()
    headers = dict((entry or {}).get("headers") or {})
    if (not content_type) and headers:
        for raw_key, raw_value in headers.items():
            if _text(raw_key, lower=True).strip() == "content-type":
                content_type = _text(raw_value, lower=True).strip()
                break

    if method in ["GET", "HEAD", "OPTIONS"] and not body_text:
        return "no_body"
    if "/graphql" in path_text and ("json" in content_type or body_text.startswith("{")):
        return "graphql_json"
    if "json" in content_type:
        return "json"
    if "x-www-form-urlencoded" in content_type:
        return "form_urlencoded"
    if "multipart/form-data" in content_type:
        return "multipart"
    if "xml" in content_type or "soap" in content_type:
        return "xml"
    if body_text.startswith("{") or body_text.startswith("["):
        return "json_like"
    if "=" in body_text and "&" in body_text:
        return "form_like"
    if body_text:
        return "raw_body"
    return "unknown"


def _auth_context(entry):
    """Normalized auth-context fingerprint. Prefers an explicit role label
    (from the Burp bridge), falls back to detected auth schemes."""
    role = _text((entry or {}).get("role") or "", lower=True).strip()
    if role:
        return role
    auth_detected = [_text(x, lower=True).strip() for x in ((entry or {}).get("auth_detected") or [])]
    auth_detected = [x for x in auth_detected if x]
    if auth_detected:
        return ",".join(sorted(set(auth_detected))[:4])
    return "none"


def _is_weak_context(auth_context):
    text = _text(auth_context or "", lower=True).strip()
    if not text:
        return True
    return any(tok in text for tok in _WEAK_TOKENS)


def _status_code(entry):
    try:
        return int((entry or {}).get("response_status", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _is_success(status_code):
    value = int(status_code or 0)
    return 200 <= value < 400


def _add_param_value(container, source_name, param_name, raw_value):
    source = _text(source_name, lower=True).strip() or "unknown"
    name = _text(param_name, lower=True).strip()
    if not name:
        return
    slot = container.setdefault(name, {}).setdefault(source, set())
    if isinstance(raw_value, list):
        for item in raw_value:
            slot.add(_text(item))
        return
    if isinstance(raw_value, dict):
        try:
            slot.add(json.dumps(raw_value, sort_keys=True))
        except Exception:
            slot.add(_text(raw_value))
        return
    slot.add(_text(raw_value))


def _param_source_values(entry):
    """Flatten parameters into name -> {source -> {values}} for precedence checks.

    Accepts both the Burp `parameters` shape ({source: {name: value}}) and a
    derived shape: query params (source=query), path ids (source=path), and
    JSON body top-level keys (source=body)."""
    out = {}
    params = (entry or {}).get("parameters", {}) or {}
    if isinstance(params, dict):
        for source_name, source_values in params.items():
            if isinstance(source_values, dict):
                for pn, rv in source_values.items():
                    _add_param_value(out, source_name, pn, rv)
            elif isinstance(source_values, list):
                for pn in source_values:
                    _add_param_value(out, source_name, pn, "<present>")

    # Derive from raw URL query + path segments when parameters absent.
    url = _text((entry or {}).get("url") or "")
    if "?" in url:
        qs = url.split("?", 1)[1]
        for pair in qs.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                _add_param_value(out, "query", k, v)
    path = _text((entry or {}).get("path") or "")
    for seg in path.strip("/").split("/"):
        if re.match(r"^\d+$", seg) or re.match(r"^[0-9a-f]{8}-", seg, re.I):
            _add_param_value(out, "path", "id", seg)

    # JSON body top-level keys.
    body = _text((entry or {}).get("request_body") or "").strip()
    if body.startswith("{"):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if not isinstance(v, (dict, list)):
                        _add_param_value(out, "body", k, v)
        except Exception:
            pass
    return out


def _collect_json_paths(value, out_paths, prefix="", depth=0):
    if depth > 6:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            safe_key = _text(key).strip()
            if not safe_key:
                continue
            dotted = "{}.{}".format(prefix, safe_key) if prefix else safe_key
            out_paths.add(dotted)
            _collect_json_paths(child, out_paths, prefix=dotted, depth=depth + 1)
    elif isinstance(value, list):
        for item in value[:20]:
            _collect_json_paths(item, out_paths, prefix=prefix, depth=depth + 1)


def _extract_sensitive_fields(entry):
    body_text = _text((entry or {}).get("response_body") or "")
    if not body_text:
        return []
    parsed = None
    trimmed = body_text.lstrip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            parsed = json.loads(body_text)
        except Exception:
            parsed = None
    candidate_paths = set()
    if parsed is not None:
        _collect_json_paths(parsed, candidate_paths, prefix="", depth=0)
    else:
        for match in re.findall(r'"([A-Za-z0-9_\-]{2,64})"\s*:', body_text):
            candidate_paths.add(_text(match))
    sensitive = []
    for path in sorted(candidate_paths):
        lower = _text(path, lower=True)
        if any(tok in lower for tok in _SENSITIVE_FIELD_TOKENS):
            sensitive.append(path)
    return sensitive[:60]


def _is_identifier_param(param_name):
    text = _text(param_name or "", lower=True).strip()
    if not text:
        return False
    if text in _IDENTIFIER_TOKENS:
        return True
    return bool(re.search(r"(^|_|\.)id$", text))


def _add_finding(findings, invariant_name, title, severity, endpoint_key,
                 evidence_lines, suggested_checks):
    findings.append({
        "id": "cdf-{0:03d}".format(len(findings) + 1),
        "category": "COUNTERFACTUAL",
        "invariant": _text(invariant_name),
        "title": _text(title),
        "severity": _text(severity, lower=True),
        "endpoint_scope": [_text(endpoint_key)],
        "evidence": [_text(x) for x in list(evidence_lines or [])[:12] if _text(x).strip()],
        "suggested_checks": [_text(x) for x in list(suggested_checks or [])[:8] if _text(x).strip()],
        "non_destructive": True,
        "no_scoring": True,
    })


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_counterfactual_findings(data_snapshot, get_entry=None):
    endpoint_rows = {}
    for endpoint_key, entries in (data_snapshot or {}).items():
        entries_list = entries if isinstance(entries, list) else [entries]
        for entry in entries_list:
            if not isinstance(entry, dict):
                continue
            endpoint = _text(endpoint_key)
            status_code = _status_code(entry)
            auth_context = _auth_context(entry)
            endpoint_rows.setdefault(endpoint, []).append({
                "entry": entry,
                "request_format": _request_format(entry),
                "auth_context": auth_context,
                "is_weak_auth": _is_weak_context(auth_context),
                "status_code": status_code,
                "is_success": _is_success(status_code),
                "param_values": _param_source_values(entry),
                "sensitive_fields": _extract_sensitive_fields(entry),
            })

    findings = []
    for endpoint_key in sorted(endpoint_rows.keys()):
        rows = endpoint_rows.get(endpoint_key, [])
        if len(rows) < 2:
            continue

        # Invariant A: auth must be representation-invariant.
        format_stats = {}
        for row in rows:
            fmt = _text(row.get("request_format") or "unknown", lower=True)
            slot = format_stats.setdefault(fmt, {
                "sample_count": 0, "weak_success": False,
                "strong_success": False, "status_codes": set(),
            })
            slot["sample_count"] += 1
            sc = int(row.get("status_code", 0) or 0)
            if sc:
                slot["status_codes"].add(sc)
            if bool(row.get("is_success")):
                if bool(row.get("is_weak_auth")):
                    slot["weak_success"] = True
                else:
                    slot["strong_success"] = True

        if len(format_stats.keys()) >= 2:
            weak_open = [f for f, s in format_stats.items() if s.get("weak_success")]
            protected = [f for f, s in format_stats.items()
                         if (not s.get("weak_success")) and s.get("strong_success")]
            if weak_open and protected:
                evidence = []
                for fmt, slot in sorted(format_stats.items()):
                    status_text = ",".join(_text(x) for x in sorted(slot.get("status_codes", set()))[:6])
                    evidence.append(
                        "format={} samples={} weak_success={} strong_success={} statuses={}".format(
                            fmt, int(slot.get("sample_count", 0) or 0),
                            bool(slot.get("weak_success")), bool(slot.get("strong_success")),
                            status_text or "n/a"))
                _add_finding(
                    findings, "authorization_must_be_representation_invariant",
                    "Auth enforcement appears to differ by request representation",
                    "high", endpoint_key, evidence,
                    ["Replay identical business request in JSON, form, and multipart with the same weak auth context.",
                     "Verify one representation does not bypass checks enforced in another representation."])

        # Invariant B: identifier source precedence must not be ambiguous.
        conflict_samples = []
        weak_conflict_seen = False
        for row in rows:
            if not bool(row.get("is_success")):
                continue
            for param_name, source_values in dict(row.get("param_values") or {}).items():
                if not _is_identifier_param(param_name) or not isinstance(source_values, dict):
                    continue
                if len(source_values.keys()) < 2:
                    continue
                flattened = set()
                for values in source_values.values():
                    for item in list(values or []):
                        vt = _text(item).strip()
                        if vt:
                            flattened.add(vt)
                if len(flattened) < 2:
                    continue
                if bool(row.get("is_weak_auth")):
                    weak_conflict_seen = True
                fragments = []
                for source_name in sorted(source_values.keys()):
                    vs = sorted(_text(x) for x in list(source_values.get(source_name, set())))
                    fragments.append("{}={}".format(source_name, ",".join(vs[:2])))
                conflict_samples.append("param={} {}".format(_text(param_name), " | ".join(fragments[:4])))
                if len(conflict_samples) >= 6:
                    break
            if len(conflict_samples) >= 6:
                break
        if conflict_samples:
            _add_finding(
                findings, "identifier_resolution_must_not_depend_on_source_precedence",
                "Conflicting identifier values from multiple sources reached successful responses",
                "critical" if weak_conflict_seen else "high", endpoint_key, conflict_samples,
                ["Replay path/query/body identifier conflicts and verify server rejects ambiguous combinations.",
                 "Enforce one canonical identifier source with strict mismatch rejection."])

        # Invariant C: weak-context sensitive exposure must not exceed protected.
        weak_sensitive, strong_sensitive = set(), set()
        for row in rows:
            if not bool(row.get("is_success")):
                continue
            fields = set(_text(x) for x in (row.get("sensitive_fields") or []))
            if not fields:
                continue
            if bool(row.get("is_weak_auth")):
                weak_sensitive |= fields
            else:
                strong_sensitive |= fields
        if weak_sensitive:
            leaked_only_to_weak = sorted(weak_sensitive - strong_sensitive)
            if (not strong_sensitive) or leaked_only_to_weak:
                evidence = ["weak_sensitive_count={} strong_sensitive_count={}".format(
                    len(weak_sensitive), len(strong_sensitive))]
                if leaked_only_to_weak:
                    evidence.append("weak_only_fields={}".format(
                        ", ".join(_text(x) for x in leaked_only_to_weak[:8])))
                _add_finding(
                    findings, "sensitive_response_redaction_must_be_auth_monotonic",
                    "Weak-auth responses expose sensitive fields not seen in stronger contexts",
                    "high", endpoint_key, evidence,
                    ["Replay same object read across guest/user/admin and diff field-level redaction.",
                     "Fail closed on weak contexts and verify serializer redaction parity per role."])

    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    findings.sort(key=lambda item: (
        severity_order.get(_text(item.get("severity"), lower=True), 4),
        _text(item.get("invariant"), lower=True),
        _text((item.get("endpoint_scope") or [""])[0], lower=True)))
    return findings


def build_counterfactual_package(data_snapshot, get_entry=None):
    findings = build_counterfactual_findings(data_snapshot, get_entry=get_entry)
    severity_distribution = {"critical": 0, "high": 0, "medium": 0, "info": 0}
    invariant_distribution = {}
    for item in findings:
        sev = _text(item.get("severity"), lower=True)
        if sev not in severity_distribution:
            sev = "info"
        severity_distribution[sev] += 1
        inv = _text(item.get("invariant"))
        invariant_distribution[inv] = invariant_distribution.get(inv, 0) + 1
    return {
        "schema_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "analysis_type": "counterfactual_differentials",
        "no_scoring": True,
        "non_destructive": True,
        "finding_count": len(findings),
        "findings": findings,
        "summary": {
            "severity_distribution": severity_distribution,
            "invariant_distribution": invariant_distribution,
        },
    }
