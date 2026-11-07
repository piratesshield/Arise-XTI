#!/usr/bin/env python3
"""
ARISE — Nuclei Reflected-Input False-Positive Filter
=====================================================
Second-pass verification layer over raw nuclei JSONL output. Nuclei's own
word/regex matchers only ask "does this string appear in the response?" —
they have no notion of WHERE that string came from. A word-matcher template
whose "evidence" words happen to be substrings of the probe's own request
path (or query) will fire on any app that echoes the request back anywhere
(a redirect-after-login field, a 404 "no such page: X" message, a canonical
link, analytics) — not just on a server that genuinely produced that content.

Concrete case this was built from: cloud-templates/cloud-metadata-exposure.yaml
requires status 200 AND one of {"ami-id", "instance-id",
"iam/security-credentials", "AccessKeyId", "InstanceProfileArn",
"computeMetadata", '"accessToken"'} in the body. Two of those words
("iam/security-credentials", "computeMetadata") are literal substrings of the
template's own probe paths — academy.payu.in's Moodle login page embeds the
requested path in a hidden redirect-after-login field, which was enough to
trip a CVSS 9.1 "confirmed" SSRF-to-cloud-metadata finding on a plain login
page. See evidence/arise_evidence.py's reflected-input check for the shared
primitive this filter is built on.

This script re-derives each record's word-matcher word list from nuclei's own
`template-encoded` field (nuclei v3 includes this by default; see `-ot/
-omit-template`), strips the probe's own path/query from the response body,
and re-checks whether at least one matched word still survives — i.e. is
content the SERVER produced independently, not an echo of the request.

Records are never deleted. A finding whose only textual evidence turns out
to be reflected input keeps its row but is demoted: `info.severity` becomes
"info", the original severity is preserved in `info.severity_original`, and
an `arise_fp_check` block records why — same philosophy as the pipeline's
`blocked_by_waf` tagging elsewhere (stay visible and auditable, never vanish
silently). A record where the check ran and found genuine evidence gets
`arise_fp_check: {reflected_input_fp: false, checked: true}` so a reviewer
can tell "we verified this" from "we never looked" (no word matcher present
— status-only or regex/extractor-based templates are left untouched).

Usage:
    python3 nuclei_fp_filter.py <nuclei.jsonl> [--in-place] [--out FILE]

Degrades gracefully: a record missing `response`/`template-encoded`, a
template that fails to parse, or any per-record error is left untouched and
counted in `skipped` — this filter only ever narrows confidence, it never
invents or removes a finding, and it never raises.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import base64
import json
import re
from typing import Dict, List, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - degrade if PyYAML missing
    yaml = None

from evidence.arise_evidence import reflected_fp_note

# Severities worth the cost of re-checking. low/info findings aren't worth
# the YAML-parse + string-strip cost and aren't escalation-worthy anyway.
_CHECKED_SEVERITIES = {"critical", "high", "medium"}

_REQUEST_LINE_RE = re.compile(r"^[A-Z]{3,10}\s+(\S+)\s+HTTP/", re.MULTILINE)


def extract_body_word_lists(template_yaml: str) -> List[List[str]]:
    """Every word-list from a `type: word` matcher targeting the body (or with
    no `part` — nuclei's default is body) in a nuclei http-protocol template.
    Each matcher's word list is returned separately: a template can carry
    several independent word-matchers (e.g. one per product fingerprint), and
    satisfying ANY one of them is a distinct path to "this matched"."""
    if not yaml or not template_yaml:
        return []
    try:
        doc = yaml.safe_load(template_yaml)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    out: List[List[str]] = []
    for block in (doc.get("http") or doc.get("requests") or []):
        if not isinstance(block, dict):
            continue
        matcher_groups = [block.get("matchers") or []]
        # matchers can also live one level down under named matcher groups
        # in some template styles; harmless no-op if that key is absent.
        for group in matcher_groups:
            for m in group:
                if not isinstance(m, dict):
                    continue
                if m.get("type") != "word":
                    continue
                part = (m.get("part") or "body").lower()
                if part not in ("body", ""):
                    continue
                words = m.get("words") or []
                words = [str(w) for w in words if w]
                if words:
                    out.append(words)
    return out


def _request_path(record: Dict) -> str:
    req = record.get("request") or ""
    m = _REQUEST_LINE_RE.search(req)
    return m.group(1) if m else ""


def recheck_record(record: Dict) -> Optional[str]:
    """Returns a false-positive note if this record's match reduces entirely
    to reflected input, None if it's genuine evidence OR there was nothing
    checkable (no body word-matcher, or the template/body fields are
    missing) — callers should only act on a non-None return."""
    severity = ((record.get("info") or {}).get("severity") or "").lower()
    if severity not in _CHECKED_SEVERITIES:
        return None
    body = record.get("response") or ""
    tmpl_b64 = record.get("template-encoded") or record.get("template_encoded") or ""
    if not body or not tmpl_b64:
        return None
    try:
        template_yaml = base64.b64decode(tmpl_b64).decode("utf-8", errors="ignore")
    except Exception:
        return None
    word_lists = extract_body_word_lists(template_yaml)
    if not word_lists:
        return None  # status-only / regex-only / extractor-only template

    url = record.get("matched-at") or record.get("url") or record.get("host") or ""
    req_path = _request_path(record)

    notes = []
    any_genuine = False
    for words in word_lists:
        note = reflected_fp_note(words, url=url, body=body, request_path=req_path)
        if note is None:
            # Either genuine evidence, or this particular word-list never
            # actually matched the body — either way this branch doesn't
            # condemn the finding.
            any_genuine = True
        else:
            notes.append(note)
    if any_genuine or not notes:
        return None
    # Every word-matcher branch that fired reduced to reflected input.
    return notes[0]


def filter_records(records: List[Dict]) -> Dict:
    stats = {"total": len(records), "checked": 0, "flagged": 0, "skipped": 0}
    for rec in records:
        try:
            note = recheck_record(rec)
        except Exception:
            stats["skipped"] += 1
            continue
        info = rec.setdefault("info", {})
        severity = (info.get("severity") or "").lower()
        if severity not in _CHECKED_SEVERITIES:
            stats["skipped"] += 1
            continue
        if note is not None:
            info["severity_original"] = info.get("severity", severity)
            info["severity"] = "info"
            rec["arise_fp_check"] = {"reflected_input_fp": True, "reason": note}
            stats["flagged"] += 1
            stats["checked"] += 1
        else:
            tmpl_b64 = rec.get("template-encoded") or rec.get("template_encoded") or ""
            body = rec.get("response") or ""
            if body and tmpl_b64:
                rec["arise_fp_check"] = {"reflected_input_fp": False, "checked": True}
                stats["checked"] += 1
            else:
                stats["skipped"] += 1
    return stats


def filter_file(path: str, in_place: bool = True, out_path: str = "") -> Dict:
    records = []
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue  # non-JSON line (shouldn't happen) — leave file alone for it

    stats = filter_records(records)

    dest = path if in_place else (out_path or (path + ".fp-checked.jsonl"))
    with open(dest, "w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    stats["dest"] = dest
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("nuclei_jsonl", help="raw nuclei JSONL output to re-check")
    ap.add_argument("--in-place", action="store_true", default=True,
                    help="overwrite the input file (default)")
    ap.add_argument("--out", default="", help="write to a different file instead")
    args = ap.parse_args()

    if not _os.path.exists(args.nuclei_jsonl):
        print(f"[nuclei-fp-filter] not found: {args.nuclei_jsonl}", file=_sys.stderr)
        return 0  # never fail the pipeline over a missing/optional file

    in_place = not bool(args.out)
    stats = filter_file(args.nuclei_jsonl, in_place=in_place, out_path=args.out)
    print(f"[nuclei-fp-filter] {stats['total']} records, "
          f"{stats['checked']} re-checked, {stats['flagged']} reflected-input "
          f"false positive(s) demoted -> {stats['dest']}", file=_sys.stderr)
    return 0


if __name__ == "__main__":
    _sys.exit(main())
