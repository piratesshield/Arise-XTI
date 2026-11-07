#!/usr/bin/env python3
"""Regression tests for the cloud-scanner false-positive / noise reduction work
(W1–W6). Run:  python3 cloud/test_cloud_regression.py

Each test encodes a specific false-positive class called out in the cloud/*.md
notes and asserts the scanner now grades it correctly. No network access — the
storage tests classify synthetic listing bodies and the asset tests run over a
synthetic on-disk scan directory (passive mode, so no active probes fire).
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import cloud.cloud_storage_enum as cse
import cloud.cloud_asset_intel as cai

_fail = 0


def check(name: str, cond: bool, detail: str = ""):
    global _fail
    status = "PASS" if cond else "FAIL"
    if not cond:
        _fail += 1
    print(f"  [{status}] {name}" + (f" — {detail}" if detail and not cond else ""))


def _listing(keys):
    body = "".join(f"<Contents><Key>{k}</Key><Size>10</Size></Contents>" for k in keys)
    return f"<ListBucketResult>{body}</ListBucketResult>"


# --------------------------------------------------------------------------- #
def test_storage_classification():
    print("W2 — storage content classification")

    r = cse.classify_listing(_listing(
        ["logo.png", "app.js", "main.css", "img/hero.jpg", "config.yaml"]))
    check("static-web bucket w/ stray yaml -> low static_asset_bucket",
          r["severity"] == "low" and r["category"] == "static_asset_bucket",
          f"got {r['severity']}/{r['category']}")

    r = cse.classify_listing(_listing(["assets/app.js", ".env"]))
    check(".env present -> critical secret_config",
          r["severity"] == "critical" and r["category"] == "secret_config_exposure",
          f"got {r['severity']}/{r['category']}")

    r = cse.classify_listing(_listing(["settings.yaml", "app.conf"]))
    check("generic config only -> medium (was critical)",
          r["severity"] == "medium", f"got {r['severity']}")

    r = cse.classify_listing(_listing(["firmware.bin", "font.bin"]))
    check(".bin blobs -> not high ML (FP removed)",
          r["severity"] == "low", f"got {r['severity']}/{r['category']}")

    r = cse.classify_listing(_listing(["data.xyz", "blob.qqq"]))
    check("unknown extensions -> low (was medium)",
          r["severity"] == "low" and r["category"] == "unknown_content",
          f"got {r['severity']}/{r['category']}")

    r = cse.classify_listing(_listing(["exports/passport_data.csv", "img/a.png"]))
    check("PII object still escalates -> critical (not suppressed by images)",
          r["severity"] == "critical", f"got {r['severity']}/{r['category']}")


class _FakeResp:
    def __init__(self, code, text="", headers=None):
        self.status_code = code
        self.text = text
        self.headers = headers or {}
        self.content = text.encode()


def _mock_fetch(scanner, resp):
    """Neutralize all network I/O on a scanner and pin a single fetch result."""
    scanner._fetch = lambda prov, name: (resp, resp.text,
                                          f"https://s3.amazonaws.com/{name}/")
    scanner._cors = lambda u: False
    scanner._object_headers = lambda u, k: ("none", False)
    scanner._static_website = lambda p, n: False
    scanner._object_level_read = lambda p, n, u: (False, "")
    scanner._permission_probes = lambda u: {
        "acl_public_grants": [], "policy_readable": False, "policy_public": False,
        "versioning_enabled": False, "version_count": 0, "delete_markers": 0}


def test_storage_detection_status_fp():
    print("storage detection — candidate coverage, open/closed status, FP drop")

    sc = cse.CloudStorageScanner("example.com", ["s3"], threads=2, timeout=2)

    # (1) targeted expansion generates rich, provider-valid variants
    cands = sc.targeted_candidates(["acme"], cap=1500)
    check("targeted expansion generates many candidates (>50)", len(cands) > 50,
          f"got {len(cands)}")
    for want in ("acme", "acme-backup", "backup-acme", "acme.assets"):
        check(f"candidate '{want}' generated", want in cands)

    # (2) full brute falls back to DEFAULT_AFFIXES when no --mutations supplied
    fb = sc.generate_candidates(["acme"], [], cap=1500)
    check("brute non-empty with no mutations (DEFAULT_AFFIXES fallback)",
          len(fb) > 1, f"got {len(fb)}")

    # (3) dotted names valid for S3, rejected for Azure
    check("dotted name valid for S3", cse.valid_bucket_name("acme.assets", True))
    check("dotted name rejected for Azure",
          not cse.valid_bucket_name("acme.assets", False))

    listing = ("<ListBucketResult><Contents><Key>a.txt</Key>"
               "<Size>3</Size></Contents></ListBucketResult>")

    # (4) open bucket -> status=open
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(200, listing))
    f = s._probe("s3", "acme-data", "preknown")
    check("public listable -> status=open", f is not None
          and f.status == cse.STATUS_OPEN and f.access == "public",
          f"got {getattr(f, 'status', None)}")

    # (5) 403 from AUTHORITATIVE source -> status=closed (kept)
    denied = "<Error><Code>AccessDenied</Code></Error>"
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(403, denied))
    f = s._probe("s3", "acme-data", "preknown")
    check("403 (preknown) -> status=closed", f is not None
          and f.status == cse.STATUS_CLOSED, f"got {getattr(f, 'status', None)}")

    # (6) FP control: 403 from brute/expansion -> DROPPED (unattributable noise)
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(403, denied))
    check("403 (brute-force) dropped as noise",
          s._probe("s3", "acme-data", "brute-force") is None)
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(403, denied))
    check("403 (expansion) dropped as noise",
          s._probe("s3", "acme-data", "expansion") is None)

    # (7) NoSuchBucket -> not-found (info, authoritative) / dropped (brute)
    nf = "<Error><Code>NoSuchBucket</Code></Error>"
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(404, nf))
    f = s._probe("s3", "acme-data", "preknown")
    check("404 (preknown) -> status=not-found/info", f is not None
          and f.status == cse.STATUS_NOT_FOUND and f.severity == "info",
          f"got {getattr(f, 'status', None)}")
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(404, nf))
    check("404 (brute-force) dropped",
          s._probe("s3", "acme-data", "brute-force") is None)

    # (8) listing denied but a sensitive object readable -> open-objects
    s = cse.CloudStorageScanner("t", ["s3"]); _mock_fetch(s, _FakeResp(403, denied))
    s._object_level_read = lambda p, n, u: (True, ".env")
    f = s._probe("s3", "acme-data", "preknown")
    check("listing denied + object readable -> status=open-objects", f is not None
          and f.status == cse.STATUS_OPEN_OBJECTS and f.access == "public",
          f"got {getattr(f, 'status', None)}")


def test_org_anchoring_fp():
    print("org anchoring — api.myntra.com third-party-bucket FP fix")

    # (1) registrable org label extraction (the brute anchor)
    for host, want in [("api.myntra.com", "myntra"), ("myntra.com", "myntra"),
                       ("a.b.myntra.com", "myntra"), ("shop.foo.co.uk", "foo"),
                       ("1.2.3.4", "")]:
        check(f"registrable_label({host}) == {want!r}",
              cse.registrable_label(host) == want,
              f"got {cse.registrable_label(host)!r}")

    # (2) generic service labels are recognised (never used as a brute base)
    check("'api' is a generic label", "api" in cse.GENERIC_LABELS)
    check("'myntra' is NOT a generic label", "myntra" not in cse.GENERIC_LABELS)

    listing = ("<ListBucketResult><Contents><Key>a.txt</Key>"
               "<Size>3</Size></Contents></ListBucketResult>")

    # (3) keyword-derived OPEN bucket NOT referencing the org -> dropped (FP).
    #     'api-static' for target api.myntra.com (anchor 'myntra') is unrelated.
    s = cse.CloudStorageScanner("api.myntra.com", ["s3"], anchor_tokens={"myntra"})
    _mock_fetch(s, _FakeResp(200, listing))
    check("expansion hit 'api-static' (no org token) -> dropped",
          s._probe("s3", "api-static", "expansion") is None)
    s = cse.CloudStorageScanner("api.myntra.com", ["s3"], anchor_tokens={"myntra"})
    _mock_fetch(s, _FakeResp(200, listing))
    check("expansion hit 'secret-api' (no org token) -> dropped",
          s._probe("s3", "secret-api", "expansion") is None)

    # (4) keyword-derived OPEN bucket that DOES reference the org -> kept.
    s = cse.CloudStorageScanner("api.myntra.com", ["s3"], anchor_tokens={"myntra"})
    _mock_fetch(s, _FakeResp(200, listing))
    f = s._probe("s3", "myntra-backups", "expansion")
    check("expansion hit 'myntra-backups' (org-anchored) -> kept",
          f is not None and f.access == "public")

    # (5) AUTHORITATIVE (preknown) names are exempt from the org-anchor filter —
    #     they were observed on the target's DNS/pages, so attribution is given.
    s = cse.CloudStorageScanner("api.myntra.com", ["s3"], anchor_tokens={"myntra"})
    _mock_fetch(s, _FakeResp(200, listing))
    f = s._probe("s3", "some-vendor-bucket", "preknown")
    check("preknown 'some-vendor-bucket' kept despite no org token",
          f is not None and f.access == "public")

    # (6) no anchor configured -> never drop (don't blank out on missing anchor)
    s = cse.CloudStorageScanner("x", ["s3"], anchor_tokens=set())
    _mock_fetch(s, _FakeResp(200, listing))
    check("no anchor -> keyword-derived hit still kept",
          s._probe("s3", "api-static", "expansion") is not None)


# --------------------------------------------------------------------------- #
def _write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj) if not isinstance(obj, str) else obj)


def test_asset_intel_noise():
    print("W3/W4 — asset-intel noise + port truth (passive)")
    with tempfile.TemporaryDirectory() as td:
        scan = Path(td)
        _write(scan / "manifest.json", {"hosts": {
            # naming-only 'redis' host, no ports -> must be info/referenced
            "redis-tutorial.example.com": {"ip": "203.0.113.10", "http_status": 200,
                                           "ports_open": []},
            # real service host, redis+mysql ports, not fronted
            "db.example.com": {"ip": "203.0.113.20", "ports_open": [6379, 3306]},
            # port behind CDN -> must be skipped
            "edge.example.com": {"ip": "203.0.113.30", "cdn": True,
                                 "ports_open": [6379]},
            # port behind WAF -> must be skipped
            "waf.example.com": {"ip": "203.0.113.40", "waf_vendor": "cloudflare",
                                "ports_open": [3306]},
            # two hostnames, same origin IP -> one origin finding (dedup)
            "app1.example.com": {"ip": "203.0.113.50", "http_status": 200,
                                 "ports_open": []},
            "app2.example.com": {"ip": "203.0.113.50", "http_status": 200,
                                 "ports_open": []},
        }})
        _write(scan / "03b_dns_discovery/dns_all_records.json", {
            "app1.example.com": {"CNAME": ["x.us-east-1.elb.amazonaws.com"]},
            "app2.example.com": {"CNAME": ["x.us-east-1.elb.amazonaws.com"]},
        })

        clf = cai.CloudAssetClassifier(scan, active=False, verbose=False)
        clf.run()
        rows = [json.loads(l) for l in
                (scan / "17_cloud_exposure/cloud_asset_map.jsonl").read_text().splitlines()]

        def find(host, cat=None, port=None):
            return [r for r in rows if r["host"] == host
                    and (cat is None or r["category"] == cat)
                    and (port is None or r.get("port") == port)]

        redis_name = [r for r in find("redis-tutorial.example.com")
                      if r["source"] != "ports"]
        check("naming-only 'redis' host -> info/referenced",
              bool(redis_name) and all(r["severity"] == "info"
                                       and r["exposure_state"] == "referenced"
                                       for r in redis_name),
              f"got {[(r['severity'], r['exposure_state']) for r in redis_name]}")

        db_redis = find("db.example.com", "cache", 6379)
        check("open redis port (passive) -> high, exists (not critical)",
              bool(db_redis) and db_redis[0]["severity"] == "high"
              and db_redis[0]["exposure_state"] == "exists",
              f"got {[(r['severity'], r['exposure_state']) for r in db_redis]}")

        check("CDN-fronted port skipped",
              not find("edge.example.com", "cache"),
              "edge host produced a port finding")
        check("WAF-fronted port skipped",
              not find("waf.example.com", "database"),
              "waf host produced a port finding")

        origins = [r for r in rows if r["service"].startswith("Exposed origin")]
        check("origin exposure deduped by IP (<=1 for shared IP .50)",
              len([o for o in origins if o["ip"] == "203.0.113.50"]) == 1,
              f"got {len([o for o in origins if o['ip'] == '203.0.113.50'])}")
        check("bare cloud origin -> info (corroboration-gated)",
              all(o["severity"] in ("info", "medium") for o in origins)
              and any(o["severity"] == "info" for o in origins),
              f"got {[o['severity'] for o in origins]}")


# --------------------------------------------------------------------------- #
# C1–C6 cloud-depth (recon → takeover) regression — all offline
# --------------------------------------------------------------------------- #
def test_c2_content_and_sas():
    print("C2 — VHD/cloud-cred content rules + SAS scope")

    def _first(name):
        for pat, ftype, sev, score, cat in cse.CONTENT_RULES:
            if pat.search(name):
                return ftype, sev
        return None, None

    for name, want_sev in [("backups/prod.vhd", "critical"),
                           ("disk.vmdk", "critical"),
                           ("app.publishsettings", "critical"),
                           ("azureProfile.json", "critical")]:
        _, sev = _first(name)
        check(f"{name} -> critical", sev == want_sev, f"got {sev}")

    w = cse._signed_url_scope(
        "https://x.blob.core.windows.net/c/o?sv=2021&sp=rwdl&sr=c&sig=a&se=2030-01-01t00:00:00z",
        "azure")
    check("SAS sp=rwdl -> writable (critical grade)", w["writable"] is True)
    ro = cse._signed_url_scope(
        "https://x.blob.core.windows.net/c/o?sv=2021&sp=r&sr=b&sig=a&se=2030-01-01t00:00:00z",
        "azure")
    check("SAS sp=r -> not writable (high grade)", ro["writable"] is False)


def test_c3_cred_scan():
    print("C3 — cloud credential detection + masking")
    import cloud.cloud_cred_scan as ccs
    # NOT AWS's own doc-example key/id (wJalrXUtnFEMI.../<AWS-docs-example>)
    # -- those are now deliberately excluded by an EXAMPLE-value denylist
    # (F03, ARISE_REMEDIATION_ROADMAP.md: that exact placeholder was traced
    # as the "secret" in a fabricated finding this session). Use a
    # realistic-looking but fake value instead so this test still exercises
    # real detection logic rather than the exclusion it would now trigger.
    text = ('aws_secret_access_key = "ObroVR5fBbnGbmPIoLZaZSvj9vfg2MZUI/yJ1N3K"\n'
            'A' 'KIAZBIKCIDKWNNHJ7XV\n')
    fs = ccs.scan_text(text, "app.js")
    dets = {f.detector for f in fs}
    check("AWS access key id detected", "aws-access-key-id" in dets, str(dets))
    check("AWS secret key detected", "aws-secret-access-key" in dets, str(dets))
    check("secret is masked (not raw in output)",
          all("ObroVR5fBbnGbmPI" not in f.masked for f in fs))
    check("known AWS doc-example key is excluded (F03 fix)",
          not ccs.scan_text('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
                            "app.js"))


def test_c4_ssrf_extract_and_bypass():
    print("C4 — SSRF param extraction + bypass variants + inactive gating")
    import cloud.ssrf_metadata as sm
    with tempfile.TemporaryDirectory() as td:
        ep = Path(td) / "ep.jsonl"
        ep.write_text(json.dumps({"url": "https://t/fetch?url=x&id=1"}) + "\n"
                      + json.dumps({"url": "https://t/p", "params": ["image", "q"]}) + "\n")
        tg = sm.extract_targets(str(ep))
        params = {p for _, p, _ in tg}
        check("SSRF-prone params selected (url,image)", params == {"url", "image"},
              str(params))
    labels = {lbl for lbl, _ in sm._bypass_variants(
        "http://169.254.169.254/latest/meta-data/")}
    check("IMDS bypass variants include decimal+hex",
          {"host-decimal", "host-hex"}.issubset(labels), str(labels))
    sc = sm.SSRFMetadataScanner(active=False)
    sc.run([("https://t/fetch?url=x", "url", "GET")])
    check("inactive scanner sends nothing", sc.findings == [])


def test_c5_posture():
    print("C5 — control-presence inversion")
    import cloud.cloud_posture as cp
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "cloud_buckets.jsonl").write_text(json.dumps({
            "name": "b", "provider": "aws", "access": "public",
            "exposure_state": "sensitive_confirmed"}) + "\n")
        (d / "ssrf_metadata.jsonl").write_text(json.dumps({
            "confidence": "confirmed", "metadata_target": "aws-imdsv1-iam",
            "parameter": "url", "endpoint": "https://x"}) + "\n")
        g = cp.PostureGrader(d)
        g.grade()
        gids = {f.guardrail for f in g.findings}
        check("public bucket -> S3 Block-Public-Access gap",
              "s3-block-public-access" in gids, str(gids))
        imds = [f for f in g.findings if f.guardrail == "imdsv2-not-enforced"]
        check("SSRF→IMDS -> IMDSv2-not-enforced (critical)",
              bool(imds) and imds[0].severity == "critical")


def test_c6_cloud_paths():
    print("C6 — cloud attack-path synthesis")
    import intel.capec_attack_paths as cap
    import os
    with tempfile.TemporaryDirectory() as td:
        sub = Path(td) / "17_cloud_exposure"
        sub.mkdir(parents=True)
        (sub / "ssrf_metadata.jsonl").write_text(json.dumps({
            "attack_path_seed": "ssrf_to_imds", "confidence": "confirmed",
            "severity": "critical", "evidence": "SSRF→IMDS"}) + "\n")
        (sub / "cloud_saas_fingerprint.jsonl").write_text(json.dumps({
            "category": "federation", "host": "adfs.x", "note": "ADFS",
            "severity": "low"}) + "\n")
        paths, seeds = cap.build_cloud_paths(str(td))
        ids = {p["id"] for p in paths}
        check("SSRF seed -> ssrf-imds-takeover chain realized",
              "cloud-ssrf-imds-takeover" in ids
              and any(p["realized"] for p in paths
                      if p["id"] == "cloud-ssrf-imds-takeover"), str(ids))
        check("federation seed -> golden-saml chain present",
              "cloud-golden-saml" in ids, str(ids))


if __name__ == "__main__":
    test_storage_classification()
    test_storage_detection_status_fp()
    test_org_anchoring_fp()
    test_asset_intel_noise()
    test_c2_content_and_sas()
    test_c3_cred_scan()
    test_c4_ssrf_extract_and_bypass()
    test_c5_posture()
    test_c6_cloud_paths()
    print()
    if _fail:
        print(f"❌ {_fail} check(s) failed")
        sys.exit(1)
    print("✅ all regression checks passed")
