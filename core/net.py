#!/usr/bin/env python3
"""
Shared, OS-independent HTTPS verification context.

Why this exists
----------------
`ssl.create_default_context()` with no `cafile` trusts whatever CA bundle the
interpreter's OpenSSL was built to expect at a fixed path. On python.org's
macOS builds that path is only populated if "Install Certificates.command"
was run after installing/upgrading Python — otherwise EVERY outbound HTTPS
call from stdlib `urllib`/`http.client` fails with
`CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`, for
every well-known, legitimate external service (ipinfo.io, Shodan, Censys,
GreyNoise, credential-provider validation APIs, ...) — not because those
services are untrusted, but because the interpreter has no way to check.

`certifi` bundles the Mozilla CA root store directly inside the Python
package, so pointing the SSL context at `certifi.where()` verifies exactly
as strictly as the platform-correct config would, without depending on the
OS/interpreter install having been set up correctly. `certifi` is already a
declared dependency (requirements.txt) and a transitive dependency of
`requests`, so it's always present.

This is for calls to TRUSTED THIRD-PARTY SERVICES (enrichment/intel APIs,
credential-provider validation, DoH resolvers) where certificate
verification should stay ON. It is NOT for probing a scan TARGET's own web
server, which may legitimately present a self-signed/expired/mismatched
certificate that has nothing to do with the vulnerability being tested —
those call sites intentionally disable verification (CERT_NONE) and should
keep doing so; this helper would just make them fail loudly on invalid
target certs instead of on the interpreter's own missing CA path, which is
not the goal there.
"""

from __future__ import annotations

import ssl
from functools import lru_cache


@lru_cache(maxsize=1)
def verified_ssl_context() -> ssl.SSLContext:
    """A strict (verification ON) SSL context backed by certifi's portable CA
    bundle, falling back to the interpreter's own default if certifi is
    somehow unavailable. Cached — building it is cheap but not free, and
    every caller wants the identical context."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _selftest() -> int:
    ctx = verified_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert verified_ssl_context() is ctx, "should be cached, not rebuilt"
    print("[core.net] self-test OK — verified_ssl_context() returns a cached, "
          "verification-on context")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
