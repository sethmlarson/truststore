import json
import ssl

import pytest
import urllib3
from urllib3.exceptions import InsecureRequestWarning

import truststore


def test_minimum_maximum_version():
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    with urllib3.PoolManager(ssl_context=ctx) as http:

        resp = http.request("GET", "https://howsmyssl.com/a/check")
        data = json.loads(resp.data)
        assert data["tls_version"] == "TLS 1.2"

    assert ctx.minimum_version in (
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.MINIMUM_SUPPORTED,
    )
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2


def test_disable_verification():
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with urllib3.PoolManager(ssl_context=ctx) as http, pytest.warns(
        InsecureRequestWarning
    ) as w:
        http.request("GET", "https://expired.badssl.com/")
    assert len(w) == 1
