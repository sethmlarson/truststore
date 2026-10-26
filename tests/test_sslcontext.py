import datetime
import socket
import ssl

import pytest
import urllib3
from urllib3.exceptions import InsecureRequestWarning, SSLError

import truststore
from tests.conftest import NETWORK_TIMEOUT


def test_minimum_maximum_version(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    with (
        socket.create_connection(
            (httpserver.host, httpserver.port), timeout=NETWORK_TIMEOUT
        ) as sock,
        ctx.wrap_socket(sock, server_hostname="localhost") as tls,
    ):
        assert tls.version() == "TLSv1.2"

    assert ctx.minimum_version in (
        ssl.TLSVersion.TLSv1_2,
        ssl.TLSVersion.MINIMUM_SUPPORTED,
    )
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2


def test_check_hostname_rejects_mismatch(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    # Establish trust first so an unrelated CA failure cannot satisfy the rejection.
    with (
        socket.create_connection(
            (httpserver.host, httpserver.port), timeout=NETWORK_TIMEOUT
        ) as sock,
        ctx.wrap_socket(sock, server_hostname="localhost"),
    ):
        pass

    with (
        socket.create_connection(
            (httpserver.host, httpserver.port), timeout=NETWORK_TIMEOUT
        ) as sock,
        pytest.raises(ssl.SSLCertVerificationError),
    ):
        ctx.wrap_socket(sock, server_hostname="wrong.example")


def test_verify_mode_cert_none(trustme_ca, httpserver, httpserver_ssl_context):
    expired = trustme_ca.issue_cert(
        "localhost",
        not_before=datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc),
        not_after=datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc),
    )
    expired.configure_cert(httpserver_ssl_context)
    httpserver.expect_request("/").respond_with_data("ok")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED

    with (
        urllib3.PoolManager(
            ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
        ) as http,
        pytest.raises(SSLError),
    ):
        http.request("GET", httpserver.url_for("/"), redirect=False)

    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE

    with (
        urllib3.PoolManager(
            ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
        ) as http,
        pytest.warns(InsecureRequestWarning) as w,
    ):
        response = http.request("GET", httpserver.url_for("/"), redirect=False)

    assert response.status == 200
    assert response.data == b"ok"
    assert len(w) == 1
