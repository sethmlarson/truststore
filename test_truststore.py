import asyncio
import os
import platform
import socket
import ssl
import tempfile

import aiohttp
import aiohttp.client_exceptions
import pytest
import trustme
import urllib3
import urllib3.exceptions
from OpenSSL.crypto import X509

import truststore

# Make sure the httpserver doesn't hang
# if the client drops the connection due to a cert verification error
socket.setdefaulttimeout(10)

successful_hosts = pytest.mark.parametrize("host", ["example.com", "1.1.1.1"])

failure_hosts_list = [
    "wrong.host.badssl.com",
    "expired.badssl.com",
    "self-signed.badssl.com",
    "untrusted-root.badssl.com",
    "superfish.badssl.com",
]

if platform.system() != "Linux":
    failure_hosts_list.append("revoked.badssl.com")

failure_hosts = pytest.mark.parametrize(
    "host",
    failure_hosts_list,
)


@pytest.fixture(scope="session")
def trustme_ca():
    ca = trustme.CA()
    yield ca


@pytest.fixture(scope="session")
def httpserver_ssl_context(trustme_ca):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert = trustme_ca.issue_cert("localhost")
    server_cert.configure_cert(server_context)
    return server_context


def connect_to_host(host: str, use_server_hostname: bool = True):
    with socket.create_connection((host, 443)) as sock:
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with ctx.wrap_socket(
            sock, server_hostname=host if use_server_hostname else None
        ):
            pass


@successful_hosts
def test_success(host):
    connect_to_host(host)


@failure_hosts
def test_failures(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    with pytest.raises(ssl.SSLCertVerificationError):
        connect_to_host(host)


@successful_hosts
def test_sslcontext_api_success(host):
    if host == "1.1.1.1":
        pytest.skip("urllib3 doesn't pass server_hostname for IP addresses")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with urllib3.PoolManager(ssl_context=ctx) as http:
        resp = http.request("GET", f"https://{host}")
    assert resp.status == 200
    assert len(resp.data) > 0


@successful_hosts
@pytest.mark.asyncio
async def test_sslcontext_api_success_async(host):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with aiohttp.ClientSession() as http:
        resp = await http.request("GET", f"https://{host}", ssl=ctx)

        assert resp.status == 200
        assert len(await resp.text()) > 0
    # workaround https://github.com/aio-libs/aiohttp/issues/5426
    await asyncio.sleep(0.2)


@failure_hosts
def test_sslcontext_api_failures(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with urllib3.PoolManager(ssl_context=ctx) as http:
        with pytest.raises(urllib3.exceptions.SSLError) as e:
            http.request("GET", f"https://{host}", retries=False)

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


@failure_hosts
@pytest.mark.asyncio
async def test_sslcontext_api_failures_async(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with aiohttp.ClientSession() as http:
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError
        ) as e:
            await http.request("GET", f"https://{host}", ssl=ctx)
    # workaround https://github.com/aio-libs/aiohttp/issues/5426
    await asyncio.sleep(0.2)

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


def test_trustme_cert(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    httpserver.expect_request("/", method="GET").respond_with_json({})

    with urllib3.PoolManager(ssl_context=ctx) as http:
        resp = http.request("GET", httpserver.url_for("/"))
    assert resp.status == 200
    assert len(resp.data) > 0


def test_trustme_cert_loaded_via_capath(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with tempfile.TemporaryDirectory() as capath:
        with open(f"{capath}/cert.pem", "wb") as certfile:
            certfile.write(trustme_ca.cert_pem.bytes())
        cert_hash = X509.from_cryptography(trustme_ca._certificate).subject_name_hash()
        os.symlink(f"{capath}/cert.pem", f"{capath}/{cert_hash:x}.0")
        ctx.load_verify_locations(capath=capath)

        httpserver.expect_request("/", method="GET").respond_with_json({})

        with urllib3.PoolManager(ssl_context=ctx) as http:
            resp = http.request("GET", httpserver.url_for("/"))
        assert resp.status == 200
        assert len(resp.data) > 0


def test_trustme_cert_still_uses_system_certs(trustme_ca):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    with urllib3.PoolManager(ssl_context=ctx) as http:
        resp = http.request("GET", "https://example.com")
    assert resp.status == 200
    assert len(resp.data) > 0
