import platform
import socket
import ssl

import aiohttp
import aiohttp.client_exceptions
import pytest
import trustme
import urllib3
import urllib3.exceptions

import truststore

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
    if platform.system() == "Windows":
        pytest.skip("Windows doesn't implement custom CA certificates yet")
    ca = trustme.CA()
    yield ca


@pytest.fixture(scope="session")
def httpserver_ssl_context(trustme_ca):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert = trustme_ca.issue_cert("localhost")
    server_cert.configure_cert(server_context)
    return server_context


def connect_to_host(host: str, use_server_hostname: bool = True):
    sock = socket.create_connection((host, 443))
    try:
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.wrap_socket(sock, server_hostname=host if use_server_hostname else None)
    finally:
        sock.close()


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
    http = urllib3.PoolManager(ssl_context=ctx)
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


@failure_hosts
def test_sslcontext_api_failures(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    http = urllib3.PoolManager(ssl_context=ctx)
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

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


def test_trustme_cert(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    httpserver.expect_request("/", method="GET").respond_with_json({})

    http = urllib3.PoolManager(ssl_context=ctx)
    resp = http.request("GET", httpserver.url_for("/"))
    assert resp.status == 200
    assert len(resp.data) > 0


def test_trustme_cert_still_uses_system_certs(trustme_ca):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    http = urllib3.PoolManager(ssl_context=ctx)
    resp = http.request("GET", "https://example.com")
    assert resp.status == 200
    assert len(resp.data) > 0
