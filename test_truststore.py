import platform
import socket
import ssl

import aiohttp
import aiohttp.client_exceptions
import pytest
import urllib3
import urllib3.exceptions

from truststore import TruststoreSSLContext

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


def connect_to_host(host: str, use_server_hostname: bool = True):
    sock = socket.create_connection((host, 443))
    try:
        ctx = TruststoreSSLContext(ssl.PROTOCOL_TLS_CLIENT)
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
    ctx = TruststoreSSLContext(ssl.PROTOCOL_TLS_CLIENT)
    http = urllib3.PoolManager(ssl_context=ctx)
    resp = http.request("GET", f"https://{host}")
    assert resp.status == 200
    assert len(resp.data) > 0


@successful_hosts
@pytest.mark.asyncio
async def test_sslcontext_api_success_async(host):
    ctx = TruststoreSSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with aiohttp.ClientSession() as http:
        resp = await http.request("GET", f"https://{host}", ssl=ctx)

        assert resp.status == 200
        assert len(await resp.text()) > 0


@failure_hosts
def test_sslcontext_api_failures(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    ctx = TruststoreSSLContext(ssl.PROTOCOL_TLS_CLIENT)
    http = urllib3.PoolManager(ssl_context=ctx)
    with pytest.raises(urllib3.exceptions.SSLError) as e:
        http.request("GET", f"https://{host}", retries=False)

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


@failure_hosts
@pytest.mark.asyncio
async def test_sslcontext_api_failures_async(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    ctx = TruststoreSSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with aiohttp.ClientSession() as http:
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError
        ) as e:
            await http.request("GET", f"https://{host}", ssl=ctx)

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()
