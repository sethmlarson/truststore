import platform
import socket
import ssl

import pytest

from truststore import Truststore


def connect_to_host(host: str, use_server_hostname: bool = True):
    sock = socket.create_connection((host, 443))
    try:
        ts = Truststore()
        ts._ctx.check_hostname &= use_server_hostname
        ts.wrap_socket(sock, server_hostname=host if use_server_hostname else None)
    finally:
        sock.close()


def test_success():
    connect_to_host("example.com")


@pytest.mark.parametrize(
    "host",
    [
        "wrong.host.badssl.com",  # Fails on macOS?
        "expired.badssl.com",
        "self-signed.badssl.com",
        "untrusted-root.badssl.com",
        "revoked.badssl.com",
        "superfish.badssl.com",
    ],
)
def test_failures(host):
    if platform.system() == "Linux" and host == "revoked.badssl.com":
        pytest.skip("Linux currently doesn't support CRLs")

    with pytest.raises(ssl.SSLCertVerificationError):
        connect_to_host(host)
