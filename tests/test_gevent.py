import os
import pathlib
import ssl
import subprocess
import sys

import pytest
import trustme
from pytest_httpserver import HTTPServer

pytestmark = pytest.mark.skipif(
    sys.implementation.name != "cpython", reason="CPython SSLContext descriptors"
)


@pytest.mark.parametrize("operation", ["wrap_bio", "properties"])
def test_patch_ssl_before_import(operation):
    # Monkey patching must happen before importing truststore, and must not
    # affect the SSL classes used by the rest of the test suite.
    script = """
import gevent.monkey
gevent.monkey.patch_ssl()

import ssl
import truststore

ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
"""
    if operation == "wrap_bio":
        script += """
ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="localhost")
assert ctx.check_hostname is True
assert ctx.verify_mode == ssl.CERT_REQUIRED
"""
    else:
        script += """
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
assert ctx.verify_mode == ssl.CERT_NONE
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.check_hostname = True
assert ctx.verify_mode == ssl.CERT_REQUIRED
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
assert ctx.maximum_version == ssl.TLSVersion.TLSv1_3
ctx.options |= ssl.OP_NO_COMPRESSION
assert ctx.options & ssl.OP_NO_COMPRESSION
ctx.verify_flags = ssl.VERIFY_DEFAULT
assert ctx.verify_flags == ssl.VERIFY_DEFAULT
"""
    _run_script(script)


@pytest.mark.parametrize("trust_ca", [True, False])
def test_patch_ssl_before_import_tls(tmp_path, trust_ca):
    ca = trustme.CA()
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost").configure_cert(server_ctx)
    ca_path = tmp_path / "ca.pem"
    ca.cert_pem.write_to_path(ca_path)

    with HTTPServer(host="127.0.0.1", ssl_context=server_ctx) as server:
        server.expect_request("/").respond_with_data("ok")
        _run_script(
            """
import gevent.monkey
gevent.monkey.patch_ssl()

import ssl
import sys
from gevent import socket
import truststore

ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
trust_ca = sys.argv[3] == "True"
if trust_ca:
    ctx.load_verify_locations(cafile=sys.argv[2])

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5) as sock:
    try:
        tls = ctx.wrap_socket(sock, server_hostname="localhost")
    except ssl.SSLCertVerificationError:
        assert not trust_ca
    else:
        with tls:
            assert trust_ca, "An untrusted certificate was accepted"
            tls.sendall(b"GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n")
            response = b""
            while chunk := tls.recv(4096):
                response += chunk
            assert b"200 OK" in response
            assert response.endswith(b"ok")

assert ctx.check_hostname is True
assert ctx.verify_mode == ssl.CERT_REQUIRED
""",
            str(server.port),
            str(ca_path),
            str(trust_ca),
        )


def _run_script(script, *args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", script, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
