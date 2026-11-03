import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

import pytest
import trustme

import truststore
from truststore._api import _original_SSLContext


def handshake_without_client_certificate(
    verify_mode, client_class=_original_SSLContext, trust_server=True
):
    ca = trustme.CA()
    server_context = truststore.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost").configure_cert(server_context)
    server_context.verify_mode = verify_mode
    client_context = client_class(ssl.PROTOCOL_TLS_CLIENT)
    if trust_server:
        ca.configure_trust(client_context)

    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    client = client_context.wrap_bio(client_in, client_out, server_hostname="localhost")
    completed = set()
    for _ in range(10):
        for connection in (server, client):
            if connection in completed:
                continue
            try:
                connection.do_handshake()
            except ssl.SSLWantReadError:
                pass
            else:
                completed.add(connection)
        client_in.write(server_out.read())
        server_in.write(client_out.read())
        if len(completed) == 2:
            server.write(b"hello")
            client_in.write(server_out.read())
            assert client.read(5) == b"hello"
            return
    pytest.fail("TLS handshake did not complete")


@pytest.mark.parametrize("verify_mode", [ssl.CERT_NONE, ssl.CERT_OPTIONAL])
def test_server_without_client_certificate(verify_mode):
    handshake_without_client_certificate(verify_mode)


def test_server_still_requires_client_certificate():
    with pytest.raises(ssl.SSLError):
        handshake_without_client_certificate(ssl.CERT_REQUIRED)


def test_client_still_verifies_server_certificate():
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake_without_client_certificate(
            ssl.CERT_NONE, client_class=truststore.SSLContext, trust_server=False
        )


@pytest.mark.parametrize("handshake_on_connect", [False, True])
def test_server_socket_without_client_certificate(handshake_on_connect):
    ca = trustme.CA()
    server_context = truststore.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert("localhost").configure_cert(server_context)
    client_context = _original_SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ca.configure_trust(client_context)
    server_socket, client_socket = socket.socketpair()
    server_socket.settimeout(5)
    client_socket.settimeout(5)

    def serve():
        with (
            server_socket,
            server_context.wrap_socket(
                server_socket,
                server_side=True,
                do_handshake_on_connect=handshake_on_connect,
            ) as connection,
        ):
            if not handshake_on_connect:
                connection.do_handshake()
            request = connection.recv(4)
            connection.sendall(b"pong")
            return request

    with ThreadPoolExecutor(max_workers=1) as executor:
        response = executor.submit(serve)
        with (
            client_socket,
            client_context.wrap_socket(
                client_socket, server_hostname="localhost"
            ) as connection,
        ):
            connection.sendall(b"ping")
            assert connection.recv(4) == b"pong"
        assert response.result(timeout=5) == b"ping"
