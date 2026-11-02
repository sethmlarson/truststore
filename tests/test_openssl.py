import socket
import ssl
import sys
import threading
from collections.abc import Callable

import pytest
import trustme

import truststore
from tests.conftest import NETWORK_TIMEOUT
from truststore import _api

pytestmark = pytest.mark.skipif(
    sys.platform in ("win32", "darwin"), reason="requires OpenSSL"
)


def handshake_bio(
    client_context: truststore.SSLContext,
    server_context: ssl.SSLContext,
    hostname: str,
) -> str | None:
    """Complete a real TLS exchange without network sockets."""
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    pending = {client, server}

    for _ in range(10):
        for peer, outgoing, incoming in (
            (client, client_out, server_in),
            (server, server_out, client_in),
        ):
            if peer in pending:
                try:
                    peer.do_handshake()
                except ssl.SSLWantReadError:
                    pass
                else:
                    pending.remove(peer)
            incoming.write(outgoing.read())
        if not pending:
            return client.version()

    raise AssertionError("TLS handshake did not complete")


def handshake_socket(
    client_context: truststore.SSLContext,
    server_context: ssl.SSLContext,
    hostname: str,
) -> str | None:
    """Complete a real TLS exchange through connected local sockets."""
    client_socket, server_socket = socket.socketpair()
    # Bound failure cleanup if either side cannot finish its handshake.
    client_socket.settimeout(NETWORK_TIMEOUT)
    server_socket.settimeout(NETWORK_TIMEOUT)

    def serve() -> None:
        try:
            with server_context.wrap_socket(server_socket, server_side=True):
                pass
        except ssl.SSLError:
            # A rejected server certificate sends a TLS alert back here.
            pass

    server_thread = threading.Thread(target=serve)
    server_thread.start()
    try:
        with client_context.wrap_socket(
            client_socket, server_hostname=hostname
        ) as client:
            return client.version()
    finally:
        client_socket.close()
        server_thread.join(NETWORK_TIMEOUT + 1)
        server_socket.close()
        assert not server_thread.is_alive()


_Handshake = Callable[[truststore.SSLContext, ssl.SSLContext, str], str | None]


@pytest.mark.parametrize("handshake", (handshake_bio, handshake_socket))
@pytest.mark.parametrize(
    "trusted, hostname", [(True, "localhost"), (False, "localhost"), (True, "other")]
)
def test_openssl_handshake_does_not_extract_peer_chain(
    monkeypatch: pytest.MonkeyPatch,
    handshake: _Handshake,
    trusted: bool,
    hostname: str,
    trustme_ca: trustme.CA,
    httpserver_ssl_context: ssl.SSLContext,
) -> None:
    client_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trusted:
        trustme_ca.configure_trust(client_context)

    def unexpected_extraction(sslobj: ssl.SSLObject) -> list[bytes]:
        raise AssertionError("OpenSSL verification does not consume the peer chain")

    monkeypatch.setattr(_api, "_get_unverified_chain_bytes", unexpected_extraction)

    if trusted and hostname == "localhost":
        assert handshake(client_context, httpserver_ssl_context, hostname) is not None
    else:
        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(client_context, httpserver_ssl_context, hostname)


@pytest.mark.parametrize("handshake", (handshake_bio, handshake_socket))
def test_handshake_passes_chain_to_verification_backend(
    monkeypatch: pytest.MonkeyPatch,
    handshake: _Handshake,
    trustme_ca: trustme.CA,
    httpserver_ssl_context: ssl.SSLContext,
) -> None:
    client_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(client_context)
    verified_chains = []

    def verify_chain(
        context: ssl.SSLContext, cert_chain: list[bytes], server_hostname: str | None
    ) -> None:
        assert context is client_context._ctx
        assert server_hostname == "localhost"
        verified_chains.append(cert_chain)

    monkeypatch.setattr(_api, "_verify_peercerts_impl", verify_chain)
    assert handshake(client_context, httpserver_ssl_context, "localhost") is not None

    assert verified_chains
    assert all(
        chain and all(isinstance(cert, bytes) for cert in chain)
        for chain in verified_chains
    )
