import socket
import ssl
import threading

import pytest
import trustme

import truststore


def test_wrap_socket_before_connect_stays_lazy_and_still_verifies() -> None:
    """Unconnected wrap_socket must not verify yet, and connect still must.

    stdlib allows wrap_socket() before connect(). Issue #210: truststore
    verified immediately and raised AttributeError because _sslobj is None.
    A later handshake against a CA that is not in the OS trust store must
    still fail.
    """
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_ctx)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        try:
            with server_ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(5)
                tls.recv(16)
        except Exception:
            try:
                conn.close()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrapped: ssl.SSLSocket | None = None
    try:
        wrapped = ctx.wrap_socket(raw, server_hostname="localhost")
        wrapped.settimeout(5)
        with pytest.raises(ssl.SSLError):
            wrapped.connect(("127.0.0.1", port))
    finally:
        if wrapped is not None:
            wrapped.close()
        listener.close()
        thread.join(timeout=5)
