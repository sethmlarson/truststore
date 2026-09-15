import asyncio
import contextlib
import socket
import ssl
import threading

import pytest

import truststore
from truststore import _api


def wrap_and_close_sockets(ctx: truststore.SSLContext, host: str, port: int) -> None:
    for _ in range(100):
        sock = None
        try:
            sock = socket.create_connection((host, port))
            sock = ctx.wrap_socket(sock, server_hostname=host)
        finally:
            if sock:
                sock.close()


@pytest.mark.asyncio
async def test_threading(server):
    def run_threads():
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        threads = [
            threading.Thread(
                target=wrap_and_close_sockets, args=(ctx, server.host, server.port)
            )
            for _ in range(16)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    thread = asyncio.to_thread(run_threads)
    await thread


def test_wrap_bio_configures_context_under_lock(monkeypatch):
    """wrap_bio() must configure the shared context while holding the
    context lock, the same as wrap_socket() does, because configuring
    the context mutates it.
    """
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    original_configure_context = _api._configure_context
    locked_while_configuring = []

    @contextlib.contextmanager
    def tracking_configure_context(inner_ctx):
        with original_configure_context(inner_ctx):
            locked_while_configuring.append(ctx._ctx_lock.locked())
            yield

    monkeypatch.setattr(_api, "_configure_context", tracking_configure_context)

    ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="localhost")

    assert locked_while_configuring == [True]
    # The lock is only held across the configuration itself,
    # not for the duration of the wrap.
    assert not ctx._ctx_lock.locked()


def test_threading_wrap_bio():
    """Stress the wrap_bio() path from many threads sharing one context.

    Unlike the test above this one is probabilistic: without the lock the
    concurrent mutation of the shared context is a data race inside OpenSSL,
    so the failure is a native abort or segfault that takes the whole
    process (and therefore the test run) down rather than a failed assert.
    """
    def wrap_bios(ctx: truststore.SSLContext, host: str) -> None:
        for _ in range(100):
            ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname=host)

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    threads = [
        threading.Thread(target=wrap_bios, args=(ctx, "localhost")) for _ in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
