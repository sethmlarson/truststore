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


class _PausingContext:
    """Stands in for the wrapped ssl.SSLContext and makes wrap_bio() wait,
    so that threads can be held inside the configured section."""

    def __init__(self, real, entered, release):
        self._real = real
        self._entered = entered
        self._release = release

    def __getattr__(self, name):
        return getattr(self._real, name)

    def wrap_bio(self, *args, **kwargs):
        self._entered[threading.current_thread().name].set()
        assert self._release[threading.current_thread().name].wait(10)


def test_overlapping_threads_restore_the_verification_settings(monkeypatch):
    """Two threads inside wrap_bio() at once must not leave the shared context
    with its verification relaxed. _configure_context() is replaced by a copy of
    the macOS and Windows one, which relaxes the settings and restores what it
    saved."""
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    real = ctx._ctx
    assert real.verify_mode == ssl.CERT_REQUIRED
    assert real.check_hostname

    @contextlib.contextmanager
    def relax_and_restore(_):
        check_hostname = real.check_hostname
        verify_mode = real.verify_mode
        real.check_hostname = False
        real.verify_mode = ssl.CERT_NONE
        try:
            yield
        finally:
            real.check_hostname = check_hostname
            real.verify_mode = verify_mode

    monkeypatch.setattr(_api, "_configure_context", relax_and_restore)
    names = ("first", "second")
    entered = {name: threading.Event() for name in names}
    release = {name: threading.Event() for name in names}
    ctx._ctx = _PausingContext(real, entered, release)

    def call():
        ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="localhost")

    threads = {name: threading.Thread(target=call, name=name) for name in names}
    threads["first"].start()
    assert entered["first"].wait(10)
    threads["second"].start()
    assert entered["second"].wait(10)

    # the thread that came first leaves first, then the other one
    release["first"].set()
    threads["first"].join(10)
    release["second"].set()
    threads["second"].join(10)

    assert real.verify_mode == ssl.CERT_REQUIRED
    assert real.check_hostname


def test_configure_context_is_restored_when_the_last_thread_leaves(monkeypatch):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    calls = []

    @contextlib.contextmanager
    def tracking(_):
        calls.append("enter")
        try:
            yield
        finally:
            calls.append("exit")

    monkeypatch.setattr(_api, "_configure_context", tracking)
    with ctx._configured_ctx():
        with ctx._configured_ctx():
            assert calls == ["enter"]
        assert calls == ["enter"]
    assert calls == ["enter", "exit"]

    with ctx._configured_ctx():
        pass
    assert calls == ["enter", "exit", "enter", "exit"]
