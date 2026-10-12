import asyncio
import concurrent.futures
import contextlib
import socket
import ssl
import threading
import typing

import pytest

import truststore
from tests.conftest import Server
from truststore import _api

# Make sure the httpserver doesn't hang
# if the client drops the connection due to a cert verification error
socket.setdefaulttimeout(10)


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

    def is_locked(ctx_lock):
        if acquired := ctx_lock.acquire(blocking=False):
            ctx_lock.release()
        return not acquired

    @contextlib.contextmanager
    def tracking_configure_context(inner_ctx):
        with original_configure_context(inner_ctx):

            def check_lock():
                # Has to be checked from another thread to avoid
                # RLock allowing us to acquire the lock.
                locked_while_configuring.append(is_locked(ctx._ctx_lock))

            check_thread = threading.Thread(target=check_lock)
            check_thread.start()
            check_thread.join()

            yield

    monkeypatch.setattr(_api, "_configure_context", tracking_configure_context)

    ctx.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="localhost")

    assert locked_while_configuring == [True]
    # The lock is only held across the configuration itself,
    # not for the duration of the wrap.
    assert not is_locked(ctx._ctx_lock)


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


def handshake_on_connect(ctx: ssl.SSLContext, server: Server) -> None:
    # wrap_socket() on a connected socket, handshake during wrap.
    sock = socket.create_connection((server.host, server.port))
    try:
        ctx.wrap_socket(sock, server_hostname=server.host).close()
    finally:
        sock.close()


def handshake_deferred(ctx: ssl.SSLContext, server: Server) -> None:
    # wrap_socket(do_handshake_on_connect=False), then explicit do_handshake().
    sock = socket.create_connection((server.host, server.port))
    try:
        tls = ctx.wrap_socket(
            sock, server_hostname=server.host, do_handshake_on_connect=False
        )
        try:
            tls.do_handshake()
        finally:
            tls.close()
    finally:
        sock.close()


def handshake_wrap_then_connect(ctx: ssl.SSLContext, server: Server) -> None:
    # wrap_socket() on an unconnected socket; handshake happens in connect().
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tls = ctx.wrap_socket(sock, server_hostname=server.host)
        try:
            tls.connect((server.host, server.port))
        finally:
            tls.close()
    finally:
        sock.close()


def handshake_bio(ctx: ssl.SSLContext, server: Server) -> None:
    # wrap_bio() + do_handshake() driven over a plain socket
    sock = socket.create_connection((server.host, server.port))
    try:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=server.host)
        while True:
            try:
                obj.do_handshake()
                return
            except ssl.SSLWantReadError:
                pending = outgoing.read()
                if pending:
                    sock.sendall(pending)
                chunk = sock.recv(65536)
                if chunk:
                    incoming.write(chunk)
                else:
                    incoming.write_eof()
    finally:
        sock.close()


handshakes = pytest.mark.parametrize(
    "handshake",
    [
        handshake_on_connect,
        handshake_deferred,
        handshake_wrap_then_connect,
        handshake_bio,
    ],
    ids=["on_connect", "deferred", "wrap_then_connect", "bio"],
)


@handshakes
@pytest.mark.asyncio
async def test_single_handshake_fails_verification(
    handshake: typing.Callable[[ssl.SSLContext, Server], None], invalid_server: Server
) -> None:
    def test_thread():
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(ctx, invalid_server)

        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    thread = asyncio.to_thread(test_thread)
    await thread


@handshakes
@pytest.mark.asyncio
async def test_concurrent_handshakes_never_skip_verification(
    handshake: typing.Callable[[ssl.SSLContext, Server], None],
    invalid_server: Server,
) -> None:
    def test_thread():
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

        # Observer thread: through the public API, the context must never appear
        # relaxed, even while other threads are inside _configure_context().
        stop = threading.Event()
        relaxed_observations: list[tuple[ssl.VerifyMode, bool]] = []

        def observer_thread() -> None:
            while not stop.wait(0.0005):
                mode, check = ctx.verify_mode, ctx.check_hostname
                if mode != ssl.CERT_REQUIRED or check is not True:
                    relaxed_observations.append((mode, check))

        observer = threading.Thread(target=observer_thread, daemon=True)
        observer.start()

        def attempt_handshake(
            handshake: typing.Callable[[ssl.SSLContext, Server], None],
            ctx: ssl.SSLContext,
            server: Server,
        ) -> BaseException | None:
            # Attempt a handshake, returning None only if the handshake
            # fails with a cert verification error, otherwise an exception.
            try:
                handshake(ctx, server)
            except ssl.SSLCertVerificationError:
                return None
            except Exception as e:
                return e
            return AssertionError("Handshake didn't raise an error")

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                outcomes = list(
                    pool.map(
                        lambda _: attempt_handshake(handshake, ctx, invalid_server),
                        range(50),
                    )
                )
        finally:
            stop.set()
            observer.join(timeout=5)

        failures = [o for o in outcomes if o is not None]
        unexpected_successes = sum(isinstance(o, AssertionError) for o in failures)
        assert not failures
        assert not relaxed_observations
        assert not unexpected_successes

        # Context hasn't been downgraded.
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

        with pytest.raises(ssl.SSLCertVerificationError):
            handshake(ctx, invalid_server)

    thread = asyncio.to_thread(test_thread)
    await thread
