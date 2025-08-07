import asyncio
import socket
import ssl
import threading

import pytest

import truststore


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
