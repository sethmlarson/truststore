import asyncio
import ssl

import pytest
import urllib3

import truststore

from .conftest import Server

try:
    import pytest_memray  # noqa: F401

    memray_installed = True
except ImportError:
    memray_installed = False


@pytest.mark.skipif(not memray_installed, reason="Memray isn't installed")
@pytest.mark.limit_memory("1MB")
@pytest.mark.asyncio
async def test_memory_limit(server: Server) -> None:
    def run_requests():
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for _ in range(10000):
            with urllib3.PoolManager(ssl_context=ctx) as http:
                http.request("HEAD", server.base_url)
                http.clear()  # Close connections so we get new ones.

    thread = asyncio.to_thread(run_requests)
    await thread
