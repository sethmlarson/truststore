import asyncio
from asyncio.subprocess import PIPE
import pathlib
import ssl
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from typing import AsyncIterator, Iterator

import pytest
from aiohttp import web, ClientSession

import truststore


@dataclass
class CertFiles:
    key_file: pathlib.Path
    cert_file: pathlib.Path


@contextmanager
def get_cert_files() -> Iterator[CertFiles]:
    with TemporaryDirectory() as tmp_dir:
        tmpdir_path = pathlib.Path(tmp_dir)
        cert_path = tmpdir_path / "localhost.pem"
        key_path = tmpdir_path / "localhost-key.pem"
        yield CertFiles(cert_path, key_path)


async def create_certs(cert_files: CertFiles) -> None:
    p = await asyncio.create_subprocess_exec(
        "mkcert",
        "-install",  # idempotent, installs CA authority
        stderr=PIPE,
        stdout=PIPE,
    )
    await asyncio.wait_for(p.wait(), timeout=1)
    assert p.returncode == 0
    cmd = f"mkcert -cert-file {cert_files.cert_file} -key-file {cert_files.key_file} localhost"
    p = await asyncio.create_subprocess_shell(
        cmd,
        stderr=PIPE,
        stdout=PIPE,
    )
    await asyncio.wait_for(p.wait(), timeout=1)
    assert p.returncode == 0


async def send_request() -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with ClientSession() as client:
        resp = await client.get("https://localhost:8000", ssl=ctx)
        assert resp.status == 200


async def handler(request: web.Request) -> web.Response:
    return web.Response(status=200)


app = web.Application()
app.add_routes([web.get("/", handler)])


@asynccontextmanager
async def run_server(cert_files: CertFiles) -> AsyncIterator[None]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        certfile=cert_files.cert_file,
        keyfile=cert_files.key_file,
    )
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, ssl_context=ctx, port=8000)
    await site.start()
    try:
        yield
    finally:
        await site.stop()


@pytest.mark.asyncio
async def test_aiohttp_request_response() -> None:
    with get_cert_files() as cert_files:
        await create_certs(cert_files)
        async with run_server(cert_files):
            await send_request()


if __name__ == "__main__":
    asyncio.run(test_aiohttp_request_response())
