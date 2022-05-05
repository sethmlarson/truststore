import asyncio
import pathlib
import ssl
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from typing import AsyncIterator, Iterator

import pytest
from aiohttp import web, ClientSession

import truststore


PORT = 9999  # arbitrary choice
MISSING_CA_ERR_TXT = b"local CA is not installed in the system trust store"


class MissingCAError(Exception):
    pass


async def is_mkcert_installed() -> bool:
    try:
        p = await asyncio.create_subprocess_exec(
            "mkcert",
            "-help",
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return False
    await asyncio.wait_for(p.wait(), timeout=1)
    return p.returncode == 0


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


@asynccontextmanager
async def install_certs() -> AsyncIterator[CertFiles]:
    with get_cert_files() as certfiles:
        cmd = (
            "mkcert"
            f" -cert-file {certfiles.cert_file}"
            f" -key-file {certfiles.key_file}"
            " localhost"
        )
        p = await asyncio.create_subprocess_shell(
            cmd,
            stderr=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(p.wait(), timeout=1)
        stdout, stderr = await p.communicate()
        if MISSING_CA_ERR_TXT in stderr + stdout:
            raise MissingCAError
        assert p.returncode == 0
        yield certfiles


@asynccontextmanager
async def run_server(cert_files: CertFiles) -> AsyncIterator[None]:
    async def handler(request: web.Request) -> web.Response:
        assert request.scheme == "https"  # sanity check
        return web.Response(status=200)

    app = web.Application()
    app.add_routes([web.get("/", handler)])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        certfile=cert_files.cert_file,
        keyfile=cert_files.key_file,
    )
    # we need keepalive_timeout=0
    # see https://github.com/aio-libs/aiohttp/issues/5426
    runner = web.AppRunner(app, keepalive_timeout=0)
    await runner.setup()
    site = web.TCPSite(runner, ssl_context=ctx, port=PORT)
    await site.start()
    try:
        yield
    finally:
        await site.stop()
        await runner.cleanup()


async def send_request() -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with ClientSession() as client:
        resp = await client.get(f"https://localhost:{PORT}", ssl=ctx)
        assert resp.status == 200


@pytest.mark.asyncio
async def test_aiohttp_request_response() -> None:
    if not await is_mkcert_installed():
        pytest.skip(reason="requires mkcert")
    try:
        async with install_certs() as cert_files:
            async with run_server(cert_files):
                await send_request()
    except MissingCAError:
        pytest.skip(reason='mkcert root CA is not installed; run "mkcert -install"')


if __name__ == "__main__":
    asyncio.run(test_aiohttp_request_response())
