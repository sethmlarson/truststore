import asyncio
import pathlib
import ssl
from contextlib import contextmanager
from dataclasses import dataclass
from tempfile import TemporaryDirectory
from typing import Any, Awaitable, Callable, Dict, Iterator

import aiohttp
import pytest
from uvicorn import Config, Server  # type: ignore[import]

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
        "mkcert", "-install"  # idempotent, installs CA authority
    )
    await asyncio.wait_for(p.wait(), timeout=1)
    assert p.returncode == 0
    p = await asyncio.create_subprocess_shell(
        f"mkcert -cert-file {cert_files.cert_file} -key-file {cert_files.key_file} localhost",
    )
    await asyncio.wait_for(p.wait(), timeout=1)
    assert p.returncode == 0


async def send_request() -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    async with aiohttp.ClientSession() as client:
        resp = await client.get("https://localhost:8000", ssl=ctx)
        assert resp.status == 200


def get_server(event: asyncio.Event, cert_files: CertFiles) -> Server:
    async def app(
        scope: Dict[str, Any],
        receive: Callable[[], Awaitable[Dict[str, Any]]],
        send: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        event.set()
        assert scope["type"] == "http"  # swallowed by ASGI server
        assert scope["scheme"] == "https"  # sanity check
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    config = Config(
        app=app,
        ssl_certfile=str(cert_files.cert_file),
        ssl_keyfile=str(cert_files.key_file),
    )
    server = Server(config)
    return server


@pytest.mark.asyncio
async def test_uvicorn_aiohttp_request() -> None:
    with get_cert_files() as cert_files:
        await create_certs(cert_files)
        event = asyncio.Event()
        server = get_server(event, cert_files)
        server_task = asyncio.create_task(server.serve())
        await asyncio.wait_for(event.wait(), timeout=1)
        await send_request()
        server.should_exit = True
        await server.shutdown()
        await server_task


if __name__ == "__main__":
    asyncio.run(test_uvicorn_aiohttp_request())
