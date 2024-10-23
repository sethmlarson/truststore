# Used by the test: test_inject.py::test_aiohttp_work_with_inject

import asyncio
import sys

import truststore

truststore.inject_into_ssl()

import aiohttp  # noqa: E402


async def main():
    async with aiohttp.ClientSession() as client:
        resp = await client.get("https://localhost:9999")
        assert resp.status == 200
        sys.exit(resp.status)


asyncio.run(main())
