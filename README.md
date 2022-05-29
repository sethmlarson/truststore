# Truststore

[![PyPI](https://img.shields.io/pypi/v/truststore)](https://pypi.org/project/truststore)
[![CI](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml)

Verify certificates using OS trust stores. Supports macOS, Windows, and Linux (with OpenSSL). **This project should be considered experimental.**

## Usage

```python
# The following code works on Linux, macOS, and Windows without dependencies.
import socket
import ssl
import truststore

# Create an SSLContext for the system trust store
ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

# Connect to the peer and initiate a TLS handshake
sock = socket.create_connection(("example.com", 443))
sock = ctx.wrap_socket(sock, server_hostname="example.com")

# Also works with libraries that accept an SSLContext object
import urllib3

http = urllib3.PoolManager(ssl_context=ctx)
http.request("GET", "https://example.com")

# Works with ssl.MemoryBIO objects for async I/O
import aiohttp

http = aiohttp.ClientSession()
await http.request("GET", "https://example.com", ssl=ctx)
```

## Platforms

Works in the following configurations:

- macOS 10.8+ via [Security framework](https://developer.apple.com/documentation/security)
- Windows via [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#certificate-verification-functions)
- Linux via OpenSSL

## Prior art

- [The future of trust stores in Python (PyCon US 2022 lightning talk)](https://youtu.be/1IiL31tUEVk?t=698) ([slides](https://speakerdeck.com/sethmlarson/the-future-of-trust-stores-in-python))
- [Experimental APIs in Python 3.10 and the future of trust stores](https://sethmlarson.dev/blog/2021-11-27/experimental-python-3.10-apis-and-trust-stores)
- [PEP 543: A Unified TLS API for Python](https://www.python.org/dev/peps/pep-0543)

## License

MIT
