# Truststore

[![CI](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml/badge.svg)](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml)

Verify certificates using OS trust stores. Supports macOS, Windows, and Linux (with OpenSSL). **This project should be considered experimental.**

## Usage

```python
# The following code works on Linux and macOS without other dependencies.

import socket
from truststore import TruststoreSSLContext

sock = socket.create_connection(("example.com", 443))
ctx = TruststoreSSLContext()
sock = ctx.wrap_socket(sock, server_hostname="example.com")

# Also works with libraries that accept an SSLContext object
import urllib3

http = urllib3.PoolManager(ssl_context=ctx)
http.request("GET", "https://example.com")

import aiohttp

http = aiohttp.ClientSession()
await http.request("GET", "https://example.com", ssl=ctx)
```

## Platforms

Works in the following configurations:

- macOS 10.8+ using Python 3.10+ (via [Security framework](https://developer.apple.com/documentation/security))
- Linux using any Python version

## Prior art

- [PEP 543: A Unified TLS API for Python](https://www.python.org/dev/peps/pep-0543)
- [Experimental APIs in Python 3.10 and the future of trust stores](https://sethmlarson.dev/blog/2021-11-27/experimental-python-3.10-apis-and-trust-stores)

## License

MIT
