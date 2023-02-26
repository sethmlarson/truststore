# Truststore

[![PyPI](https://img.shields.io/pypi/v/truststore)](https://pypi.org/project/truststore)
[![CI](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml)

Verify certificates using OS trust stores. This is useful when your system contains
custom certificate authorities such as when using a corporate proxy or using test certificates.
Supports macOS, Windows, and Linux (with OpenSSL).

## Installation

Truststore is installed from [PyPI](https://pypi.org/project/truststore) with pip:

```{code-block} shell
$ python -m pip install truststore
```

Truststore **requires Python 3.10 or later** and supports the following platforms:
- macOS 10.8+ via [Security framework](https://developer.apple.com/documentation/security)
- Windows via [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#certificate-verification-functions)
- Linux via OpenSSL

## User Guide

You can inject `truststore` into the standard library `ssl` module so the functionality is used
by every library by default. To do so use the `truststore.inject_into_ssl()` function:

```python
import truststore
truststore.inject_into_ssl()

# Automatically works with urllib3, requests, aiohttp, and more:
import urllib3
http = urllib3.PoolManager()
resp = http.request("GET", "https://example.com")

import aiohttp
http = aiohttp.ClientSession()
resp = await http.request("GET", "https://example.com")

import requests
resp = requests.get("https://example.com")
```

If you'd like finer-grained control you can create your own `truststore.SSLContext` instance
and use it anywhere you'd use an `ssl.SSLContext`:

```python
import ssl
import truststore

ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

import urllib3
http = urllib3.PoolManager(ssl_context=ctx)
resp = http.request("GET", "https://example.com")
```

You can read more in the [user guide in the documentation](https://truststore.readthedocs.io/en/latest/#user-guide).

## License

MIT
