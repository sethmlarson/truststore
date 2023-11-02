# Truststore

[![PyPI](https://img.shields.io/pypi/v/truststore)](https://pypi.org/project/truststore)
[![CI](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sethmlarson/truststore/actions/workflows/ci.yml)

Truststore is a library which exposes native system certificate stores (ie "trust stores")
through an `ssl.SSLContext`-like API. This means that Python applications no longer need to
rely on certifi as a root certificate store. Native system certificate stores
have many helpful features compared to a static certificate bundle like certifi:

- Automatically update certificates as new CAs are created and removed
- Fetch missing intermediate certificates
- Check certificates against certificate revocation lists (CRLs) to avoid monster-in-the-middle (MITM) attacks
- Managed per-system rather than per-application by a operations/IT team
- PyPI is no longer a CA distribution channel 🥳

Right now truststore is a stand-alone library that can be installed globally in your
application to immediately take advantage of the benefits in Python 3.10+. Truststore
has also been integrated into pip as an opt-in method for verifying HTTPS certificates
with truststore instead of certifi.

Long-term the hope is to make truststore the default way to verify HTTPS certificates in pip
and to add this functionality into Python itself. Wish us luck!

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

> **Warning**
> **PLEASE READ:** `inject_into_ssl()` **must not be used by libraries or packages** as it will cause issues on import time when integrated with other libraries.
> Libraries and packages should instead use `truststore.SSLContext` directly which is detailed below.
> 
> The `inject_into_ssl()` function is intended only for use in applications and scripts.

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

If you'd like finer-grained control or you're developing a library or package you can create your own `truststore.SSLContext` instance
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
