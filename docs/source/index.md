# Truststore

```{toctree}
:maxdepth: 2
:caption: Contents
```

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

Truststore can be installed from [PyPI](https://pypi.org/project/truststore) with pip:

```{code-block} shell
$ python -m pip install truststore
```

Truststore **requires Python 3.10 or later** and supports the following platforms:
- macOS 10.8+ via [Security framework](https://developer.apple.com/documentation/security)
- Windows via [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#certificate-verification-functions)
- Linux via OpenSSL

## User Guide

```{warning}
**PLEASE READ:** `inject_into_ssl()` **must not be used by libraries or packages** as it will cause issues on import time when integrated with other libraries.
Libraries and packages should instead use `truststore.SSLContext` directly which is detailed below. 
The `inject_into_ssl()` function is intended only for use in applications and scripts.
```

You can inject `truststore` into the standard library `ssl` module so the functionality is used
by every library by default. To do so use the `truststore.inject_into_ssl()` function.

The call to `truststore.inject_into_ssl()` should be called as early as possible in
your program as modules that have already imported `ssl.SSLContext` won't be affected.

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

If Truststore can't work for a given platform due to APIs not being available then
at import time the exception `ImportError` will be raised with an informative message:

```python
# On Python 3.9 and earlier:
import truststore  # Raises 'ImportError'

# On macOS 10.7 and earlier:
import truststore  # Raises 'ImportError'
```

### Using truststore with pip

[Pip v22.2](https://discuss.python.org/t/announcement-pip-22-2-release/17543) includes experimental support for verifying certificates with system trust stores using `truststore`. To enable the feature, use the flag `--use-feature=truststore` when installing a package like so:

```{code-block} bash
# Install Django using system trust stores
$ python -m pip install --use-feature=truststore Django
```

This requires `truststore` to be installed in the same environment as the one running pip and to be running Python 3.10 or later. For more information you can [read the pip documentation about the feature](https://pip.pypa.io/en/stable/user_guide/#using-system-trust-stores-for-verifying-https).

### Using truststore with urllib3

```{code-block} python
import urllib3
import truststore

truststore.inject_into_ssl()

http = urllib3.PoolManager()
resp = http.request("GET", "https://example.com")
```

If you'd like to use the `truststore.SSLContext` directly you can pass
the instance via the `ssl_context` parameter:

```{code-block} python
import ssl
import urllib3
import truststore

ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

http = urllib3.PoolManager(ssl_context=ctx)
resp = http.request("GET", "https://example.com")
```

### Using truststore with aiohttp

Truststore supports wrapping either {py:class}`socket.socket` or {py:class}`ssl.MemoryBIO` which means both synchronous and asynchronous I/O can be used:

```{code-block} python
import aiohttp
import truststore

truststore.inject_into_ssl()

async with aiohttp.ClientSession() as http_client:
    async with http_client.get("https://example.com") as http_response:
        ...
```

If you'd like to use the `truststore.SSLContext` directly you can pass
the instance via the `ssl` parameter:

```{code-block} python
import ssl
import aiohttp
import truststore

ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

async with aiohttp.ClientSession(ssl=ctx) as http_client:
    async with http_client.get("https://example.com") as http_response:
        ...
```

### Using truststore with Requests

Just like with `urllib3` using `truststore.inject_into_ssl()` is the easiest method for using Truststore with Requests:

```{code-block} python
import requests
import truststore

truststore.inject_into_ssl()

resp = requests.request("GET", "https://example.com")
```

## Prior art

* [pip v22.2 with support for `--use-feature=truststore`](https://discuss.python.org/t/announcement-pip-22-2-release/17543)
* [The future of trust stores in Python (PyCon US 2022 lightning talk)](https://youtu.be/1IiL31tUEVk?t=698) ([slides](https://speakerdeck.com/sethmlarson/the-future-of-trust-stores-in-python))
* [Experimental APIs in Python 3.10 and the future of trust stores](https://sethmlarson.dev/blog/2021-11-27/experimental-python-3.10-apis-and-trust-stores)
* [PEP 543: A Unified TLS API for Python](https://www.python.org/dev/peps/pep-0543)

## License

MIT
