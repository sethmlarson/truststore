# Truststore

```{toctree}
:maxdepth: 2
:caption: Contents
```

Verify certificates using OS trust stores. Supports macOS, Windows, and Linux (with OpenSSL).

```{warning}
This project should be considered experimental so shouldn't be used in production.
```

## Platforms

- Requires Python 3.10 or later
- Supports macOS 10.8+ via [Security framework](https://developer.apple.com/documentation/security)
- Supports Windows via [CryptoAPI](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions#certificate-verification-functions)
- Supports Linux via OpenSSL

## Usage

The `truststore` module has a single API: `truststore.SSLContext`

```{code-block} python
   import truststore

   ctx = truststore.SSLContext()
```

### Using truststore with pip

Pip v22.2 includes experimental support for verifying certificates with system trust stores using `truststore`. To enable the feature, use the flag `--use-feature=truststore` when installing a package like so:

```{code-block} bash
   # Install Django using system trust stores
   $ python -m pip install --use-feature=truststore Django
```

This requires `truststore` to be installed in the same environment as the one running pip and to be running Python 3.10 or later. For more information you can [read the pip documentation about the feature](https://pip.pypa.io/en/stable/user_guide/#using-system-trust-stores-for-verifying-https).

### Using truststore with urllib3

This `SSLContext` works the same as an {py:class}`ssl.SSLContext`.
You can use it anywhere you would use an {py:class}`ssl.SSLContext` and
system trust stores are automatically used to verify peer certificates:

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
   import ssl
   import aiohttp
   import truststore

   ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

   http = aiohttp.ClientSession(ssl=ctx)
   resp = await http.request("GET", "https://example.com")
```

### Using truststore with Requests

Requests doesn't support passing an {py:class}`ssl.SSLContext` object to a `requests.Session` object directly so there's an additional class you need to inject the `truststore.SSLContext` instance to the lower-level {py:class}`urllib3.PoolManager` instance:

```{code-block} python
   import ssl
   import requests
   import requests.adapters
   import truststore

   class SSLContextAdapter(requests.adapters.HTTPAdapter):
       def __init__(self, *, ssl_context=None, **kwargs):
           self._ssl_context = ssl_context
           super().__init__(**kwargs)

       def init_poolmanager(self, *args, **kwargs):
           if self._ssl_context is not None:
               kwargs.setdefault("ssl_context", self._ssl_context)
           return super().init_poolmanager(*args, **kwargs)

   ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

   http = requests.Session()
   adapter = SSLContextAdapter(ssl_context=ctx)
   http.mount("https://", adapter)

   resp = http.request("GET", "https://example.com")
```

## Prior art

* [The future of trust stores in Python (PyCon US 2022 lightning talk)](https://youtu.be/1IiL31tUEVk?t=698) ([slides](https://speakerdeck.com/sethmlarson/the-future-of-trust-stores-in-python))
* [Experimental APIs in Python 3.10 and the future of trust stores](https://sethmlarson.dev/blog/2021-11-27/experimental-python-3.10-apis-and-trust-stores)
* [PEP 543: A Unified TLS API for Python](https://www.python.org/dev/peps/pep-0543)

## License

MIT
