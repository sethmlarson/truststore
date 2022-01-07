# Native OS trust stores in Python

[![CI](https://github.com/sethmlarson/python-truststore/actions/workflows/ci.yml/badge.svg)](https://github.com/sethmlarson/python-truststore/actions/workflows/ci.yml)

Verify peer certificates using OS trust stores. Supports macOS, Windows, and Linux+OpenSSL. This

**This project should be considered experimental.**

## Usage

```python
# The following code works on Linux and macOS without other dependencies.

import socket
from truststore import Truststore

sock = socket.create_connection(("example.com", 443))
ts = Truststore()
sock = ts.wrap_socket(sock, server_hostname="example.com")
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
