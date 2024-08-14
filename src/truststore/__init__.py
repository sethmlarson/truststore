"""Verify certificates using native system trust stores"""

import sys as _sys

if _sys.version_info < (3, 10):
    raise ImportError("truststore requires Python 3.10 or later")

# Detect Python runtimes which don't implement SSLObject.get_unverified_chain() API
# This API only became public in CPython 3.13 but was available in CPython since 3.10.
try:
    import ssl as _ssl
except ImportError:
    raise ImportError("truststore requires the 'ssl' module")
else:
    if not hasattr(_ssl.SSLSocket, "get_unverified_chain"):
        raise ImportError("truststore requires peer certificate APIs to be available")

from ._api import SSLContext, extract_from_ssl, inject_into_ssl  # noqa: E402

del _api, _sys, _ssl  # type: ignore[name-defined] # noqa: F821

__all__ = ["SSLContext", "inject_into_ssl", "extract_from_ssl"]
__version__ = "0.9.2"
