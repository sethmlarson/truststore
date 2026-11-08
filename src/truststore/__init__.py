"""Verify certificates using native system trust stores"""

import sys as _sys


def _check_runtime() -> None:
    """Reject runtimes without the SSL APIs needed for certificate verification."""
    if _sys.version_info < (3, 10):  # noqa: UP036
        raise ImportError("truststore requires Python 3.10 or later")

    # The chain API is public since 3.13 and available in CPython/PyPy since 3.10.
    if _sys.version_info >= (3, 13) or _sys.implementation.name in ("cpython", "pypy"):
        return

    try:
        import ssl as _ssl
    except ImportError:
        raise ImportError("truststore requires the 'ssl' module")

    _sslmem = _ssl.MemoryBIO()
    _sslobj = _ssl.create_default_context().wrap_bio(
        _sslmem,
        _sslmem,
    )
    try:
        while not hasattr(_sslobj, "get_unverified_chain"):
            _sslobj = _sslobj._sslobj  # type: ignore[attr-defined]
    except AttributeError:
        raise ImportError(
            "truststore requires peer certificate chain APIs to be available"
        ) from None


_check_runtime()

from ._api import SSLContext, extract_from_ssl, inject_into_ssl

__all__ = ["SSLContext", "extract_from_ssl", "inject_into_ssl"]
__version__ = "0.10.5"
