"""Verify certificates using OS trust stores"""

import sys as _sys

if _sys.version_info < (3, 10):
    raise ImportError("truststore requires Python 3.10 or later")
del _sys

from ._api import TruststoreSSLContext  # noqa: E402

__all__ = ["TruststoreSSLContext"]
__version__ = "0.2.0"
