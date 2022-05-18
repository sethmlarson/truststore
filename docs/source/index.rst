Truststore
==========

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Verify certificates using OS trust stores. Supports macOS, Windows, and Linux (with OpenSSL).

.. warning::
   
   This project should be considered experimental so shouldn't be used in production.

Usage
-----

The ``truststore`` module has a single API: ``truststore.SSLContext``

.. code-block:: python

   import truststore

   ctx = truststore.SSLContext()

This ``SSLContext`` works the same as an :py:class:`ssl.SSLContext`.
You can use it anywhere you would use an :py:class:`ssl.SSLContext` and
system trust stores are automatically used to verify peer certificates:

.. code-block:: python

   import urllib3

   http = urllib3.PoolManager(ssl_context=ctx)
   http.request("GET", "https://example.com")

Supports wrapping :py:class:`socket.socket` and :py:class:`ssl.MemoryBIO` so
works with both synchronous and asynchronous I/O:

.. code-block:: python

   import aiohttp

   http = aiohttp.ClientSession(ssl=ctx)
   await http.request("GET", "https://example.com")

Prior art
---------

* `The future of trust stores in Python (PyCon US 2022 lightning talk) <https://speakerdeck.com/sethmlarson/the-future-of-trust-stores-in-python>`_
* `Experimental APIs in Python 3.10 and the future of trust stores <https://sethmlarson.dev/blog/2021-11-27/experimental-python-3.10-apis-and-trust-stores>`_
* `PEP 543: A Unified TLS API for Python <https://www.python.org/dev/peps/pep-0543>`_

License
-------

MIT
