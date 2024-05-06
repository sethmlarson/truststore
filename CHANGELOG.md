# 0.9.1

* Fixed an issue for CPython 3.13 where `ssl.SSLSocket` and `ssl.SSLObject` certificate
  chain APIs would return different types.

# 0.9.0

* Added support for Python 3.13.
* Fixed loading additional certificates on macOS.
* Changed error message for Windows when peer offers no certificates
  and verification is enabled. Previously was `IndexError`, now is `SSLCertVerificationError`.

# 0.8.0

* Added support for PyPy 3.10 and later.

# 0.7.0

* Changed the error raised when using an unsupported macOS version (10.7 or earlier) from an `OSError` to an `ImportError`
  to match the error raised in other situations where the module isn't supported.

# 0.6.1

* Fixed issue where a `RecursionError` that would be raised when setting `SSLContext.minimum_version` or `.maximum_version`.

# 0.6.0

* **Truststore is now beta! Truststore will be made the default in a future pip release**.
* Added `inject_into_ssl()` and `extract_from_ssl()` to enable Truststore for all
  packages using `ssl.SSLContext` automatically.
* Added support for setting `check_hostname`, `verify_mode`, and `verify_flags`.
* Added pass-through implementations for many `ssl.SSLContext` methods like
  `load_cert_chain()`, `set_alpn_protocols()`, etc. 

# 0.5.0

* **Support for using truststore was released with pip v22.2**!
  You can [read more here](https://sethmlarson.dev/blog/help-test-system-trust-stores-in-python) about how to help us test truststore.
* Added David Glick as an author in packaging metadata.
* Added documentation for how to use `truststore` with urllib3, Requests, aiohttp, and pip.
* Changed macOS SecureTransport error handling to raise as `ssl.SSLError` with
  message from the OS.

# 0.4.0

* Added more descriptive error messages to `ssl.SSLCertVerificationError` determined by the OS on macOS and Windows.
* Changed Windows to follow `SSLContext.verify_flags` for strictly checking CRLs instead of checking CRLs strictly by default.

# 0.3.0

* Added support for loading extra CA certificates via `SSLContext.load_verify_locations()`.
* Added type hints.
* Changed the name of `TruststoreSSLContext` to `SSLContext`.
* Changed certificate hostname verification to rely on macOS and Windows instead of OpenSSL.
* Fixed the order default certificates are loaded for OpenSSL backend.

# 0.2.0

* Added support for Windows via the CryptoAPI.

# 0.1.0

* Initial release with support for macOS and Linux.

