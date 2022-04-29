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

