from .._openssl import _configure_context

try:
    import OpenSSL.crypto
    import OpenSSL.SSL
except ImportError:
    raise Exception("Certificate chain verification on OpenSSL requires pyOpenSSL")


def _verify_intermediate_cert_and_add_to_store(store, cert):
    store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)
    store_ctx.verify_certificate()
    store.add_cert(cert)


def _verify_cert_chain_impl(ssl_context, cert_chain, server_hostname=None):
    # We use the pyOpenSSL SSL context, not the stdlib ssl one.
    # Discard the one that was passed in to avoid confusion.
    ssl_context = None

    pyopenssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_CLIENT_METHOD)
    with _configure_context(pyopenssl_context):
        store = pyopenssl_context.get_cert_store()
        for cert in reversed(cert_chain):
            pyopenssl_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1, cert
            )
            _verify_intermediate_cert_and_add_to_store(store, pyopenssl_cert)
