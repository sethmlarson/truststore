import platform
import ssl

if platform.system() == "Windows":
    from .._windows import _verify_peercerts_impl as _verify_cert_chain_impl
elif platform.system() == "Darwin":
    from .._macos import _verify_peercerts_impl as _verify_cert_chain_impl
else:
    from ._openssl import _verify_cert_chain_impl


def verify_cert_chain(cert_chain):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    _verify_cert_chain_impl(
        ssl_context=context, cert_chain=cert_chain, server_hostname=None
    )
