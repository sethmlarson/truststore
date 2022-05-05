import os
import platform
import socket
import ssl

from _ssl import ENCODING_DER  # type: ignore[import]

if platform.system() == "Windows":
    from ._windows import _configure_context, _verify_peercerts_impl
elif platform.system() == "Darwin":
    from ._macos import _configure_context, _verify_peercerts_impl
else:
    from ._openssl import _configure_context, _verify_peercerts_impl


class TruststoreSSLObject(ssl.SSLObject):
    # This object exists because wrap_bio() doesn't
    # immediately do the handshake so we need to do
    # certificate verifications after SSLObject.do_handshake()

    def do_handshake(self) -> None:
        ret = super().do_handshake()
        _verify_peercerts(self, server_hostname=self.server_hostname)
        return ret


class SSLContext(ssl.SSLContext):
    """SSLContext API that uses system certificates on all platforms"""

    sslobject_class = TruststoreSSLObject

    def __new__(cls, protocol: int = ssl.PROTOCOL_TLS) -> "SSLContext":
        self = ssl.SSLContext.__new__(cls, protocol)
        _configure_context(self)
        return self

    def wrap_socket(
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLSocket:
        ssl_sock = super().wrap_socket(
            sock,
            server_side=server_side,
            server_hostname=server_hostname,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            session=session,
        )
        try:
            _verify_peercerts(ssl_sock, server_hostname=server_hostname)
        except ssl.SSLError:
            ssl_sock.close()
            raise
        return ssl_sock

    def wrap_bio(
        self,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
        server_side: bool = False,
        server_hostname: str | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLObject:
        ssl_obj = super().wrap_bio(
            incoming,
            outgoing,
            server_hostname=server_hostname,
            server_side=server_side,
            session=session,
        )
        return ssl_obj

    def load_verify_locations(
        self,
        cafile: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,
        capath: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,
        cadata: str | bytes | None = None,
    ) -> None:
        return super().load_verify_locations(cafile, capath, cadata)

    @property
    def verify_mode(self) -> ssl.VerifyMode:
        # Indicate that this truststore always verifies certificates,
        # even when _configure_context has set the OpenSSL verify_mode to NONE
        # to avoid verifying twice when we're also using the OS APIs.
        return ssl.CERT_REQUIRED

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode):
        if value != ssl.CERT_REQUIRED:
            raise NotImplementedError("truststore.SSLContext does not support disabling certificate verification.")

    @property
    def check_hostname(self) -> bool:
        return True

    @check_hostname.setter
    def check_hostname(self, value: bool):
        if not value:
            raise NotImplementedError("truststore.SSLContext does not support disabling check_hostname")


def _verify_peercerts(
    sock_or_sslobj: ssl.SSLSocket | ssl.SSLObject, server_hostname: str | None
) -> None:
    """
    Verifies the peer certificates from an SSLSocket or SSLObject
    against the certificates in the OS trust store.
    """
    sslobj: ssl.SSLObject = sock_or_sslobj  # type: ignore[assignment]
    try:
        while not hasattr(sslobj, "get_unverified_chain"):
            sslobj = sslobj._sslobj  # type: ignore[attr-defined]
    except AttributeError:
        pass

    cert_bytes = [
        cert.public_bytes(ENCODING_DER) for cert in sslobj.get_unverified_chain()  # type: ignore[attr-defined]
    ]
    _verify_peercerts_impl(
        sock_or_sslobj.context, cert_bytes, server_hostname=server_hostname
    )
