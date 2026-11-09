from __future__ import annotations

import _ssl
import errno
import os
import platform
import socket
import ssl
import sys
import threading
import typing

from ._ssl_constants import (
    _original_SSLContext,
    _original_super_SSLContext,
    _truststore_SSLContext_dunder_class,
    _truststore_SSLContext_super_class,
)
from ._verify import PeerVerificationState

if platform.system() == "Windows":
    from ._windows import _configure_context, _verify_peercerts_impl

    _verify_after_handshake = True
elif platform.system() == "Darwin":
    from ._macos import _configure_context, _verify_peercerts_impl

    _verify_after_handshake = True
else:
    from ._openssl import _configure_context, _verify_peercerts_impl

    _verify_after_handshake = False

if typing.TYPE_CHECKING:
    from typing_extensions import Buffer

    if sys.version_info >= (3, 14):
        _SocketAddress: typing.TypeAlias = tuple[typing.Any, ...] | str | Buffer | int
    else:
        _SocketAddress: typing.TypeAlias = tuple[typing.Any, ...] | str | Buffer

# From typeshed/stdlib/ssl.pyi
_StrOrBytesPath: typing.TypeAlias = str | bytes | os.PathLike[str] | os.PathLike[bytes]
_PasswordType: typing.TypeAlias = str | bytes | typing.Callable[[], str | bytes]


def _handshake_if_connected(
    ssl_sock: ssl.SSLSocket, *, do_handshake_on_connect: bool
) -> None:
    """Run the requested handshake when wrap_socket() received a connected socket."""
    try:
        ssl_sock.getpeername()
    except OSError as error:
        if error.errno == errno.ENOTCONN:
            return
        ssl_sock.close()
        raise

    if not do_handshake_on_connect:
        return
    if ssl_sock.gettimeout() == 0.0:
        ssl_sock.close()
        raise ValueError(
            "do_handshake_on_connect should not be specified for non-blocking sockets"
        )
    try:
        ssl_sock.do_handshake()
    except Exception:
        ssl_sock.close()
        raise


def inject_into_ssl() -> None:
    """Injects the :class:`truststore.SSLContext` into the ``ssl``
    module by replacing :class:`ssl.SSLContext`.
    """
    vars(ssl)["SSLContext"] = SSLContext
    # urllib3 holds on to its own reference of ssl.SSLContext
    # so we need to replace that reference too.
    try:
        import urllib3.util.ssl_ as urllib3_ssl

        vars(urllib3_ssl)["SSLContext"] = SSLContext
    except ImportError:
        pass

    # requests starting with 2.32.0 added a preloaded SSL context to improve concurrent performance;
    # this unfortunately leads to a RecursionError, which can be avoided by patching the preloaded SSL context with
    # the truststore patched instance
    # also see https://github.com/psf/requests/pull/6667
    try:
        import requests.adapters

        preloaded_context = getattr(requests.adapters, "_preloaded_ssl_context", None)
        if preloaded_context is not None:
            vars(requests.adapters)["_preloaded_ssl_context"] = SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )
    except ImportError:
        pass


def extract_from_ssl() -> None:
    """Restores the :class:`ssl.SSLContext` class to its original state"""
    vars(ssl)["SSLContext"] = _original_SSLContext
    try:
        import urllib3.util.ssl_ as urllib3_ssl

        vars(urllib3_ssl)["SSLContext"] = _original_SSLContext
    except ImportError:
        pass


class _VerificationStateCarrier(typing.Protocol):
    _truststore_verification_state: PeerVerificationState | None


def _stored_verification_state(
    wrapped: _VerificationStateCarrier,
) -> PeerVerificationState:
    """Return the verification policy captured while wrapping the object."""
    verification_state = wrapped._truststore_verification_state
    if verification_state is None:
        raise RuntimeError("Missing peer verification state")
    return verification_state


class SSLContext(_truststore_SSLContext_super_class):  # type: ignore[misc]
    """SSLContext API that uses system certificates on all platforms"""

    @property  # type: ignore[misc]
    def __class__(self) -> type:
        # Dirty hack to get around isinstance() checks
        # for ssl.SSLContext instances in aiohttp/trustme
        # when using non-CPython implementations.
        return _truststore_SSLContext_dunder_class or SSLContext

    def __init__(self, protocol: int | None = None) -> None:
        self._ctx = _original_SSLContext(protocol)
        self._ctx_lock = threading.RLock()

        ctx_lock = self._ctx_lock  # Reference used by sslobject/sslsocket classes.

        class TruststoreSSLObject(ssl.SSLObject):
            """Complete MemoryBIO handshakes with truststore peer verification."""

            _truststore_verification_state: PeerVerificationState | None = None

            def do_handshake(self) -> None:
                """Run the TLS handshake, then verify its peer certificate."""
                if _verify_after_handshake:
                    verification_state = _stored_verification_state(self)
                    super().do_handshake()
                    _verify_peercerts(
                        self,
                        server_hostname=self.server_hostname,
                        verification_state=verification_state,
                    )
                    return

                with ctx_lock:
                    verification_state = PeerVerificationState(self.context)
                    super().do_handshake()
                    _verify_peercerts(
                        self,
                        server_hostname=self.server_hostname,
                        verification_state=verification_state,
                    )

        class TruststoreSSLSocket(ssl.SSLSocket):
            """Complete socket handshakes with truststore peer verification."""

            _truststore_verification_state: PeerVerificationState | None = None
            do_handshake_on_connect: bool

            def do_handshake(self, block: bool = False) -> None:
                """Run the TLS handshake, then verify its peer certificate."""
                if _verify_after_handshake:
                    verification_state = _stored_verification_state(self)
                    super().do_handshake(block)
                    self._verify_peer(verification_state)
                    return

                with ctx_lock:
                    verification_state = PeerVerificationState(self.context)
                    super().do_handshake(block)
                    self._verify_peer(verification_state)

            def _verify_peer(self, verification_state: PeerVerificationState) -> None:
                """Verify the peer and close the socket on failure."""
                try:
                    _verify_peercerts(
                        self,
                        server_hostname=self.server_hostname,
                        verification_state=verification_state,
                    )
                except Exception:
                    self.close()
                    raise

            def _stdlib_connect(
                self, address: _SocketAddress, *, connect_ex: bool
            ) -> int | None:
                """Call the selected stdlib connection method."""
                if connect_ex:
                    return super().connect_ex(address)
                super().connect(address)
                return None

            @typing.overload
            def _connect_with_system_verifier(
                self,
                address: _SocketAddress,
                *,
                connect_ex: typing.Literal[False],
            ) -> None: ...

            @typing.overload
            def _connect_with_system_verifier(
                self,
                address: _SocketAddress,
                *,
                connect_ex: typing.Literal[True],
            ) -> int: ...

            def _connect_with_system_verifier(
                self, address: _SocketAddress, *, connect_ex: bool
            ) -> int | None:
                """Create a deferred SSL object before its verified handshake."""
                if not _verify_after_handshake:
                    return self._stdlib_connect(address, connect_ex=connect_ex)

                # Split native SSL object creation from the automatic handshake.
                do_handshake_on_connect = self.do_handshake_on_connect
                self.do_handshake_on_connect = False

                # A deferred SSL object must inherit wrap_socket()'s temporary state.
                try:
                    with ctx_lock, _configure_context(self.context):
                        result = self._stdlib_connect(address, connect_ex=connect_ex)
                finally:
                    self.do_handshake_on_connect = do_handshake_on_connect

                # Verify after restoring the public context state.
                if do_handshake_on_connect and (result is None or result == 0):
                    self.do_handshake()

                return result

            def connect(self, address: _SocketAddress) -> None:
                self._connect_with_system_verifier(address, connect_ex=False)

            def connect_ex(self, address: _SocketAddress) -> int:
                return self._connect_with_system_verifier(address, connect_ex=True)

        self._ctx.sslsocket_class = TruststoreSSLSocket
        self._ctx.sslobject_class = TruststoreSSLObject

    def _wrap_socket_for_post_handshake_verification(
        self,
        sock: socket.socket,
        *,
        server_side: bool,
        do_handshake_on_connect: bool,
        suppress_ragged_eofs: bool,
        server_hostname: str | None,
        session: ssl.SSLSession | None,
    ) -> ssl.SSLSocket:
        """Wrap a socket without holding the context lock during its handshake."""
        with self._ctx_lock:
            verification_state = PeerVerificationState(self._ctx)

            # Create under temporary OpenSSL state; handshake after restoring it.
            with _configure_context(self._ctx):
                ssl_sock = self._ctx.wrap_socket(
                    sock,
                    server_side=server_side,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=False,
                    suppress_ragged_eofs=suppress_ragged_eofs,
                    session=session,
                )

            # Preserve the public verification policy for the later handshake.
            ssl_sock._truststore_verification_state = verification_state  # type: ignore[attr-defined]
            ssl_sock.do_handshake_on_connect = do_handshake_on_connect  # type: ignore[attr-defined]

        _handshake_if_connected(
            ssl_sock, do_handshake_on_connect=do_handshake_on_connect
        )

        return ssl_sock

    def wrap_socket(
        self,
        sock: socket.socket,
        server_side: bool = False,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = True,
        server_hostname: str | None = None,
        session: ssl.SSLSession | None = None,
    ) -> ssl.SSLSocket:
        if self.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")

        if _verify_after_handshake:
            return self._wrap_socket_for_post_handshake_verification(
                sock,
                server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs,
                server_hostname=server_hostname,
                session=session,
            )

        with self._ctx_lock:
            verification_state = PeerVerificationState(self._ctx)
            with _configure_context(self._ctx):
                ssl_sock = self._ctx.wrap_socket(
                    sock,
                    server_side=server_side,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=do_handshake_on_connect,
                    suppress_ragged_eofs=suppress_ragged_eofs,
                    session=session,
                )

            # Connected sockets verify now; deferred sockets verify on handshake.
            if ssl_sock.version() is not None:
                try:
                    _verify_peercerts(
                        ssl_sock,
                        server_hostname=server_hostname,
                        verification_state=verification_state,
                    )
                except Exception:
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
        if self.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")

        with self._ctx_lock:
            verification_state = PeerVerificationState(self._ctx)
            with _configure_context(self._ctx):
                ssl_obj = self._ctx.wrap_bio(
                    incoming,
                    outgoing,
                    server_hostname=server_hostname,
                    server_side=server_side,
                    session=session,
                )
            # MemoryBIO defers its handshake, so retain the captured policy.
            ssl_obj._truststore_verification_state = verification_state  # type: ignore[attr-defined]
        return ssl_obj

    def load_verify_locations(
        self,
        cafile: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,
        capath: str | bytes | os.PathLike[str] | os.PathLike[bytes] | None = None,
        cadata: str | Buffer | None = None,
    ) -> None:
        return self._ctx.load_verify_locations(
            cafile=cafile, capath=capath, cadata=cadata
        )

    def load_cert_chain(
        self,
        certfile: _StrOrBytesPath,
        keyfile: _StrOrBytesPath | None = None,
        password: _PasswordType | None = None,
    ) -> None:
        return self._ctx.load_cert_chain(
            certfile=certfile, keyfile=keyfile, password=password
        )

    def load_default_certs(
        self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH
    ) -> None:
        return self._ctx.load_default_certs(purpose)

    def set_alpn_protocols(self, alpn_protocols: typing.Iterable[str]) -> None:
        return self._ctx.set_alpn_protocols(alpn_protocols)

    def set_npn_protocols(self, npn_protocols: typing.Iterable[str]) -> None:
        return self._ctx.set_npn_protocols(npn_protocols)

    def set_ciphers(self, cipherlist: str, /) -> None:
        return self._ctx.set_ciphers(cipherlist)

    def get_ciphers(self) -> typing.Any:
        return self._ctx.get_ciphers()

    if sys.version_info >= (3, 13):

        def set_psk_client_callback(
            self,
            callback: typing.Callable[[str | None], tuple[str | None, bytes]] | None,
        ) -> None:
            """Set the TLS-PSK client callback."""
            return self._ctx.set_psk_client_callback(callback)

        def set_psk_server_callback(
            self,
            callback: typing.Callable[[str | None], bytes] | None,
            identity_hint: str | None = None,
        ) -> None:
            """Set the TLS-PSK server callback."""
            return self._ctx.set_psk_server_callback(callback, identity_hint)

    def session_stats(self) -> dict[str, int]:
        return self._ctx.session_stats()

    def cert_store_stats(self) -> dict[str, int]:
        raise NotImplementedError()

    def set_default_verify_paths(self) -> None:
        self._ctx.set_default_verify_paths()

    @typing.overload
    def get_ca_certs(
        self, binary_form: typing.Literal[False] = ...
    ) -> list[typing.Any]: ...

    @typing.overload
    def get_ca_certs(self, binary_form: typing.Literal[True] = ...) -> list[bytes]: ...

    @typing.overload
    def get_ca_certs(self, binary_form: bool = ...) -> typing.Any: ...

    def get_ca_certs(self, binary_form: bool = False) -> list[typing.Any] | list[bytes]:
        raise NotImplementedError()

    @property
    def check_hostname(self) -> bool:
        with self._ctx_lock:
            return self._ctx.check_hostname

    @check_hostname.setter
    def check_hostname(self, value: bool) -> None:
        with self._ctx_lock:
            self._ctx.check_hostname = value

    @property
    def hostname_checks_common_name(self) -> bool:
        return self._ctx.hostname_checks_common_name

    @hostname_checks_common_name.setter
    def hostname_checks_common_name(self, value: bool) -> None:
        self._ctx.hostname_checks_common_name = value

    @property
    def keylog_filename(self) -> str:
        return self._ctx.keylog_filename

    @keylog_filename.setter
    def keylog_filename(self, value: str) -> None:
        self._ctx.keylog_filename = value

    @property
    def maximum_version(self) -> ssl.TLSVersion:
        return self._ctx.maximum_version

    @maximum_version.setter
    def maximum_version(self, value: ssl.TLSVersion) -> None:
        _original_super_SSLContext.maximum_version.__set__(  # type: ignore[attr-defined]
            self._ctx, value
        )

    @property
    def minimum_version(self) -> ssl.TLSVersion:
        return self._ctx.minimum_version

    @minimum_version.setter
    def minimum_version(self, value: ssl.TLSVersion) -> None:
        _original_super_SSLContext.minimum_version.__set__(  # type: ignore[attr-defined]
            self._ctx, value
        )

    @property
    def options(self) -> ssl.Options:
        return self._ctx.options

    @options.setter
    def options(self, value: ssl.Options) -> None:
        _original_super_SSLContext.options.__set__(  # type: ignore[attr-defined]
            self._ctx, value
        )

    @property
    def post_handshake_auth(self) -> bool:
        return self._ctx.post_handshake_auth

    @post_handshake_auth.setter
    def post_handshake_auth(self, value: bool) -> None:
        self._ctx.post_handshake_auth = value

    @property
    def protocol(self) -> ssl._SSLMethod:
        return self._ctx.protocol

    @property
    def security_level(self) -> int:
        return self._ctx.security_level

    @property
    def verify_flags(self) -> ssl.VerifyFlags:
        return self._ctx.verify_flags

    @verify_flags.setter
    def verify_flags(self, value: ssl.VerifyFlags) -> None:
        _original_super_SSLContext.verify_flags.__set__(  # type: ignore[attr-defined]
            self._ctx, value
        )

    @property
    def verify_mode(self) -> ssl.VerifyMode:
        with self._ctx_lock:
            return self._ctx.verify_mode

    @verify_mode.setter
    def verify_mode(self, value: ssl.VerifyMode) -> None:
        with self._ctx_lock:
            _original_super_SSLContext.verify_mode.__set__(  # type: ignore[attr-defined]
                self._ctx, value
            )


# Python 3.13+ makes get_unverified_chain() a public API that only returns DER
# encoded certificates. We detect whether we need to call public_bytes() for 3.10->3.12
# Pre-3.13 returned None instead of an empty list from get_unverified_chain()
if sys.version_info >= (3, 13):

    def _get_unverified_chain_bytes(sslobj: ssl.SSLObject) -> list[bytes]:
        unverified_chain = sslobj.get_unverified_chain() or ()
        return [
            cert if isinstance(cert, bytes) else cert.public_bytes(_ssl.ENCODING_DER)
            for cert in unverified_chain
        ]

else:

    def _get_unverified_chain_bytes(sslobj: ssl.SSLObject) -> list[bytes]:
        unverified_chain = sslobj.get_unverified_chain() or ()  # type: ignore[attr-defined]
        return [cert.public_bytes(_ssl.ENCODING_DER) for cert in unverified_chain]


def _verify_peercerts(
    sock_or_sslobj: ssl.SSLSocket | ssl.SSLObject,
    server_hostname: str | None,
    verification_state: PeerVerificationState,
) -> None:
    """Verify a peer certificate chain with the selected platform backend."""
    if verification_state.check_hostname and not server_hostname:
        raise ValueError("check_hostname requires server_hostname")

    sslobj: ssl.SSLObject = sock_or_sslobj  # type: ignore[assignment]
    try:
        while not hasattr(sslobj, "get_unverified_chain"):
            sslobj = sslobj._sslobj  # type: ignore[attr-defined]
    except AttributeError:
        pass

    cert_bytes = _get_unverified_chain_bytes(sslobj)
    _verify_peercerts_impl(
        verification_state, cert_bytes, server_hostname=server_hostname
    )
