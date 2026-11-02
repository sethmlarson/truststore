import datetime as dt
import os
import platform
import ssl
from pathlib import Path

import pytest
import trustme
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import truststore
import truststore._openssl as openssl_backend

pytestmark = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="These tests exercise the OpenSSL system-store backend",
)


def _handshake(ctx: truststore.SSLContext, cert: trustme.LeafCert) -> None:
    """Complete one in-memory client/server TLS handshake."""

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert.configure_cert(server_context)

    client_in = ssl.MemoryBIO()
    client_out = ssl.MemoryBIO()
    server_in = ssl.MemoryBIO()
    server_out = ssl.MemoryBIO()

    client = ctx.wrap_bio(client_in, client_out, server_hostname="localhost")
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    connections = (client, server)
    transfers = ((client_out, server_in), (server_out, client_in))
    completed = [False, False]

    for _ in range(20):
        # Advance each side until it needs records from its peer.
        for index, connection in enumerate(connections):
            if completed[index]:
                continue
            try:
                connection.do_handshake()
                completed[index] = True
            except ssl.SSLWantReadError:
                pass

        # Transfer pending records in both directions.
        for outgoing, incoming in transfers:
            if data := outgoing.read():
                incoming.write(data)

        if all(completed):
            return
    raise RuntimeError("TLS handshake did not finish")


def _make_crl(
    ca: trustme.CA,
    leaf: x509.Certificate,
    *,
    revoked: bool,
    number: int,
    age_minutes: int,
) -> bytes:
    """Return a signed CRL for the generated CA and leaf."""

    now = dt.datetime.now(dt.timezone.utc)
    ca_certificate = x509.load_pem_x509_certificate(ca.cert_pem.bytes())
    ca_key = serialization.load_pem_private_key(ca.private_key_pem.bytes(), None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Expected trustme to generate an EC CA key")

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_certificate.subject)
        .last_update(now - dt.timedelta(minutes=age_minutes))
        .next_update(now + dt.timedelta(days=1))
        .add_extension(x509.CRLNumber(number), critical=False)
    )

    if revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(leaf.serial_number)
            .revocation_date(now - dt.timedelta(seconds=1))
            .build()
        )
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM
    )


def _default_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    contents: bytes,
) -> Path:
    """Create a CA bundle selected through OpenSSL's environment variables."""

    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(contents)
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "missing"))
    return bundle


def test_reused_context_loads_replaced_default_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first_ca = trustme.CA()
    second_ca = trustme.CA()
    first_pem = first_ca.cert_pem.bytes()
    second_pem = second_ca.cert_pem.bytes()
    assert len(first_pem) == len(second_pem)

    bundle = _default_bundle(monkeypatch, tmp_path, first_pem)
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _handshake(ctx, first_ca.issue_cert("localhost"))

    # Preserve common cache fields so ctime is the only invalidation signal.
    before = bundle.stat()
    bundle.write_bytes(second_pem)
    os.utime(bundle, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = bundle.stat()

    assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    assert before.st_ctime_ns != after.st_ctime_ns

    _handshake(ctx, second_ca.issue_cert("localhost"))


def test_reused_context_loads_changed_default_crl(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ca = trustme.CA()
    server_cert = ca.issue_cert("localhost")
    leaf = x509.load_pem_x509_certificate(server_cert.cert_chain_pems[0].bytes())

    initial_bundle = ca.cert_pem.bytes() + _make_crl(
        ca, leaf, revoked=False, number=1, age_minutes=2
    )
    bundle = _default_bundle(monkeypatch, tmp_path, initial_bundle)

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    _handshake(ctx, server_cert)

    # OpenSSL selects the newer CRL for the same issuer.
    revoked_bundle = ca.cert_pem.bytes() + _make_crl(
        ca, leaf, revoked=True, number=2, age_minutes=0
    )
    bundle.write_bytes(revoked_bundle)

    with pytest.raises(ssl.SSLCertVerificationError, match="certificate revoked"):
        _handshake(ctx, server_cert)


class _RecordingContext:
    """Record the CA loading operations used by the backend."""

    def __init__(self, *, failures_remaining: int = 0) -> None:
        self.default_path_loads = 0
        self.file_loads: list[str] = []
        self.failures_remaining = failures_remaining

    def set_default_verify_paths(self) -> None:
        self.default_path_loads += 1
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise ssl.SSLError("load failed")

    def load_verify_locations(
        self,
        *,
        cafile: str | None = None,
        cadata: str | None = None,
    ) -> None:
        if cafile is not None:
            self.file_loads.append(cafile)


def _default_source(
    *,
    path: str = "/tmp/roots.pem",
    capath: str | None = "/tmp/certs",
    changed_ns: int = 5,
) -> openssl_backend._CASourceState:
    """Return a default-source state for mechanism tests."""

    cafile = openssl_backend._FileIdentity(
        path=path,
        device=1,
        inode=2,
        size=3,
        modified_ns=4,
        changed_ns=changed_ns,
    )
    return openssl_backend._CASourceState(
        cafile=cafile,
        capath=capath,
        fallback_files=(),
    )


def _configure_twice(ctx: _RecordingContext) -> None:
    """Run two automatic CA setup attempts on one context."""

    with openssl_backend._configure_context(ctx):
        pass
    with openssl_backend._configure_context(ctx):
        pass


def test_changed_default_file_does_not_reregister_default_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = "/tmp/roots.pem"
    sources = iter(
        (_default_source(path=path), _default_source(path=path, changed_ns=6))
    )
    monkeypatch.setattr(openssl_backend, "_discover_ca_source", lambda: next(sources))
    ctx = _RecordingContext()

    _configure_twice(ctx)

    assert ctx.default_path_loads == 1
    assert ctx.file_loads == [path]


def test_changed_default_directory_is_registered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = iter(
        (
            _default_source(capath="/tmp/first-certs"),
            _default_source(capath="/tmp/second-certs"),
        )
    )
    monkeypatch.setattr(openssl_backend, "_discover_ca_source", lambda: next(sources))
    ctx = _RecordingContext()

    _configure_twice(ctx)

    assert ctx.default_path_loads == 2
    assert ctx.file_loads == []


def test_source_appearing_after_first_wrap_is_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _default_source(capath=None)
    sources = iter((None, source))
    monkeypatch.setattr(openssl_backend, "_discover_ca_source", lambda: next(sources))
    ctx = _RecordingContext()

    _configure_twice(ctx)

    assert ctx.default_path_loads == 1


def test_empty_fallback_directory_does_not_hide_later_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "certs"
    directory.mkdir()

    # The first candidate looks valid by name but contains no readable PEM.
    directory_file = directory / "12345678.0"
    directory_file.write_bytes(b"\xff")
    fallback_file = tmp_path / "roots.pem"
    fallback_file.write_text("fallback")

    monkeypatch.setattr(
        openssl_backend,
        "_CA_FILE_CANDIDATES",
        [str(directory), str(fallback_file)],
    )

    directory_identity = openssl_backend._file_identity(str(directory_file))
    fallback_identity = openssl_backend._file_identity(str(fallback_file))
    assert directory_identity is not None
    assert fallback_identity is not None

    source = openssl_backend._CASourceState(
        cafile=None,
        capath=None,
        fallback_files=(directory_identity, fallback_identity),
    )
    ctx = _RecordingContext()

    assert openssl_backend._load_ca_source(ctx, source)
    assert ctx.file_loads == [str(fallback_file)]


def test_failed_load_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    source = _default_source(capath=None)
    monkeypatch.setattr(openssl_backend, "_discover_ca_source", lambda: source)
    ctx = _RecordingContext(failures_remaining=1)

    with (
        pytest.raises(ssl.SSLError, match="load failed"),
        openssl_backend._configure_context(ctx),
    ):
        pass
    with openssl_backend._configure_context(ctx):
        pass

    assert ctx.default_path_loads == 2
