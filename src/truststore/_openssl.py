import contextlib
import os
import re
import ssl
import typing

# candidates based on https://github.com/tiran/certifi-system-store by Christian Heimes
_CA_FILE_CANDIDATES = [
    # Alpine, Arch, Fedora 34-43, OpenWRT, RHEL 9-10, BSD
    "/etc/ssl/cert.pem",
    # Fedora 44+, RHEL 11+
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    # Fedora <= 34, RHEL <= 9, CentOS <= 9
    "/etc/pki/tls/cert.pem",
    # Debian, Ubuntu (requires ca-certificates)
    "/etc/ssl/certs/ca-certificates.crt",
    # SUSE
    "/etc/ssl/ca-bundle.pem",
    # Android stores its system CA certificates as one PEM file per certificate.
    # Since Android 14 the store lives in the (updatable) Conscrypt APEX module;
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
]

_HASHED_CERT_FILENAME_RE = re.compile(r"^[0-9a-fA-F]{8}\.[0-9]$")
_CONTEXT_STATE_ATTR = "_truststore_openssl_ca_state"


class _FileIdentity(typing.NamedTuple):
    """Identify a file version without reading its contents."""

    path: str
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


class _CASourceState(typing.NamedTuple):
    """Describe the automatic sources whose changes require a reload."""

    cafile: _FileIdentity | None
    capath: str | None
    fallback_files: tuple[_FileIdentity, ...]


@contextlib.contextmanager
def _configure_context(ctx: ssl.SSLContext) -> typing.Iterator[None]:
    """Load a changed automatic CA source before wrapping a connection."""

    # Repeated wraps reuse this context's OpenSSL store and its source state.
    previous_source = getattr(ctx, _CONTEXT_STATE_ATTR, None)
    if not isinstance(previous_source, _CASourceState):
        previous_source = None

    source = _discover_ca_source()
    if source is not None and source != previous_source:
        loaded = _load_changed_ca_source(ctx, source, previous_source)
        if loaded:
            # Keep the snapshot with the OpenSSL store that it describes.
            setattr(ctx, _CONTEXT_STATE_ATTR, source)

    yield


def _file_identity(path: str | None) -> _FileIdentity | None:
    """Return the file metadata that changes for ordinary content updates."""

    if path is None:
        return None
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return _FileIdentity(
        path=path,
        device=stat.st_dev,
        inode=stat.st_ino,
        size=stat.st_size,
        modified_ns=stat.st_mtime_ns,
        changed_ns=stat.st_ctime_ns,
    )


def _directory_file_identities(path: str) -> list[_FileIdentity]:
    """Return identities for hashed certificate files in one directory."""

    files = []
    for name in sorted(os.listdir(path)):
        if not _HASHED_CERT_FILENAME_RE.match(name):
            continue

        identity = _file_identity(os.path.join(path, name))
        if identity is not None:
            files.append(identity)
    return files


def _fallback_ca_source_state() -> tuple[_FileIdentity, ...]:
    """Return the versions of files available through fallback sources."""

    files = []
    for candidate in _CA_FILE_CANDIDATES:
        if os.path.isdir(candidate):
            files.extend(_directory_file_identities(candidate))
            continue

        identity = _file_identity(candidate)
        if identity is not None:
            files.append(identity)
    return tuple(files)


def _discover_ca_source() -> _CASourceState | None:
    """Return the automatic CA source and its current version."""

    # First, check whether the default locations from OpenSSL
    # seem like they will give us a usable set of CA certs.
    # ssl.get_default_verify_paths already takes care of:
    # - getting cafile from either the SSL_CERT_FILE env var
    #   or the path configured when OpenSSL was compiled,
    #   and verifying that that path exists
    # - getting capath from either the SSL_CERT_DIR env var
    #   or the path configured when OpenSSL was compiled,
    #   and verifying that that path exists
    # In addition we'll check whether capath appears to contain certs.
    defaults = ssl.get_default_verify_paths()
    cafile = defaults.cafile
    capath = defaults.capath
    cafile_identity = _file_identity(cafile)

    # A capath is usable only after it contains a hashed certificate.
    if cafile is not None or (capath is not None and _capath_contains_certs(capath)):
        return _CASourceState(
            cafile=cafile_identity,
            capath=capath,
            fallback_files=(),
        )

    # OpenSSL found no usable defaults, so inspect platform fallbacks.
    fallback_files = _fallback_ca_source_state()
    if not fallback_files:
        return None
    return _CASourceState(
        cafile=None,
        capath=None,
        fallback_files=fallback_files,
    )


def _load_changed_ca_source(
    ctx: ssl.SSLContext,
    source: _CASourceState,
    previous_source: _CASourceState | None,
) -> bool:
    """Apply a source change and report whether its state can be stored."""

    same_default_directory = (
        not source.fallback_files
        and previous_source is not None
        and not previous_source.fallback_files
        and source.capath == previous_source.capath
    )
    if same_default_directory:
        # OpenSSL looks up directory certificates lazily; refresh only the file.
        if source.cafile is not None:
            ctx.load_verify_locations(cafile=source.cafile.path)
        return True
    return _load_ca_source(ctx, source)


def _load_ca_source(ctx: ssl.SSLContext, source: _CASourceState) -> bool:
    """Load one discovered automatic CA source."""

    if not source.fallback_files:
        ctx.set_default_verify_paths()
        return True

    # cafile from OpenSSL doesn't exist and capath from OpenSSL doesn't
    # contain certs. If the path is a directory, load the PEM files in
    # that directory; if it's a single file, load it as a file.
    for cafile_or_cadir in _CA_FILE_CANDIDATES:
        if os.path.isdir(cafile_or_cadir):
            cadata = load_cadir_to_cadata(cafile_or_cadir)
            if cadata:
                ctx.load_verify_locations(cadata=cadata)
                return True
        elif os.path.isfile(cafile_or_cadir):
            ctx.load_verify_locations(cafile=cafile_or_cadir)
            return True
    return False


def load_cadir_to_cadata(cadir: str) -> str | None:
    """Load the CA certificates in a directory by constructing a single PEM
    string.

    Returns None if no certificates could be found.
    """
    pems = []
    for name in os.listdir(cadir):
        if _HASHED_CERT_FILENAME_RE.match(name):
            try:
                with open(os.path.join(cadir, name), encoding="ascii") as f:
                    pems.append(f.read())
            except (OSError, UnicodeDecodeError):
                pass
    if pems:
        return "\n".join(pems)
    return None


def _capath_contains_certs(capath: str) -> bool:
    """Check whether capath exists and contains certs in the expected format."""
    if not os.path.isdir(capath):
        return False
    return any(_HASHED_CERT_FILENAME_RE.match(name) for name in os.listdir(capath))


def _verify_peercerts_impl(
    ssl_context: ssl.SSLContext,
    cert_chain: list[bytes],
    server_hostname: str | None = None,
) -> None:
    # This is a no-op because we've enabled SSLContext's built-in
    # verification via verify_mode=CERT_REQUIRED, and don't need to repeat it.
    pass
