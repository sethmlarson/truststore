import os
import ssl

_CA_FILES = [
    "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu/Gentoo etc.
    "/etc/pki/tls/certs/ca-bundle.crt",  # Fedora/RHEL 6
    "/etc/ssl/ca-bundle.pem",  # OpenSUSE
    "/etc/pki/tls/cacert.pem",  # OpenELEC
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # CentOS/RHEL 7
    "/etc/ssl/cert.pem",  # Alpine Linux
    "/usr/local/etc/ssl/cert.pem",  # FreeBSD
    "/etc/ssl/cert.pem",  # OpenBSD
    "/usr/local/share/certs/ca-root-nss.crt",  # DragonFly
    "/etc/openssl/certs/ca-certificates.crt",  # NetBSD
    "/etc/certs/ca-certificates.crt",  # Solaris 11.2+
    "/etc/ssl/certs/ca-certificates.crt",  # Joyent SmartOS
    "/etc/ssl/cacert.pem",  # OmniOS
]

_CA_DIRS = [
    "/etc/ssl/certs",  # SLES10/SLES11, FreeBSD 12.2+
    "/etc/pki/tls/certs",  # Fedora/RHEL
    "/system/etc/security/cacerts",  # Android
    "/usr/local/share/certs",  # FreeBSD
    "/etc/openssl/certs",  # NetBSD
    "/etc/certs/CA",  # Solaris
]


def _configure_context(ctx: ssl.SSLContext) -> None:
    for cafile in _CA_FILES:
        if os.path.isfile(cafile):
            ctx.load_verify_locations(cafile=cafile)
            break
    else:
        for cadir in _CA_DIRS:
            if os.path.isdir(cadir):
                ctx.load_verify_locations(capath=cadir)

    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True


def _verify_peercerts_impl(
    cert_chain: list[bytes], server_hostname: str | None = None
) -> None:
    pass
