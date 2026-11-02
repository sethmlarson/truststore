import importlib
import os
import platform
import socket
import ssl
import sys
import tempfile
import typing
import warnings
from dataclasses import dataclass
from operator import attrgetter
from unittest import mock

import aiohttp
import aiohttp.client_exceptions
import pytest
import requests
import urllib3
import urllib3.exceptions

import truststore
from tests import SSLContextAdapter
from tests.conftest import NETWORK_TIMEOUT, decorator_requires_internet

# Make sure the httpserver doesn't hang
# if the client drops the connection due to a cert verification error
socket.setdefaulttimeout(NETWORK_TIMEOUT)


successful_hosts = decorator_requires_internet(
    pytest.mark.parametrize("host", ["example.com", "1.1.1.1"])
)


@dataclass
class FailureHost:
    host: str
    error_messages: list[str]


wrong_host_failure_host = FailureHost(
    host="wrong.host.badssl.com",
    error_messages=[
        # OpenSSL
        "Hostname mismatch, certificate is not valid for 'wrong.host.badssl.com'",
        # macOS
        "certificate name does not match",
        # macOS with revocation checks
        "certificates do not meet pinning requirements",
        # macOS 10.13
        "Recoverable trust failure occurred",
        # Windows
        "The certificate's CN name does not match the passed value.",
    ],
)
failure_hosts_list = [
    wrong_host_failure_host,
    FailureHost(
        host="expired.badssl.com",
        error_messages=[
            # OpenSSL
            "certificate has expired",
            # macOS
            "“*.badssl.com” certificate is expired",
            # macOS with revocation checks
            "certificates do not meet pinning requirements",
            # macOS 10.13
            "Recoverable trust failure occurred",
            # Windows
            (
                "A required certificate is not within its validity period when verifying "
                "against the current system clock or the timestamp in the signed file."
            ),
        ],
    ),
    FailureHost(
        host="self-signed.badssl.com",
        error_messages=[
            # OpenSSL
            "self-signed certificate",
            "self signed certificate",
            # macOS
            "“*.badssl.com” certificate is not trusted",
            # macOS with revocation checks
            "certificates do not meet pinning requirements",
            # macOS 10.13
            "Recoverable trust failure occurred",
            # Windows
            (
                "A certificate chain processed, but terminated in a root "
                "certificate which is not trusted by the trust provider."
            ),
        ],
    ),
    FailureHost(
        host="untrusted-root.badssl.com",
        error_messages=[
            # OpenSSL
            "self-signed certificate in certificate chain",
            "self signed certificate in certificate chain",
            # macOS
            "“BadSSL Untrusted Root Certificate Authority” certificate is not trusted",
            # macOS with revocation checks
            "certificates do not meet pinning requirements",
            # macOS 10.13
            "Recoverable trust failure occurred",
            # Windows
            (
                "A certificate chain processed, but terminated in a root "
                "certificate which is not trusted by the trust provider."
            ),
        ],
    ),
    FailureHost(
        host="superfish.badssl.com",
        error_messages=[
            # OpenSSL
            "unable to get local issuer certificate",
            # macOS
            "“superfish.badssl.com” certificate is not trusted",
            # macOS with revocation checks
            "certificates do not meet pinning requirements",
            # macOS 10.13
            "Recoverable trust failure occurred",
            # Windows
            (
                "A certificate chain processed, but terminated in a root "
                "certificate which is not trusted by the trust provider."
            ),
        ],
    ),
]

failure_hosts_no_revocation = decorator_requires_internet(
    pytest.mark.parametrize(
        "failure", failure_hosts_list.copy(), ids=attrgetter("host")
    )
)

if platform.system() != "Linux":
    failure_hosts_list.append(
        FailureHost(
            host="revoked.badssl.com",
            error_messages=[
                # macOS
                "“revoked.badssl.com” certificate is revoked",
                # macOS 10.13
                "Fatal trust failure occurred",
                # macOS 10.14 ISRG Root X1 expired (SecTrustEvaluateWithError)
                "certificates do not meet pinning requirements",
                # macOS 10.13 ISRG Root X1 expired (SecTrustEvaluate)
                "Recoverable trust failure occurred",
                # Windows
                "The certificate is revoked.",
            ],
        )
    )

failure_hosts = decorator_requires_internet(
    pytest.mark.parametrize("failure", failure_hosts_list, ids=attrgetter("host"))
)

# Fixture which tests both the SecTrustEvaluate (macOS <=10.13) and
# SecTrustEvaluateWithError (macOS >=10.14) APIs
# on macOS versions that support both APIs.
if platform.system() == "Darwin" and tuple(
    map(int, platform.mac_ver()[0].split("."))
) >= (10, 14):

    @pytest.fixture(autouse=True, params=[True, False])
    def mock_macos_version_10_13(request):
        import truststore._macos

        prev = truststore._macos._is_macos_version_10_14_or_later
        truststore._macos._is_macos_version_10_14_or_later = request.param
        try:
            yield
        finally:
            truststore._macos._is_macos_version_10_14_or_later = prev


def connect_to_host(
    host: str, use_server_hostname: bool = True, verify_flags=ssl.VERIFY_CRL_CHECK_CHAIN
):
    with socket.create_connection((host, 443), timeout=NETWORK_TIMEOUT) as sock:
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if verify_flags and platform.system() != "Linux":
            ctx.verify_flags |= verify_flags
        with ctx.wrap_socket(
            sock, server_hostname=host if use_server_hostname else None
        ):
            pass


@successful_hosts
def test_success(host):
    connect_to_host(host)


@failure_hosts
def test_failures(failure):
    with pytest.raises(ssl.SSLCertVerificationError) as e:
        connect_to_host(failure.host)

    error_repr = repr(e.value)
    assert any(message in error_repr for message in failure.error_messages), error_repr


@successful_hosts
def test_success_after_loading_additional_anchors(host, trustme_ca):
    with socket.create_connection((host, 443), timeout=NETWORK_TIMEOUT) as sock:
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # See if loading additional anchors still uses system anchors.
        trustme_ca.configure_trust(ctx)
        with ctx.wrap_socket(sock, server_hostname=host):
            pass


@failure_hosts
def test_failure_after_loading_additional_anchors(failure, trustme_ca):
    with (
        pytest.raises(ssl.SSLCertVerificationError) as e,
        socket.create_connection((failure.host, 443), timeout=NETWORK_TIMEOUT) as sock,
    ):
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if platform.system() != "Linux":
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

        # See if loading additional anchors still fails.
        trustme_ca.configure_trust(ctx)
        with ctx.wrap_socket(sock, server_hostname=failure.host):
            pass

    error_repr = repr(e.value)
    assert any(message in error_repr for message in failure.error_messages), error_repr


@failure_hosts_no_revocation
def test_failures_without_revocation_checks(failure):
    # On macOS with revocation checks required, we get a
    # "certificates do not meet pinning requirements"
    # error for some of the badssl certs. So let's also test
    # with revocation checks disabled and make sure we get the
    # expected error messages in that case.
    with pytest.raises(ssl.SSLCertVerificationError) as e:
        connect_to_host(failure.host, verify_flags=None)

    error_repr = repr(e.value)
    assert any(message in error_repr for message in failure.error_messages), error_repr


@successful_hosts
def test_sslcontext_api_success(host):
    if host == "1.1.1.1":
        pytest.skip("urllib3 doesn't pass server_hostname for IP addresses")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with urllib3.PoolManager(
        ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
    ) as http:
        http.request("GET", f"https://{host}", redirect=False)


@successful_hosts
def test_urllib3_warnings(host):
    # Capture urllib3 warnings to compare verified and unverified requests.
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with urllib3.PoolManager(
        ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
    ) as http:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            http.request("GET", f"https://{host}", redirect=False)
        assert w == []

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with urllib3.PoolManager(
        ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
    ) as http:
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            http.request("GET", f"https://{host}", redirect=False)
        assert w and any(
            wn.category == urllib3.exceptions.InsecureRequestWarning for wn in w
        )


@successful_hosts
@pytest.mark.filterwarnings("ignore:enable_cleanup_closed ignored.*:DeprecationWarning")
@pytest.mark.asyncio
async def test_sslcontext_api_success_async(host):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # connector avoids https://github.com/aio-libs/aiohttp/issues/5426
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True),
        timeout=aiohttp.ClientTimeout(total=NETWORK_TIMEOUT),
    ) as http:
        resp = await http.request(
            "GET", f"https://{host}", ssl=ctx, allow_redirects=False
        )

        # Read the response without requiring an HTTP status or a nonempty body.
        await resp.read()


@failure_hosts
def test_sslcontext_api_failures(failure):
    host = failure.host
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if platform.system() != "Linux":
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    with (
        urllib3.PoolManager(
            ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
        ) as http,
        pytest.raises(urllib3.exceptions.SSLError) as e,
    ):
        http.request("GET", f"https://{host}", redirect=False)

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


@failure_hosts
@pytest.mark.filterwarnings("ignore:enable_cleanup_closed ignored.*:DeprecationWarning")
@pytest.mark.asyncio
async def test_sslcontext_api_failures_async(failure):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if platform.system() != "Linux":
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    # connector avoids https://github.com/aio-libs/aiohttp/issues/5426
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True),
        timeout=aiohttp.ClientTimeout(total=NETWORK_TIMEOUT),
    ) as http:
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError
        ) as e:
            await http.request(
                "GET", f"https://{failure.host}", ssl=ctx, allow_redirects=False
            )

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


@successful_hosts
def test_requests_sslcontext_api_success(host):
    if host == "1.1.1.1":
        pytest.skip("urllib3 doesn't pass server_hostname for IP addresses")

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    with requests.Session() as http:
        http.mount("https://", SSLContextAdapter(ssl_context=ctx))
        http.request(
            "GET", f"https://{host}", allow_redirects=False, timeout=NETWORK_TIMEOUT
        )


@failure_hosts
def test_requests_sslcontext_api_failures(failure):
    host = failure.host

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if platform.system() != "Linux":
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN

    with requests.Session() as http:
        http.mount("https://", SSLContextAdapter(ssl_context=ctx))

        with pytest.raises(requests.exceptions.SSLError) as e:
            http.request(
                "GET", f"https://{host}", allow_redirects=False, timeout=NETWORK_TIMEOUT
            )

    assert "cert" in repr(e.value).lower() and "verif" in repr(e.value).lower()


def test_wrong_host_succeeds_with_hostname_verification_disabled(
    trustme_ca, httpserver
) -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)
    ctx.check_hostname = False
    httpserver.expect_request("/").respond_with_data("ok")

    with urllib3.PoolManager(
        ssl_context=ctx,
        retries=False,
        timeout=NETWORK_TIMEOUT,
        server_hostname="wrong.example",
        assert_hostname=False,
    ) as http:
        resp = http.request("GET", httpserver.url_for("/"), redirect=False)

    assert resp.status == 200
    assert resp.data == b"ok"
    assert ctx.check_hostname is False


def test_trustme_cert(trustme_ca, httpserver):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    httpserver.expect_request("/", method="GET").respond_with_json({})

    with urllib3.PoolManager(
        ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
    ) as http:
        resp = http.request("GET", httpserver.url_for("/"))
    assert resp.status == 200
    assert len(resp.data) > 0


# This subject produces a certificate hash with a leading zero.
@pytest.mark.parametrize(
    "trustme_ca",
    [
        {
            "organization_name": "truststore capath 15",
            "organization_unit_name": "unit 15",
        }
    ],
    ids=["leading-zero-hash"],
    indirect=True,
)
def test_trustme_cert_loaded_via_capath(trustme_ca, httpserver):
    from OpenSSL.crypto import X509

    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with tempfile.TemporaryDirectory() as capath:
        with open(f"{capath}/cert.pem", "wb") as certfile:
            certfile.write(trustme_ca.cert_pem.bytes())
        cert_hash = X509.from_cryptography(trustme_ca._certificate).subject_name_hash()
        cert_filename = f"{cert_hash:08x}.0"
        os.symlink(f"{capath}/cert.pem", f"{capath}/{cert_filename}")
        assert set(os.listdir(capath)) == {"cert.pem", cert_filename}

        ctx.load_verify_locations(capath=capath)

        httpserver.expect_request("/", method="GET").respond_with_json({})

        with urllib3.PoolManager(
            ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
        ) as http:
            resp = http.request("GET", httpserver.url_for("/"))
        assert resp.status == 200
        assert len(resp.data) > 0


@pytest.mark.internet
def test_trustme_cert_still_uses_system_certs(trustme_ca):
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    trustme_ca.configure_trust(ctx)

    with urllib3.PoolManager(
        ssl_context=ctx, retries=False, timeout=NETWORK_TIMEOUT
    ) as http:
        http.request("GET", "https://example.com", redirect=False)


def test_reload_preserves_sslcontext():
    context = truststore.SSLContext

    importlib.reload(truststore)

    assert truststore.SSLContext is context


def test_macos_10_7_import_error():
    with mock.patch("platform.mac_ver") as mac_ver:
        # This isn't the full structure, but the version is the first element.
        mac_ver.return_value = ("10.7",)

        with pytest.raises(ImportError) as e:
            # We want to force a fresh import, so either we get it on the
            # first try because the OS isn't macOS or we get it on
            # the call to importlib.reload(...).
            import truststore._macos

            importlib.reload(truststore._macos)

        assert str(e.value) == "Only OS X 10.8 and newer are supported, not 10.7"


@pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="TLS-PSK support requires Python 3.13+",
)
def test_psk_client_callback_delegates():
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    callback = mock.Mock()

    with mock.patch.object(context._ctx, "set_psk_client_callback") as set_callback:
        context.set_psk_client_callback(callback)

    set_callback.assert_called_once_with(callback)


@pytest.mark.skipif(
    sys.version_info < (3, 13),
    reason="TLS-PSK support requires Python 3.13+",
)
def test_psk_server_callback_delegates():
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    callback = mock.Mock()

    with mock.patch.object(context._ctx, "set_psk_server_callback") as set_callback:
        context.set_psk_server_callback(callback, "test-hint")

    set_callback.assert_called_once_with(callback, "test-hint")


empty_server_hostname_kwargs = pytest.mark.parametrize(
    "server_hostname_kwargs", [{}, {"server_hostname": None}, {"server_hostname": ""}]
)


@empty_server_hostname_kwargs
def test_wrap_socket_server_hostname_validation(
    server_hostname_kwargs: dict[str, typing.Any],
) -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    sock = mock.Mock()

    with pytest.raises(ValueError) as e:
        ctx.wrap_socket(sock, **server_hostname_kwargs)
    assert str(e.value) == "check_hostname requires server_hostname"


@empty_server_hostname_kwargs
def test_wrap_bio_server_hostname_validation(
    server_hostname_kwargs: dict[str, typing.Any],
) -> None:
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = True
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()

    with pytest.raises(ValueError) as e:
        ctx.wrap_bio(incoming, outgoing, **server_hostname_kwargs)
    assert str(e.value) == "check_hostname requires server_hostname"
