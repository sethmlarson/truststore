import ssl
import sys
from collections.abc import Sized

import pytest
import trustme

if sys.platform == "win32":
    from ctypes import WINFUNCTYPE, c_void_p, cast, pointer, sizeof

    from truststore import _windows as windows

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows")


def test_policy_error_buffer_size_counts_wide_characters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_size: tuple[int, int] | None = None
    original_format_message = windows.FormatMessageW

    def record_format_message(
        flags: int,
        source: object,
        message_id: int,
        language_id: int,
        buffer: Sized,
        size: int,
        arguments: object,
    ) -> int:
        nonlocal observed_size
        observed_size = size, len(buffer)
        return original_format_message(
            flags,
            source,
            message_id,
            language_id,
            buffer,
            size,
            arguments,
        )

    monkeypatch.setattr(windows, "FormatMessageW", record_format_message)

    certificate = trustme.CA().issue_cert("example.com")
    certificate_der = ssl.PEM_cert_to_DER_cert(
        certificate.cert_chain_pems[0].bytes().decode("ascii")
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    with pytest.raises(ssl.SSLCertVerificationError):
        windows._verify_peercerts_impl(context, [certificate_der], "example.com")

    assert observed_size == (1024, 1024)


def test_policy_api_failure_raises_windows_error() -> None:
    status = windows.CERT_CHAIN_POLICY_STATUS()
    status.cbSize = sizeof(status)
    policy_function = WINFUNCTYPE(
        windows.BOOL,
        *windows.CertVerifyCertificateChainPolicy.argtypes,
    )
    callback = policy_function(lambda *_: False)
    # PyPy applies errcheck to foreign calls, but not direct callback calls.
    fail = policy_function(cast(callback, c_void_p).value)
    policy_error_check = windows.CertVerifyCertificateChainPolicy.errcheck
    assert policy_error_check is not None
    fail.errcheck = policy_error_check

    with pytest.raises(OSError) as error:
        fail(windows.CERT_CHAIN_POLICY_SSL, None, None, pointer(status))
    assert error.value.winerror is not None
    assert status.dwError == 0
