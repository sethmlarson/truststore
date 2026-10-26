import sys

import pytest

if sys.platform == "win32":
    from ctypes import WINFUNCTYPE, pointer, sizeof

    from truststore import _windows as windows

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows")


def test_policy_api_failure_raises_windows_error() -> None:
    status = windows.CERT_CHAIN_POLICY_STATUS()
    status.cbSize = sizeof(status)
    fail = WINFUNCTYPE(
        windows.BOOL,
        *windows.CertVerifyCertificateChainPolicy.argtypes,
    )(lambda *_: False)
    policy_error_check = windows.CertVerifyCertificateChainPolicy.errcheck
    assert policy_error_check is not None
    fail.errcheck = policy_error_check

    with pytest.raises(OSError) as error:
        fail(windows.CERT_CHAIN_POLICY_SSL, None, None, pointer(status))
    assert error.value.winerror is not None
    assert status.dwError == 0
