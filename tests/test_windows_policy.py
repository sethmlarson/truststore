import sys

import pytest

if sys.platform == "win32":
    from ctypes import WINFUNCTYPE, c_void_p, cast, pointer, sizeof

    from truststore import _windows as windows

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows")


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
