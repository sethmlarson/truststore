import sys

import pytest

if sys.platform == "win32":
    from truststore import _windows as windows

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires Windows")


def test_store_api_failure_raises_windows_error() -> None:
    store = windows.CertOpenStore(windows.CERT_STORE_PROV_MEMORY, 0, None, 0, None)
    try:
        invalid_certificate = b"not a DER certificate"
        with pytest.raises(OSError) as error:
            windows.CertAddEncodedCertificateToStore(
                store,
                windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING,
                invalid_certificate,
                len(invalid_certificate),
                windows.CERT_STORE_ADD_USE_EXISTING,
                None,
            )
        assert error.value.winerror is not None
    finally:
        windows.CertCloseStore(store, 0)
