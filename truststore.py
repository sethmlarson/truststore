"""Verify certificates using OS trust stores"""

import ipaddress
import os
import platform
import re
import socket
import ssl
from typing import Any, List, Match, Optional, Tuple, Union

from _ssl import ENCODING_DER

__all__ = ["TruststoreSSLContext"]
__version__ = "0.1.0"

try:
    # Grab this value so we know which path we can ignore.
    import certifi

    _CERTIFI_WHERE = certifi.where()
except ImportError:
    _CERTIFI_WHERE = None


# ===== macOS =====

if platform.system() == "Darwin":
    import ctypes
    from ctypes import (
        CDLL,
        POINTER,
        c_bool,
        c_char_p,
        c_int32,
        c_long,
        c_uint32,
        c_ulong,
        c_void_p,
    )
    from ctypes.util import find_library

    _mac_version = platform.mac_ver()[0]
    _mac_version_info = tuple(map(int, _mac_version.split(".")))
    if _mac_version_info < (10, 8):
        raise OSError(
            f"Only OS X 10.8 and newer are supported, not {_mac_version_info[0]}.{_mac_version_info[1]}"
        )

    def _load_cdll(name: str, macos10_16_path: str) -> CDLL:
        """Loads a CDLL by name, falling back to known path on 10.16+"""
        try:
            # Big Sur is technically 11 but we use 10.16 due to the Big Sur
            # beta being labeled as 10.16.
            path: Optional[str]
            if _mac_version_info >= (10, 16):
                path = macos10_16_path
            else:
                path = find_library(name)
            if not path:
                raise OSError  # Caught and reraised as 'ImportError'
            return CDLL(path, use_errno=True)
        except OSError:
            raise ImportError(f"The library {name} failed to load") from None

    Security = _load_cdll(
        "Security", "/System/Library/Frameworks/Security.framework/Security"
    )
    CoreFoundation = _load_cdll(
        "CoreFoundation",
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    )

    Boolean = c_bool
    CFIndex = c_long
    CFStringEncoding = c_uint32
    CFData = c_void_p
    CFString = c_void_p
    CFArray = c_void_p
    CFMutableArray = c_void_p
    CFError = c_void_p
    CFType = c_void_p
    CFTypeID = c_ulong
    CFTypeRef = POINTER(CFType)
    CFAllocatorRef = c_void_p

    OSStatus = c_int32

    CFErrorRef = POINTER(CFError)
    CFDataRef = POINTER(CFData)
    CFStringRef = POINTER(CFString)
    CFArrayRef = POINTER(CFArray)
    CFMutableArrayRef = POINTER(CFMutableArray)
    CFArrayCallBacks = c_void_p

    SecCertificateRef = POINTER(c_void_p)
    SecPolicyRef = POINTER(c_void_p)
    SecTrustRef = POINTER(c_void_p)
    SecTrustResultType = c_uint32
    SecTrustOptionFlags = c_uint32

    try:
        Security.SecCertificateCreateWithData.argtypes = [CFAllocatorRef, CFDataRef]
        Security.SecCertificateCreateWithData.restype = SecCertificateRef

        Security.SecCertificateCopyData.argtypes = [SecCertificateRef]
        Security.SecCertificateCopyData.restype = CFDataRef

        Security.SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
        Security.SecCopyErrorMessageString.restype = CFStringRef

        Security.SecTrustSetAnchorCertificates.argtypes = [SecTrustRef, CFArrayRef]
        Security.SecTrustSetAnchorCertificates.restype = OSStatus

        Security.SecTrustSetAnchorCertificatesOnly.argtypes = [SecTrustRef, Boolean]
        Security.SecTrustSetAnchorCertificatesOnly.restype = OSStatus

        Security.SecTrustEvaluate.argtypes = [SecTrustRef, POINTER(SecTrustResultType)]
        Security.SecTrustEvaluate.restype = OSStatus

        Security.SecPolicyCreateSSL.argtypes = [Boolean, CFStringRef]
        Security.SecPolicyCreateSSL.restype = SecPolicyRef

        Security.SecTrustCreateWithCertificates.argtypes = [
            CFTypeRef,
            CFTypeRef,
            POINTER(SecTrustRef),
        ]
        Security.SecTrustCreateWithCertificates.restype = OSStatus

        Security.SecTrustGetTrustResult.argtypes = [
            SecTrustRef,
            POINTER(SecTrustResultType),
        ]
        Security.SecTrustGetTrustResult.restype = OSStatus

        Security.SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
        Security.SecCopyErrorMessageString.restype = CFStringRef

        Security.SecTrustRef = SecTrustRef
        Security.SecTrustResultType = SecTrustResultType
        Security.OSStatus = OSStatus

        CoreFoundation.CFRelease.argtypes = [CFTypeRef]
        CoreFoundation.CFRelease.restype = None

        CoreFoundation.CFGetTypeID.argtypes = [CFTypeRef]
        CoreFoundation.CFGetTypeID.restype = CFTypeID

        CoreFoundation.CFStringCreateWithCString.argtypes = [
            CFAllocatorRef,
            c_char_p,
            CFStringEncoding,
        ]
        CoreFoundation.CFStringCreateWithCString.restype = CFStringRef

        CoreFoundation.CFStringGetCStringPtr.argtypes = [CFStringRef, CFStringEncoding]
        CoreFoundation.CFStringGetCStringPtr.restype = c_char_p

        CoreFoundation.CFStringGetCString.argtypes = [
            CFStringRef,
            c_char_p,
            CFIndex,
            CFStringEncoding,
        ]
        CoreFoundation.CFStringGetCString.restype = c_bool

        CoreFoundation.CFDataCreate.argtypes = [CFAllocatorRef, c_char_p, CFIndex]
        CoreFoundation.CFDataCreate.restype = CFDataRef

        CoreFoundation.CFDataGetLength.argtypes = [CFDataRef]
        CoreFoundation.CFDataGetLength.restype = CFIndex

        CoreFoundation.CFDataGetBytePtr.argtypes = [CFDataRef]
        CoreFoundation.CFDataGetBytePtr.restype = c_void_p

        CoreFoundation.CFArrayCreate.argtypes = [
            CFAllocatorRef,
            POINTER(CFTypeRef),
            CFIndex,
            CFArrayCallBacks,
        ]
        CoreFoundation.CFArrayCreate.restype = CFArrayRef

        CoreFoundation.CFArrayCreateMutable.argtypes = [
            CFAllocatorRef,
            CFIndex,
            CFArrayCallBacks,
        ]
        CoreFoundation.CFArrayCreateMutable.restype = CFMutableArrayRef

        CoreFoundation.CFArrayAppendValue.argtypes = [CFMutableArrayRef, c_void_p]
        CoreFoundation.CFArrayAppendValue.restype = None

        CoreFoundation.CFArrayGetCount.argtypes = [CFArrayRef]
        CoreFoundation.CFArrayGetCount.restype = CFIndex

        CoreFoundation.CFArrayGetValueAtIndex.argtypes = [CFArrayRef, CFIndex]
        CoreFoundation.CFArrayGetValueAtIndex.restype = c_void_p

        CoreFoundation.CFErrorGetCode.argtypes = [CFErrorRef]
        CoreFoundation.CFErrorGetCode.restype = CFIndex

        CoreFoundation.CFErrorCopyDescription.argtypes = [CFErrorRef]
        CoreFoundation.CFErrorCopyDescription.restype = CFStringRef

        CoreFoundation.kCFAllocatorDefault = CFAllocatorRef.in_dll(
            CoreFoundation, "kCFAllocatorDefault"
        )
        CoreFoundation.kCFTypeArrayCallBacks = c_void_p.in_dll(
            CoreFoundation, "kCFTypeArrayCallBacks"
        )

        CoreFoundation.CFTypeRef = CFTypeRef
        CoreFoundation.CFArrayRef = CFArrayRef
        CoreFoundation.CFStringRef = CFStringRef
        CoreFoundation.CFErrorRef = CFErrorRef

    except AttributeError:
        raise ImportError("Error initializing ctypes") from None

    class CFConst:
        """CoreFoundation constants"""

        kCFStringEncodingUTF8 = CFStringEncoding(0x08000100)

    def _bytes_to_cf_data_ref(value: bytes) -> CFDataRef:
        return CoreFoundation.CFDataCreate(
            CoreFoundation.kCFAllocatorDefault, value, len(value)
        )

    def _bytes_to_cf_string(value: bytes) -> CFString:
        """
        Given a Python binary data, create a CFString.
        The string must be CFReleased by the caller.
        """
        c_str = ctypes.c_char_p(value)
        cf_str = CoreFoundation.CFStringCreateWithCString(
            CoreFoundation.kCFAllocatorDefault,
            c_str,
            CFConst.kCFStringEncodingUTF8,
        )
        return cf_str

    def _cf_string_ref_to_str(cf_string_ref: CFStringRef) -> Optional[str]:
        """
        Creates a Unicode string from a CFString object. Used entirely for error
        reporting.
        Yes, it annoys me quite a lot that this function is this complex.
        """

        string = CoreFoundation.CFStringGetCStringPtr(
            cf_string_ref, CFConst.kCFStringEncodingUTF8
        )
        if string is None:
            buffer = ctypes.create_string_buffer(1024)
            result = CoreFoundation.CFStringGetCString(
                cf_string_ref, buffer, 1024, CFConst.kCFStringEncodingUTF8
            )
            if not result:
                raise OSError("Error copying C string from CFStringRef")
            string = buffer.value
        if string is not None:
            string = string.decode("utf-8")
        return string  # type: ignore[no-any-return]

    def _configure_context(ctx: ssl.SSLContext):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    def _verify_peercerts_impl(cert_chain: List[bytes], server_hostname=None) -> None:
        certs = None
        policy = None
        trust = None
        cf_error = None
        try:
            if server_hostname is not None:
                cf_str_hostname = None
                try:
                    cf_str_hostname = _bytes_to_cf_string(
                        server_hostname.encode("ascii")
                    )
                    policy = Security.SecPolicyCreateSSL(True, cf_str_hostname)
                finally:
                    if cf_str_hostname:
                        CoreFoundation.CFRelease(cf_str_hostname)
            else:
                policy = Security.SecPolicyCreateSSL(True, None)

            certs = None
            try:
                certs = CoreFoundation.CFArrayCreateMutable(
                    CoreFoundation.kCFAllocatorDefault,
                    0,
                    ctypes.byref(CoreFoundation.kCFTypeArrayCallBacks),
                )
                if not certs:
                    raise MemoryError("Unable to allocate memory!")

                # Load all the DER-encoded certificates in the chain
                for cert_data in cert_chain:
                    cf_data = None
                    cert = None
                    try:
                        cf_data = _bytes_to_cf_data_ref(cert_data)
                        cert = Security.SecCertificateCreateWithData(
                            CoreFoundation.kCFAllocatorDefault, cf_data
                        )
                        CoreFoundation.CFArrayAppendValue(certs, cert)
                    finally:
                        if cf_data:
                            CoreFoundation.CFRelease(cf_data)
                        if cert:
                            CoreFoundation.CFRelease(cert)

                # Now that we have certificates loaded and a SecPolicy
                # we can finally create a SecTrust object!
                trust = Security.SecTrustRef()
                status = Security.SecTrustCreateWithCertificates(
                    certs, policy, ctypes.byref(trust)
                )
                assert status == 0  # TODO: Check status

            finally:
                # The certs are now being held by SecTrust so we can
                # release our handles for the array.
                if certs:
                    CoreFoundation.CFRelease(certs)

            # Set the Trust to use the default anchor certificates (system, keychain, fetched)
            status = Security.SecTrustSetAnchorCertificates(trust, None)
            assert status == 0  # TODO: Check status

            cf_error = CoreFoundation.CFErrorRef()
            sec_trust_eval_result = Security.SecTrustEvaluateWithError(
                trust, ctypes.byref(cf_error)
            )
            # sec_trust_eval_result is a bool (0 or 1)
            # where 1 means that the certs are trusted.
            if sec_trust_eval_result == 1:
                is_trusted = True
            elif sec_trust_eval_result == 0:
                is_trusted = False
            else:
                raise ssl.SSLError(
                    f"Unknown result from Security.SecTrustEvaluateWithError: {sec_trust_eval_result!r}"
                )

            if not is_trusted:
                cf_error_code = CoreFoundation.CFErrorGetCode(cf_error)
                cf_error_string_ref = None
                try:
                    cf_error_string_ref = CoreFoundation.CFErrorCopyDescription(
                        cf_error
                    )
                    cf_error_message = _cf_string_ref_to_str(cf_error_string_ref)

                    # TODO: Not sure if we need the SecTrustResultType for anything?
                    # We only care whether or not it's a success or failure for now.
                    sec_trust_result_type = Security.SecTrustResultType()
                    status = Security.SecTrustGetTrustResult(
                        trust, ctypes.byref(sec_trust_result_type)
                    )
                    assert status == 0  # TODO: Check status

                    err = ssl.SSLCertVerificationError()
                    err.verify_message = cf_error_message
                    err.verify_code = cf_error_code
                    raise err
                finally:
                    if cf_error_string_ref:
                        CoreFoundation.CFRelease(cf_error_string_ref)

        finally:
            if policy:
                CoreFoundation.CFRelease(policy)
            if trust:
                CoreFoundation.CFRelease(trust)


# ===== Windows =====

elif platform.system() == "Windows":

    from ctypes import (
        POINTER,
        Structure,
        WinDLL,
        WinError,
        cast,
        c_char_p,
        c_ulong,
        c_void_p,
        c_wchar_p,
        pointer,
        sizeof,
    )
    from ctypes.wintypes import (
        BOOL,
        DWORD,
        HANDLE,
        LONG,
        LPCSTR,
        LPCWSTR,
        LPFILETIME,
        LPSTR,
    )

    HCERTCHAINENGINE = HANDLE
    HCERTSTORE = HANDLE
    HCRYPTPROV_LEGACY = HANDLE

    class CERT_CONTEXT(Structure):
        _fields_ = (
            ("dwCertEncodingType", DWORD),
            ("pbCertEncoded", c_void_p),
            ("cbCertEncoded", DWORD),
            ("pCertInfo", c_void_p),
            ("hCertStore", HCERTSTORE),
        )

    PCERT_CONTEXT = POINTER(CERT_CONTEXT)
    PCCERT_CONTEXT = POINTER(PCERT_CONTEXT)

    class CERT_ENHKEY_USAGE(Structure):
        _fields_ = (
            ("cUsageIdentifier", DWORD),
            ("rgpszUsageIdentifier", POINTER(LPSTR)),
        )

    PCERT_ENHKEY_USAGE = POINTER(CERT_ENHKEY_USAGE)

    class CERT_USAGE_MATCH(Structure):
        _fields_ = (
            ("dwType", DWORD),
            ("Usage", CERT_ENHKEY_USAGE),
        )

    class CERT_CHAIN_PARA(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("RequestedUsage", CERT_USAGE_MATCH),
            ("RequestedIssuancePolicy", CERT_USAGE_MATCH),
            ("dwUrlRetrievalTimeout", DWORD),
            ("fCheckRevocationFreshnessTime", BOOL),
            ("dwRevocationFreshnessTime", DWORD),
            ("pftCacheResync", LPFILETIME),
            ("pStrongSignPara", c_void_p),
            ("dwStrongSignFlags", DWORD),
        )

    PCERT_CHAIN_PARA = POINTER(CERT_CHAIN_PARA)

    class CERT_TRUST_STATUS(Structure):
        _fields_ = (
            ("dwErrorStatus", DWORD),
            ("dwInfoStatus", DWORD),
        )

    class CERT_CHAIN_ELEMENT(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("pCertContext", PCERT_CONTEXT),
            ("TrustStatus", CERT_TRUST_STATUS),
            ("pRevocationInfo", c_void_p),
            ("pIssuanceUsage", PCERT_ENHKEY_USAGE),
            ("pApplicationUsage", PCERT_ENHKEY_USAGE),
            ("pwszExtendedErrorInfo", LPCWSTR),
        )

    PCERT_CHAIN_ELEMENT = POINTER(CERT_CHAIN_ELEMENT)

    class CERT_SIMPLE_CHAIN(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("TrustStatus", CERT_TRUST_STATUS),
            ("cElement", DWORD),
            ("rgpElement", POINTER(PCERT_CHAIN_ELEMENT)),
            ("pTrustListInfo", c_void_p),
            ("fHasRevocationFreshnessTime", BOOL),
            ("dwRevocationFreshnessTime", DWORD),
        )

    PCERT_SIMPLE_CHAIN = POINTER(CERT_SIMPLE_CHAIN)

    class CERT_CHAIN_CONTEXT(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("TrustStatus", CERT_TRUST_STATUS),
            ("cChain", DWORD),
            ("rgpChain", POINTER(PCERT_SIMPLE_CHAIN)),
            ("cLowerQualityChainContext", DWORD),
            ("rgpLowerQualityChainContext", c_void_p),
            ("fHasRevocationFreshnessTime", BOOL),
            ("dwRevocationFreshnessTime", DWORD),
        )

    PCERT_CHAIN_CONTEXT = POINTER(CERT_CHAIN_CONTEXT)
    PCCERT_CHAIN_CONTEXT = POINTER(PCERT_CHAIN_CONTEXT)

    class SSL_EXTRA_CERT_CHAIN_POLICY_PARA(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("dwAuthType", DWORD),
            ("fdwChecks", DWORD),
            ("pwszServerName", LPCWSTR),
        )
    class CERT_CHAIN_POLICY_PARA(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("dwFlags", DWORD),
            ("pvExtraPolicyPara", c_void_p),
        )
    PCERT_CHAIN_POLICY_PARA = POINTER(CERT_CHAIN_POLICY_PARA)

    class CERT_CHAIN_POLICY_STATUS(Structure):
        _fields_ = (
            ("cbSize", DWORD),
            ("dwError", DWORD),
            ("lChainIndex", LONG),
            ("lElementIndex", LONG),
            ("pvExtraPolicyStatus", c_void_p),
        )
    PCERT_CHAIN_POLICY_STATUS = POINTER(CERT_CHAIN_POLICY_STATUS)

    X509_ASN_ENCODING = 0x00000001
    PKCS_7_ASN_ENCODING = 0x00010000
    CERT_STORE_PROV_MEMORY = b"Memory"
    USAGE_MATCH_TYPE_OR = 1
    OID_PKIX_KP_SERVER_AUTH = c_char_p(b"1.3.6.1.5.5.7.3.1")
    CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000
    AUTHTYPE_SERVER = 2
    CERT_CHAIN_POLICY_SSL = 4

    wincrypt = WinDLL("crypt32.dll")

    def _handle_win_error(result, func, args):
        if not result:
            # Note, actually raises OSError after calling GetLastError and FormatMessage
            # TODO: Wrap in ssl.SSLCertVerificationError?
            raise WinError()
        return args

    CertOpenStore = wincrypt.CertOpenStore
    CertOpenStore.argtypes = (LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, c_void_p)
    CertOpenStore.restype = HCERTSTORE
    CertOpenStore.errcheck = _handle_win_error

    CertAddEncodedCertificateToStore = wincrypt.CertAddEncodedCertificateToStore
    CertAddEncodedCertificateToStore.argtypes = (
        HCERTSTORE,
        DWORD,
        c_char_p,
        DWORD,
        DWORD,
        PCCERT_CONTEXT,
    )
    CertAddEncodedCertificateToStore.restype = BOOL

    CertCreateCertificateContext = wincrypt.CertCreateCertificateContext
    CertCreateCertificateContext.argtypes = (DWORD, c_char_p, DWORD)
    CertCreateCertificateContext.restype = PCERT_CONTEXT
    CertCreateCertificateContext.errcheck = _handle_win_error

    CertGetCertificateChain = wincrypt.CertGetCertificateChain
    CertGetCertificateChain.argtypes = (
        HCERTCHAINENGINE,
        PCERT_CONTEXT,
        LPFILETIME,
        HCERTSTORE,
        PCERT_CHAIN_PARA,
        DWORD,
        c_void_p,
        PCCERT_CHAIN_CONTEXT,
    )
    CertGetCertificateChain.restype = BOOL
    CertGetCertificateChain.errcheck = _handle_win_error

    CertVerifyCertificateChainPolicy = wincrypt.CertVerifyCertificateChainPolicy
    CertVerifyCertificateChainPolicy.argtypes = (
        c_ulong,
        PCERT_CHAIN_CONTEXT,
        PCERT_CHAIN_POLICY_PARA,
        PCERT_CHAIN_POLICY_STATUS,
    )
    CertVerifyCertificateChainPolicy.restype = BOOL

    CertCloseStore = wincrypt.CertCloseStore
    CertCloseStore.argtypes = (HCERTSTORE, DWORD)
    CertCloseStore.restype = BOOL
    CertCloseStore.errcheck = _handle_win_error

    CertFreeCertificateChain = wincrypt.CertFreeCertificateChain
    CertFreeCertificateChain.argtypes = (PCERT_CHAIN_CONTEXT,)

    CertFreeCertificateContext = wincrypt.CertFreeCertificateContext
    CertFreeCertificateContext.argtypes = (PCERT_CONTEXT,)

    def _verify_peercerts_impl(
        cert_chain: List[bytes], server_hostname: Optional[str] = None
    ):
        # TODO: Test with intermediate certs; add them to in-memory cert store
        pCertContext = None
        ppChainContext = None
        # hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, None, 0, None)
        try:
            # Cert context for leaf cert
            leaf_cert = cert_chain[0]
            pCertContext = CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, leaf_cert, len(leaf_cert)
            )

            # Chain params to match certs for serverAuth extended usage
            cert_enhkey_usage = CERT_ENHKEY_USAGE()
            cert_enhkey_usage.cUsageIdentifier = 1
            cert_enhkey_usage.rgpszUsageIdentifier = (c_char_p * 1)(OID_PKIX_KP_SERVER_AUTH)
            cert_usage_match = CERT_USAGE_MATCH()
            cert_usage_match.Usage = cert_enhkey_usage
            chain_params = CERT_CHAIN_PARA()
            chain_params.RequestedUsage = cert_usage_match
            chain_params.cbSize = sizeof(chain_params)
            pChainPara = pointer(chain_params)

            # Get cert chain
            ppChainContext = pointer(PCERT_CHAIN_CONTEXT())
            CertGetCertificateChain(
                None,  # default chain engine
                pCertContext,  # leaf cert context
                None,  # current system time
                None, # hStore,  # additional in-memory cert store
                pChainPara,  # chain-building parameters
                CERT_CHAIN_REVOCATION_CHECK_CHAIN,  # flags
                None,  # reserved
                ppChainContext,  # the resulting chain context
            )
            pChainContext = ppChainContext.contents

            # Verify cert chain
            ssl_extra_cert_chain_policy_para = SSL_EXTRA_CERT_CHAIN_POLICY_PARA()
            ssl_extra_cert_chain_policy_para.cbSize = sizeof(ssl_extra_cert_chain_policy_para)
            ssl_extra_cert_chain_policy_para.dwAuthType = AUTHTYPE_SERVER
            ssl_extra_cert_chain_policy_para.fdwChecks = 0
            if server_hostname:
                ssl_extra_cert_chain_policy_para.pwszServerName = c_wchar_p(server_hostname)
            chain_policy = CERT_CHAIN_POLICY_PARA()
            chain_policy.pvExtraPolicyPara = cast(pointer(ssl_extra_cert_chain_policy_para), c_void_p)
            chain_policy.cbSize = sizeof(chain_policy)
            pPolicyPara = pointer(chain_policy)
            policy_status = CERT_CHAIN_POLICY_STATUS()
            policy_status.cbSize = sizeof(policy_status)
            pPolicyStatus = pointer(policy_status)
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL,
                pChainContext,
                pPolicyPara,
                pPolicyStatus,
            )

            # Check status
            # TODO: Better error messages
            error_code = policy_status.dwError
            if error_code:
                err = ssl.SSLCertVerificationError()
                err.verify_code = error_code
                raise err
        finally:
            # result = CertCloseStore(hStore, 0)
            if ppChainContext:
                CertFreeCertificateChain(ppChainContext.contents)
            if pCertContext:
                CertFreeCertificateContext(pCertContext)

    def _configure_context(ctx: ssl.SSLContext):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE


# ===== Linux =====
else:
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

    def _configure_context(ctx: ssl.SSLContext):
        for cafile in _CA_FILES:
            if os.path.isfile(cafile):
                ctx.load_verify_locations(cafile=cafile)
                break
        else:
            for cadir in _CA_DIRS:
                if os.path.isdir(cadir):
                    ctx.load_verify_locations(capath=cadir)

        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

    def _verify_peercerts_impl(
        cert_chain: List[bytes], server_hostname: Optional[str] = None
    ):
        pass


class TruststoreSSLContext(ssl.SSLContext):
    """SSLContext API that uses system certificates on all platforms"""

    def __init__(self, protocol: int = None):
        self._ctx = ssl.SSLContext(protocol)
        _configure_context(self._ctx)

        class TruststoreSSLObject(ssl.SSLObject):
            # This object exists because wrap_bio() doesn't
            # immediately do the handshake so we need to do
            # certificate verifications after SSLObject.do_handshake()
            _TRUSTSTORE_SERVER_HOSTNAME = None

            def do_handshake(self) -> None:
                ret = super().do_handshake()
                _verify_peercerts(
                    self, server_hostname=self._TRUSTSTORE_SERVER_HOSTNAME
                )
                return ret

        self._ctx.sslobject_class = TruststoreSSLObject

    def wrap_socket(self, sock: socket.socket, server_hostname: Optional[str] = None):
        ssl_sock = self._ctx.wrap_socket(sock, server_hostname=server_hostname)
        _verify_peercerts(ssl_sock, server_hostname=server_hostname)
        return ssl_sock

    def wrap_bio(
        self,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
        server_hostname: Optional[str] = None,
        server_side: bool = False,
    ) -> ssl.SSLObject:

        # Super hacky way of passing the server_hostname value forward to sslobject_class.
        self._ctx.sslobject_class._TRUSTSTORE_SERVER_HOSTNAME = server_hostname
        ssl_obj = self._ctx.wrap_bio(
            incoming, outgoing, server_hostname=server_hostname, server_side=server_side
        )
        return ssl_obj

    def load_verify_locations(
        self, cafile=None, capath=None, cadata: str | bytes | None = ...
    ) -> None:
        # Ignore certifi.where() being used as a default, otherwise we raise an error.
        if (
            _CERTIFI_WHERE
            and not cadata
            and (cafile is None or cafile == _CERTIFI_WHERE)
            and (capath is None or capath == _CERTIFI_WHERE)
        ):
            return
        raise NotImplementedError(
            "TruststoreSSLContext.load_verify_locations() isn't implemented"
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ctx, name)


def _verify_peercerts(
    sock_or_sslobj: ssl.SSLSocket | ssl.SSLObject, server_hostname: Optional[str]
) -> None:
    """
    Verifies the peer certificates from an SSLSocket or SSLObject
    against the certificates in the OS trust store.
    """
    sslobj: ssl.SSLObject = sock_or_sslobj
    try:
        while not hasattr(sslobj, "get_unverified_chain"):
            sslobj = sslobj._sslobj
    except AttributeError:
        pass

    cert_bytes = [
        cert.public_bytes(ENCODING_DER) for cert in sslobj.get_unverified_chain()
    ]
    _verify_peercerts_impl(cert_bytes, server_hostname=server_hostname)

    if server_hostname is not None:
        # SSLObject.get_verified_chain()[0].get_info() isn't the same as .getpeercert()
        # as .getpeercert() is None when verify_mode=CERT_NONE whereas get_verified_chain()
        # always returns the peers certificate decoded.
        _match_hostname(
            cert=sslobj.get_verified_chain()[0].get_info(), hostname=server_hostname
        )


def _dnsname_match(
    dn: Any, hostname: str, max_wildcards: int = 1
) -> Union[Optional[Match[str]], bool]:
    """Matching according to RFC 6125, section 6.4.3

    http://tools.ietf.org/html/rfc6125#section-6.4.3
    """
    pats = []
    if not dn:
        return False

    # Ported from python3-syntax:
    # leftmost, *remainder = dn.split(r'.')
    parts = dn.split(r".")
    leftmost = parts[0]
    remainder = parts[1:]

    wildcards = leftmost.count("*")
    if wildcards > max_wildcards:
        # Issue #17980: avoid denials of service by refusing more
        # than one wildcard per fragment.  A survey of established
        # policy among SSL implementations showed it to be a
        # reasonable choice.
        raise ssl.SSLCertVerificationError(
            "too many wildcards in certificate DNS name: " + repr(dn)
        )

    # speed up common case w/o wildcards
    if not wildcards:
        return bool(dn.lower() == hostname.lower())

    # RFC 6125, section 6.4.3, subitem 1.
    # The client SHOULD NOT attempt to match a presented identifier in which
    # the wildcard character comprises a label other than the left-most label.
    if leftmost == "*":
        # When '*' is a fragment by itself, it matches a non-empty dotless
        # fragment.
        pats.append("[^.]+")
    elif leftmost.startswith("xn--") or hostname.startswith("xn--"):
        # RFC 6125, section 6.4.3, subitem 3.
        # The client SHOULD NOT attempt to match a presented identifier
        # where the wildcard character is embedded within an A-label or
        # U-label of an internationalized domain name.
        pats.append(re.escape(leftmost))
    else:
        # Otherwise, '*' matches any dotless string, e.g. www*
        pats.append(re.escape(leftmost).replace(r"\*", "[^.]*"))

    # add the remaining fragments, ignore any wildcards
    for frag in remainder:
        pats.append(re.escape(frag))

    pat = re.compile(r"\A" + r"\.".join(pats) + r"\Z", re.IGNORECASE)
    return pat.match(hostname)


def _ipaddress_match(ipname: Any, host_ip: str) -> bool:
    """Exact matching of IP addresses.

    RFC 6125 explicitly doesn't define an algorithm for this
    (section 1.7.2 - "Out of Scope").
    """
    # OpenSSL may add a trailing newline to a subjectAltName's IP address
    # Divergence from upstream: ipaddress can't handle byte str
    ip = ipaddress.ip_address(ipname.rstrip())
    return bool(ip == host_ip)


def _match_hostname(
    cert: Optional[Any],
    hostname: str,
    hostname_checks_common_name: bool = False,
) -> None:
    """Verify that *cert* (in decoded format as returned by
    SSLSocket.getpeercert()) matches the *hostname*.  RFC 2818 and RFC 6125
    rules are followed, but IP addresses are not accepted for *hostname*.

    CertificateError is raised on failure. On success, the function
    returns nothing.
    """
    if not cert:
        raise ValueError(
            "empty or no certificate, match_hostname needs a "
            "SSL socket or SSL context with either "
            "CERT_OPTIONAL or CERT_REQUIRED"
        )
    try:
        # Divergence from upstream: ipaddress can't handle byte str
        host_ip = ipaddress.ip_address(hostname)
    except ValueError:
        # Not an IP address (common case)
        host_ip = None

    dnsnames = []
    san: Tuple[Tuple[str, str], ...] = cert.get("subjectAltName", ())
    key: str
    value: str
    for key, value in san:
        if key == "DNS":
            if host_ip is None and _dnsname_match(value, hostname):
                return
            dnsnames.append(value)
        elif key == "IP Address":
            if host_ip is not None and _ipaddress_match(value, host_ip):
                return
            dnsnames.append(value)

    # We only check 'commonName' if it's enabled and we're not verifying
    # an IP address. IP addresses aren't valid within 'commonName'.
    if hostname_checks_common_name and host_ip is None and not dnsnames:
        for sub in cert.get("subject", ()):
            for key, value in sub:
                if key == "commonName":
                    if _dnsname_match(value, hostname):
                        return
                    dnsnames.append(value)

    if len(dnsnames) > 1:
        raise ssl.SSLCertVerificationError(
            "hostname %r "
            "doesn't match either of %s" % (hostname, ", ".join(map(repr, dnsnames)))
        )
    elif len(dnsnames) == 1:
        raise ssl.SSLCertVerificationError(
            f"hostname {hostname!r} doesn't match {dnsnames[0]!r}"
        )
    else:
        raise ssl.SSLCertVerificationError(
            "no appropriate subjectAltName fields were found"
        )
