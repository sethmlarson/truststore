"""Verify certificates using OS trust stores"""

import platform
import ssl
from typing import List, Optional

from _ssl import ENCODING_DER

__all__ = ["verify_peercerts"]
__version__ = "0.1.0"


def _verify_peercerts(
    certs: List[bytes], server_hostname: Optional[str] = None
) -> None:
    ...


# ===== macOS =====

if platform.system() == "Darwin":
    import ctypes
    import ssl
    from ctypes import (
        CDLL,
        CFUNCTYPE,
        POINTER,
        c_bool,
        c_byte,
        c_char_p,
        c_int32,
        c_long,
        c_size_t,
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
    CFDictionary = c_void_p
    CFError = c_void_p
    CFType = c_void_p
    CFTypeID = c_ulong

    CFTypeRef = POINTER(CFType)
    CFAllocatorRef = c_void_p

    OSStatus = c_int32

    CFDataRef = POINTER(CFData)
    CFStringRef = POINTER(CFString)
    CFArrayRef = POINTER(CFArray)
    CFMutableArrayRef = POINTER(CFMutableArray)
    CFDictionaryRef = POINTER(CFDictionary)
    CFArrayCallBacks = c_void_p
    CFDictionaryKeyCallBacks = c_void_p
    CFDictionaryValueCallBacks = c_void_p

    SecCertificateRef = POINTER(c_void_p)
    SecPolicyRef = POINTER(c_void_p)
    SecTrustRef = POINTER(c_void_p)
    SecTrustResultType = c_uint32
    SecTrustOptionFlags = c_uint32

    try:
        Security.SecCertificateGetTypeID.argtypes = []
        Security.SecCertificateGetTypeID.restype = CFTypeID

        Security.SecCertificateCreateWithData.argtypes = [CFAllocatorRef, CFDataRef]
        Security.SecCertificateCreateWithData.restype = SecCertificateRef

        Security.SecCertificateCopyData.argtypes = [SecCertificateRef]
        Security.SecCertificateCopyData.restype = CFDataRef

        Security.SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
        Security.SecCopyErrorMessageString.restype = CFStringRef

        Security.SecTrustSetAnchorCertificates.argtypes = [SecTrustRef, CFArrayRef]
        Security.SecTrustSetAnchorCertificates.restype = OSStatus

        Security.SecTrustSetAnchorCertificatesOnly.argstypes = [SecTrustRef, Boolean]
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

        Security.SecCopyErrorMessageString.argtypes = [OSStatus, c_void_p]
        Security.SecCopyErrorMessageString.restype = CFStringRef

        Security.SecTrustRef = SecTrustRef
        Security.SecTrustResultType = SecTrustResultType
        Security.OSStatus = OSStatus

        CoreFoundation.CFRetain.argtypes = [CFTypeRef]
        CoreFoundation.CFRetain.restype = CFTypeRef

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

        CoreFoundation.CFDictionaryCreate.argtypes = [
            CFAllocatorRef,
            POINTER(CFTypeRef),
            POINTER(CFTypeRef),
            CFIndex,
            CFDictionaryKeyCallBacks,
            CFDictionaryValueCallBacks,
        ]
        CoreFoundation.CFDictionaryCreate.restype = CFDictionaryRef

        CoreFoundation.CFDictionaryGetValue.argtypes = [CFDictionaryRef, CFTypeRef]
        CoreFoundation.CFDictionaryGetValue.restype = CFTypeRef

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

        CoreFoundation.kCFAllocatorDefault = CFAllocatorRef.in_dll(
            CoreFoundation, "kCFAllocatorDefault"
        )
        CoreFoundation.kCFTypeArrayCallBacks = c_void_p.in_dll(
            CoreFoundation, "kCFTypeArrayCallBacks"
        )
        CoreFoundation.kCFTypeDictionaryKeyCallBacks = c_void_p.in_dll(
            CoreFoundation, "kCFTypeDictionaryKeyCallBacks"
        )
        CoreFoundation.kCFTypeDictionaryValueCallBacks = c_void_p.in_dll(
            CoreFoundation, "kCFTypeDictionaryValueCallBacks"
        )

        CoreFoundation.CFTypeRef = CFTypeRef
        CoreFoundation.CFArrayRef = CFArrayRef
        CoreFoundation.CFStringRef = CFStringRef
        CoreFoundation.CFDictionaryRef = CFDictionaryRef

    except AttributeError:
        raise ImportError("Error initializing ctypes") from None

    class CFConst:
        """
        A class object that acts as essentially a namespace for CoreFoundation
        constants.
        """

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

    def _create_cf_string_array(lst: List[bytes]) -> CFMutableArray:
        """
        Given a list of Python binary data, create an associated CFMutableArray.
        The array must be CFReleased by the caller.
        Raises an ssl.SSLError on failure.
        """
        cf_array = None
        try:
            cf_array = CoreFoundation.CFArrayCreateMutable(
                CoreFoundation.kCFAllocatorDefault,
                0,
                ctypes.byref(CoreFoundation.kCFTypeArrayCallBacks),
            )
            if not cf_array:
                raise MemoryError("Unable to allocate memory!")
            for item in lst:
                cf_string = _bytes_to_cf_string(item)
                if not cf_string:
                    raise MemoryError("Unable to allocate memory!")
                try:
                    CoreFoundation.CFArrayAppendValue(cf_array, cf_string)
                finally:
                    CoreFoundation.CFRelease(cf_string)
        except BaseException as e:
            if cf_array:
                CoreFoundation.CFRelease(cf_array)
            raise ssl.SSLError(f"Unable to allocate array: {e}") from None
        return cf_array

    def _verify_peercerts(cert_chain: List[bytes], server_hostname=None) -> None:
        certs = None
        policy = None
        trust = None
        try:
            if server_hostname is not None:
                cf_str_hostname = None
                try:
                    cf_str_hostname = _bytes_to_cf_string(
                        server_hostname.encode("ascii")
                    )
                    policy = Security.SecPolicyCreateSSL(False, cf_str_hostname)
                finally:
                    if cf_str_hostname:
                        CoreFoundation.CFRelease(cf_str_hostname)
            else:
                policy = Security.SecPolicyCreateSSL(False, None)

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
                        if cf_data is not None:
                            CoreFoundation.CFRelease(cf_data)
                        if cert is not None:
                            CoreFoundation.CFRelease(cert)

                # Now that we have certificates loaded and a SecPolicy
                # we can finally create a SecTrust object!
                trust = Security.SecTrustRef()
                status = Security.SecTrustCreateWithCertificates(
                    certs, policy, ctypes.byref(trust)
                )
                # TODO: Check status

            finally:
                # The certs are now being held by SecTrust so we can
                # release our handles for the array.
                if certs:
                    CoreFoundation.CFRelease(certs)

            # Add the default anchor certificates to the SecTrust
            status = Security.SecTrustSetAnchorCertificates(trust, None)
            # TODO: Check status

            cf_error = CoreFoundation.CFError()
            success = Security.SecTrustEvaluateWithError(trust, ctypes.byref(cf_error))

        finally:
            if policy is not None:
                CoreFoundation.CFRelease(policy)
            if trust is not None:
                CoreFoundation.CFRelease(trust)


# ===== Windows =====

elif platform.system() == "Windows":
    pass

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
        "/etc/ssl/certs",  # SLES10/SLES11
        "/etc/pki/tls/certs",  # Fedora/RHEL
        "/system/etc/security/cacerts",  # Android
        "/etc/ssl/certs",  # FreeBSD 12.2+
        "/usr/local/share/certs",  # FreeBSD
        "/etc/openssl/certs",  # NetBSD
        "/etc/certs/CA",  # Solaris
    ]


def verify_peercerts(
    sock_or_sslobj: ssl.SSLSocket | ssl.SSLObject, server_hostname: Optional[str] = None
) -> None:
    """
    Verifies the peer certificates from an SSLSocket or SSLObject
    against the certificates in the OS trust store.
    """
    sslobj: ssl.SSLObject
    if isinstance(sock_or_sslobj, ssl.SSLSocket):
        sslobj = sock_or_sslobj._sslobj
    elif isinstance(sock_or_sslobj, ssl.SSLObject):
        sslobj = sock_or_sslobj
    else:
        raise TypeError(
            "Must either pass a single 'socket.socket' or two 'ssl.MemoryBIO'"
        )

    certs = [cert.public_bytes(ENCODING_DER) for cert in sslobj.get_unverified_chain()]
    _verify_peercerts(certs, server_hostname=server_hostname)
