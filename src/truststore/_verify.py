import ssl


class PeerVerificationState:
    """Verification settings captured before temporary context changes."""

    __slots__ = ("check_hostname", "context", "verify_flags", "verify_mode")

    # Keep the context because capath certificates can resolve during handshake.
    context: ssl.SSLContext
    check_hostname: bool
    verify_flags: ssl.VerifyFlags
    verify_mode: ssl.VerifyMode

    def __init__(self, context: ssl.SSLContext) -> None:
        """Capture settings used by the platform verifier."""
        self.context = context
        self.check_hostname = context.check_hostname
        self.verify_flags = context.verify_flags
        self.verify_mode = context.verify_mode

    def custom_ca_certs(self) -> tuple[bytes, ...]:
        """Return CA certificates after OpenSSL has resolved lazy capath entries."""
        return tuple(self.context.get_ca_certs(binary_form=True))
