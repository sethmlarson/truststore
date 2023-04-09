"""
This is the "Hazardous Materials" part of the truststore API. It
contains advanced cryptographic primitives that are often dangerous
and can be used incorrectly. They require an in-depth knowledge of the
cryptographic concepts at work. Using this part of the API without a
thorough understanding of the details involved will put your
application and its users at severe risk.
"""

from ._api import verify_cert_chain
